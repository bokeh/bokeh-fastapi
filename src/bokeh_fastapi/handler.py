from __future__ import annotations

import calendar
import datetime as dt
import json
import logging

from typing import TYPE_CHECKING, Any, cast, Optional
from urllib.parse import urlparse

from fastapi import (
    Request, WebSocket, WebSocketDisconnect
)
from fastapi.responses import HTMLResponse

from panel.io.server import server_html_page_for_session
from bokeh.protocol import Protocol
from bokeh.protocol.exceptions import MessageError, ProtocolError, ValidationError
from bokeh.protocol.message import Message
from bokeh.protocol.receiver import Receiver
from bokeh.server.contexts import ApplicationContext
from bokeh.server.protocol_handler import ProtocolHandler
from bokeh.server.session import ServerSession
from bokeh.server.util import check_allowlist
from bokeh.settings import settings
from bokeh.util.token import (
    check_token_signature,
    generate_jwt_token,
    generate_session_id,
    get_session_id,
    get_token_payload,
)
from tornado.ioloop import IOLoop

if TYPE_CHECKING:
    from .application import BokehFastAPI


#-----------------------------------------------------------------------------
# Globals and constants
#-----------------------------------------------------------------------------

log = logging.getLogger(__name__)

__all__ = (
    'DocHandler',
    'WSHandler',
)

#-----------------------------------------------------------------------------
# General API
#-----------------------------------------------------------------------------

class SessionHandler:

    def __init__(self, application: BokehFastAPI, application_context: ApplicationContext):
        self.application = application
        self.application_context = application_context

    async def get_session(
        self,
        request: Request,
        session_id: Optional[str],
        token: Optional[str] = None
    ) -> ServerSession:
        app = self.application
        if session_id is None:
            session_id = generate_session_id(
                secret_key=app.secret_key,
                signed=app.sign_sessions
            )
    
        # Patch the request
        request.protocol = 'http'
        request.host = request.client.host
        request.uri = request.url.path

        if app.include_headers is None:
            excluded_headers = (app.exclude_headers or [])
            allowed_headers = [header for header in request.headers
                               if header not in excluded_headers]
        else:
            allowed_headers = app.include_headers
        headers = {k: v for k, v in request.headers.items()
                   if k in allowed_headers}

        if app.include_cookies is None:
            excluded_cookies = (app.exclude_cookies or [])
            allowed_cookies = [cookie for cookie in request.cookies
                               if cookie not in excluded_cookies]
        else:
            allowed_cookies = app.include_cookies
        cookies = {k: v for k, v in request.cookies.items()
                   if k in allowed_cookies}

        if cookies and 'Cookie' in headers and 'Cookie' not in (app.include_headers or []):
            # Do not include Cookie header since cookies can be restored from cookies dict
            del headers['Cookie']

        arguments = {} if request.query_params is None else request.query_params._dict
        payload = {'headers': headers, 'cookies': cookies, 'arguments': arguments}
        payload.update(self.application_context.application.process_request(request))
        token = generate_jwt_token(
            session_id,
            secret_key=app.secret_key,
            signed=app.sign_sessions,
            expiration=300,
            extra_payload=payload
        )
        if self.application_context.io_loop is None:
            self.application_context._loop = IOLoop.current()
        session = await self.application_context.create_session_if_needed(
            session_id, request, token
        )
        return session


class DocHandler(SessionHandler):

    async def get(self, request: Request, bokeh_session_id: Optional[str] = None) -> HTMLResponse:
        session = await self.get_session(request, bokeh_session_id)
        page = server_html_page_for_session(
            session,
            resources=self.application.resources(),
            title=session.document.title,
            template=session.document.template,
            template_variables=session.document.template_variables
        )
        return HTMLResponse(page)


class WSHandler(SessionHandler):
    
    def __init__(self, application: BokehFastAPI, application_context: ApplicationContext):
        super().__init__(application, application_context)
        self.receiver = None
        self.handler = None
        self.connection = None
        self._socket = None

    def check_origin(self, origin: str) -> bool:
        ''' Implement a check_origin policy for Tornado to call.

        The supplied origin will be compared to the Bokeh server allowlist. If the
        origin is not allow, an error will be logged and ``False`` will be returned.

        Args:
            origin (str) :
                The URL of the connection origin

        Returns:
            bool, True if the connection is allowed, False otherwise

        '''
        parsed_origin = urlparse(origin)
        origin_host = parsed_origin.netloc.lower()

        allowed_hosts = self.application.websocket_origins
        if settings.allowed_ws_origin():
            allowed_hosts = set(settings.allowed_ws_origin())

        allowed = check_allowlist(origin_host, allowed_hosts)
        if allowed:
            return True
        else:
            log.error("Refusing websocket connection from Origin '%s'; \
                      use --allow-websocket-origin=%s or set BOKEH_ALLOW_WS_ORIGIN=%s to permit this; currently we allow origins %r",
                      origin, origin_host, origin_host, allowed_hosts)
            return False

    async def ws_connect(self, websocket):
        if len(websocket.scope['subprotocols']) == 2:
            subprotocol, token = websocket.scope['subprotocols']
        else:
            subprotocol = None
        if subprotocol != 'bokeh' or token is None:
            websocket.close()
            raise RuntimeError("Subprotocol header is not 'bokeh' or token not provided")

        now = calendar.timegm(dt.datetime.now(tz=dt.timezone.utc).timetuple())
        payload = get_token_payload(token)
        if 'session_expiry' not in payload:
            websocket.close()
            raise RuntimeError("Session expiry has not been provided")
        elif now >= payload['session_expiry']:
            websocket.close()
            raise RuntimeError("Token is expired.")
        elif not check_token_signature(
            token,
            signed=self.application.sign_sessions,
            secret_key=self.application.secret_key
        ):
            session_id = get_session_id(token)
            log.error("Token for session %r had invalid signature", session_id)
            raise ProtocolError("Invalid token signature")

        self._socket = websocket
        await websocket.accept('bokeh')

        try:
            await self._async_open(websocket, token)
        except Exception as e:
            # this isn't really an error (unless we have a
            # bug), it just means a client disconnected
            # immediately, most likely.
            print(e)
            log.debug("Failed to fully open connection %r", e)
            return

        try:
            await self._receive_loop()
        except Exception:
            pass

    async def _receive(self, fragment: str | bytes) -> Optional[Message[Any]]:
        # Receive fragments until a complete message is assembled
        try:
            message = await self.receiver.consume(fragment)
            return message
        except (MessageError, ProtocolError, ValidationError) as e:
            self._protocol_error(str(e))
            return None

    async def _handle(self, message: Message[Any]) -> Optional[Any]:
        # Handle the message, possibly resulting in work to do
        try:
            work = await self.handler.handle(message, self.connection)
            return work
        except (MessageError, ProtocolError, ValidationError) as e: # TODO (other exceptions?)
            self._internal_error(str(e))
            return None

    async def _schedule(self, work: Any) -> None:
        if isinstance(work, Message):
            await self.send_message(cast(Message[Any], work))
        else:
            self._internal_error(f"expected a Message not {work!r}")

        return None

    async def _receive_loop(self):
        while True:
            try:
                ws_msg = await self._socket.receive()
            except WebSocketDisconnect as e:
                log.info('WebSocket connection closed: code=%s, reason=%r', e.code, e.reason)
                self.application.client_lost(self.connection)

            if 'text' in ws_msg:
                fragment = ws_msg['text']
            elif 'bytes' in ws_msg:
                fragment = ws_msg['bytes']
            else:
                continue

            try:
                message = await self._receive(fragment)
            except Exception as e:
                # If you go look at self._receive, it's catching the
                # expected error types... here we have something weird.
                log.error("Unhandled exception receiving a message: %r: %r", e, fragment, exc_info=True)
                self._internal_error("server failed to parse a message")
                message = None

            if not message:
                continue
            try:
                work = await self._handle(message)
                if work:
                    await self.send_message(work)
            except Exception as e:
                log.error("Handler or its work threw an exception: %r: %r", e, message, exc_info=True)
                self._internal_error("server failed to handle a message")

    def _internal_error(self, message: str) -> None:
        log.error("Bokeh Server internal error: %s, closing connection", message)
        self._socket.close(10000, message)
        self.on_close(10000, message)

    def _protocol_error(self, message: str) -> None:
        log.error("Bokeh Server protocol error: %s, closing connection", message)
        self._socket.close(10001, message)

    async def _async_open(self, socket: WebSocket, token: str):
        session_id = get_session_id(token)
        await self.application_context.create_session_if_needed(session_id, socket.scope, token)
        session = self.application_context.get_session(session_id)

        protocol = Protocol()
        log.debug("Receiver created for %r", protocol)
        self.receiver = Receiver(protocol)

        self.handler = ProtocolHandler()
        log.debug("ProtocolHandler created for %r", protocol)

        self.connection = self.application.new_connection(
            protocol, self, self.application_context, session
        )

        msg = self.connection.protocol.create('ACK')
        await self.send_message(msg)

    def on_close(self, code: int, reason: str) -> None:
        ''' Clean up when the connection is closed.

        '''
        log.info('WebSocket connection closed: code=%s, reason=%r', code, reason)
        if self.connection is not None:
            self.application.client_lost(self.connection)

    async def send_text(self, text):
        await self._socket.send_text(text)
        
    async def send_bytes(self, bytestream):
        await self._socket.send_bytestream(bytestream)

    async def send_message(self, message: Message) -> int:
        sent = 0
        try:
            await self._socket.send_text(message.header_json)
            sent += len(message.header_json)

            await self._socket.send_text(message.metadata_json)
            sent += len(message.metadata_json)

            await self._socket.send_text(message.content_json)
            sent += len(message.content_json)

            for header, payload in message._buffers:
                await self._socket.send_text(json.dumps(header))
                await self._socket.send_bytes(payload)
                sent += len(header) + len(payload)
        except WebSocketDisconnect as e:
            self.on_close(e.code, e.reason)
        return sent
