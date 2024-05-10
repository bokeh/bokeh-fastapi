from __future__ import annotations

import calendar
import contextlib
import datetime as dt
import json
import os
import pathlib
from functools import partial
from types import FunctionType, MethodType
from typing import Optional
from urllib.parse import urljoin

from tornado.ioloop import IOLoop

from bokeh.application import Application
from bokeh.application.handlers.function import FunctionHandler
from bokeh.command.util import build_single_handler_application
from bokeh.document import Document
from bokeh.embed.bundle import extension_dirs
from bokeh.protocol import Protocol
from bokeh.protocol.message import Message
from bokeh.protocol.receiver import Receiver
from bokeh.resources import Resources
from bokeh.server.connection import ServerConnection
from bokeh.server.contexts import ApplicationContext
from bokeh.server.protocol_handler import ProtocolHandler
from bokeh.server.session import ServerSession
from bokeh.server.views.static_handler import StaticHandler
from bokeh.settings import settings
from bokeh.util.token import (
    generate_jwt_token,
    generate_session_id,
    get_session_id,
    get_token_payload,
)

from fastapi import APIRouter, FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from panel import panel as as_panel
from panel.io.server import server_html_page_for_session
from panel.io.state import set_curdoc


class DocRouter:
    def __init__(self, prefix: str, application_contexts: list[ApplicationContext]):
        self.application_contexts = application_contexts

        self._prefix = prefix
        self.router = APIRouter()
        for route, context in application_contexts.items():
            self.router.add_api_route("/{app:path}", self.get, methods=["GET"])
            self.router.add_websocket_route("/{app:path}/ws", self.ws_connect)
            if context.io_loop is None:
                context._loop = IOLoop.current()

    async def _get_session(
        self, app: str, request: Request, session_id: Optional[str]
    ) -> ServerSession:
        if session_id is None:
            session_id = generate_session_id(secret_key=None, signed=False)
        payload = {"headers": dict(request.headers), "cookies": dict(request.cookies)}
        token = generate_jwt_token(
            session_id,
            secret_key=None,
            signed=False,
            expiration=300,
            extra_payload=payload,
        )
        request.protocol = "http"
        request.host = request.client.host
        request.uri = request.url.path
        session = await self.application_contexts[f"/{app}"].create_session_if_needed(
            session_id, request, token
        )
        return session

    def resources(self, absolute_url: Optional[str] = None) -> Resources:
        mode = settings.resources(default="server")
        if mode == "server":
            root_url = (
                urljoin(absolute_url, self._prefix) if absolute_url else self._prefix
            )
            return Resources(
                mode="server",
                root_url=root_url,
                path_versioner=StaticHandler.append_version,
            )
        return Resources(mode=mode)

    async def get(
        self, app: str, request: Request, bokeh_session_id: Optional[str] = None
    ) -> HTMLResponse:
        if f"/{app}" not in self.application_contexts:
            return
        session = await self._get_session(app, request, bokeh_session_id)
        page = server_html_page_for_session(
            session,
            resources=self.resources(),
            title=session.document.title,
            template=session.document.template,
            template_variables=session.document.template_variables,
        )
        return HTMLResponse(page)

    async def ws_connect(self, websocket):
        app = websocket.path_params["app"]
        if len(websocket.scope["subprotocols"]) == 2:
            subprotocol, token = websocket.scope["subprotocols"]
        else:
            subprotocol = None
        if subprotocol != "bokeh" or token is None:
            websocket.close()
            raise RuntimeError(
                "Subprotocol header is not 'bokeh' or token not provided"
            )

        now = calendar.timegm(dt.datetime.now(tz=dt.timezone.utc).timetuple())
        payload = get_token_payload(token)
        if "session_expiry" not in payload:
            websocket.close()
            raise RuntimeError("Session expiry has not been provided")
        elif now >= payload["session_expiry"]:
            websocket.close()
            raise RuntimeError("Token is expired.")

        await websocket.accept("bokeh")
        self._websocket = websocket

        context = self.application_contexts[f"/{app}"]

        # log.debug("ProtocolHandler created for %r", protocol)

        await websocket_handler(websocket, context, token)


class SocketHandler:
    def __init__(self, websocket: WebSocket):
        self._socket = websocket

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
        except Exception as e:
            print(e)
        return sent


async def websocket_handler(
    socket: WebSocket, application_context: ApplicationContext, token
):
    session_id = get_session_id(token)
    await application_context.create_session_if_needed(session_id, socket.scope, token)
    session = application_context.get_session(session_id)

    ws_handler = SocketHandler(socket)
    protocol = Protocol()
    receiver = Receiver(protocol)
    handler = ProtocolHandler()
    connection = ServerConnection(protocol, ws_handler, application_context, session)

    msg = connection.protocol.create("ACK")
    await ws_handler.send_message(msg)

    with contextlib.suppress(WebSocketDisconnect):
        while True:
            fragment = await socket.receive_text()
            message = await receiver.consume(fragment)

            if not message:
                continue

            work = await handler.handle(message, connection)
            if not work:
                continue

            await ws_handler.send_message(work)

from panel.io.document import extra_socket_handlers
def dispatch_fastapi(conn, events=None, msg=None):
    if msg is None:
        msg = conn.protocol.create('PATCH-DOC', events)
    return [conn._socket.send_message(msg)]

extra_socket_handlers[SocketHandler] = dispatch_fastapi

def _eval_panel(obj, doc: Document):
    from panel.io.state import state
    from panel.template import BaseTemplate

    doc.on_event('document_ready', partial(state._schedule_on_load, doc))

    with set_curdoc(doc):
        if isinstance(obj, (FunctionType, MethodType)):
            obj = obj()
        if isinstance(obj, BaseTemplate):
            doc = obj._modify_doc(None, None, doc, True)
        else:
            doc = as_panel(obj)._modify_doc(None, None, doc, False)
        return doc

def add_application_routes(server, apps, prefix='/'):
    contexts = {}
    for url, app in apps.items():
        if isinstance(app, pathlib.Path):
            app = str(app)  # enables serving apps from Paths
        if (
            isinstance(app, str)
            and app.endswith((".py", ".ipynb", ".md"))
            and os.path.isfile(app)
        ):
            app = build_single_handler_application(app)
        elif not isinstance(app, Application):
            handler = FunctionHandler(partial(_eval_panel, app))
            app = Application(handler)
        contexts[url] = app_context = ApplicationContext(app, url=url)
    router = DocRouter(prefix=prefix, application_contexts=contexts)

    # Mount static file handlers
    for ext_name, ext_path in extension_dirs.items():
        server.mount(
            f"/static/extensions/{ext_name}",
            StaticFiles(directory=ext_path),
            name=ext_name,
        )
    server.mount("/static", StaticFiles(directory=settings.bokehjsdir()), name="static")

    # Mount application router
    server.include_router(router.router)


def create_server(apps):
    server = FastAPI()
    add_application_routes(server, apps)
    return server


def panel_app():
    import panel as pn
    import html
    slider = pn.widgets.IntSlider(start=0, end=10, value=5)
    out = pn.pane.Markdown('### ' + pn.rx('*') * slider)
    def callback():
        return pn.pane.HTML(
            "<br>".join(
                html.escape(line)
                for line in [
                        f"{pn.state.session_info=}",
                        f"{pn.state.curdoc=!r}",
                ]
            )
    )
    return pn.template.MaterialTemplate(main=[slider, out, callback], title='Hello World')

app = create_server({"/foo": panel_app})
