from __future__ import annotations

import logging

from typing import TYPE_CHECKING, Any, Mapping, Sequence, Optional
from urllib.parse import urljoin

from bokeh.application import Application
from bokeh.application.handlers.document_lifecycle import DocumentLifecycleHandler
from bokeh.application.handlers.function import FunctionHandler
from bokeh.embed.bundle import extension_dirs
from bokeh.resources import Resources
from bokeh.server.connection import ServerConnection
from bokeh.server.contexts import ApplicationContext
from bokeh.server.session import ServerSession
from bokeh.server.views.static_handler import StaticHandler
from bokeh.settings import settings
from fastapi import APIRouter, FastAPI
from fastapi.staticfiles import StaticFiles

from .handler import DocHandler, WSHandler

if TYPE_CHECKING:
    from bokeh.application.handlers.function import ModifyDoc

    from bokeh.protocol import Protocol

#-----------------------------------------------------------------------------
# Globals and constants
#-----------------------------------------------------------------------------

log = logging.getLogger(__name__)

DEFAULT_CHECK_UNUSED_MS                  = 17000
DEFAULT_KEEP_ALIVE_MS                    = 37000  # heroku, nginx default to 60s timeout, so use less than that
DEFAULT_UNUSED_LIFETIME_MS               = 15000
DEFAULT_SESSION_TOKEN_EXPIRATION         = 300

__all__ = (
    'BokehFastAPI',
)

#-----------------------------------------------------------------------------
# General API
#-----------------------------------------------------------------------------

class BokehFastAPI:
    """
        applications (dict[str,Application] or Application) :
            A map from paths to ``Application`` instances.

            If the value is a single Application, then the following mapping
            is generated:

            .. code-block:: python

                applications = {{ '/' : applications }}

            When a connection comes in to a given path, the associate
            Application is used to generate a new document for the session.

        prefix (str, optional) :
            A URL prefix to use for all Bokeh server paths. (default: None)

        secret_key (str, optional) :
            A secret key for signing session IDs.

            Defaults to the current value of the environment variable
            ``BOKEH_SECRET_KEY``

        sign_sessions (bool, optional) :
            Whether to cryptographically sign session IDs

            Defaults to the current value of the environment variable
            ``BOKEH_SIGN_SESSIONS``. If ``True``, then ``secret_key`` must
            also be provided (either via environment setting or passed as
            a parameter value)

        keep_alive_milliseconds (int, optional) :
            Number of milliseconds between keep-alive pings
            (default: {DEFAULT_KEEP_ALIVE_MS})

            Pings normally required to keep the websocket open. Set to 0 to
            disable pings.

        check_unused_sessions_milliseconds (int, optional) :
            Number of milliseconds between checking for unused sessions
            (default: {DEFAULT_CHECK_UNUSED_MS})

        unused_session_lifetime_milliseconds (int, optional) :
            Number of milliseconds for unused session lifetime
            (default: {DEFAULT_UNUSED_LIFETIME_MS})

        include_headers (list, optional) :
            List of request headers to include in session context
            (by default all headers are included)

        exclude_headers (list, optional) :
            List of request headers to exclude in session context
            (by default all headers are included)

        include_cookies (list, optional) :
            List of cookies to include in session context
            (by default all cookies are included)

        exclude_cookies (list, optional) :
            List of cookies to exclude in session context
            (by default all cookies are included)

        session_token_expiration (int, optional) :
            Duration in seconds that a new session token is valid
            for session creation. After the expiry time has elapsed,
            the token will not be able create a new session
            (default: {DEFAULT_SESSION_TOKEN_EXPIRATION})
    """

    def __init__(
        self,
        applications: Mapping[str, Application | ModifyDoc] | Application | ModifyDoc,
        app: Optional[FastAPI] = None,
        prefix: Optional[str] = None,
        extra_websocket_origins: Optional[Sequence[str]] = None,
        secret_key: Optional[bytes] = settings.secret_key_bytes(),
        sign_sessions: bool = settings.sign_sessions(),
        generate_session_ids: bool = True,
        keep_alive_milliseconds: int = DEFAULT_KEEP_ALIVE_MS,
        check_unused_sessions_milliseconds: int = DEFAULT_CHECK_UNUSED_MS,
        unused_session_lifetime_milliseconds: int = DEFAULT_UNUSED_LIFETIME_MS,
        index: Optional[str] = None,
        xsrf_cookies: bool = False,
        include_headers: Optional[list[str]] = None,
        include_cookies: Optional[list[str]] = None,
        exclude_headers: Optional[list[str]] = None,
        exclude_cookies: Optional[list[str]] = None,
        session_token_expiration: int = DEFAULT_SESSION_TOKEN_EXPIRATION,
        **kwargs: Any
    ):
        if callable(applications):
            applications = Application(FunctionHandler(applications))

        if isinstance(applications, Application):
            applications = {'/': applications}
        else:
            applications = dict(applications)
        
        for url, application in applications.items():
            if callable(application):
                applications[url] = application = Application(FunctionHandler(application))
            if all(not isinstance(handler, DocumentLifecycleHandler) for handler in application._handlers):
                application.add(DocumentLifecycleHandler())

        # Wrap applications in ApplicationContext
        self._applications = {}
        for url, application in applications.items():
            self._applications[url] = ApplicationContext(application, url=url)

        if app is None:
            app = FastAPI()
        self.app = app

        if prefix is None:
            prefix = ""
        prefix = prefix.strip("/")
        if prefix:
            prefix = "/" + prefix

        self._prefix = prefix

        if keep_alive_milliseconds < 0:
            # 0 means "disable"
            raise ValueError("keep_alive_milliseconds must be >= 0")
        else:
            if keep_alive_milliseconds == 0:
                log.info("Keep-alive ping disabled")
            elif keep_alive_milliseconds != DEFAULT_KEEP_ALIVE_MS:
                log.info("Keep-alive ping configured every %d milliseconds", keep_alive_milliseconds)
        self._keep_alive_milliseconds = keep_alive_milliseconds

        if check_unused_sessions_milliseconds <= 0:
            raise ValueError("check_unused_sessions_milliseconds must be > 0")
        elif check_unused_sessions_milliseconds != DEFAULT_CHECK_UNUSED_MS:
            log.info("Check for unused sessions every %d milliseconds", check_unused_sessions_milliseconds)
        self._check_unused_sessions_milliseconds = check_unused_sessions_milliseconds

        if unused_session_lifetime_milliseconds <= 0:
            raise ValueError("unused_session_lifetime_milliseconds must be > 0")
        elif unused_session_lifetime_milliseconds != DEFAULT_UNUSED_LIFETIME_MS:
            log.info("Unused sessions last for %d milliseconds", unused_session_lifetime_milliseconds)
        self._unused_session_lifetime_milliseconds = unused_session_lifetime_milliseconds

        if exclude_cookies and include_cookies:
            raise ValueError("Declare either an include or an exclude list for the cookies, not both.")
        self._exclude_cookies = exclude_cookies
        self._include_cookies = include_cookies

        if exclude_headers and include_headers:
            raise ValueError("Declare either an include or an exclude list for the headers, not both.")
        self._exclude_headers = exclude_headers
        self._include_headers = include_headers

        if extra_websocket_origins is None:
            self._websocket_origins = set()
        else:
            self._websocket_origins = set(extra_websocket_origins)

        self._secret_key = secret_key
        self._sign_sessions = sign_sessions

        self._clients = set()
        self.router = APIRouter()

        for route, ctx in self._applications.items():
            doc_handler = DocHandler(self, application_context=ctx)
            self.router.add_api_route(f'{route}', doc_handler.get, methods=['GET'])
            ws_handler = WSHandler(self, application_context=ctx)
            route = route if route.endswith('/') else f'{route}/'
            self.router.add_websocket_route(f'{route}ws', ws_handler.ws_connect)
        app.include_router(self.router)

        # Mount static file handlers
        for ext_name, ext_path in extension_dirs.items():
            app.mount(f"/static/extensions/{ext_name}", StaticFiles(directory=ext_path), name=ext_name)
        app.mount("/static", StaticFiles(directory=settings.bokehjs_path()), name="static")

    def new_connection(
        self, protocol: Protocol, socket: WSHandler,
        application_context: ApplicationContext, session: ServerSession
    ) -> ServerConnection:
        connection = ServerConnection(protocol, socket, application_context, session)
        self._clients.add(connection)
        return connection

    def client_lost(self, connection: ServerConnection) -> None:
        self._clients.discard(connection)
        connection.detach_session()

    @property
    def websocket_origins(self) -> set[str]:
        ''' A list of websocket origins permitted to connect to this server.

        '''
        return self._websocket_origins

    @property
    def secret_key(self) -> Optional[bytes]:
        ''' A secret key for this Bokeh Server Tornado Application to use when
        signing session IDs, if configured.

        '''
        return self._secret_key

    @property
    def include_cookies(self) -> Optional[list[str]]:
        ''' A list of request cookies to make available in the session
        context.

        '''
        return self._include_cookies

    @property
    def include_headers(self) -> Optional[list[str]]:
        ''' A list of request headers to make available in the session
        context.

        '''
        return self._include_headers

    @property
    def exclude_cookies(self) -> Optional[list[str]]:
        ''' A list of request cookies to exclude in the session context.

        '''
        return self._exclude_cookies

    @property
    def exclude_headers(self) -> Optional[list[str]]:
        ''' A list of request headers to exclude in the session context.

        '''
        return self._exclude_headers

    @property
    def sign_sessions(self) -> bool:
        ''' Whether this Bokeh Server Tornado Application has been configured
        to cryptographically sign session IDs

        If ``True``, then ``secret_key`` must also have been configured.
        '''
        return self._sign_sessions

    @property
    def generate_session_ids(self) -> bool:
        ''' Whether this Bokeh Server Tornado Application has been configured
        to automatically generate session IDs.

        '''
        return self._generate_session_ids

    @property
    def session_token_expiration(self) -> int:
        ''' Duration in seconds that a new session token is valid for
        session creation.

        After the expiry time has elapsed, the token will not be able
        create a new session.
        '''
        return self._session_token_expiration

    def resources(self, absolute_url: Optional[str] = None) -> Resources:
        mode = settings.resources(default="server")
        if mode == "server":
            root_url = urljoin(absolute_url, self._prefix) if absolute_url else self._prefix
            return Resources(mode="server", root_url=root_url, path_versioner=StaticHandler.append_version)
        return Resources(mode=mode)
