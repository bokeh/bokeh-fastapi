from functools import partial

import panel as pn

from bokeh.application import Application
from bokeh.application.handlers.function import FunctionHandler
from bokeh_fastapi import BokehFastAPI
from bokeh_fastapi.handler import WSHandler 
from panel.io.document import extra_socket_handlers

def dispatch_fastapi(conn, events=None, msg=None):
    if msg is None:
        msg = conn.protocol.create('PATCH-DOC', events)
    return [conn._socket.send_message(msg)]

extra_socket_handlers[WSHandler] = dispatch_fastapi

def panel_app(doc):

    from panel.io.state import set_curdoc

    doc.on_event('document_ready', partial(pn.state._schedule_on_load, doc))

    with set_curdoc(doc):
        slider = pn.widgets.IntSlider(start=0, end=10, value=5)
        out = pn.Column(
            pn.pane.Markdown('### ' + pn.rx('*') * slider),
            pn.state.session_info,
            pn.state.curdoc
        )
        tmpl = pn.template.MaterialTemplate(main=[slider, out], title='Hello World')
        tmpl.server_doc(doc)

handler = FunctionHandler(panel_app)
application = Application(handler)

app = BokehFastAPI(app).server
