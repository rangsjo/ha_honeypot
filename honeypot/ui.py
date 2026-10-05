"""Ingress web UI: recent events, service status and a test-notification button."""

import os
from pathlib import Path

from aiohttp import web

from enrich import Enricher
from events import EventStore
from notifier import Notifier

HTML_PATH = Path(__file__).parent / "templates" / "index.html"
# The Supervisor's ingress proxy. With host_network the UI port is also
# reachable from the LAN, so refuse everyone else when running as an add-on.
INGRESS_IPS = {"172.30.32.2", "127.0.0.1", "::1"}


def make_app(store: EventStore, notifier: Notifier, status: dict,
             enricher: Enricher | None = None, alerts: EventStore | None = None, restrict: bool | None = None) -> web.Application:
    if restrict is None:
        restrict = "SUPERVISOR_TOKEN" in os.environ

    @web.middleware
    async def ingress_only(request: web.Request, handler):
        if restrict and request.remote not in INGRESS_IPS:
            raise web.HTTPForbidden()
        return await handler(request)

    async def index(request: web.Request) -> web.Response:
        return web.FileResponse(HTML_PATH)

    async def api_events(request: web.Request) -> web.Response:
        limit = min(int(request.query.get("limit", 200)), 1000)
        return web.json_response(store.recent(limit))

    async def api_status(request: web.Request) -> web.Response:
        return web.json_response({"services": status, "webhook": notifier.url})

    async def api_alerts(request: web.Request) -> web.Response:
        limit = min(int(request.query.get("limit", 50)), 300)
        return web.json_response(alerts.recent(limit) if alerts else [])

    async def api_hosts(request: web.Request) -> web.Response:
        return web.json_response(enricher.cached() if enricher else {})

    async def api_test(request: web.Request) -> web.Response:
        try:
            await notifier.test()
        except Exception as e:
            return web.json_response({"ok": False, "error": str(e)}, status=502)
        return web.json_response({"ok": True})

    app = web.Application(middlewares=[ingress_only])
    app.router.add_get("/", index)
    app.router.add_get("/api/events", api_events)
    app.router.add_get("/api/status", api_status)
    app.router.add_get("/api/hosts", api_hosts)
    app.router.add_get("/api/alerts", api_alerts)
    app.router.add_post("/api/test", api_test)
    return app
