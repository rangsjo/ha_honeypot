"""Fake web admin login page: logs every request, captures form and Basic-auth credentials."""

import base64
import html

from aiohttp import web

from services.common import Report

LOGIN_PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>{title}</title>
<style>
body{font-family:Arial,sans-serif;background:#e9edf1;margin:0}
.box{width:320px;margin:120px auto;background:#fff;padding:28px;border-radius:4px;box-shadow:0 1px 4px #0003}
h1{font-size:18px;margin:0 0 18px;color:#2a4d69}
input{width:100%;box-sizing:border-box;padding:8px;margin:6px 0 12px;border:1px solid #bbb}
button{width:100%;padding:9px;background:#2a4d69;color:#fff;border:0;cursor:pointer}
.err{color:#b00;font-size:13px}
</style></head><body><div class="box">
<h1>{title}</h1>
{error}
<form method="post" action="/login">
<label>Username</label><input name="username" autocomplete="username">
<label>Password</label><input name="password" type="password" autocomplete="current-password">
<button type="submit">Log in</button>
</form></div></body></html>"""

USER_FIELDS = ("username", "user", "login", "uname", "email", "name")
PASS_FIELDS = ("password", "pass", "passwd", "pwd")


def _page(title: str, error: str = "", status: int = 200) -> web.Response:
    body = (LOGIN_PAGE.replace("{title}", html.escape(title))
            .replace("{error}", f'<p class="err">{error}</p>' if error else ""))
    return web.Response(text=body, content_type="text/html", status=status)


def _basic_auth(header: str) -> tuple[str, str] | None:
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "basic":
        return None
    try:
        user, _, password = base64.b64decode(value).decode(errors="replace").partition(":")
    except ValueError:
        return None
    return user, password


def _pick(form, names: tuple[str, ...]) -> str | None:
    for key in form:
        if key.lower() in names:
            return str(form[key])
    return None


def make_app(report: Report, title: str = "Router Administration",
             server: str = "lighttpd/1.4.59") -> web.Application:
    async def handler(request: web.Request) -> web.Response:
        peer = request.transport.get_extra_info("peername") if request.transport else None
        target = f"{request.method} {request.path_qs}"[:200]
        auth = _basic_auth(request.headers.get("Authorization", ""))
        if auth:
            report("http", peer, "login", username=auth[0], password=auth[1], detail=target)
            return _page(title, "Invalid username or password.", 401)
        if request.method == "POST":
            form = await request.post()
            user, password = _pick(form, USER_FIELDS), _pick(form, PASS_FIELDS)
            if user is not None or password is not None:
                report("http", peer, "login", username=user or "", password=password or "", detail=target)
                return _page(title, "Invalid username or password.")
        ua = request.headers.get("User-Agent", "")[:120]
        report("http", peer, "connect", detail=f"{target} UA={ua!r}")
        return _page(title)

    async def disguise(request: web.Request, response: web.StreamResponse) -> None:
        response.headers["Server"] = server

    app = web.Application(client_max_size=64 * 1024)
    app.on_response_prepare.append(disguise)
    app.router.add_route("*", "/{tail:.*}", handler)
    return app


async def start(port: int, report: Report, title: str = "Router Administration",
                server: str = "lighttpd/1.4.59", host: str = "0.0.0.0", sock=None) -> web.AppRunner:
    runner = web.AppRunner(make_app(report, title, server), access_log=None)
    await runner.setup()
    site = web.SockSite(runner, sock) if sock is not None else web.TCPSite(runner, host, port)
    await site.start()
    return runner
