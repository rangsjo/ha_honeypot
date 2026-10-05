"""Tests for the HA integration: notify channel, events, entities, ignore list, and
HAClient against a fake Home Assistant (REST + websocket)."""

import asyncio
import json

from aiohttp import WSMsgType, web

import channels
from entities import INTRUSION, LAST, TODAY, Entities
from ha_api import HAClient
from ignore import IgnoreList
from notifier import Notifier


# ── channels ──────────────────────────────────────────────────────────────────

def test_notify_service_accepts_both_spellings():
    assert channels.notify_service("notify.mobile_app_x") == "mobile_app_x"
    assert channels.notify_service(" mobile_app_x ") == "mobile_app_x"


def test_notification_data_has_panel_link_and_ignore_button():
    data = channels.notification_data({"src_ip": "192.168.1.9", "panel_path": "/local_honeypot"})
    assert data["url"] == data["clickAction"] == "/local_honeypot"
    assert data["push"]["interruption-level"] == "time-sensitive"
    assert data["actions"] == [{"action": "HONEYPOT_IGNORE_192.168.1.9", "title": "Ignore this device"}]
    assert "actions" not in channels.notification_data({"src_ip": ""})  # test alert


def test_critical_alerts_sound_on_silent():
    data = channels.notification_data({"src_ip": "192.168.1.9"}, critical=True)
    assert data["push"]["sound"] == {"name": "default", "critical": 1, "volume": 1.0}
    assert data["push"]["interruption-level"] == "critical"
    assert data["channel"] == "alarm_stream"
    assert "channel" not in channels.notification_data({"src_ip": "192.168.1.9"})


def test_parse_ignore_action_rejects_garbage():
    assert channels.parse_ignore_action("HONEYPOT_IGNORE_192.168.1.9") == "192.168.1.9"
    assert channels.parse_ignore_action("HONEYPOT_IGNORE_not-an-ip") is None
    assert channels.parse_ignore_action("SOME_OTHER_ACTION") is None
    assert channels.parse_ignore_action("") is None


# ── ignore list ───────────────────────────────────────────────────────────────

def test_ignore_list_persists(tmp_path):
    path = tmp_path / "ignored.json"
    ig = IgnoreList(path, ["10.0.0.1"])
    ig.add("192.168.1.9")
    assert "192.168.1.9" in ig and "10.0.0.1" in ig and "192.168.1.10" not in ig
    again = IgnoreList(path)
    assert "192.168.1.9" in again
    again.remove("192.168.1.9")
    assert "192.168.1.9" not in IgnoreList(path)


# ── notifier delivery ─────────────────────────────────────────────────────────

def _event(ip="192.168.1.9"):
    return {"service": "ssh", "kind": "login", "src_ip": ip, "username": "root", "password": "x"}


def test_deliver_succeeds_if_any_channel_works_and_fails_if_all_fail():
    saved = []

    async def ok(p):
        pass

    async def bad(p):
        raise RuntimeError("down")

    n = Notifier("http://ha", "", 0, on_alert=saved.append, channels=[bad, ok])
    assert asyncio.run(n.handle(_event())) is True
    n = Notifier("http://ha", "", 0, on_alert=saved.append, channels=[bad])
    assert asyncio.run(n.handle(_event())) is False
    assert [a["delivered"] for a in saved] == [True, False]


def test_no_target_configured_keeps_alert_without_retry_loop():
    saved = []
    n = Notifier("http://ha", "", 600, on_alert=saved.append)
    assert n.url is None
    asyncio.run(n.handle(_event()))
    asyncio.run(n.handle(_event()))  # within cooldown: suppressed, not retried
    assert len(saved) == 1 and saved[0]["delivered"] is False


# ── entities ──────────────────────────────────────────────────────────────────

class FakeHA:
    available = True

    def __init__(self):
        self.states = {}

    async def set_state(self, entity_id, state, attrs):
        self.states[entity_id] = (state, attrs)


def test_entities_intrusion_window_counter_and_last_intruder():
    now = [1_000_000.0]
    ha = FakeHA()
    ent = Entities(ha, hold=300, clock=lambda: now[0])
    asyncio.run(ent.publish())
    assert ha.states[INTRUSION][0] == "off" and ha.states[TODAY][0] == "0"

    ent.event(_event())
    ent.event(_event())
    ent.alert({**_event(), "message": "m", "ts": now[0],
               "host": {"ha_entities": ["Garage Pi"], "mac": "b8:27:eb:00:00:01", "vendor": "Raspberry Pi"}})
    asyncio.run(ent.publish())
    assert ha.states[INTRUSION][0] == "on"
    assert ha.states[TODAY][0] == "2"
    state, attrs = ha.states[LAST]
    assert state == "Garage Pi" and attrs["ip"] == "192.168.1.9" and attrs["vendor"] == "Raspberry Pi"

    ent.alert({**_event("192.168.1.50"), "ts": now[0] - 10, "host": {}})  # older alert finishing late
    asyncio.run(ent.publish({LAST}))
    assert ha.states[LAST][0] == "Garage Pi"

    now[0] += 301
    asyncio.run(ent.publish({INTRUSION}))
    assert ha.states[INTRUSION][0] == "off"


# ── HAClient against a fake Home Assistant ────────────────────────────────────

def test_ha_client_rest_and_websocket_against_fake_ha():
    calls = []

    async def rest(request):
        assert request.headers["Authorization"] == "Bearer tok"
        calls.append((request.method, request.match_info["tail"], await request.json()))
        return web.json_response({})

    async def websocket(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        await ws.send_json({"type": "auth_required"})
        assert (await ws.receive_json())["access_token"] == "tok"
        await ws.send_json({"type": "auth_ok"})
        sub = await ws.receive_json()
        assert sub["event_type"] == "mobile_app_notification_action"
        await ws.send_json({"id": 1, "type": "event",
                            "event": {"data": {"action": "HONEYPOT_IGNORE_192.168.1.9"}}})
        async for msg in ws:
            if msg.type == WSMsgType.CLOSE:
                break
        return ws

    async def go():
        app = web.Application()
        app.router.add_route("*", "/core/websocket", websocket)
        app.router.add_route("*", "/core/api/{tail:.*}", rest)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = runner.addresses[0][1]
        # First base is dead: the client must fall back to the second.
        ha = HAClient("tok", bases=["http://127.0.0.1:1/core", f"http://127.0.0.1:{port}/core"])

        send = channels.notify_channel(ha, "notify.mobile_app_phone")
        await send({"title": "T", "message": "M", "src_ip": "192.168.1.9", "panel_path": "/p"})
        await ha.fire_event("honeypot_alert", {"src_ip": "192.168.1.9"})
        await ha.set_state(INTRUSION, "on", {"device_class": "safety"})

        got, connected = asyncio.Queue(), []

        async def on_connect():
            connected.append(True)

        listener = asyncio.create_task(
            ha.listen("mobile_app_notification_action", lambda d: got.put(d), on_connect=on_connect))
        data = await asyncio.wait_for(got.get(), 5)
        listener.cancel()
        await runner.cleanup()
        return data, connected

    async def put_wrapper():
        return await go()

    data, connected = asyncio.run(put_wrapper())
    assert data == {"action": "HONEYPOT_IGNORE_192.168.1.9"}
    assert connected == [True]
    (m1, p1, b1), (m2, p2, b2), (m3, p3, b3) = calls
    assert (m1, p1) == ("POST", "services/notify/mobile_app_phone")
    assert b1["data"]["actions"][0]["action"] == "HONEYPOT_IGNORE_192.168.1.9"
    assert (m2, p2, b2) == ("POST", "events/honeypot_alert", {"src_ip": "192.168.1.9"})
    assert (m3, p3, b3["state"]) == ("POST", f"states/{INTRUSION}", "on")
    json.dumps(b1)  # payloads are plain JSON
