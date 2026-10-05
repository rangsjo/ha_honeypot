"""Tests for the own_ip helpers that don't need root (the namespace setup itself
is tested in Docker, see README)."""

import random

import netns
import persona


def test_parse_default_iface():
    out = "default via 192.168.1.1 dev enp2s0 proto dhcp src 192.168.1.204 metric 100\n"
    assert netns.parse_default_iface(out) == "enp2s0"
    assert netns.parse_default_iface("") is None


def test_parse_ipv4():
    out = "5: honeypot0    inet 192.168.1.128/24 brd 192.168.1.255 scope global honeypot0\n"
    assert netns.parse_ipv4(out) == "192.168.1.128"
    assert netns.parse_ipv4("") is None


def test_persona_mac_is_a_real_vendor_prefix():
    for seed in range(20):
        mac = persona.generate(random.Random(seed))["mac"]
        assert mac[:8] in {o for ouis in persona.OUIS.values() for o in ouis}
        assert not int(mac[:2], 16) & 0x02  # not "randomized"/locally administered


def test_parse_gateway():
    assert netns.parse_gateway("default via 192.168.1.1 dev honeypot0\n") == "192.168.1.1"
    assert netns.parse_gateway("192.168.1.0/24 dev honeypot0 proto kernel\n") is None


def test_refresh_ip_follows_dhcp_renewal(tmp_path):
    own = netns.OwnIP("00:11:32:00:00:01", "nas")
    own.ip = "192.168.1.191"
    f = tmp_path / "ip"
    assert own.refresh_ip(f) is None          # no file yet
    f.write_text("192.168.1.191\n")
    assert own.refresh_ip(f) is None          # unchanged
    f.write_text("192.168.1.77\n")
    assert own.refresh_ip(f) == "192.168.1.77" and own.ip == "192.168.1.77"
