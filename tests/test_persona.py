"""Tests for the per-install persona."""

import json
import random

import persona


def test_generate_is_consistent_and_varies():
    seen = {json.dumps(persona.generate(random.Random(i)), sort_keys=True) for i in range(30)}
    assert len(seen) > 5
    p = persona.generate(random.Random(1))
    assert set(p) == set(persona.FIELDS)
    # SSH and telnet banners come from the same system profile.
    assert any(s["ssh_banner"] == p["ssh_banner"] and s["telnet_banner"] == p["telnet_banner"]
               for s in persona.SYSTEMS)


def test_persona_is_stable_across_restarts(tmp_path):
    path = tmp_path / "persona.json"
    first = persona.load_or_create(path)
    assert persona.load_or_create(path) == first


def test_overrides_win_but_are_not_saved(tmp_path):
    path = tmp_path / "persona.json"
    saved = persona.load_or_create(path)
    p = persona.load_or_create(path, {"hostname": "mynas", "http_title": "", "ha_url": "x"})
    assert p["hostname"] == "mynas"
    assert p["http_title"] == saved["http_title"]  # empty option = keep persona value
    assert "ha_url" not in p
    assert json.loads(path.read_text())["hostname"] == saved["hostname"]


def test_corrupt_file_is_replaced(tmp_path):
    path = tmp_path / "persona.json"
    path.write_text("{not json")
    p = persona.load_or_create(path)
    assert json.loads(path.read_text()) == p
