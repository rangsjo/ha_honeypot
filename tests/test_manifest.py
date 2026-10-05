"""Validate the add-on manifest the way the Supervisor does, so a bad schema
can't make the add-on silently disappear from the store."""

import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).parent.parent / "honeypot"
# Copied from the Supervisor (supervisor/addons/validate.py, RE_SCHEMA_ELEMENT).
RE_SCHEMA_ELEMENT = re.compile(
    r"^(?:"
    r"|bool"
    r"|email"
    r"|url"
    r"|port"
    r"|device(?:\((?P<filter>subsystem=[a-z]+)\))?"
    r"|str(?:\((?P<s_min>\d+)?,(?P<s_max>\d+)?\))?"
    r"|password(?:\((?P<p_min>\d+)?,(?P<p_max>\d+)?\))?"
    r"|int(?:\((?P<i_min>-?\d+)?,(?P<i_max>-?\d+)?\))?"
    r"|float(?:\((?P<f_min>-?\d*\.?\d+)?,(?P<f_max>-?\d*\.?\d+)?\))?"
    r"|match\((?P<match>.*)\)"
    r"|list\((?P<list>.+)\)"
    r")\??$"
)


def _elements(schema):
    if isinstance(schema, dict):
        for v in schema.values():
            yield from _elements(v)
    elif isinstance(schema, list):
        for v in schema:
            yield from _elements(v)
    else:
        yield schema


def test_schema_elements_match_supervisor_format():
    manifest = json.loads((ROOT / "config.json").read_text())
    bad = [e for e in _elements(manifest["schema"]) if not RE_SCHEMA_ELEMENT.match(e)]
    assert bad == []


def test_every_option_has_schema_and_translation():
    manifest = json.loads((ROOT / "config.json").read_text())
    translations = yaml.safe_load((ROOT / "translations" / "en.yaml").read_text())["configuration"]
    assert set(manifest["options"]) <= set(manifest["schema"])
    assert set(translations) == set(manifest["schema"])


def test_changelog_has_current_version():
    version = json.loads((ROOT / "config.json").read_text())["version"]
    assert f"## {version}\n" in (ROOT / "CHANGELOG.md").read_text()
