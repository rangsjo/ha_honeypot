"""privileges.drop is exercised for real in Docker (it needs root); these cover the checks."""

import os

import privileges


def _status(tmp_path, tid, uid, cap_eff="0000000000000000", cap_prm="0000000000000000"):
    d = tmp_path / tid
    d.mkdir()
    (d / "status").write_text(f"Name:\tpython\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n"
                              f"CapPrm:\t{cap_prm}\nCapEff:\t{cap_eff}\n")


def test_privileged_threads(tmp_path):
    _status(tmp_path, "1", 999)
    _status(tmp_path, "2", 0)
    _status(tmp_path, "3", 999, cap_eff="0000000000001000")
    assert sorted(privileges.privileged_threads(tmp_path)) == ["2", "3"]


def test_drop_is_noop_when_not_root(tmp_path):
    if os.geteuid() == 0:
        return
    assert privileges.drop(tmp_path).startswith("not root")
