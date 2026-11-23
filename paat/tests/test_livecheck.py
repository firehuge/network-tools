# SPDX-License-Identifier: Apache-2.0
"""Live hop checks vs a config trace. Synthetic devices and flows only."""
from __future__ import annotations

import pytest

from fake_panos import FakeBox, live_factory_for
from panlab.customers import load_profile
from panlab.livecheck import check_hop, check_trace
import panlab.liveconfig as liveconfig


@pytest.fixture
def fwtest(tmp_path, monkeypatch):
    d = tmp_path / "customers" / "acme"
    d.mkdir(parents=True)
    (d / "profile.yaml").write_text(
        "name: acme\n"
        "targets:\n"
        "  - {name: pano, type: panorama, host_env: H, api_key_env: K, api_key_ro_env: KR}\n"
        "  - {name: fw, type: firewall, host_env: FH, api_key_env: FK, api_key_ro_env: FKR}\n"
    )
    monkeypatch.setenv("PANLAB_CUSTOMERS_DIR", str(tmp_path / "customers"))
    monkeypatch.setenv("PANLAB_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("H", "192.0.2.10")
    monkeypatch.setenv("K", "admin-key")
    monkeypatch.setenv("KR", "ro-key")
    monkeypatch.setenv("FH", "192.0.2.20")
    monkeypatch.setenv("FK", "admin-fw")
    monkeypatch.setenv("FKR", "ro-fw")
    pano = FakeBox("ACME-PANO", kind="panorama", serial="P100")
    fw = FakeBox("ACME-FW", serial="F100")
    pano.managed = [fw]
    fw.policy_matches["default"] = {"name": "deny-web", "action": "deny"}
    fw.fib["default"] = {"interface": "ethernet1/2", "nexthop": "192.0.2.1", "zone": "dmz"}
    fw.logs = [{
        "rule": "deny-web", "action": "deny", "from": "trust", "to": "dmz",
        "app": "ssl", "receive_time": "2026/11/22 00:00:00", "repeatcnt": "2",
        "src": "10.10.1.50", "dst": "10.20.1.50", "dport": "443",
    }]
    monkeypatch.setattr(liveconfig, "device_factory", live_factory_for({"pano": pano, "fw": fw}))
    return load_profile("acme"), {"pano": pano, "fw": fw}


def _hop(**kw):
    base = {"n": 1, "device": "ACME-FW", "serial": "F100", "vsys": "vsys1",
            "fromZone": "trust", "toZone": "dmz", "verdict": "deny", "rule": "deny-web"}
    base.update(kw)
    return base


def _query():
    return {"src": "10.10.1.50", "dst": "10.20.1.50", "proto": "tcp", "port": 443}


def test_live_check_agrees_with_deny_trace(fwtest):
    prof, _ = fwtest
    out = check_hop(prof, _hop(), _query())
    assert out["ok"] is True
    assert out["agree"] is True
    assert out["disagreements"] == []
    assert out["policy_match"]["rule"] == "deny-web"
    assert out["policy_match"]["kind"] == "deny"
    assert out["fib"]["ok"] is True
    assert out["logs"]["summary"]["hits"] == 2


def test_live_check_flags_policy_mismatch(fwtest):
    prof, boxes = fwtest
    boxes["fw"].policy_matches["default"] = {"name": "allow-web", "action": "allow"}
    boxes["fw"].logs = []  # no log disagreement, only policy-match
    out = check_hop(prof, _hop(verdict="deny", rule="interzone-default"), _query())
    assert out["agree"] is False
    assert any("policy-match" in d and "allow" in d for d in out["disagreements"])


def test_live_check_flags_log_mismatch(fwtest):
    prof, boxes = fwtest
    boxes["fw"].policy_matches["default"] = {"name": "allow-web", "action": "allow"}
    boxes["fw"].logs = [{
        "rule": "deny-web", "action": "deny", "from": "trust", "to": "dmz",
        "app": "ssl", "receive_time": "2026/11/22 00:00:00", "repeatcnt": "1",
    }]
    out = check_hop(prof, _hop(verdict="allow", rule="allow-web"), _query())
    assert out["agree"] is False
    assert any("traffic logs" in d for d in out["disagreements"])


def test_check_trace_rolls_up_rows(fwtest):
    prof, _ = fwtest
    result = {"rows": [{"query": _query(), "hops": [_hop(), _hop(n=2, vsys="vsys2")]}]}
    out = check_trace(prof, result)
    assert out["hops"] == 2
    assert out["disagreements"] == 0
    assert out["rows"][0]["hops"][0]["agree"] is True
