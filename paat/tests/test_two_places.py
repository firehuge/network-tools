# SPDX-License-Identifier: Apache-2.0
"""A flow checked by security policy in two places on one firewall (synthetic hairpin).

One vsys, three virtual routers, no next-vr: the flow leaves VR-A toward an
outside router and comes back in on VR-B (or VR-C). The firewall checks
policy on both passes, so the plan must list both places, put a new rule in
each one that needs it, place it above a deny that would shadow it, and the
push must write and verify every one. All names and addresses are invented.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from panlab.changeplan import enforcement_lines, render_changeplan
from panlab.changeset import build_changeset
from panlab.customers import load_profile
from panlab.flowmapper import request_from_query
from panlab.netmodel import load_environment
from panlab.placement import place

FIX = Path(__file__).parent / "fixtures" / "synthetic-hairpin-pano.xml"


def _env():
    return load_environment(FIX, target="pano-synth")


def _cs(*flows, prof=None):
    prof = prof or load_profile("example-pano")
    reqs = [request_from_query(q, row=i + 1, project="T") for i, q in enumerate(flows)]
    return build_changeset(prof, [_env()], reqs)


def test_placement_splits_cross_router_flow_into_two_places():
    r = place([_env()], "10.66.1.10", "10.66.2.10")
    got = [(p.from_zone, p.to_zone, p.hop, p.hops_total) for p in r.placements]
    assert got == [("Z-A-LAN", "Z-A-WAN", 1, 2), ("Z-B-WAN", "Z-B-LAN", 2, 2)]
    assert any("2 places" in n for n in r.notes)
    assert all(any(c["code"] == "multi-place" for c in p.callouts) for p in r.placements)


def test_same_router_flow_is_still_one_place():
    r = place([_env()], "10.66.1.10", "10.66.1.20")
    assert len(r.placements) == 1 and r.placements[0].hop is None


def test_plan_lists_every_place_and_adds_a_rule_in_each_missing_one():
    cs = _cs({"src": "10.66.1.10", "dst": "10.66.2.10", "proto": "udp", "port": "500"})
    pts = cs["requests"][0]["enforcement_points"]
    assert [(p["from"], p["to"], p["status"]) for p in pts] == [
        ("Z-A-LAN", "Z-A-WAN", "new-rule"), ("Z-B-WAN", "Z-B-LAN", "new-rule")]
    names = [r["name"] for g in cs["groups"] for r in g["rules"]]
    assert len(names) == 2 and len(set(names)) == 2 and names[1].endswith("-hop2")
    assert cs["summary"]["multi_place"] == 1
    assert any(f["code"] == "multi-place" and f["level"] == "yellow" for f in cs["requests"][0]["flags"])


def test_only_the_missing_place_gets_a_rule_and_it_goes_above_the_deny():
    cs = _cs({"src": "10.66.1.10", "dst": "10.66.3.10", "proto": "tcp", "port": "443"})
    pts = cs["requests"][0]["enforcement_points"]
    assert pts[0]["status"] == "already-allowed" and pts[0]["rule"] == "A-EGRESS"
    assert pts[1]["status"] == "new-rule" and pts[1]["place_before"] == "DENY-A-C-IN"
    new = [r for g in cs["groups"] for r in g["rules"] if r.get("operation") != "already-allowed"]
    assert len(new) == 1 and new[0]["from"] == ["Z-C-WAN"] and new[0]["place_before"] == "DENY-A-C-IN"


def test_fully_allowed_two_place_flow_is_info_not_a_warning():
    cs = _cs({"src": "10.66.1.10", "dst": "10.66.2.10", "proto": "tcp", "port": "443"})
    pts = cs["requests"][0]["enforcement_points"]
    assert [p["rule"] for p in pts] == ["A-EGRESS", "ALLOW-A-B-IN"]
    fl = [f for f in cs["requests"][0]["flags"] if f["code"] == "multi-place"]
    assert fl and fl[0]["level"] == "info"
    assert not [r for g in cs["groups"] for r in g["rules"] if r.get("operation") != "already-allowed"]


def test_change_plan_shows_the_places_and_the_move():
    cs = _cs({"src": "10.66.1.10", "dst": "10.66.3.10", "proto": "tcp", "port": "443"})
    lines = "\n".join(enforcement_lines(cs))
    assert "RULE NEEDED IN 2 PLACES" in lines and "A-EGRESS" in lines and "DENY-A-C-IN" in lines
    md = render_changeplan(cs)
    assert "move device-group DG-HP pre-rulebase security rules" in md and "before DENY-A-C-IN" in md


class _Pano:
    """Records writes, moves and firewall policy-match calls. Matches the new rule only if it was moved."""

    def __init__(self, xml: str):
        self.xml, self.calls, self.phase, self.moved = xml, [], "empty", set()

    def export_running(self):
        return self.xml

    def set(self, xpath, element):
        self.calls.append(("set", xpath)); self.phase = "applied"

    def move(self, xpath, where, dst=None):
        self.calls.append(("move", xpath, where, dst)); self.moved.add(xpath.split("@name='")[-1].rstrip("']"))

    def delete(self, xpath):
        self.calls.append(("delete", xpath)); self.phase = "rolled"

    def revert(self):
        self.calls.append("revert")

    def commit(self, description):
        return {"jobid": "1", "success": True, "messages": []}

    def commit_all(self, cmd):
        self.calls.append(("commit_all", cmd)); return {"jobid": "2", "success": True, "messages": []}

    def exists_running(self, xpath):
        return self.phase == "applied"

    def pending_changes(self):
        return False

    def policy_match(self, q):
        raise AssertionError("not on Panorama")

    def policy_match_on(self, serial, q):
        self.calls.append(("pm", serial, q["from"], q["to"]))
        return self.rule_for.get((q["from"], q["to"])) if hasattr(self, "rule_for") else None


@pytest.fixture
def live(tmp_path, monkeypatch):
    monkeypatch.setenv("PANLAB_DATA_DIR", str(tmp_path / "data"))
    prof = load_profile("example-pano")
    prof.allow_live_panorama_push = True
    return prof


def _push(prof, cs, dev):
    from panlab import pusher
    (prof.data_dir("changesets") / "cs-hp.json").write_text(json.dumps(cs))
    s = pusher.prepare(prof, cs, "cs-hp", actor="eng", cr="CHG0000001", dev=dev)
    assert s["status"] == "prepared", s.get("errors")
    return pusher.apply(prof, cs, s["id"], actor="eng", confirm_target="pano-synth", dev=dev)


def test_push_writes_both_rules_moves_them_and_checks_each_on_the_firewall(live):
    cs = _cs({"src": "10.66.1.10", "dst": "10.66.2.10", "proto": "udp", "port": "500"}, prof=live)
    names = {(r["from"][0], r["to"][0]): r["name"] for g in cs["groups"] for r in g["rules"]}
    dev = _Pano(FIX.read_text())
    dev.rule_for = names
    s = _push(live, cs, dev)
    assert s["status"] == "committed", s.get("result")
    rule_sets = [c for c in dev.calls if c[0] == "set" and c[1].endswith("/security/rules")]
    assert len(rule_sets) == 2
    moves = [c for c in dev.calls if c[0] == "move"]
    assert len(moves) == 2 and all(c[2] == "before" and c[3] == "HP-DENY-ALL" for c in moves)
    pms = [c for c in dev.calls if c[0] == "pm"]
    assert {(c[2], c[3]) for c in pms} == {("Z-A-LAN", "Z-A-WAN"), ("Z-B-WAN", "Z-B-LAN")}
    assert all(c[1] == "000000000901" for c in pms)
    assert len(s["firewall_checks"]) == 2 and all(v["ok"] for v in s["firewall_checks"])


def test_push_flags_a_firewall_that_does_not_pick_the_new_rule(live):
    cs = _cs({"src": "10.66.1.10", "dst": "10.66.2.10", "proto": "udp", "port": "500"}, prof=live)
    first = next(r for g in cs["groups"] for r in g["rules"])
    dev = _Pano(FIX.read_text())
    dev.rule_for = {(first["from"][0], first["to"][0]): first["name"]}  # second place still hits the deny
    s = _push(live, cs, dev)
    assert s["status"] == "committed-verify-failed"
    assert "does not pick the new rule" in s["result"]


def test_gui_change_set_page_shows_the_multi_place_banner():
    from panlab.web.multiplace import banner_html
    cs = _cs({"src": "10.66.1.10", "dst": "10.66.3.10", "proto": "tcp", "port": "443"})
    h = banner_html(cs)
    assert "Rule needed in more than one place" in h and "Place 2" in h and "DENY-A-C-IN" in h
    assert banner_html(_cs({"src": "10.66.1.10", "dst": "10.66.1.20", "proto": "tcp", "port": "443"})) == ""


def test_engine_trace_agrees_and_carries_vr_and_zone_scoped_filters():
    from panlab.flowmapper import ConfigFile, node_bin, run_trace
    try:
        node_bin()
    except Exception:
        pytest.skip("node is not installed")
    res = run_trace([ConfigFile(path=FIX, name=FIX.name)], "10.66.1.10 -> 10.66.2.10 udp/500")
    row = res["rows"][0]
    hops = row["hops"]
    assert [(h["fromZone"], h["toZone"]) for h in hops] == [("Z-A-LAN", "Z-A-WAN"), ("Z-B-WAN", "Z-B-LAN")]
    assert [h.get("vr") for h in hops] == ["VR-A", "VR-B"]
    # every pass is on the mapped firewall, never on the unattached spare stack that shares its template
    assert {h["device"] for h in hops} == {"FW-HAIRPIN"}
    assert [h.get("rule") for h in hops] == ["HP-DENY-ALL", "HP-DENY-ALL"]
    assert [h.get("egressIf") for h in hops] == ["ethernet1/3.201", "ethernet1/3.102"]
    assert row["enforcement"]["points"] == 2 and row["enforcement"]["needRule"] == 2
    f = row["filters"]["hops"]
    assert "(zone.src eq Z-A-LAN)" in f[0]["filter"] and "(zone.src eq Z-B-WAN)" in f[1]["filter"]


def test_livecheck_logs_are_zone_scoped_and_fib_uses_the_hop_router():
    from panlab import livecheck

    class Dev:
        def __init__(self):
            self.filters, self.ops = [], []

        def traffic_logs(self, q, n):
            self.filters.append(q)
            return []

        def op(self, cmd):
            import xml.etree.ElementTree as ET
            self.ops.append(cmd)
            return ET.fromstring("<response status='success'><result><interface>ethernet1/3.999</interface></result></response>")

    d = Dev()
    hop = {"n": 2, "fromZone": "Z-B-WAN", "toZone": "Z-B-LAN", "vr": "VR-B", "egressIf": "ethernet1/3.102"}
    livecheck.hop_logs(d, {"src": "10.66.1.10", "dst": "10.66.2.10", "port": 500}, hop=hop)
    assert "(zone.src eq Z-B-WAN)" in d.filters[0] and "(zone.dst eq Z-B-LAN)" in d.filters[0]
    fib = livecheck.fib_lookup(d, "10.66.2.10", hop["vr"])
    assert fib["virtual_router"] == "VR-B" and "<virtual-router>VR-B</virtual-router>" in d.ops[0]


def test_newest_traffic_log_decides_after_a_change():
    from panlab import livecheck

    class Dev:
        def traffic_logs(self, q, n):
            old = [{"action": "deny", "rule": "DENY-A-C-IN", "receive_time": f"2026/11/20 10:0{i}:00"} for i in range(6)]
            return [{"action": "allow", "rule": "NEW-RULE-hop2", "receive_time": "2026/11/21 09:00:00"}] + old

    out = livecheck.hop_logs(Dev(), {"src": "10.66.1.10", "dst": "10.66.3.10", "port": 443},
                             hop={"fromZone": "Z-C-WAN", "toZone": "Z-C-LAN"})
    assert out["kind"] == "allow" and out["top_rule"] == "NEW-RULE-hop2"
    assert out["last_time"] == "2026/11/21 09:00:00" and out["summary"]["hits"] == 7
