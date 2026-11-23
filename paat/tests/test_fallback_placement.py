# SPDX-License-Identifier: Apache-2.0
"""Fallback placement when requested networks are not on the firewall yet."""

from __future__ import annotations

import copy
import ipaddress
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from fcr_factory import make_fcr  # noqa: E402
from test_push import FakeDevice, FWXML, _client, _login, fwtest  # noqa: E402,F401

from panlab import pusher  # noqa: E402
from panlab.changeplan import render_changeplan  # noqa: E402
from panlab.changeset import build_changeset, requests_from_changeset  # noqa: E402
from panlab.customers import load_profile  # noqa: E402
from panlab.fcr import Tickets, read_fcr  # noqa: E402
from panlab.netmodel import Route, load_environment  # noqa: E402
from panlab.placement import place  # noqa: E402
from panlab.report import to_html, to_markdown  # noqa: E402
from panlab.sources import load_customer_envs  # noqa: E402

FIX = Path(__file__).parent / "fixtures"
PANO = FIX / "synthetic-panorama.xml"


def _fw_cs(tmp_path, rows, override=None, requester="", fallback_firewall=None):
    prof = load_profile("fwtest")
    f = make_fcr(tmp_path / "RITM0000999.xlsx", rows, project="fallback")
    reqs, meta = read_fcr(f, ticket_patterns=prof.tickets, override=override, requester=requester)
    return build_changeset(
        prof, load_customer_envs(prof, configs=[str(FWXML)]), reqs, files=[meta],
        fallback_firewall=fallback_firewall,
    )


def test_single_firewall_builds_plan_for_unknown_rfc1918():
    env = load_environment(FWXML, target="fw-1")
    r = place([env], "10.99.0.0/18", "10.98.96.86")
    assert r.fallback and r.placements
    p = r.placements[0]
    assert p.role == "fallback"
    assert p.from_zone == "untrust" and p.to_zone == "untrust"
    assert p.intrazone and p.rule_needed and p.needs_human
    assert p.confidence == "low"
    assert "default route" in p.reason and "ethernet1/1" in p.reason and "untrust" in p.reason
    codes = {c["code"] for c in p.callouts}
    assert "route-needed" in codes and "route-same-zone" in codes
    dests = {sr["destination"] for sr in p.suggested_routes}
    assert dests == {"10.99.0.0/18", "10.98.96.86/32"}
    for sr in p.suggested_routes:
        assert sr["vr"] == "default"
        assert sr["nexthop"] == "REQUIRED-CONFIRM"
        assert sr["nexthop_confirmed"] is False
        assert sr["push"] is False
        assert "set network virtual-router default routing-table ip static-route" in sr["cli"]
        assert sr["rollback"].startswith("delete network virtual-router default routing-table ip static-route")


def test_multi_firewall_needs_a_pick_then_places_on_choice():
    pano = load_environment(PANO, target="pano-synth")
    r = place([pano], "10.99.0.0/18", "10.98.96.86")
    # No connected/specific owner: propose a rule on each firewall that only
    # matched a broad or default route, marked needs-human (not a silent skip).
    assert r.placements and r.needs_human
    assert all(p.rule_needed and p.needs_human for p in r.placements)
    assert "FW-BR-A" in {p.device for p in r.placements}
    r2 = place([pano], "10.99.0.0/18", "10.98.96.86", fallback_firewall="FW-BR-A")
    assert {p.device for p in r2.placements} == {"FW-BR-A"}
    assert r2.placements[0].suggested_routes
    assert r2.placements[0].rule_needed


def test_same_zone_is_flagged_not_skipped():
    env = load_environment(FWXML, target="fw-1")
    r = place([env], "10.99.10.1", "10.99.10.2")
    p = r.placements[0]
    assert p.intrazone and p.rule_needed
    assert any(c["code"] == "route-same-zone" for c in p.callouts)


def test_rfc1918_on_default_with_connected_peer_suggests_route():
    env = load_environment(FWXML, target="fw-1")
    r = place([env], "10.1.20.5", "10.98.96.86")
    p = r.placements[0]
    assert p.from_zone == "LAN" and p.to_zone == "untrust"
    assert any(c["code"] == "route-needed" for c in p.callouts)
    assert any(sr["destination"] == "10.98.96.86/32" for sr in p.suggested_routes)


def test_overlap_existing_192_is_flagged_not_suggested():
    env = copy.deepcopy(load_environment(FWXML, target="fw-1"))
    vr = env.devices[0].routers["default"]
    vr.routes.append(Route("fw-192", ipaddress.IPv4Network("192.168.80.0/24"), "static",
                           nexthop_type="ip", nexthop="10.1.10.2", iface="ethernet1/2"))
    env.devices[0].cache.clear()
    r = place([env], "10.1.20.5", "192.168.0.0/16")
    p = r.placements[0]
    assert any(c["code"] == "route-192-overlap" for c in p.callouts)
    assert any(sr.get("overlap_192") and "192.168.80.0/24" in " ".join(sr.get("existing") or [])
               for sr in p.suggested_routes)
    assert all("set network" not in (sr.get("cli") or "") for sr in p.suggested_routes if sr.get("overlap_192"))


def test_changeset_and_changeplan_show_proposed_objects_rule_and_routes(tmp_path):
    cs = _fw_cs(
        tmp_path,
        [("10.99.0.0/18", "src-net.example.test", "10.98.96.86", "app-host.example.test",
          "TCP", "443", None, "new nets", None)],
        override=Tickets(ritm=["RITM0000999"], sctask=["SCTASK0000999"], cr=["CHG0000999"]),
        requester="Pat Example",
    )
    assert cs["summary"]["placed"] == 1 and cs["summary"]["unplaced"] == 0
    assert cs["summary"]["rules"] == 1 and cs["summary"]["new_objects"] >= 2
    assert cs["fallback"]
    g = cs["groups"][0]
    rule = g["rules"][0]
    assert rule["from"] == ["untrust"] and rule["to"] == ["untrust"]
    objs = {o["name"]: o for o in g["objects"]["new"] if o["kind"] == "address"}
    assert any(o["value"] in ("10.99.0.0/18",) for o in objs.values())
    assert any(o["value"] in ("10.98.96.86/32",) for o in objs.values())
    assert any("src-net.example.test" in (o.get("description") or "") for o in objs.values())
    assert any("app-host.example.test" in (o.get("description") or "") for o in objs.values())
    assert g["suggested_routes"] and all(sr["nexthop"] == "REQUIRED-CONFIRM" for sr in g["suggested_routes"])

    html = to_html(cs)
    assert "proposed plan, not a failure" in html
    assert "route suggested on VR default" in html.lower() or "Route suggested on VR default" in html
    assert "Needs a human: could not place" not in html
    assert "10.99.0.0/18 is not on any connected subnet" in html
    md = to_markdown(cs)
    assert "proposed plan, not a failure" in md

    text = render_changeplan(cs)
    assert "### Add Address Object" in text
    assert "### Add Policy" in text
    assert "### Add Static Route" in text
    assert "Navigate to: Network > Virtual Routers > default > Static Routes" in text
    assert "Next Hop: `REQUIRED-CONFIRM`" in text
    assert "set network virtual-router default routing-table ip static-route" in text
    assert "delete network virtual-router default routing-table ip static-route" in text
    assert "do not paste until the next hop is confirmed" in text
    assert "Zone: `untrust`" in text


def test_push_skips_unconfirmed_routes(tmp_path, fwtest):
    prof, _existing, dev = fwtest
    cs = _fw_cs(tmp_path, [("10.99.0.0/18", None, "10.98.96.86", None, "TCP", "443", None, "x", None)])
    # needs_human (same-zone) blocks a full prepare, but ops must never include routes
    target = next(t for t in prof.targets if t.name == "fw-1")
    ops, _rb, diff = pusher.build_ops(cs, target, {})
    blob = json.dumps(ops) + "\n" + "\n".join(diff)
    assert "virtual-router" not in blob and "static-route" not in blob
    msg = pusher.unconfirmed_route_warning(cs)
    assert msg and "REQUIRED-CONFIRM" in msg and "not included in this push" in msg


def test_upload_form_has_target_firewall_picker(tmp_path, monkeypatch, fwtest):
    c = _client(tmp_path, monkeypatch)
    _login(c, "eng1", "pw-eng")
    page = c.get("/").text
    assert "Target firewall (if networks aren't on any firewall yet)" in page
    assert 'name="target_firewall"' in page


def test_requests_from_changeset_roundtrip(tmp_path):
    cs = _fw_cs(tmp_path, [("10.99.0.0/18", "src-net.example.test", "10.98.96.86", None, "TCP", "443", None, "x", None)])
    reqs = requests_from_changeset(cs)
    assert len(reqs) == 1
    assert reqs[0].sources[0].value.startswith("10.99.0.0")
    assert reqs[0].sources[0].dns == "src-net.example.test"
