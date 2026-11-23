"""Assessment callouts (routing, app/port, near-match objects), rule notes, plan export, push audit report."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from fcr_factory import make_fcr  # noqa: E402
from test_push import FakeDevice, FWXML, _client, _login, fwtest  # noqa: E402,F401

from panlab import pusher  # noqa: E402
from panlab.apps import app_flags  # noqa: E402
from panlab.changeplan import render_changeplan  # noqa: E402
from panlab.changeset import build_changeset  # noqa: E402
from panlab.customers import load_profile  # noqa: E402
from panlab.fcr import PortSpec, Tickets, read_fcr  # noqa: E402
from panlab.netmodel import load_environment  # noqa: E402
from panlab.placement import Side, place, route_callouts  # noqa: E402
from panlab.report import to_html  # noqa: E402
from panlab.sources import load_customer_envs  # noqa: E402

FIX = Path(__file__).parent / "fixtures"


def _fw_cs(tmp_path, rows, override=None, requester=""):
    prof = load_profile("fwtest")
    f = make_fcr(tmp_path / "RITM0000555.xlsx", rows, project="callouts")
    reqs, meta = read_fcr(f, ticket_patterns=prof.tickets, override=override, requester=requester)
    return build_changeset(prof, load_customer_envs(prof, configs=[str(FWXML)]), reqs, files=[meta])


def codes(cs):
    return {f["code"]: f["message"] for g in cs["groups"] for r in g["rules"] for f in r["flags"]}


def test_default_route_callout_with_vr_and_suggestion():
    env = load_environment(FWXML, target="fw-1")
    r = place([env], "10.1.20.5", "8.8.8.8")
    co = [c for p in r.placements for c in p.callouts if c["code"] == "route-default"]
    assert co and "virtual router default" in co[0]["message"]
    assert "set network virtual-router default routing-table ip static-route to-8.8.8.8_32 destination 8.8.8.8/32" in co[0]["message"]
    assert "suggestion, not pushed" in co[0]["message"]


def test_next_vr_and_vr_mismatch_callouts():
    pano = load_environment(FIX / "synthetic-panorama.xml", target="pano-synth")
    r = place([pano], "10.10.1.1", "8.8.8.8")
    assert any(c["code"] == "route-next-vr" for p in r.placements for c in p.callouts)
    import ipaddress
    s = Side("static", "ethernet1/3", "LAN", "vsys1", "r1", "10.9.0.0/16", router="VR-A", iface_router="VR-B")
    out = route_callouts("fw", "vsys1", [("destination", ipaddress.IPv4Network("10.9.1.1/32"), s)])
    assert out[0]["code"] == "route-vr-mismatch" and "VR-B" in out[0]["message"]


def test_app_port_flags():
    f = {x["code"]: x for x in app_flags([PortSpec("tcp", "22")], [])}
    assert "ssh" in f["app-suggest"]["message"] and "application-default" in f["app-suggest"]["message"]
    f = {x["code"]: x for x in app_flags([PortSpec("tcp", "2222")], ["ssh"])}
    assert f["app-port-mismatch"]["level"] == "yellow" and "tcp/22" in f["app-port-mismatch"]["message"]
    f = {x["code"]: x for x in app_flags([PortSpec("tcp", "443")], [])}
    assert "service-https" in f["predefined-service"]["message"] and "ssl" in f["app-suggest"]["message"]
    f = {x["code"]: x for x in app_flags([PortSpec("tcp", "3389")], ["ms-rdp"])}
    assert "app-default" in f
    assert "app-unknown" in {x["code"] for x in app_flags([PortSpec("tcp", "9999")], ["acme-app"])}


def test_near_match_and_existing_reuse_shown(tmp_path):
    cs = _fw_cs(tmp_path, [("10.200.1.5", None, "10.1.20.50/31", None, "TCP", "5432", None, "x", None),
                            ("10.200.1.6", None, "10.1.20.50", None, "TCP", "5433", None, "y", None)])
    nm = cs["groups"][0]["objects"]["near_matches"]
    assert nm and nm[0]["existing"] == "LAN-PRINTER"
    assert "near-match" in codes(cs)
    html = to_html(cs)
    assert "EXISTING object LAN-PRINTER matches, will reuse" in html and "same IP with a different mask" in html


def test_rule_description_and_tags_carry_tickets_and_requester(tmp_path):
    cs = _fw_cs(tmp_path, [("10.200.1.5", None, "10.1.20.60", None, "TCP", "5432", None, "z", None)],
                 override=Tickets(ritm=["RITM0000555"], sctask=["SCTASK0000556"], cr=["CHG0000557"]), requester="Pat Smith")
    r = cs["groups"][0]["rules"][0]
    for t in ("RITM0000555", "SCTASK0000556", "CHG0000557", "requester: Pat Smith"):
        assert t in r["description"]
    assert {"TST-RITM0000555", "TST-SCTASK0000556", "TST-CHG0000557", "TST-panlab"} <= set(r["tags"])
    from panlab.pusher import _rule_element
    el = _rule_element(r)
    assert "RITM0000555" in el and "Pat Smith" in el and "<tag>" in el


def test_changeplan_is_junior_friendly(tmp_path):
    cs = _fw_cs(tmp_path, [("10.1.20.5", None, "8.8.8.8", None, "TCP", "22", None, "z", None)])
    text = render_changeplan(cs)
    for s in ("How to use this plan", "Callouts and advice", "routing:", "App-ID ssh", "Add Policy", "Log Forwarding"):
        assert s in text, s


def test_gui_plan_copy_and_download(tmp_path, monkeypatch, fwtest):
    c = _client(tmp_path, monkeypatch)
    _login(c, "viewer1", "pw-viewer")
    page = c.get("/changesets/fwtest/cs-test/changeplan").text
    assert "Copy" in page and "changeplan.txt" in page
    for part in ("cr", "cli", "rollback", "verify"):
        assert f"id='plan-{part}'" in page
        assert f"changeplan/{part}.md" in page and f"changeplan/{part}.txt" in page
    for field in ("Add Policy", "Log at Session Start", "Log at Session End", "Log Forwarding",
                  "Profile Type", "Group Profile", "URL Category", "Audit Comment"):
        assert field in page, field
    assert "set rulebase security rules" in page or "set vsys" in page
    assert "Firewall Change Request" in page
    r = c.get("/changesets/fwtest/cs-test/changeplan.md")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"] and "## Rollback" in r.text
    cli = c.get("/changesets/fwtest/cs-test/changeplan/cli.md")
    assert cli.status_code == 200 and "## Implementation (CLI)" in cli.text and "set " in cli.text
    cr = c.get("/changesets/fwtest/cs-test/changeplan/cr.md")
    assert cr.status_code == 200 and "### Add Policy" in cr.text and "Log Forwarding" in cr.text
    assert c.get("/changesets/fwtest/cs-test/changeplan.exe").status_code == 404
    assert c.get("/changesets/fwtest/cs-test/changeplan/nope.md").status_code == 404


def test_push_audit_report(tmp_path, monkeypatch, fwtest):
    prof, cs, dev = fwtest
    s = pusher.prepare(prof, cs, "cs-test", actor="eng", cr="CHG0001234", dev=dev)
    s = pusher.apply(prof, cs, s["id"], actor="eng", confirm_target="fw-1", dev=dev)
    md = (prof.data_dir("push") / f"{s['id']}-report.md").read_text()
    for t in ("CHG0001234", "RITM0000777", "fw-1-pre-push-", "job 1", "policy-match", "America/Chicago", "| apply: commit |"):
        assert t in md, t
    s = pusher.rollback(prof, cs, s["id"], actor="eng", confirm_target="fw-1", dev=dev)
    md = (prof.data_dir("push") / f"{s['id']}-report.md").read_text()
    assert "## Rollback" in md and "rollback: finished (rolled-back)" in md
    import json
    j = json.loads((prof.data_dir("push") / f"{s['id']}-report.json").read_text())
    assert j["status"] == "rolled-back" and j["ritm"] == ["RITM0000777"] and j["commit_jobs"][1]["jobid"] == "2"
    c = _client(tmp_path, monkeypatch)
    _login(c, "eng1", "pw-eng")
    assert "report.md" in c.get("/audit/fwtest").text
    r = c.get(f"/push/fwtest/session/{s['id']}/report.md")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]


def test_no_route_callout_names_vr():
    env = load_environment(FWXML, target="fw-1")
    import copy
    e2 = copy.deepcopy(env)
    for r in e2.devices[0].routers.values():
        r.routes = [x for x in r.routes if x.dest.prefixlen != 0]
    res = place([e2], "10.1.20.5", "8.8.8.8")
    assert res.fallback and res.placements
    assert res.placements[0].from_zone == "LAN"
    assert any("no route at all in virtual router default" in n and "static-route" in n for n in res.notes)


def test_panorama_route_callout_targets_template():
    pano = load_environment(FIX / "synthetic-panorama.xml", target="pano-synth")
    assert pano.stacks["ST-DC"] == ["TPL-DC-NET", "TPL-COMMON"]
    assert pano.vr_template[("ST-DC", "VR-EDGE")] == "TPL-DC-NET"
    r = place([pano], "10.101.1.1", "10.30.0.1")
    br = next(p for p in r.placements if p.device == "FW-BR-A")
    m = next(c["message"] for c in br.callouts if c["code"] in ("route-default", "route-needed"))
    assert "set template TPL-BRANCH config network virtual-router default routing-table ip static-route" in m
    assert "template stack ST-BRANCH" in m and "Push to Devices" in m
