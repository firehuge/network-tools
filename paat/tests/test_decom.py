"""Decommission flow: resolve items, plan edits/deletes, CR plan, CLI, and gated push."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from openpyxl import Workbook

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from test_push import FakeDevice  # noqa: E402

from panlab import pusher  # noqa: E402
from panlab.changeplan import changeplan_sections, render_changeplan  # noqa: E402
from panlab.cli import main  # noqa: E402
from panlab.customers import DEFAULT_CHANGE_PLAN, DEFAULT_TICKETS, Profile, Target  # noqa: E402
from panlab.decom import (  # noqa: E402
    build_decom_changeset,
    delete_commands,
    inventory_from_xml,
    parse_item_text,
    parse_item_xlsx,
    rollback_commands,
    verify_steps,
)
from panlab.netmodel import load_environment  # noqa: E402
from panlab.report import set_commands, to_markdown  # noqa: E402

FIX = Path(__file__).parent / "fixtures"
FWXML = FIX / "synthetic-decom-fw.xml"
PANOXML = FIX / "synthetic-decom-pano.xml"
TICKETS = {"ritm": ["RITM0001111"], "sctask": ["SCTASK0002222"], "cr": ["CHG0003333"]}


@pytest.fixture(autouse=True)
def _data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("PANLAB_DATA_DIR", str(tmp_path / "data"))


def _prof(name: str = "fwtest", typ: str = "firewall", tname: str = "fw-1") -> Profile:
    return Profile(
        name=name,
        path=Path("customers/fwtest/profile.yaml"),
        targets=[Target(name=tname, type=typ)],
        change_plan=dict(DEFAULT_CHANGE_PLAN),
        tickets=dict(DEFAULT_TICKETS),
        default_tags=["panlab"],
    )


def _fw_cs(items: list[str], tmp_path=None):
    env = load_environment(FWXML.resolve(), target="fw-1")
    return build_decom_changeset(_prof(), [env], items, tickets=TICKETS)


def _pano_cs(items: list[str]):
    env = load_environment(PANOXML.resolve(), target="pano-1")
    return build_decom_changeset(_prof("example-pano", "panorama", "pano-1"), [env], items, tickets=TICKETS)


def _ops(cs):
    return [a for g in cs["groups"] for a in g["actions"]]


def test_parse_items_and_xlsx(tmp_path):
    assert parse_item_text("10.1.2.3, TST-HOST\n# comment\nTST-HOST\nold.example.test") == [
        "10.1.2.3", "TST-HOST", "old.example.test",
    ]
    wb = Workbook()
    ws = wb.active
    ws.append(["Item"])
    ws.append(["203.0.113.50"])
    ws.append(["TST-AUTO-TEST-HOST"])
    path = tmp_path / "items.xlsx"
    wb.save(path)
    assert parse_item_xlsx(path) == ["203.0.113.50", "TST-AUTO-TEST-HOST"]


def test_exact_ip_vs_containing_and_contained():
    inv = inventory_from_xml(FWXML, target="fw-1", kind="firewall")
    names = {a.name for a in inv.addresses}
    assert "TST-AUTO-TEST-HOST" in names and "TST-AUTO-TEST-NET" in names
    cs = _fw_cs(["203.0.113.50"])
    tiers = {c["name"]: c["tier"] for c in cs["decom"]["candidates"]}
    assert tiers["TST-AUTO-TEST-HOST"] == "exact"
    # the /24 holding the host is Possible: advice only, never selectable, never in the plan
    assert tiers["TST-AUTO-TEST-NET"] == "possible"
    net = next(c for c in cs["decom"]["candidates"] if c["name"] == "TST-AUTO-TEST-NET")
    assert not net["selectable"] and not net["selected"] and net["advice"] and net["blast"]["otherAddresses"] == 255
    assert any(a["op"] == "delete-address" and a["name"] == "TST-AUTO-TEST-HOST" for a in _ops(cs))
    assert not any(a.get("name") == "TST-AUTO-TEST-NET" for a in _ops(cs))
    assert cs["summary"]["tiers"] == {"exact": 1, "likely": 0, "possible": 1}
    # prefix: the exact net is removed; the host inside it is Highly likely and not pre-selected
    cs2 = _fw_cs(["203.0.113.0/24"])
    tiers2 = {c["name"]: c for c in cs2["decom"]["candidates"]}
    assert tiers2["TST-AUTO-TEST-NET"]["tier"] == "exact" and tiers2["TST-AUTO-TEST-HOST"]["tier"] == "likely"
    assert not tiers2["TST-AUTO-TEST-HOST"]["selected"]
    assert any(a["op"] == "delete-address" and a["name"] == "TST-AUTO-TEST-NET" for a in _ops(cs2))
    assert not any(a.get("name") == "TST-AUTO-TEST-HOST" and a["op"] == "delete-address" for a in _ops(cs2))


def test_fqdn_and_named_object():
    cs = _fw_cs(["decom-host.example.test"])
    assert any(a["op"] == "delete-address" and a["name"] == "TST-AUTO-TEST-FQDN" for a in _ops(cs))
    cs2 = _fw_cs(["TST-AUTO-TEST-FQDN"])
    assert any(a["name"] == "TST-AUTO-TEST-FQDN" for a in _ops(cs2))


def test_edit_rule_keeps_remaining_and_empty_becomes_delete():
    cs = _fw_cs(["TST-AUTO-TEST-HOST"])
    edits = [a for a in _ops(cs) if a["op"] == "edit-rule" and a["name"] == "TST-AUTO-TEST-MULTI"]
    assert len(edits) == 1
    assert edits[0]["remove"]["source"] == ["TST-AUTO-TEST-HOST"]
    assert "TST-AUTO-TEST-KEEP" in edits[0]["remaining"]["source"]
    assert "TST-AUTO-TEST-HOST" not in edits[0]["remaining"]["source"]
    deleted = {a["name"] for a in _ops(cs) if a["op"] == "delete-rule"}
    assert {"TST-AUTO-TEST-SOLE", "TST-AUTO-TEST-NAT", "TST-AUTO-TEST-PBF"} <= deleted
    for a in _ops(cs):
        if a["op"] == "delete-rule" and a["name"] == "TST-AUTO-TEST-SOLE":
            assert a["reason"] == "empty-field-would-become-any"
            assert a.get("flag") == "red"
    assert any(f["code"] == "would-broaden" and f["level"] == "red" for f in cs["flags"])
    assert cs["summary"]["dangers"] >= 1 and cs["summary"]["needs_human"] == 0  # callouts, not blockers
    # never propose an edit that leaves source/dest empty
    for a in _ops(cs):
        if a["op"] == "edit-rule":
            for field, rem in (a.get("remaining") or {}).items():
                assert rem, (a["name"], field)


def test_group_edit_empty_delete_and_dynamic_flag():
    cs = _fw_cs(["TST-AUTO-TEST-HOST"])
    assert any(a["op"] == "edit-group" and a["name"] == "TST-AUTO-TEST-GRP"
               and "TST-AUTO-TEST-HOST" in a["remove"] and "TST-AUTO-TEST-KEEP" in a["remaining"] for a in _ops(cs))
    assert any(a["op"] == "delete-group" and a["name"] == "TST-AUTO-TEST-EMPTY-GRP"
               and a["reason"] == "empty-group" for a in _ops(cs))
    # named dynamic group is flagged, not deleted
    cs2 = _fw_cs(["TST-AUTO-TEST-DYN"])
    assert any(f["code"] == "dynamic-group-named" for f in cs2["flags"])
    assert not any(a["op"] == "delete-group" and a["name"] == "TST-AUTO-TEST-DYN" for a in _ops(cs2))
    # tagged object vs dynamic group
    cs3 = _fw_cs(["TST-AUTO-TEST-TAGGED"])
    assert any(f["code"] == "dynamic-group" for f in cs3["flags"])


def test_named_rule_deletes_exclusive_objects_keeps_shared(tmp_path):
    from panlab.decom import current_selection, rebuild_with_selection

    cs = _fw_cs(["TST-AUTO-TEST-NAMED"])
    assert any(a["op"] == "delete-rule" and a["name"] == "TST-AUTO-TEST-NAMED" and a["reason"] == "named-rule" for a in _ops(cs))
    # the object only that rule used is Highly likely: one click, not automatic
    only = next(c for c in cs["decom"]["candidates"] if c["name"] == "TST-AUTO-TEST-ONLY")
    assert only["tier"] == "likely" and only["selectable"] and not only["selected"]
    assert "TST-AUTO-TEST-ONLY" not in {a["name"] for a in _ops(cs) if a["op"] == "delete-address"}
    env = load_environment(FWXML.resolve(), target="fw-1")
    cs_l = rebuild_with_selection(_prof(), [env], cs, current_selection(cs) + [only["id"]])
    names = {a["name"] for a in _ops(cs_l) if a["op"] == "delete-address"}
    assert "TST-AUTO-TEST-ONLY" in names and "TST-AUTO-TEST-SHARED-USE" not in names
    # Possible ids can never be selected, even if posted
    cs_p = rebuild_with_selection(_prof(), [env], _fw_cs(["203.0.113.50"]), ["addr|bogus", "addr|whatever"])
    assert not _ops(cs_p)
    # deleting OTHER keeps SHARED-USE (OTHER2 still uses it); the object is not even proposed
    cs2 = _fw_cs(["TST-AUTO-TEST-OTHER"])
    assert not any(a["op"] == "delete-address" and a["name"] == "TST-AUTO-TEST-SHARED-USE" for a in _ops(cs2))


def test_unresolved_and_ambiguous_name():
    cs = _fw_cs(["NO-SUCH-OBJECT"])
    assert cs["summary"]["unplaced"] == 1
    assert any(f["code"] == "unresolved" and f["level"] == "red" for f in cs["flags"])
    # a name that is both a rule and (not) an object — HOST is only an object
    # TST-AUTO-TEST-MULTI is only a rule
    cs2 = _fw_cs(["TST-AUTO-TEST-MULTI"])
    assert any(a["op"] == "delete-rule" and a["name"] == "TST-AUTO-TEST-MULTI" for a in _ops(cs2))


def test_shared_parent_dg_flagged_red():
    cs = _pano_cs(["SH-DECOM-HOST"])
    assert any(f["code"] == "shared-objects" for f in cs["flags"])  # shared delete: firewall-local rules are not in the export
    dgs = {a["location"]["device_group"] for a in _ops(cs) if a["op"] in {"edit-rule", "delete-rule"}}
    assert {"DG-DC", "DG-EDGE"} <= dgs
    seq = {(a["op"], a["name"]): a["seq"] for a in _ops(cs)}
    assert seq[("delete-address", "SH-DECOM-HOST")] == max(seq.values())  # shared object last
    cs2 = _pano_cs(["DC-DECOM-PARENT"])
    # a parent-DG object used by a child DG: the child's rule goes first, the object last
    s2 = {(a["op"], a["name"]): a["seq"] for a in _ops(cs2)}
    assert s2[("delete-rule", "EDGE-allow-shared")] < s2[("delete-address", "DC-DECOM-PARENT")]
    assert any(f["code"] == "would-broaden" for f in cs2["flags"])


def test_change_plan_cr_format_and_cli_order():
    cs = _fw_cs(["203.0.113.50"])
    text = render_changeplan(cs)
    assert text.startswith("# Firewall Change Request (Decommission)")
    assert "**RITM:** RITM0001111" in text and "**SCTask:** SCTASK0002222" in text
    assert "### Edit Policy" in text
    assert "- Remove source address:" in text
    assert "  - `TST-AUTO-TEST-HOST`" in text
    assert "### Delete Policy" in text
    assert "### Edit Address Group" in text
    assert "### Delete Address Object" in text
    assert text.index("### Edit Policy") < text.index("### Delete Address Object")
    assert "## Commit" in text
    assert "## Impact Analysis Statement" in text
    assert "will no longer match those rules" in text
    assert "## Implementation (CLI)" in text
    cli = "\n".join(delete_commands(cs))
    assert cli.index("delete rulebase security rules TST-AUTO-TEST-MULTI") < cli.index("delete address TST-AUTO-TEST-HOST")
    assert "delete address-group TST-AUTO-TEST-EMPTY-GRP" in cli
    rb = "\n".join(rollback_commands(cs))
    assert "set address TST-AUTO-TEST-HOST ip-netmask 203.0.113.50/32" in rb
    assert "set rulebase security rules TST-AUTO-TEST-SOLE" in rb
    assert rb.index("set address TST-AUTO-TEST-HOST") < rb.index("set rulebase security rules TST-AUTO-TEST-SOLE")
    assert "test security-policy-match" not in text or "gone" in text
    assert "TST-AUTO-TEST-HOST" in text and "is gone" in text
    parts = changeplan_sections(cs)
    assert "### Edit Policy" in parts["cr"]
    assert "delete rulebase" in parts["cli"]
    assert "set address TST-AUTO-TEST-HOST" in parts["rollback"]
    assert "is gone" in parts["verify"]
    # report dispatch
    md = to_markdown(cs)
    assert md.startswith("# Decommission change set")
    assert set_commands(cs) == [l for l in delete_commands(cs)]


def test_panorama_plan_wording():
    cs = _pano_cs(["SH-DECOM-HOST"])
    text = render_changeplan(cs)
    assert text.startswith("# Panorama Change Request (Decommission)")
    assert "Policies > Security > Pre Rules (Device Group: DG-DC)" in text
    assert "delete device-group DG-DC pre-rulebase security rules" in text
    assert "delete device-group DG-EDGE pre-rulebase security rules" in text


def test_cli_decom(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "out"
    rc = main([
        "decom", "--customer", "fwtest",
        "--config", str(FWXML.resolve()),
        "--items", "TST-AUTO-TEST-HOST",
        "--ritm", "RITM0001111", "--sctask", "SCTASK0002222", "--cr", "CHG0003333",
        "--out", str(out), "--stem", "decom-test", "--quiet",
    ])
    # needs_human is non-zero because of would-broaden red flags
    assert rc in (0, 1)
    data = json.loads((out / "decom-test.json").read_text())
    assert data["kind"] == "decommission"
    assert data["schema"] == "panlab.changeset/v1"
    assert any(a["name"] == "TST-AUTO-TEST-HOST" for g in data["groups"] for a in g["actions"])


def test_push_apply_and_rollback(tmp_path):
    env = load_environment(FWXML.resolve(), target="fw-1")
    # Use an item with no would-broaden issues? HOST has them but they are warnings for push.
    # SHARED-USE is used by two rules, both would remain non-empty if we only... actually
    # we decommission the object, so both rules get edits (source or dest still have 'any' or the other?).
    # OTHER source is only SHARED-USE -> would-broaden delete. OTHER2 dest only SHARED-USE -> delete.
    # That's fine; push should still be allowed (would-broaden is a warning).
    prof = _prof()
    # point data dir already patched
    cs = build_decom_changeset(prof, [env], ["TST-AUTO-TEST-HOST"], tickets=TICKETS)
    d = prof.data_dir("changesets")
    (d / "decom-test.json").write_text(json.dumps(cs))
    dev = FakeDevice(FWXML.read_text())
    s = pusher.prepare(prof, cs, "decom-test", actor="eng", cr="CHG0003333", dev=dev)
    assert s["status"] == "prepared", s.get("errors")
    assert not dev.dirty
    assert any(l.startswith("- address TST-AUTO-TEST-HOST") for l in s["diff"])
    s = pusher.apply(prof, cs, s["id"], actor="eng", confirm_target="fw-1", dev=dev)
    assert s["status"] == "committed", s.get("result")
    import xml.etree.ElementTree as ET
    assert dev.exists_running("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='TST-AUTO-TEST-HOST']") is False
    assert dev.exists_running("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='TST-AUTO-TEST-SOLE']") is False
    assert dev.exists_running("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='TST-AUTO-TEST-MULTI']") is True
    rules = dev._walk(dev.running, "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules")
    for r in rules:
        if r.get("name") == "TST-AUTO-TEST-MULTI":
            multi = [m.text for m in r.find("source")]
    assert multi == ["TST-AUTO-TEST-KEEP"]
    assert all(v["ok"] for v in s["verify"]), s["verify"]
    s = pusher.rollback(prof, cs, s["id"], actor="eng", confirm_target="fw-1", dev=dev)
    assert s["status"] == "rolled-back", s.get("result") or s.get("rollback_result")
    assert dev.exists_running("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='TST-AUTO-TEST-HOST']") is True
    assert dev.exists_running("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='TST-AUTO-TEST-SOLE']") is True
    for r in dev._walk(dev.running, "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules"):
        if r.get("name") == "TST-AUTO-TEST-MULTI":
            assert "TST-AUTO-TEST-HOST" in [m.text for m in r.find("source")]


def test_push_refuses_unresolved():
    env = load_environment(FWXML.resolve(), target="fw-1")
    prof = _prof()
    cs = build_decom_changeset(prof, [env], ["NO-SUCH-THING"], tickets=TICKETS)
    dev = FakeDevice(FWXML.read_text())
    s = pusher.prepare(prof, cs, "decom-bad", actor="eng", cr="CHG0003333", dev=dev)
    assert s["status"] == "blocked"
    assert any("NO-SUCH-THING" in x for x in s["errors"])


def test_gui_decom_page(tmp_path, monkeypatch):
    from test_push import _client, _login
    from panlab.web import auth

    # Cached fwtest config the GUI reads (never live).
    cache = tmp_path / "data" / "fwtest" / "cache"
    cache.mkdir(parents=True)
    (cache / "fw-1-latest.xml").write_bytes(FWXML.read_bytes())
    c = _client(tmp_path, monkeypatch)
    assert c.get("/decom", follow_redirects=False).status_code == 303
    _login(c, "viewer1", "pw-viewer")
    assert c.get("/decom").status_code == 403
    c = _client(tmp_path, monkeypatch)
    auth.add_user("prep1", "prep", "pw-prep", tmp_path / "users.yaml")
    _login(c, "prep1", "pw-prep")
    page = c.get("/decom").text
    assert "Decommission" in page and "RITM" in page and "Items to decommission" in page
    r = c.post("/decom", data={"customer": "fwtest", "items": "TST-AUTO-TEST-HOST\n203.0.113.50",
                               "ritm": "RITM0001111", "sctask": "SCTASK0002222", "cr": "CHG0003333", "target": ""})
    assert r.status_code == 200, r.text[:500]
    assert "Decommission change set" in r.text or "TST-AUTO-TEST-HOST" in r.text
    assert "Change plan" in r.text
    # follow the saved change set's plan
    import re
    m = re.search(r"/changesets/fwtest/(decom-[0-9-]+)/changeplan", r.text)
    assert m, r.text[:800]
    plan = c.get(m.group(0)).text
    assert "Firewall Change Request (Decommission)" in plan
    assert "Remove source address" in plan
    assert "Delete Address Object" in plan
    assert "Copy" in plan



BLOCKXML = FIX / "synthetic-decom-block-fw.xml"


class PolicyFakeDevice(FakeDevice):
    """FakeDevice whose policy match also checks the destination (literal, object or static group) and service."""

    def policy_match(self, q):
        import ipaddress
        vs = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']"

        def kids(xp):
            el = self._walk(self.running, xp)
            return list(el) if el is not None else []
        addrs = {e.get("name"): e.findtext("ip-netmask") for e in kids(vs + "/address")}
        grps = {e.get("name"): [m.text for m in e.find("static")] for e in kids(vs + "/address-group")}
        dst = ipaddress.ip_address(q["destination"])

        def hit(m, depth=0):
            if m == "any":
                return True
            if m in grps and depth < 5:
                return any(hit(x, depth + 1) for x in grps[m])
            val = addrs.get(m, m)
            try:
                return dst in ipaddress.ip_network(val, strict=False)
            except ValueError:
                return False
        for r in kids(vs + "/rulebase/security/rules"):
            if r.find("disabled") is not None and r.findtext("disabled") == "yes":
                continue
            if q["from"] in [m.text for m in r.find("from")] and q["to"] in [m.text for m in r.find("to")] \
                    and any(hit(m.text) for m in r.find("destination")):
                return r.get("name")
        return None


def _block_cs(select=None):
    env = load_environment(BLOCKXML.resolve(), target="fw-1")
    return build_decom_changeset(_prof(), [env], ["10.1.30.25"], tickets=TICKETS, mode="block",
                                 flows_text="10.1.20.5 10.1.30.25 tcp/443", select=select)


def test_stop_traffic_finds_redundant_permit_and_adds_deny():
    cs = _block_cs()
    ops = _ops(cs)
    assert [a["op"] for a in ops][:2] == ["add-service", "add-deny-rule"]  # deny goes in first
    deny = next(a for a in ops if a["op"] == "add-deny-rule")
    assert deny["place"] == {"where": "before", "ref": "R-DMZ-BROAD"}
    assert deny["rule"]["source"] == ["10.1.20.5"] and deny["rule"]["destination"] == ["10.1.30.25"]
    assert any(a["op"] == "delete-rule" and a["name"] == "R-OLD-ONLY" for a in ops)
    assert any(a["op"] == "edit-group" and a["name"] == "GRP-WEB" and a["remaining"] == ["SRV-NEW"] for a in ops)
    assert not any(a.get("name") in ("R-DMZ-BROAD", "NET-DMZ") for a in ops)  # the broad permit and /24 stay
    place = cs["decom"]["block"]["flows"][0]["places"][0]
    assert place["after"] == "allowed" and place["permits"][0]["rule"] == "R-DMZ-BROAD"
    text = render_changeplan(cs)
    assert "### Add Deny Policy (stop traffic)" in text and "directly above `R-DMZ-BROAD`" in text
    assert "test security-policy-match" in "\n".join(delete_commands(cs) + verify_steps(cs))
    # un-ticking the deny leaves only the clean-up
    cs2 = _block_cs(select=[c["id"] for c in cs["decom"]["candidates"] if c["selected"]])
    assert not any(a["op"] == "add-deny-rule" for a in _ops(cs2))


def test_stop_traffic_push_apply_verify_and_rollback(tmp_path):
    prof = _prof()
    cs = _block_cs()
    (prof.data_dir("changesets") / "decom-block.json").write_text(json.dumps(cs))
    dev = PolicyFakeDevice(BLOCKXML.read_text())
    s = pusher.prepare(prof, cs, "decom-block", actor="eng", cr="CHG0003333", dev=dev)
    assert s["status"] == "prepared", s.get("errors")
    # member removal is a delete of the member node (PAN-OS 'set' would merge, not remove)
    assert any(op["op"] == "delete" and "/member[text()='SRV-OLD']" in op["xpath"] for op in s["ops"])
    assert not any(op["op"] == "set" and "<static>" in (op.get("element") or "") for op in s["ops"])
    s = pusher.apply(prof, cs, s["id"], actor="eng", confirm_target="fw-1", dev=dev)
    assert s["status"] == "committed", (s.get("result"), s.get("verify"))
    assert any("returns DECOM-DENY-10.1.30.25-1" in v["check"] and v["ok"] for v in s["verify"])
    vs = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']"
    names = [r.get("name") for r in dev._walk(dev.running, vs + "/rulebase/security/rules")]
    assert names.index("DECOM-DENY-10.1.30.25-1") == names.index("R-DMZ-BROAD") - 1
    grp = [m.text for m in dev._walk(dev.running, vs + "/address-group/entry[@name='GRP-WEB']/static")]
    assert grp == ["SRV-NEW"]
    s = pusher.rollback(prof, cs, s["id"], actor="eng", confirm_target="fw-1", dev=dev)
    assert s["status"] == "rolled-back", (s.get("result"), s.get("rollback_verify"))
    names = [r.get("name") for r in dev._walk(dev.running, vs + "/rulebase/security/rules")]
    assert names == ["R-OLD-ONLY", "R-WEB", "R-DMZ-BROAD"]  # back in place, deny gone
    grp = [m.text for m in dev._walk(dev.running, vs + "/address-group/entry[@name='GRP-WEB']/static")]
    assert sorted(grp) == ["SRV-NEW", "SRV-OLD"]
    assert not dev.exists_running(vs + "/service/entry[@name='DECOM-tcp-443']")


def test_push_refuses_when_live_config_changed(tmp_path):
    prof = _prof()
    cs = _block_cs()
    # someone already removed SRV-NEW from the group: removing SRV-OLD would now empty it
    xml = BLOCKXML.read_text().replace("<member>SRV-OLD</member><member>SRV-NEW</member>", "<member>SRV-OLD</member>")
    s = pusher.prepare(prof, cs, "decom-chg", actor="eng", cr="CHG0003333", dev=PolicyFakeDevice(xml))
    assert s["status"] == "blocked" and any("GRP-WEB" in x for x in s["errors"])


def test_panorama_push_plan_includes_child_groups():
    cs = _pano_cs(["DC-DECOM-PARENT"])
    steps = pusher.push_plan(cs, Target(name="pano-1", type="panorama"))
    pushed = [p["step"] for p in steps if p["api"] == "type=commit&action=all"]
    assert any("DG-DC" in x for x in pushed) and any("DG-EDGE" in x for x in pushed)
    assert all("entry name=\"\"" not in p["cmd"] for p in steps)


def test_gui_select_rebuilds_and_resets_approval(tmp_path, monkeypatch):
    from test_push import _client, _login
    from panlab.web import approval, auth

    cache = tmp_path / "data" / "fwtest" / "cache"
    cache.mkdir(parents=True)
    (cache / "fw-1-latest.xml").write_bytes(FWXML.read_bytes())
    c = _client(tmp_path, monkeypatch)
    auth.add_user("prep1", "prep", "pw-prep", tmp_path / "users.yaml")
    _login(c, "prep1", "pw-prep")
    r = c.post("/decom", data={"customer": "fwtest", "items": "TST-AUTO-TEST-NAMED", "target": "", "mode": "remove"})
    assert r.status_code == 200, r.text[:500]
    assert "Highly likely" in r.text and "Rebuild plan with this selection" in r.text
    import re
    stem = re.search(r"/changesets/fwtest/(decom-[0-9-]+)/changeplan", r.text).group(1)
    prof = __import__("panlab.customers", fromlist=["load_profile"]).load_profile("fwtest")
    approval.approve(prof, stem, actor="someone", cr="CHG0003333")
    cs = json.loads((prof.data_dir("changesets") / f"{stem}.json").read_text())
    picks = [x["id"] for x in cs["decom"]["candidates"] if x["selectable"]]
    r2 = c.post(f"/decom/fwtest/{stem}/select", data={"pick": picks}, follow_redirects=False)
    assert r2.status_code == 303
    cs2 = json.loads((prof.data_dir("changesets") / f"{stem}.json").read_text())
    assert "TST-AUTO-TEST-ONLY" in {a["name"] for a in _ops(cs2) if a["op"] == "delete-address"}
    assert approval.load(prof, stem) is None  # selection changed: approval reset
    assert c.get(f"/changesets/fwtest/{stem}/decom.csv").text.startswith("section,")
    assert "delete address TST-AUTO-TEST-ONLY" in c.get(f"/changesets/fwtest/{stem}/decom.cli").text


def test_candidate_snapshot_next_to_running_is_not_planned_twice(tmp_path):
    run = tmp_path / "x-running.xml"
    cand = tmp_path / "x-candidate.xml"
    run.write_bytes(PANOXML.read_bytes())
    cand.write_bytes(PANOXML.read_bytes())
    envs = [load_environment(run, target="pano-1"), load_environment(cand, target="pano-1")]
    cs = build_decom_changeset(_prof(), envs, ["SH-DECOM-HOST"], tickets=TICKETS)
    names = [(a["op"], a["name"], a["location"].get("device_group")) for a in _ops(cs)]
    assert len(names) == len(set(names)) and names
    assert len([c for c in cs["decom"]["candidates"] if c["tier"] == "exact"]) == 1
