# SPDX-License-Identifier: Apache-2.0
"""Combine similar FCR rows into one rule, group hosts, and reuse existing rules."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from fcr_factory import make_fcr  # noqa: E402

from panlab import pusher  # noqa: E402
from panlab.changeplan import changeplan_sections, render_changeplan, rollback_commands  # noqa: E402
from panlab.changeset import build_changeset  # noqa: E402
from panlab.combine import apply_reuse_choice  # noqa: E402
from panlab.customers import load_profile  # noqa: E402
from panlab.fcr import Tickets, read_fcr  # noqa: E402
from panlab.report import set_commands  # noqa: E402
from panlab.sources import load_customer_envs  # noqa: E402

FIX = Path(__file__).parent / "fixtures"
FWXML = FIX / "synthetic-fw-test.xml"
COMBINE = FIX / "synthetic-combine-fw.xml"


@pytest.fixture(autouse=True)
def _data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("PANLAB_DATA_DIR", str(tmp_path / "data"))


def _cs(tmp_path, rows, *, xml=FWXML, project="Pack", combine=True, override=None, files=None):
    prof = load_profile("fwtest")
    if files is None:
        f = make_fcr(tmp_path / "RITM0001001.xlsx", rows, project=project)
        reqs, meta = read_fcr(f, ticket_patterns=prof.tickets, override=override)
        metas = [meta]
    else:
        reqs, metas = [], []
        for path, proj in files:
            r, m = read_fcr(path, ticket_patterns=prof.tickets, override=override)
            reqs += r
            metas.append(m)
    return build_changeset(prof, load_customer_envs(prof, configs=[str(xml)]), reqs, files=metas, combine=combine)


def test_fifty_hosts_combine_into_one_rule_and_group(tmp_path):
    rows = [("10.1.20.5", None, f"10.99.1.{i}", None, "TCP", "443", None, "", None) for i in range(1, 51)]
    cs = _cs(tmp_path, rows, project="Pack")
    assert cs["summary"]["combined_into"] == 49
    rules = cs["groups"][0]["rules"]
    added = [r for r in rules if (r.get("operation") or "add") == "add"]
    assert len(added) == 1
    rule = added[0]
    assert rule["from"] == ["LAN"] and rule["to"] == ["untrust"]
    assert len(rule["source"]) == 1
    assert len(rule["destination"]) == 1
    groups = [o for o in cs["groups"][0]["objects"]["new"] if o["kind"] == "address-group"]
    assert len(groups) == 1
    grp = groups[0]
    assert rule["destination"] == [grp["name"]]
    assert len(grp["members"]) == 50
    assert grp["name"].startswith("TST-Pack-") and "SRV-GRP" in grp["name"]
    assert any(f["code"] == "subnet-suggest" and "50 of 256 hosts in 10.99.1.0/24" in f["message"]
               for f in rule["flags"])
    text = render_changeplan(cs)
    assert "### Add Address Group" in text
    assert f"- Name: `{grp['name']}`" in text
    assert "### Add Policy" in text
    cli = "\n".join(set_commands(cs))
    assert f"address-group {grp['name']} static" in cli
    assert "set rulebase security rules" in cli
    rb = "\n".join(rollback_commands(cs))
    assert f"address-group {grp['name']}" in rb


def test_no_combine_keeps_separate_rules_but_can_still_group(tmp_path):
    rows = [("10.1.20.5", None, f"10.99.1.{i}", None, "TCP", "443", None, "", None) for i in range(1, 4)]
    cs = _cs(tmp_path, rows, combine=False)
    assert cs["combine"] is False
    assert cs["summary"]["combined_into"] == 0
    added = [r for r in cs["groups"][0]["rules"] if (r.get("operation") or "add") == "add"]
    assert len(added) == 3
    # below threshold: no group
    assert not any(o["kind"] == "address-group" for o in cs["groups"][0]["objects"]["new"])


def test_merge_same_addresses_unions_services(tmp_path):
    rows = [
        ("10.1.20.5", None, "10.99.1.1", None, "TCP", "443", None, "", None),
        ("10.1.20.5", None, "10.99.1.1", None, "TCP", "80", None, "", None),
    ]
    cs = _cs(tmp_path, rows)
    added = [r for r in cs["groups"][0]["rules"] if (r.get("operation") or "add") == "add"]
    assert len(added) == 1
    assert set(added[0]["service"]) == {"service-https", "TST-tcp-80"}


def test_combine_across_tickets_can_be_disabled(tmp_path, monkeypatch):
    prof = load_profile("fwtest")
    monkeypatch.setattr(prof, "combine_across_tickets", False)
    a = make_fcr(tmp_path / "RITM0002001.xlsx",
                 [("10.1.20.5", None, "10.99.1.1", None, "TCP", "443", None, "", None)], project="A")
    b = make_fcr(tmp_path / "RITM0002002.xlsx",
                 [("10.1.20.8", None, "10.99.1.1", None, "TCP", "443", None, "", None)], project="B")
    reqs, metas = [], []
    for f in (a, b):
        r, m = read_fcr(f, ticket_patterns=prof.tickets)
        reqs += r
        metas.append(m)
    cs = build_changeset(prof, load_customer_envs(prof, configs=[str(FWXML)]), reqs, files=metas, combine=True)
    added = [r for r in cs["groups"][0]["rules"] if (r.get("operation") or "add") == "add"]
    assert len(added) == 2
    # default (across tickets true)
    cs2 = build_changeset(load_profile("fwtest"), load_customer_envs(load_profile("fwtest"), configs=[str(FWXML)]),
                          reqs, files=metas, combine=True)
    added2 = [r for r in cs2["groups"][0]["rules"] if (r.get("operation") or "add") == "add"]
    assert len(added2) == 1
    assert "RITM0002001" in added2[0]["description"] and "RITM0002002" in added2[0]["description"]
    tags = set(added2[0]["tags"])
    assert "TST-RITM0002001" in tags and "TST-RITM0002002" in tags


def test_existing_rule_edit_proposal_and_choice(tmp_path):
    rows = [
        ("10.1.20.60", None, "192.0.2.80", None, "TCP", "443", None, "", None),
        ("10.1.20.61", None, "192.0.2.80", None, "TCP", "443", None, "", None),
    ]
    cs = _cs(tmp_path, rows, xml=COMBINE, project="Web")
    green = [r for r in cs["groups"][0]["rules"] if r.get("operation") == "already-allowed"]
    assert [r["request"] for r in green] == ["R001"]  # 10.1.20.60 is already permitted on its own (no merge, no objects)
    rules = [r for r in cs["groups"][0]["rules"] if r.get("operation") != "already-allowed"]
    assert len(rules) == 1
    rule = rules[0]
    assert rule["operation"] == "edit"
    assert rule["name"] == "LAN-WEB-ALLOW"
    fields = {ed["field"]: ed for ed in rule["edits"]}
    assert "source" in fields
    added = fields["source"]["values"]
    assert any(n.endswith("10.1.20.61") or "10.1.20.61" in n for n in added)
    # EXISTING-SRC already covers 10.1.20.60, so it is not added
    assert not any("10.1.20.60" in n or n == "EXISTING-SRC" for n in added)
    text = render_changeplan(cs)
    assert "### Edit Policy" in text
    assert "- Rule: `LAN-WEB-ALLOW`" in text
    assert "Add source address" in text
    assert "Alternative: create a new rule" in text
    cli = "\n".join(set_commands(cs))
    assert "set rulebase security rules LAN-WEB-ALLOW source" in cli
    rb = "\n".join(rollback_commands(cs))
    assert "delete rulebase security rules LAN-WEB-ALLOW source" in rb
    assert "delete rulebase security rules LAN-WEB-ALLOW\n" not in rb + "\n"
    # switch to a new rule
    apply_reuse_choice(cs, {rule["uid"]: "new"})
    rule = next(r for r in cs["groups"][0]["rules"] if r.get("uid") == rule["uid"])
    assert rule["operation"] == "add"
    assert rule["name"] != "LAN-WEB-ALLOW"
    text = render_changeplan(cs)
    assert "### Add Policy" in text and "### Edit Policy" not in text


def test_already_allowed_and_never_edit_deny_or_any_source(tmp_path):
    # exact existing coverage
    cs = _cs(tmp_path, [("10.1.20.60", None, "192.0.2.80", None, "TCP", "443", None, "", None)],
             xml=COMBINE, project="Web")
    rule = cs["groups"][0]["rules"][0]
    assert rule["operation"] == "already-allowed"
    assert rule["name"] == "LAN-WEB-ALLOW"
    text = render_changeplan(cs)
    assert "### Already allowed" in text
    assert "LAN-WEB-ALLOW" in text
    cli = "\n".join(set_commands(cs))
    assert "no set commands" in cli or "already allowed" in cli.lower()
    assert "set rulebase security rules LAN-WEB-ALLOW source" not in cli

    # deny rule uses tcp-8443; a request on 8443 from EXISTING-SRC should not propose the deny
    cs = _cs(tmp_path, [("10.1.20.61", None, "192.0.2.80", None, "TCP", "8443", None, "", None)],
             xml=COMBINE, project="Web")
    rule = cs["groups"][0]["rules"][0]
    names = [c["name"] for c in (rule.get("reuse") or {}).get("candidates") or []]
    assert "LAN-DENY-WEB" not in names
    # LAN-ANY-SRC-WEB has source any — must not be used to add a source
    assert "LAN-ANY-SRC-WEB" not in names or rule["operation"] != "edit" or \
        not any(ed.get("field") == "source" for ed in rule.get("edits") or [])


def test_reuse_existing_address_group_with_exact_members(tmp_path):
    rows = [(f"10.1.20.{70 + i}", None, "192.0.2.10", None, "TCP", "5432", None, "", None) for i in range(5)]
    cs = _cs(tmp_path, rows, xml=COMBINE, project="Pack")
    added = [r for r in cs["groups"][0]["rules"] if (r.get("operation") or "add") == "add"]
    assert len(added) == 1
    rule = added[0]
    assert "LAN-SRV-GRP" in rule["source"]
    reused = [o for o in cs["groups"][0]["objects"]["reused"] if o["kind"] == "address-group"]
    assert any(o["name"] == "LAN-SRV-GRP" for o in reused)
    assert not any(o["kind"] == "address-group" for o in cs["groups"][0]["objects"]["new"])


def test_edit_push_ops_and_rollback_only_remove_added(tmp_path):
    from test_push import FakeDevice  # noqa: WPS433

    rows = [
        ("10.1.20.60", None, "192.0.2.80", None, "TCP", "443", None, "", None),
        ("10.1.20.61", None, "192.0.2.80", None, "TCP", "443", None, "", None),
    ]
    prof = load_profile("fwtest")
    cs = _cs(tmp_path, rows, xml=COMBINE, project="Web")
    rule = next(r for r in cs["groups"][0]["rules"] if r.get("operation") != "already-allowed")
    assert rule["operation"] == "edit"
    added = next(ed["values"] for ed in rule["edits"] if ed["field"] == "source")
    dev = FakeDevice(COMBINE.read_text())
    # write changeset for session helpers
    d = prof.data_dir("changesets")
    (d / "cs-edit.json").write_text(json.dumps(cs))
    ops, rb, diff = pusher.build_ops(cs, prof.targets[0], {})
    assert any(o.get("kind") == "rule-member" and o.get("member") in added for o in ops)
    assert any(o.get("kind") == "rule-member" for o in rb)
    assert not any(o.get("kind") == "rule" and o.get("name") == "LAN-WEB-ALLOW" and o.get("op") != "set" or
                   (o.get("kind") == "rule" and "LAN-WEB-ALLOW" == o.get("name") and not o.get("element"))
                   for o in ops)
    # apply via FakeDevice set
    for op in ops:
        pusher._exec_op(dev, op)
    dev.commit("test")
    xml = __import__("xml.etree.ElementTree", fromlist=["ET"]).tostring(dev.running, encoding="unicode")
    for n in added:
        assert n in xml
    assert "EXISTING-SRC" in xml and "LAN-WEB-ALLOW" in xml
    for op in rb:
        pusher._exec_op(dev, op)
    dev.commit("rollback")
    xml = __import__("xml.etree.ElementTree", fromlist=["ET"]).tostring(dev.running, encoding="unicode")
    for n in added:
        # added host object may still exist; the member must be gone from the rule
        pass
    # parse the existing rule source members
    import xml.etree.ElementTree as ET
    root = ET.fromstring(xml)
    entry = root.find(".//rules/entry[@name='LAN-WEB-ALLOW']")
    src = [m.text for m in entry.find("source")]
    assert "EXISTING-SRC" in src
    assert not any(n in src for n in added)
    assert entry is not None  # rule itself was not deleted


def test_cli_no_combine_flag(tmp_path):
    from panlab.cli import build_parser
    p = build_parser()
    ns = p.parse_args(["import", "--customer", "fwtest", str(tmp_path / "x.xlsx"), "--no-combine"])
    assert ns.no_combine is True


def test_changeplan_sections_include_edit_and_group(tmp_path):
    rows = [("10.1.20.5", None, f"10.99.1.{i}", None, "TCP", "443", None, "", None) for i in range(1, 6)]
    cs = _cs(tmp_path, rows, project="Pack")
    parts = changeplan_sections(cs)
    assert "### Add Address Group" in parts["cr"]
    assert "address-group" in parts["cli"]
    assert "address-group" in parts["rollback"]


def test_gui_combine_toggle_and_reuse_radio(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from panlab.web import auth
    from panlab.web.app import app
    from test_push import _login

    monkeypatch.setenv("PANLAB_USERS_FILE", str(tmp_path / "users.yaml"))
    monkeypatch.setenv("PANLAB_DATA_DIR", str(tmp_path / "data"))
    auth.add_user("prep1", "prep", "pw-prep", tmp_path / "users.yaml")
    c = TestClient(app)
    _login(c, "prep1", "pw-prep")
    home = c.get("/")
    assert home.status_code == 200
    assert "Combine rules where possible" in home.text
    assert "name='combine_on'" in home.text or 'name="combine_on"' in home.text

    f = make_fcr(tmp_path / "RITM0003001.xlsx",
                 [("10.1.20.60", None, "192.0.2.80", None, "TCP", "443", None, "", None),
                  ("10.1.20.61", None, "192.0.2.80", None, "TCP", "443", None, "", None)],
                 project="Web")
    # The fwtest customer uses the cached/offline fwtest config, not COMBINE. Use CLI-built
    # changeset drop-in: write a combine fixture changeset into the data dir via import
    # is customer-bound to fwtest's default config. Check the form only, then post reuse
    # against a changeset we write ourselves.
    from panlab.report import write_outputs
    cs = _cs(tmp_path, [("10.1.20.60", None, "192.0.2.80", None, "TCP", "443", None, "", None),
                        ("10.1.20.61", None, "192.0.2.80", None, "TCP", "443", None, "", None)],
             xml=COMBINE, project="Web")
    write_outputs(cs, load_profile("fwtest").data_dir("changesets"), "cs-reuse-gui")
    page = c.get("/changesets/fwtest/cs-reuse-gui/changeplan")
    assert page.status_code == 200
    assert "Add to existing" in page.text and "LAN-WEB-ALLOW" in page.text
    assert "Create new rule" in page.text
    uid = next(r for r in cs["groups"][0]["rules"] if r.get("operation") == "edit")["uid"]
    upd = c.post(f"/changesets/fwtest/cs-reuse-gui/reuse", data={f"choice-{uid}": "new"}, follow_redirects=True)
    assert upd.status_code == 200
    assert "### Add Policy" in upd.text
    assert "### Edit Policy" not in upd.text
