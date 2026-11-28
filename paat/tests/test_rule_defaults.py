# SPDX-License-Identifier: Apache-2.0
"""Safe defaults on generated allow rules: log at session end always, optional user-set profile group. Synthetic data only."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from fcr_factory import make_fcr  # noqa: E402

from panlab import changeplan, flowmapper as fm, pusher, report  # noqa: E402
from panlab.changeset import build_changeset  # noqa: E402
from panlab.customers import load_profile, rule_profile_group  # noqa: E402
from panlab.fcr import read_fcr  # noqa: E402
from panlab.plan import PlannedRule, _rule_xml_snippet, build_plan, render_plan  # noqa: E402
from panlab.sources import load_customer_envs  # noqa: E402

FIX = Path(__file__).parent / "fixtures"
FWXML = FIX / "synthetic-fw-test.xml"
FLOW = FIX / "synthetic-flow-multivsys.xml"


def _changeset(tmp_path, monkeypatch, group):
    monkeypatch.setenv("PANLAB_DATA_DIR", str(tmp_path / "data"))
    prof = load_profile("fwtest")
    prof.change_plan = dict(prof.change_plan, rule_profile_group=group)
    f = make_fcr(tmp_path / "RITM0000778.xlsx", [("10.200.1.5", None, "10.1.20.60", None, "TCP", "5432", None, "db", None)], project="Example defaults")
    reqs, meta = read_fcr(f, ticket_patterns=prof.tickets)
    return prof, build_changeset(prof, load_customer_envs(prof, configs=[str(FWXML)]), reqs, files=[meta])


def _all_cli(result):
    return json.dumps(result)


def test_blank_group_is_the_default():
    assert load_profile("fwtest").change_plan.get("rule_profile_group") == ""
    assert rule_profile_group(load_profile("fwtest")) == ""
    assert rule_profile_group(None) == ""


def test_group_name_is_cleaned():
    prof = load_profile("fwtest")
    prof.change_plan = dict(prof.change_plan, rule_profile_group=' My "Group"<x> ')
    assert rule_profile_group(prof) == "My Groupx"
    assert fm.clean_profile_group("x" * 100) == "x" * 63


def test_changeset_rules_log_end_and_blank_group(tmp_path, monkeypatch):
    _, cs = _changeset(tmp_path, monkeypatch, "")
    rules = [r for g in cs["groups"] for r in g["rules"] if r.get("operation") != "already-allowed"]
    assert rules and all(r["log_end"] is True and r["profile_group"] == "" for r in rules)
    xml = pusher._rule_element(rules[0])
    assert "<log-end>yes</log-end>" in xml and "profile-setting" not in xml
    cli = "\n".join(report.set_commands(cs))
    assert " log-end yes " in cli and "profile-setting" not in cli


def test_changeset_group_reaches_xml_cli_and_cr_text(tmp_path, monkeypatch):
    _, cs = _changeset(tmp_path, monkeypatch, "PG-Standard")
    rules = [r for g in cs["groups"] for r in g["rules"] if r.get("operation") != "already-allowed"]
    assert rules and all(r["profile_group"] == "PG-Standard" for r in rules)
    xml = pusher._rule_element(rules[0])
    assert "<profile-setting><group><member>PG-Standard</member></group></profile-setting>" in xml
    assert xml.index("<log-end>") < xml.index("<profile-setting>")
    cli = "\n".join(report.set_commands(cs))
    assert " log-end yes profile-setting group PG-Standard tag " in cli
    md = changeplan.render_changeplan(cs)
    assert "Group Profile: `PG-Standard`" in md and "Log at Session End: Yes" in md


def test_flowtrace_engine_adds_log_end_and_group():
    files = [fm.ConfigFile(path=FLOW, name="lab-flow-fw.xml")]
    base = _all_cli(fm.run_trace(files, "10.10.1.50 -> 10.20.1.50 tcp/443"))
    assert " action allow log-end yes" in base and "profile-setting" not in base
    grp = _all_cli(fm.run_trace(files, "10.10.1.50 -> 10.20.1.50 tcp/443", profile_group="PG-Standard"))
    assert " action allow log-end yes profile-setting group PG-Standard" in grp
    again = _all_cli(fm.run_trace(files, "10.10.1.50 -> 10.20.1.50 tcp/443"))
    assert "profile-setting" not in again  # the setting does not leak into the next run


def test_planned_rule_xml_and_text():
    r = PlannedRule(name="r1", action="create", from_zones=["a"], to_zones=["b"], source=["s"], destination=["d"],
                    applications=["ssl"], services=["application-default"], rule_action="allow", profile_group="PG-Standard")
    xml = _rule_xml_snippet(r)
    assert "<log-end>yes</log-end>" in xml and "<profile-setting><group><member>PG-Standard</member></group></profile-setting>" in xml
    r.profile_group = ""
    assert "profile-setting" not in _rule_xml_snippet(r)
