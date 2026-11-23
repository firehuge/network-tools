# SPDX-License-Identifier: Apache-2.0
"""Already-permitted detection: first-match policy evaluation per requested flow (synthetic configs only)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from fcr_factory import make_fcr  # noqa: E402

from panlab import permitted as pm  # noqa: E402
from panlab.changeplan import render_changeplan  # noqa: E402
from panlab.changeset import build_changeset  # noqa: E402
from panlab.customers import load_profile  # noqa: E402
from panlab.fcr import Endpoint, PortSpec, read_fcr  # noqa: E402
from panlab.netmodel import AddressObj, DeviceGroup, Environment, ExistingRule, ObjectScope, ServiceObj  # noqa: E402
from panlab.report import set_commands  # noqa: E402
from panlab.sources import load_customer_envs  # noqa: E402


def _scope(name="DG"):
    s = ObjectScope(name, "device-group", name)
    s.addresses = {"H-SRV": AddressObj("H-SRV", "ip-netmask", "10.2.0.10/32"),
                   "N-USERS": AddressObj("N-USERS", "ip-netmask", "10.1.0.0/16"),
                   "R-LAB": AddressObj("R-LAB", "ip-range", "10.1.5.1-10.1.5.50"),
                   "F-WEB": AddressObj("F-WEB", "fqdn", "web.example.test")}
    s.address_groups = {"AG-SRV": ["H-SRV"], "AG-NEST": ["AG-SRV"]}
    s.dynamic_address_groups = set()
    s.services = {"tcp-8080": ServiceObj("tcp-8080", "tcp", "8080"), "tcp-9000-9100": ServiceObj("tcp-9000-9100", "tcp", "9000-9100"),
                  "tcp-multi": ServiceObj("tcp-multi", "tcp", "22,2222")}
    s.service_groups = {"SG-WEB": ["tcp-8080", "service-https"]}
    s.app_groups = {"APG-REMOTE": ["ssh", "ms-rdp"]}
    s.app_filters = {"AF-RISKY"}
    return s


def R(name, *, src=("any",), dst=("any",), app=("any",), svc=("application-default",), action="allow", fz=("Trust",),
      tz=("DMZ",), disabled=False, rb="pre-rulebase", neg_src=False, neg_dst=False, targets=None, tneg=False):
    return ExistingRule(name=name, rulebase=rb, from_zones=list(fz), to_zones=list(tz), source=list(src), destination=list(dst),
                        application=list(app), service=list(svc), action=action, disabled=disabled, negate_source=neg_src,
                        negate_destination=neg_dst, target_serials=targets or [], target_negate=tneg)


def ev(rules, *, src="10.1.2.3", dst="10.2.0.10", port="22", proto="tcp", apps=("ssh",), fz="Trust", tz="DMZ", serial="SN1"):
    res = pm.Resolver([_scope()])
    s = Endpoint("ip" if "/" not in src and "-" not in src else ("range" if "-" in src else "ip"), src)
    return pm.evaluate([(r, "DG pre-rulebase") for r in rules], res, serial=serial, vsys="vsys1", fz=fz, tz=tz, src=s,
                       dst=Endpoint("ip", dst), ps=PortSpec(proto, port), apps=list(apps))


def test_addresses_groups_ranges_any_negate():
    assert ev([R("A", src=["N-USERS"], dst=["AG-NEST"])]).status == "permitted"
    assert ev([R("A", src=["N-USERS"], dst=["AG-NEST"])], src="10.9.9.9").status == "none"
    assert ev([R("A", src=["R-LAB"])], src="10.1.5.0/28").status == "none"  # .0 outside the range
    assert ev([R("A", src=["R-LAB"])], src="10.1.5.10-10.1.5.20").status == "permitted"
    assert ev([R("A", src=["10.1.0.0/16"])]).status == "permitted"  # literal value in the rule
    assert ev([R("A", src=["N-USERS"], neg_src=True)]).status == "none"
    assert ev([R("A", src=["N-USERS"], neg_src=True)], src="10.7.0.1").status == "permitted"
    assert ev([R("A", dst=["F-WEB"])]).status == "none"  # fqdn object never covers an IP


def test_zones_apps_groups_filters_and_any():
    assert ev([R("A", fz=["Untrust"])]).status == "none"
    assert ev([R("A", fz=["any"], tz=["any"])]).status == "permitted"
    assert ev([R("A", app=["APG-REMOTE"])]).status == "permitted"
    assert ev([R("A", app=["AF-RISKY"])]).status == "none"  # application filter: cannot prove
    assert ev([R("A", app=["ssl"], svc=["any"])]).status == "none"
    r = ev([R("A", app=["ssh"], svc=["any"])], apps=())  # request app unknown -> rule must allow any app
    assert r.status == "none" and "only application(s) ssh" in r.note


def test_services_appdefault_groups_ranges_any():
    assert ev([R("A")]).status == "permitted"  # ssh on 22 = application-default
    assert ev([R("A")], port="2222").status == "none"
    assert ev([R("A")], apps=()).status == "none"  # application-default needs a known app
    assert ev([R("A", svc=["tcp-multi"])], port="2222").status == "permitted"
    assert ev([R("A", svc=["SG-WEB"])], port="443", apps=("ssl",)).status == "permitted"
    assert ev([R("A", svc=["SG-WEB"])], port="8080", apps=("web-browsing",)).status == "permitted"
    assert ev([R("A", svc=["tcp-9000-9100"])], port="9050-9060", apps=()).status == "permitted"
    assert ev([R("A", svc=["tcp-9000-9100"])], port="9050-9200", apps=()).status == "none"
    assert ev([R("A", svc=["any"], app=["any"])], proto="udp", port="53", apps=()).status == "permitted"
    assert ev([R("A", svc=["tcp-8080"])], proto="udp", port="8080", apps=()).status == "none"


def test_order_deny_above_disabled_and_targets():
    allow = R("ALLOW", app=["ssh"])
    v = ev([R("DENY", action="deny", app=["any"], svc=["any"]), allow])
    assert v.status == "blocked" and v.rule == "DENY"
    assert ev([R("DENY", action="drop", svc=["any"], disabled=True), allow]).status == "permitted"
    assert ev([R("DENY", action="deny", svc=["tcp-8080"]), allow]).status == "permitted"  # deny does not overlap
    assert ev([allow, R("DENY", action="deny", svc=["any"])]).status == "permitted"  # deny below: first match wins
    assert ev([R("A", targets=[("SN2", [])])]).status == "none"  # rule targets another firewall
    assert ev([R("A", targets=[("SN1", ["vsys1"])])]).status == "permitted"
    assert ev([R("A", targets=[("SN1", [])], tneg=True)]).status == "none"
    # partial allow (part of the source) above, full allow below
    v = ev([R("PART", src=["10.1.2.0/24"]), R("FULL")], src="10.1.0.0/16")
    assert v.status == "permitted" and v.rule == "FULL" and v.partial_allow == ["PART (DG pre-rulebase)"]


def test_intrazone_and_interzone_rule_types():
    def typed(rt, **kw):
        r = R("T", **kw)
        r.rule_type = rt
        return r
    # an intrazone allow (from any to any) must not cover a cross-zone flow; an interzone allow must not cover a same-zone flow
    assert ev([typed("intrazone", fz=["any"], tz=["any"])], fz="Trust", tz="DMZ").status == "none"
    assert ev([typed("intrazone", fz=["any"], tz=["any"])], fz="Trust", tz="Trust").status == "permitted"
    assert ev([typed("interzone", fz=["any"], tz=["any"])], fz="Trust", tz="Trust").status == "none"
    assert ev([typed("interzone", fz=["any"], tz=["any"])], fz="Trust", tz="DMZ").status == "permitted"
    assert ev([typed("universal", fz=["any"], tz=["any"])], fz="Trust", tz="DMZ").status == "permitted"


def test_rule_type_is_parsed():
    import xml.etree.ElementTree as ET
    from panlab.netmodel import _security_rule_from_entry
    e = ET.fromstring('<entry name="X"><rule-type>intrazone</rule-type><from><member>any</member></from></entry>')
    assert _security_rule_from_entry(e, "rulebase").rule_type == "intrazone"
    assert _security_rule_from_entry(ET.fromstring('<entry name="Y"/>'), "rulebase").rule_type == "universal"


def test_port_based_permit_is_marked():
    assert ev([R("PB", svc=["tcp-multi"])], port="2222").port_based is True
    assert ev([R("AD", app=["ssh"])]).port_based is False


def test_panorama_evaluation_order():
    env = Environment(kind="panorama", target="p", source="test")
    env.shared.security_rules = [R("SH-PRE"), R("SH-POST", rb="post-rulebase")]
    parent, child = _scope("PARENT"), _scope("CHILD")
    parent.security_rules = [R("P-PRE"), R("P-POST", rb="post-rulebase")]
    child.security_rules = [R("C-PRE"), R("C-POST", rb="post-rulebase")]
    env.device_groups = {"PARENT": DeviceGroup("PARENT", None, [], parent), "CHILD": DeviceGroup("CHILD", "PARENT", [], child)}
    order = [r.name for r, _ in pm.ordered_rules(env, device_group="CHILD", vsys_scope=None)]
    assert order == ["SH-PRE", "P-PRE", "C-PRE", "C-POST", "P-POST", "SH-POST"]


@pytest.fixture
def pano(tmp_path, monkeypatch):
    monkeypatch.setenv("PANLAB_DATA_DIR", str(tmp_path / "data"))
    prof = load_profile("example-pano")
    return prof, load_customer_envs(prof)


def _build(prof, envs, tmp_path, rows):
    f = make_fcr(tmp_path / "RITM0010020.xlsx", rows, project="P")
    reqs, meta = read_fcr(f, ticket_patterns=prof.tickets)
    return build_changeset(prof, envs, reqs, files=[meta])


def test_changeset_green_partial_and_plan(pano, tmp_path):
    prof, envs = pano
    cs = _build(prof, envs, tmp_path, [("10.10.1.5", None, "10.20.1.10", None, "tcp", "443", None, "", "ssl"),
                                       ("10.10.1.6", None, "10.20.1.10", None, "tcp", "443, 8443", None, "", "ssl"),
                                       ("10.10.1.7", None, "10.20.1.10", None, "tcp", "443", None, "", None)])
    rules = [r for g in cs["groups"] for r in g["rules"]]
    green = [r for r in rules if r.get("operation") == "already-allowed"]
    assert [(r["request"], r["name"], r["from"], r["to"]) for r in green] == [
        ("R001", "allow-users-web", ["USERS"], ["TO-VSYS2"])]
    assert green[0]["flags"][0] == {"level": "green", "code": "already-permitted",
                                    "message": "Already permitted by allow-users-web (DG-DC)"}
    # R002 vsys1 hop: 443 permitted, only 8443 proposed (yellow)
    part = next(r for r in rules if r.get("request") == "R002" and r["from"] == ["USERS"] and r.get("operation") != "already-allowed")
    assert part["service"] == ["svc-tcp-8443"]
    assert any(f["level"] == "yellow" and f["code"] == "partly-permitted" and "tcp/443 by allow-users-web (DG-DC)" in f["message"]
               for f in part["flags"])
    # R003 without an app: application-default rule cannot prove it; a rule is proposed with an info note
    r3 = next(r for r in rules if r.get("request") == "R003" and r["from"] == ["USERS"])
    assert r3.get("operation", "add") == "add" and any(f["code"] == "permitted-other-apps" for f in r3["flags"])
    pc = {q["id"]: [c["status"] for c in q["policy_check"]] for q in cs["requests"]}
    assert pc["R001"][0] == "permitted" and pc["R002"][0] == "partial" and pc["R003"][0] == "not-permitted"
    text = render_changeplan(cs)
    assert "Already permitted by allow-users-web (DG-DC)" in text and "### Already allowed" in text
    cli = "\n".join(set_commands(cs))
    assert "allow-users-web" not in cli.replace("already allowed by existing rule allow-users-web", "")
    # nothing is created for a fully permitted request
    only = _build(prof, envs, tmp_path, [("10.10.1.5", None, "10.20.1.10", None, "tcp", "443", None, "", "ssl")])
    g = next(g for g in only["groups"] if any(r.get("operation") == "already-allowed" for r in g["rules"]))
    green_only = [r for r in g["rules"] if r.get("operation") == "already-allowed"]
    assert green_only[0]["source"] == ["10.10.1.5"] and green_only[0]["service"] == ["tcp/443"]


def test_deny_above_in_hierarchy_blocks(pano, tmp_path, monkeypatch):
    prof, envs = pano
    dc = envs[0].device_groups["DG-DC"].scope
    dc.security_rules.insert(0, R("block-web", src=["any"], dst=["DC-WEB-01"], app=["any"], svc=["any"], action="deny",
                                  fz=["USERS"], tz=["any"]))
    cs = _build(prof, envs, tmp_path, [("10.10.1.5", None, "10.20.1.10", None, "tcp", "443", None, "", "ssl")])
    rules = [r for g in cs["groups"] for r in g["rules"]]
    assert not any(r.get("operation") == "already-allowed" for r in rules)
    r = next(r for r in rules if r["from"] == ["USERS"])
    assert any(f["code"] == "blocked-above" and "block-web" in f["message"] for f in r["flags"])
    # disabled allow rule never counts
    dc.security_rules.pop(0)
    next(x for x in dc.security_rules if x.name == "allow-users-web").disabled = True
    cs = _build(prof, envs, tmp_path, [("10.10.1.5", None, "10.20.1.10", None, "tcp", "443", None, "", "ssl")])
    assert not any(r.get("operation") == "already-allowed" for g in cs["groups"] for r in g["rules"])
