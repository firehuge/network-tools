# SPDX-License-Identifier: Apache-2.0
"""Phase 2: config model, placement, FCR import, change sets, customers (all synthetic data)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from fcr_factory import make_fcr  # noqa: E402

from panlab.changeset import build_changeset, dedupe  # noqa: E402
from panlab.cli import main  # noqa: E402
from panlab.customers import load_profile  # noqa: E402
from panlab.fcr import Tickets, find_tickets, parse_endpoints, parse_ports, read_fcr  # noqa: E402
from panlab.netmodel import load_environment, merge_nodes, pair_ha  # noqa: E402
from panlab.placement import place  # noqa: E402
from panlab.report import set_commands, to_html, to_markdown  # noqa: E402
from panlab.sources import load_customer_envs  # noqa: E402

FIX = Path(__file__).parent / "fixtures"
PANO = FIX / "synthetic-panorama.xml"
LABFW = FIX / "synthetic-fw-test.xml"


@pytest.fixture(autouse=True)
def _data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("PANLAB_DATA_DIR", str(tmp_path / "data"))


@pytest.fixture(scope="module")
def pano():
    return load_environment(PANO, target="pano-synth")


@pytest.fixture(scope="module")
def labfw():
    return load_environment(LABFW, target="fw-1")


def by(placements, device, vsys):
    return next(p for p in placements if p.device == device and p.vsys == vsys)


# ------------------------------------------------------------------ model
def test_panorama_model_stacks_variables_and_dgs(pano):
    assert pano.kind == "panorama"
    names = {d.name: d for d in pano.devices}
    assert set(names) == {"FW-CORE-1", "FW-BR-A", "FW-BR-B"}
    core = names["FW-CORE-1"]
    assert core.multi_vsys and set(core.vsys) == {"vsys1", "vsys2", "vsys3"}
    assert {v: core.vsys[v].device_group for v in core.vsys} == {"vsys1": "DG-DC", "vsys2": "DG-DC", "vsys3": "DG-EDGE"}
    # per-device variables override template variables
    br_a = names["FW-BR-A"]
    assert [str(i) for i in br_a.interfaces["ethernet1/1"].ips] == ["10.101.0.1/16"]
    assert [str(i) for i in names["FW-BR-B"].interfaces["ethernet1/2"].ips] == ["10.250.0.6/30"]
    # TPL-COMMON (second template) still contributes its MGMT zone and interface
    assert br_a.interfaces["ethernet1/8"].zone == "MGMT"
    assert br_a.routers["default"].routes  # default route via variable next hop
    # DG hierarchy
    assert [g.name for g in pano.dg_chain("DG-EDGE")] == ["DG-EDGE", "DG-DC"]
    scopes = pano.scopes_for(core, "vsys3")
    assert [s.label for s in scopes] == ["DG DG-EDGE", "DG DG-DC", "shared"]
    assert core.vsys["vsys1"].intrazone_default == "allow"


def test_firewall_model(labfw):
    assert labfw.kind == "firewall" and len(labfw.devices) == 1
    d = labfw.devices[0]
    assert d.interfaces["tunnel.1"].zone == "Tunnel"
    assert {s.label for s in labfw.scopes_for(d, "vsys1")} == {"vsys vsys1", "shared"}


def test_merge_nodes_first_template_wins():
    import xml.etree.ElementTree as ET

    hi = ET.fromstring("<a><x name='1'><v>hi</v></x></a>")
    lo = ET.fromstring("<a><x name='1'><v>lo</v><w>keep</w></x><x name='2'/></a>")
    m = merge_nodes(hi, lo)
    assert m.find("x[@name='1']/v").text == "hi"
    assert m.find("x[@name='1']/w").text == "keep"
    assert m.find("x[@name='2']") is not None


def test_ha_never_pairs_across_template_stacks(tmp_path):
    a = load_environment(PANO, target="t").devices
    br_a, br_b = [d for d in a if d.name in ("FW-BR-A", "FW-BR-B")]
    for d in (br_a, br_b):
        d.ha_peer, d.ha_secondary = None, False
    # same interface addresses (looks like HA) but different stacks -> never paired
    br_b.interfaces = br_a.interfaces
    br_b.stack = "ST-OTHER-SITE"
    assert pair_ha([br_a, br_b]) == []
    br_b.stack = br_a.stack
    assert len(pair_ha([br_a, br_b])) == 1 and br_b.ha_secondary


# ------------------------------------------------------------------ placement
def test_multivsys_placement_both_vsys(pano):
    r = place([pano], "10.10.5.5", "10.20.1.10")
    assert len(r.placements) == 2
    v1, v2 = by(r.placements, "FW-CORE-1", "vsys1"), by(r.placements, "FW-CORE-1", "vsys2")
    assert (v1.from_zone, v1.to_zone, v1.device_group) == ("USERS", "TO-VSYS2", "DG-DC")
    assert (v2.from_zone, v2.to_zone) == ("FROM-VSYS1", "SERVERS")
    assert v1.confidence == "high" and not r.needs_human


def test_path_continues_into_edge_vsys(pano):
    r = place([pano], "10.10.1.1", "8.8.8.8")
    v3 = by(r.placements, "FW-CORE-1", "vsys3")
    assert (v3.from_zone, v3.to_zone, v3.device_group) == ("INSIDE", "OUTSIDE", "DG-EDGE")
    assert v3.confidence == "medium"  # default route side


def test_multiple_firewalls(pano):
    r = place([pano], "10.101.1.1", "10.102.1.1")
    devs = {(p.device, p.from_zone, p.to_zone) for p in r.placements}
    assert ("FW-BR-A", "LAN", "WAN") in devs and ("FW-BR-B", "WAN", "LAN") in devs
    core = by(r.placements, "FW-CORE-1", "vsys1")
    assert core.intrazone and not core.rule_needed  # WAN->WAN hairpin, default intrazone allow


def test_intrazone_no_rule_needed(pano):
    r = place([pano], "10.10.1.1", "10.10.2.2")
    assert len(r.placements) == 1 and r.placements[0].intrazone and not r.placements[0].rule_needed


def test_unknown_needs_human(pano, labfw):
    assert place([pano], "192.0.2.10", "198.51.100.10").needs_human
    r = place([pano], None, "172.16.30.5")
    assert r.placements[0].from_zone is None and r.placements[0].needs_human


def test_firewall_hint_limits(pano):
    r = place([pano], "10.101.1.1", "10.102.1.1", firewall_hint="fw-br-b")
    assert {p.device for p in r.placements} == {"FW-BR-B"}


def test_standalone_placement(labfw):
    r = place([labfw], "10.200.1.1", "10.1.10.5")
    p = r.placements[0]
    assert (p.from_zone, p.to_zone, p.confidence, p.backend, p.device_group) == ("Tunnel", "trust", "high", "firewall", None)


# ------------------------------------------------------------------ FCR parsing
@pytest.mark.parametrize("cell,proto,want", [
    ("80,443", "TCP", ["tcp/80", "tcp/443"]),
    ("80; 443", None, ["tcp/80", "tcp/443"]),
    ("50000-59999", "udp", ["udp/50000-59999"]),
    ("1000:2000", "tcp", ["tcp/1000-2000"]),
    ("80\n443\n8443", "", ["tcp/80", "tcp/443", "tcp/8443"]),
    ("53", "TCP/UDP", ["tcp/53", "udp/53"]),
    (None, "ICMP", ["icmp"]),
    ("443", "tcp", ["tcp/443"]),
])
def test_port_parsing(cell, proto, want):
    specs, _ = parse_ports(cell, proto)
    assert [s.text for s in specs] == want


def test_port_flags():
    _, flags = parse_ports("any", "tcp")
    assert any(f.level == "red" and f.code == "any-port" for f in flags)
    _, flags = parse_ports("abc", "tcp")
    assert any(f.code == "bad-port" for f in flags)
    _, flags = parse_ports("443", None)
    assert any(f.code == "protocol-default" for f in flags)


def test_endpoints_ad_group_dns_and_cidr():
    eps, flags = parse_endpoints("CORP\\Payroll Admins", None, "source")
    assert eps[0].kind == "user" and any(f.code == "ad-group" for f in flags)
    eps, flags = parse_endpoints(None, "app.example.test", "destination")
    assert eps[0].kind == "fqdn" and any(f.code == "fqdn-no-ip" for f in flags)
    eps, flags = parse_endpoints("10.1.1.5 /24, 10.2.2.2\n10.3.3.3-10.3.3.9", None, "source")
    assert [e.value for e in eps] == ["10.1.1.0/24", "10.2.2.2", "10.3.3.3-10.3.3.9"]
    assert any(f.code == "host-bits" for f in flags)


def test_ticket_regex():
    t = find_tickets(["RITM0012345-x.xlsx", "Project SCTASK0045678", "per CHG0009876 and CR1234"],
                     load_profile("fwtest").tickets)
    assert t.ritm == ["RITM0012345"] and t.sctask == ["SCTASK0045678"] and t.cr == ["CHG0009876", "CR1234"]


def test_read_fcr_layout_and_overrides(tmp_path):
    f = make_fcr(tmp_path / "RITM0000001.xlsx", [("10.10.0.5", None, "10.20.1.10", None, None, "443", None, "SCTASK0000002", None)],
                 project="Web")
    reqs, meta = read_fcr(f, ticket_patterns=load_profile("fwtest").tickets)
    assert meta["project"] == "Web" and reqs[0].row == 4
    assert reqs[0].tickets.ritm == ["RITM0000001"] and reqs[0].tickets.sctask == ["SCTASK0000002"]
    reqs, _ = read_fcr(f, ticket_patterns=load_profile("fwtest").tickets, override=Tickets(ritm=["RITM0099999"]))
    assert reqs[0].tickets.ritm == ["RITM0099999"] and reqs[0].tickets.sctask == ["SCTASK0000002"]


def test_real_template_headers_are_recognized():
    tpl = Path(__file__).parents[1] / "templates" / "customer-rule-request-form.xlsx"
    reqs, meta = read_fcr(tpl, ticket_patterns=load_profile("fwtest").tickets)
    assert meta["rows"] == len(reqs)  # empty form parses cleanly


# ------------------------------------------------------------------ change sets
def _two_files(tmp_path):
    a = make_fcr(tmp_path / "RITM0010001.xlsx", [
        ("10.10.0.0/24", None, "10.20.1.10", None, "TCP", "8443", None, "", None),
        ("CORP\\Payroll Admins", None, "10.20.1.20", None, "", "1433", None, "", None),
        ("10.101.3.3", None, "10.102.4.4", None, "tcp", "3389", None, "", None),
        ("10.10.0.0/24", None, "172.16.30.5", None, "tcp", "22", None, "", None),
    ], project="Payroll")
    b = make_fcr(tmp_path / "ops.xlsx", [
        ("10.10.0.0/24", None, "10.20.1.10", None, "TCP", "8443", None, "CHG0030001", None),
        ("10.0.0.0/8", None, "172.16.30.5", None, "udp", "514", None, "", None),
    ], project="Ops SCTASK0020002")
    return a, b


def test_changeset_dedupe_tags_reuse_and_groups(tmp_path):
    prof = load_profile("example-pano")
    envs = load_customer_envs(prof)
    a, b = _two_files(tmp_path)
    reqs = []
    for f in (a, b):
        reqs += read_fcr(f, ticket_patterns=prof.tickets, requester="Jane Tester")[0]
    assert len(dedupe(list(reqs))) == 5
    reqs = []
    for f in (a, b):
        reqs += read_fcr(f, ticket_patterns=prof.tickets, requester="Jane Tester")[0]
    cs = build_changeset(prof, envs, reqs)
    assert cs["summary"]["requests_in"] == 6 and cs["summary"]["requests_unique"] == 5
    groups = {g["device_group"]: g for g in cs["groups"]}
    assert set(groups) == {"DG-DC", "DG-EDGE"}
    web = next(r for r in groups["DG-DC"]["rules"] if r["to"] == ["TO-VSYS2"])
    # merged across both files: one tag per ticket, description carries all
    assert {"RITM0010001", "CHG0030001", "SCTASK0020002", "panlab"} <= set(web["tags"])
    assert web["description"].startswith("RITM0010001 / SCTASK0020002 / CHG0030001")
    assert "requester: Jane Tester" in web["description"]
    assert web["destination"] == ["DC-WEB-01"]  # reused by value from DG-DC
    assert web["service"] == ["svc-tcp-8443"]  # reused service object
    assert web["name"] == "Payroll-10.20.1.10-8443"
    ad = next(r for r in groups["DG-DC"]["rules"] if r["source_user"])
    assert ad["source_user"] == ["CORP\\Payroll Admins"] and ad["needs_human"]
    rdp = [r for r in groups["DG-EDGE"]["rules"] if r["service"] == ["tcp-3389"]]
    assert len(rdp) == 2 and all(any(f["code"] == "mgmt-port" and f["level"] == "red" for f in r["flags"]) for r in rdp)
    broad = next(r for r in groups["DG-EDGE"]["rules"] if "N-10.0.0.0_8" in r["source"])
    assert any(f["code"] == "broad" for f in broad["flags"])
    new_names = {o["name"] for o in groups["DG-DC"]["objects"]["new"]}
    assert "N-10.10.0.0_24" in new_names and "DC-WEB-01" not in new_names
    md, h = to_markdown(cs), to_html(cs)
    assert "DG-EDGE" in md and "<table>" in h
    cmds = "\n".join(set_commands(cs))
    assert "set device-group DG-DC pre-rulebase security rules Payroll-10.20.1.10-8443" in cmds
    assert "target devices 000000000101 vsys vsys1" in cmds


def test_ssh_from_vpn_landing_zone_is_not_red(tmp_path):
    prof = load_profile("fwtest")
    envs = load_customer_envs(prof, configs=[str(LABFW)])
    f = make_fcr(tmp_path / "RITM1.xlsx", [
        ("10.200.1.1", None, "10.1.10.5", None, "tcp", "22", None, "", None),
        ("10.1.20.0/24", None, "10.1.10.5", None, "tcp", "22", None, "", None),
    ])
    cs = build_changeset(prof, envs, read_fcr(f, ticket_patterns=prof.tickets)[0])
    rules = cs["groups"][0]["rules"]
    tun = next(r for r in rules if r["from"] == ["Tunnel"])
    lan = next(r for r in rules if r["from"] == ["LAN"])
    assert all(fl["level"] != "red" for fl in tun["flags"])
    assert any(fl["level"] == "red" and fl["code"] == "mgmt-port" for fl in lan["flags"])
    assert cs["groups"][0]["backend"] == "firewall" and cs["groups"][0]["vsys"] == "vsys1"


def test_name_override_and_template(tmp_path):
    prof = load_profile("fwtest")
    envs = load_customer_envs(prof, configs=[str(LABFW)])
    f = make_fcr(tmp_path / "RITM0000777.xlsx", [("10.1.20.50", None, "192.0.2.80", None, "tcp", "443", None, "", None)], project="Print")
    reqs = read_fcr(f, ticket_patterns=prof.tickets)[0]
    cs = build_changeset(prof, envs, reqs, name_template="{ritm}-{project}-{port}")
    r = cs["groups"][0]["rules"][0]
    assert r["name"] == "RITM0000777-Print-443" and r["source"] == ["LAN-PRINTER"]
    cs = build_changeset(prof, envs, read_fcr(f, ticket_patterns=prof.tickets)[0], name_overrides={"R001": "Printer to vendor portal"})
    assert cs["groups"][0]["rules"][0]["name"] == "Printer to vendor portal"


# ------------------------------------------------------------------ customers + CLI
def test_customer_isolation(tmp_path):
    prof = load_profile("fwtest")
    pano_env = load_environment(PANO, target="pano-synth")
    with pytest.raises(ValueError):
        build_changeset(prof, [pano_env], [])
    with pytest.raises(ValueError):
        load_profile("../etc")
    with pytest.raises(ValueError):
        load_customer_envs(prof, configs=[str(PANO)])  # fwtest target is a firewall, not Panorama
    assert load_profile("fwtest").data_dir() != load_profile("example-pano").data_dir()


def test_profiles_hold_no_secrets():
    for name in ("fwtest", "example-pano"):
        text = (Path(__file__).parents[1] / "tests" / "customers" / name / "profile.yaml").read_text()
        assert "api_key:" not in text and "password:" not in text


def test_cli_import_plan_push(tmp_path, capsys):
    a, b = _two_files(tmp_path)
    out = tmp_path / "out"
    assert main(["import", "--customer", "example-pano", str(a), str(b), "--out", str(out), "--stem", "cs", "--quiet"]) == 0
    cs = json.loads((out / "cs.json").read_text())
    assert cs["customer"] == "example-pano" and (out / "cs.md").is_file() and (out / "cs.html").is_file()
    main(["plan", "--customer", "example-pano", "--changeset", str(out / "cs.json")])
    assert main(["push", "--customer", "example-pano", "--changeset", str(out / "cs.json")]) == 0
    assert "Nothing was written" in capsys.readouterr().out
    assert main(["push", "--customer", "example-pano", "--changeset", str(out / "cs.json"), "--apply"]) == 2
    assert main(["push", "--customer", "fwtest", "--changeset", str(out / "cs.json")]) == 1


def test_never_pairs_layer3_with_vwire_zone(labfw):
    import copy

    env = copy.deepcopy(labfw)
    v = env.devices[0].vsys["vsys1"]
    v.zones["trust"].type = "virtual-wire"  # like the PA-440: trust/untrust are vwire
    r = place([env], "10.200.1.1", "10.1.10.5")  # Tunnel (layer3) -> trust (vwire)
    p = r.placements[0]
    assert p.needs_human and p.confidence == "low" and any("zone type mismatch" in n for n in p.notes)


# ------------------------------------------------------------------ change plan + web
def _cs(tmp_path):
    prof = load_profile("example-pano")
    a, b = _two_files(tmp_path)
    reqs = []
    for f in (a, b):
        reqs += read_fcr(f, ticket_patterns=prof.tickets)[0]
    return build_changeset(prof, load_customer_envs(prof), reqs, files=[{"file": "x", "project": "p",
                           "tickets": {"ritm": ["RITM0010001"], "sctask": [], "cr": []}, "rows": 6}])


def test_changeplan_sections(tmp_path):
    from panlab.changeplan import render_changeplan, rollback_commands

    text = render_changeplan(_cs(tmp_path))
    for h in ("## Implementation Plan", "## Implementation (CLI)", "## Verification", "## Rollback", "RITM0010001"):
        assert h in text
    assert "Policies > Security > Pre Rules" in text and "test security-policy-match" in text
    assert "### Add Policy" in text and "Log Forwarding" in text and "Group Profile" in text
    assert "LOG-FWD-DEFAULT" in text and "PROFILE-GROUP-DEFAULT" in text
    rb = rollback_commands(_cs(tmp_path))
    first_obj = next(i for i, l in enumerate(rb) if " address " in l)
    last_rule = max(i for i, l in enumerate(rb) if "security rules" in l and "DG-DC" in l)
    assert last_rule < first_obj  # rules removed before objects


def test_changeplan_customer_template(tmp_path, monkeypatch):
    import shutil

    from panlab.changeplan import render_changeplan

    cs = _cs(tmp_path)
    cdir = tmp_path / "customers"
    shutil.copytree(Path(__file__).parents[1] / "tests" / "customers", cdir)
    (cdir / "example-pano" / "changeplan.md").write_text("CR for $tickets\n$rollback\n")
    monkeypatch.setenv("PANLAB_CUSTOMERS_DIR", str(cdir))
    assert render_changeplan(cs).startswith("CR for RITM0010001")


def test_web_upload_preview(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("multipart")
    from fastapi.testclient import TestClient

    from panlab.web import auth
    from panlab.web.app import app

    monkeypatch.setenv("PANLAB_USERS_FILE", str(tmp_path / "users.yaml"))
    auth.add_user("prep1", "prep", "pw", tmp_path / "users.yaml")
    c = TestClient(app)
    c.post("/login", data={"username": "prep1", "password": "pw"})
    assert "Preview firewall change requests" in c.get("/").text
    a, b = _two_files(tmp_path)
    files = [("files", (a.name, a.read_bytes())), ("files", (b.name, b.read_bytes()))]
    r = c.post("/import", data={"customer": "example-pano", "requester": "Web Tester"}, files=files)
    assert r.status_code == 200 and "DG-DC" in r.text and "Change plan" in r.text
    assert "example-pano" in c.get("/changesets").text
    bad = c.post("/import", data={"customer": "../x"}, files=[("files", ("a.xlsx", b"x"))])
    assert bad.status_code == 400
    assert c.get("/changesets/example-pano/..%2Fetc").status_code == 404


def test_rollback_never_deletes_shared_or_existing(tmp_path):
    from panlab.changeplan import render_changeplan, rollback_commands

    cs = _cs(tmp_path)
    rb = rollback_commands(cs)
    deletes = [l for l in rb if l.startswith("delete")]
    assert not any(l.endswith(" tag panlab") for l in deletes)  # shared default tag
    assert any(l.startswith("# kept tag panlab") for l in rb)
    reused = {o["name"] for g in cs["groups"] for o in g["objects"]["reused"]}
    assert reused  # e.g. DC-WEB-01 existed before
    for n in reused:
        assert not any(l.split()[-1].strip('"') == n for l in deletes if " rules " not in l)
    created = {o["name"] for g in cs["groups"] for o in g["objects"]["new"] if o["rollback"] != "keep"}
    assert created and all(any(l.split()[-1].strip('"') == n for l in deletes) for n in created)
    text = render_changeplan(cs)
    assert "Objects that existed before" in text and "NOT checked against a current config" in text


def test_rollback_keeps_objects_referenced_elsewhere(tmp_path):
    import xml.etree.ElementTree as ET

    from panlab.changeplan import render_changeplan, rollback_commands

    cs = _cs(tmp_path)
    g = next(g for g in cs["groups"] if any(o["kind"] == "address" and o["rollback"] != "keep" for o in g["objects"]["new"]))
    addr = next(o["name"] for o in g["objects"]["new"] if o["kind"] == "address")
    tag = next(o["name"] for o in g["objects"]["new"] if o["kind"] == "tag" and o["rollback"] != "keep")
    own = g["rules"][0]["name"]
    root = ET.fromstring(
        "<config><rulebase><security><rules>"
        f"<entry name='{own}'><source><member>{addr}</member></source><tag><member>{tag}</member></tag></entry>"
        f"<entry name='someone-else'><destination><member>{addr}</member></destination></entry>"
        "</rules></security></rulebase></config>")
    rb = rollback_commands(cs, root)
    assert any(l == f"# kept address {addr}: still referenced by rule someone-else" for l in rb)
    assert not any(l.startswith("delete") and l.split()[-1].strip('"') == addr for l in rb)
    # referenced only by this change set's own rule -> still deleted
    assert any(l.startswith("delete") and l.split()[-1].strip('"') == tag for l in rb)
    assert "Checked against the supplied config: 1 created object(s)" in render_changeplan(cs, root)


def test_cli_changeplan_with_config(tmp_path, capsys):
    cs = _cs(tmp_path)
    p = tmp_path / "cs.json"
    p.write_text(json.dumps(cs))
    cfg = tmp_path / "running.xml"
    cfg.write_text("<config/>")
    assert main(["changeplan", "--customer", "example-pano", "--changeset", str(p), "--config", str(cfg)]) == 0
    assert "Checked against the supplied config: 0" in capsys.readouterr().out
