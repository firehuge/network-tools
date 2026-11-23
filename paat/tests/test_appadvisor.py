# SPDX-License-Identifier: Apache-2.0
"""Port-to-App-ID advisor: config parsing, log aggregation, suggestions, CR plan, GUI permissions (fake API, read-only)."""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from panlab import appadvisor  # noqa: E402
from panlab.customers import load_profile  # noqa: E402
from panlab.pusher import PushError  # noqa: E402
from panlab.web import auth  # noqa: E402


def _rule(name, svc, app="any", disabled="no", action="allow"):
    return (f"<entry name='{name}'><from><member>Trust</member></from><to><member>DMZ</member></to>"
            "<source><member>any</member></source><destination><member>any</member></destination>"
            f"<application><member>{app}</member></application><service>{''.join(f'<member>{s}</member>' for s in svc)}</service>"
            f"<action>{action}</action><disabled>{disabled}</disabled><log-setting>LOG-FWD-DEFAULT</log-setting>"
            "<profile-setting><group><member>PROFILE-GROUP-DEFAULT</member></group></profile-setting>"
            "<tag><member>LAB</member></tag></entry>")


def _svc(name, port, proto="tcp"):
    return f"<entry name='{name}'><protocol><{proto}><port>{port}</port></{proto}></protocol></entry>"


PANO = f"""<config><devices><entry name='localhost.localdomain'><device-group>
<entry name='DG-TST-SHARED'><service>{_svc('SVC-TST-TCP-8080', '8080')}{_svc('SVC-TST-TCP-8443', '8443')}{_svc('SVC-TST-TCP-2222', '2222')}
{_svc('SVC-TST-TCP-2525', '2525')}{_svc('SVC-TST-TCP-3389', '3389')}{_svc('SVC-TST-TCP-23', '23')}{_svc('SVC-TST-TCP-3306', '3306')}</service>
<service-group><entry name='SG-TST-ALT-WEB'><members><member>SVC-TST-TCP-8080</member><member>SVC-TST-TCP-8443</member></members></entry>
<entry name='SG-TST-LEGACY-PORTS'><members><member>SVC-TST-TCP-2222</member><member>SVC-TST-TCP-2525</member><member>SVC-TST-TCP-3389</member>
<member>SVC-TST-TCP-23</member><member>SVC-TST-TCP-3306</member><member>service-http</member></members></entry></service-group></entry>
<entry name='DG-EXAMPLE'><pre-rulebase><security><rules>
{_rule('TST-TEST-APPID-CORE', ['application-default'], app='ssh')}
{_rule('TST-TEST-PORT-ALT-WEB', ['SG-TST-ALT-WEB'])}
{_rule('TST-TEST-PORT-LEGACY', ['SG-TST-LEGACY-PORTS'])}
{_rule('TST-OLD-OFF', ['SVC-TST-TCP-23'], disabled='yes')}
</rules></security></pre-rulebase><post-rulebase><security><rules>{_rule('TST-TEST-DENY-LOG', ['any'], action='deny')}</rules></security></post-rulebase></entry>
</device-group></entry></devices></config>"""

DEFAULTS = {"web-browsing": ["tcp/80"], "ssl": ["tcp/443"], "ssh": ["tcp/22"], "telnet": ["tcp/23"], "mysql": ["tcp/3306"],
            "ms-rdp": ["tcp/3389", "udp/3389"], "smtp-base": ["tcp/25,587"]}


def L(rule, port, app, n=1, t="2026/11/18 23:30:00", b=1000):
    return {"rule": rule, "proto": "tcp", "dport": str(port), "app": app, "repeatcnt": str(n), "bytes": str(b), "action": "allow",
            "receive_time": t, "device_name": "TST-FW-FAKE", "serial": "LAB000000001"}


LOGS = {
    "TST-TEST-PORT-ALT-WEB": [L("TST-TEST-PORT-ALT-WEB", 8080, "web-browsing", 25), L("TST-TEST-PORT-ALT-WEB", 8443, "ssl", 3),
                              L("TST-TEST-PORT-ALT-WEB", 8443, "ssl", 1, t="2026/11/12 08:00:00")],
    "TST-TEST-PORT-LEGACY": [L("TST-TEST-PORT-LEGACY", 2222, "ssh", 4), L("TST-TEST-PORT-LEGACY", 2525, "smtp-base", 3),
                             L("TST-TEST-PORT-LEGACY", 23, "telnet", 30), L("TST-TEST-PORT-LEGACY", 3389, "insufficient-data", 2),
                             L("TST-TEST-PORT-LEGACY", 3306, "mysql", 3), L("TST-TEST-PORT-LEGACY", 3306, "incomplete", 1)],
}


class FakeAPI:
    def __init__(self, logs=LOGS, cap=None):
        self.logs, self.queries, self.cap, self.writes = logs, [], cap, 0

    def config_root(self):
        return ET.fromstring(PANO)

    def dg_parents(self):
        return {"DG-EXAMPLE": "DG-TST-SHARED"}

    def traffic_logs(self, query, nlogs):
        self.queries.append((query, nlogs))
        name = query.split("'")[1]
        out = self.logs.get(name, [])
        return (out * 100)[:nlogs] if self.cap else out[:nlogs]

    def app_default_ports(self, app):
        return DEFAULTS.get(app)


@pytest.fixture
def vm(tmp_path, monkeypatch):
    monkeypatch.setenv("PANLAB_DATA_DIR", str(tmp_path / "data"))
    return load_profile("panotest")


def _res(adv, name):
    return next(r for r in adv["results"] if r["rule"]["name"] == name)


def test_finds_only_enabled_port_based_allow_rules_and_resolves_groups(vm):
    api = FakeAPI()
    adv = appadvisor.run(vm, api=api, log_targets=["fw-2"], days=7)
    assert [r["rule"]["name"] for r in adv["results"]] == ["TST-TEST-PORT-ALT-WEB", "TST-TEST-PORT-LEGACY"]
    assert _res(adv, "TST-TEST-PORT-ALT-WEB")["configured_ports"] == ["tcp/8080", "tcp/8443"]
    assert _res(adv, "TST-TEST-PORT-LEGACY")["configured_ports"] == ["tcp/2222", "tcp/2525", "tcp/3389", "tcp/23", "tcp/3306", "tcp/80", "tcp/8080"]
    q = api.queries[0][0]
    assert q.startswith("(rule eq 'TST-TEST-PORT-ALT-WEB') and (receive_time geq '") and api.queries[0][1] == 5000
    assert adv["log_devices"] == [{"serial": "LAB000000001", "hostname": "TST-FW-FAKE"}]
    assert (vm.data_dir("app-advisor") / f"{adv['id']}.json").is_file()


def test_suggestions_appdefault_explicit_review_unused(vm):
    adv = appadvisor.run(vm, api=FakeAPI(), log_targets=["fw-2"], days=7)
    alt = _res(adv, "TST-TEST-PORT-ALT-WEB")
    # web-browsing on 8080 and ssl on 8443 are not their default ports -> app + explicit port, reusing the existing objects
    assert {n["name"]: (n["application"], n["service"]) for n in alt["new_rules"]} == {
        "TST-TEST-PORT-ALT-WEB-TCP8080": (["web-browsing"], ["SVC-TST-TCP-8080"]),
        "TST-TEST-PORT-ALT-WEB-TCP8443": (["ssl"], ["SVC-TST-TCP-8443"])}
    assert alt["original"]["action"] == "disable" and not alt["new_services"]
    ssl = next(p for p in alt["ports"] if p["port"] == 8443)["apps"][0]
    assert ssl["sessions"] == 4 and ssl["first"] == "2026/11/12 08:00:00" and ssl["last"] == "2026/11/18 23:30:00"
    leg = _res(adv, "TST-TEST-PORT-LEGACY")
    st = {p["port"]: p["status"] for p in leg["ports"]}
    assert st == {23: "migrate", 80: "unused", 2222: "migrate", 2525: "migrate", 3306: "mixed", 3389: "review", 8080: "unused"}
    rules = {n["name"]: (n["application"], n["service"]) for n in leg["new_rules"]}
    assert rules["TST-TEST-PORT-LEGACY-APPID"] == (["mysql", "telnet"], ["application-default"])
    assert rules["TST-TEST-PORT-LEGACY-TCP2222"] == (["ssh"], ["SVC-TST-TCP-2222"])
    assert rules["TST-TEST-PORT-LEGACY-TCP2525"] == (["smtp-base"], ["SVC-TST-TCP-2525"])
    assert leg["original"] == {"action": "narrow", "service": ["SVC-TST-TCP-3306", "SVC-TST-TCP-3389"],
                               "why": leg["original"]["why"]}
    assert leg["review_ports"] == ["tcp/3306", "tcp/3389"] and leg["remove_ports"] == ["tcp/80", "tcp/8080"]
    assert leg["overall_confidence"] == "medium"  # lowest of the suggested rules
    tel = next(p for p in leg["ports"] if p["port"] == 23)["apps"][0]
    assert tel["confidence"] == "high" and next(p for p in leg["ports"] if p["port"] == 80)["unused_confidence"] == "low"


def test_named_rule_new_service_object_and_unknown_app(vm):
    logs = {"TST-TEST-PORT-ALT-WEB": [L("TST-TEST-PORT-ALT-WEB", 8080, "my-custom-app", 5),
                                      L("TST-TEST-PORT-ALT-WEB", 9090, "web-browsing", 5)]}
    adv = appadvisor.run(vm, api=FakeAPI(logs), rules=["TST-TEST-PORT-ALT-WEB"], log_targets=["fw-2"], days=30)
    r = adv["results"][0]
    names = {n["name"]: n["service"] for n in r["new_rules"]}
    assert names["TST-TEST-PORT-ALT-WEB-TCP8080"] == ["SVC-TST-TCP-8080"]
    assert names["TST-TEST-PORT-ALT-WEB-TCP9090"] == ["VM-tcp-9090"]  # profile naming pattern
    assert r["new_services"] == [{"name": "VM-tcp-9090", "proto": "tcp", "port": "9090"}]
    assert next(p for p in r["ports"] if p["port"] == 8443)["unused_confidence"] == "medium"
    with pytest.raises(PushError, match="not found"):
        appadvisor.run(vm, api=FakeAPI(), rules=["NOPE"], log_targets=["fw-2"])
    with pytest.raises(PushError, match="bad rule name"):
        appadvisor.build_query("x') or (1 eq '1", appadvisor.now())


def test_building_block_app_is_review_with_real_app_hint(vm):
    logs = {"TST-TEST-PORT-LEGACY": [L("TST-TEST-PORT-LEGACY", 3389, "cotp", 4), L("TST-TEST-PORT-LEGACY", 2222, "ssh", 4)]}
    adv = appadvisor.run(vm, api=FakeAPI(logs), rules=["TST-TEST-PORT-LEGACY"], log_targets=["fw-2"])
    r = adv["results"][0]
    p = next(p for p in r["ports"] if p["port"] == 3389)
    assert p["status"] == "review" and "allow ms-rdp with service application-default" in p["apps"][0]["why"]
    assert all("cotp" not in n["application"] for n in r["new_rules"]) and "tcp/3389" in r["review_ports"]


def test_capped_and_default_port_parsing(vm):
    adv = appadvisor.run(vm, api=FakeAPI(cap=True), rules=["TST-TEST-PORT-LEGACY"], max_logs=100, log_targets=["fw-2"])
    assert adv["results"][0]["capped"] is True
    assert appadvisor.parse_default_ports(["tcp/25,587", "udp/1000-1010", "tcp/dynamic"]) == [
        ("tcp", "25"), ("tcp", "587"), ("udp", "1000-1010"), ("tcp", "dynamic")]
    assert appadvisor.port_in("udp", 1005, [("udp", "1000-1010")]) and not appadvisor.port_in("tcp", 1005, [("udp", "1000-1010")])
    assert not appadvisor.port_in("tcp", 5000, [("tcp", "dynamic")])


def test_cr_plan_has_template_sections_cli_and_rollback(vm):
    adv = appadvisor.run(vm, api=FakeAPI(), log_targets=["fw-2"], days=7)
    md = appadvisor.render_cr(adv, "TST-FW-FAKE · SN LAB000000001")
    for h in ("## Implementation Plan", "## Implementation (CLI)", "## Impact Analysis Statement", "## Backout Plan",
              "## Validation Plan", "## Communications Plan", "Log window: last 7 day(s)"):
        assert h in md
    assert ("set device-group DG-EXAMPLE pre-rulebase security rules TST-TEST-PORT-LEGACY-TCP2222 from Trust to DMZ source any "
            "destination any application ssh service SVC-TST-TCP-2222 action allow") in md
    assert "move device-group DG-EXAMPLE pre-rulebase security rules TST-TEST-PORT-LEGACY-APPID before TST-TEST-PORT-LEGACY" in md
    assert "set device-group DG-EXAMPLE pre-rulebase security rules TST-TEST-PORT-ALT-WEB disabled yes" in md
    assert "set device-group DG-EXAMPLE pre-rulebase security rules TST-TEST-PORT-LEGACY service [ SVC-TST-TCP-3306 SVC-TST-TCP-3389 ]" in md
    assert "set device-group DG-EXAMPLE pre-rulebase security rules TST-TEST-PORT-LEGACY service SG-TST-LEGACY-PORTS" in md  # backout
    assert "delete device-group DG-EXAMPLE pre-rulebase security rules TST-TEST-PORT-LEGACY-APPID" in md
    assert "commit-all shared-policy device-group DG-EXAMPLE" in md and "Needs review / more data" in md
    assert "log-setting LOG-FWD-DEFAULT profile-setting group PROFILE-GROUP-DEFAULT tag LAB" in md


def _client(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from panlab.web.app import app

    uf = tmp_path / "users.yaml"
    monkeypatch.setenv("PANLAB_USERS_FILE", str(uf))
    auth.add_user("prep1", "prep", "pw-prep-123456", uf)
    auth.add_user("view1", "viewer", "pw-view-123456", uf)
    auth.add_user("other", "prep", "pw-other-123456", uf, permissions=["view", "fcr"], customers=["fwtest"])
    auth.add_user("scoped", "prep", "pw-scoped-12345", uf, permissions=["view", "fcr"], customers=["panotest"],
                  devices={"panotest": ["pano-1"]})
    return TestClient(app)


def _login(c, u, p):
    c.cookies.clear()
    assert c.post("/login", data={"username": u, "password": p}, follow_redirects=False).status_code == 303


def test_gui_run_view_download_and_permissions(vm, tmp_path, monkeypatch):
    api = FakeAPI()
    seen = []
    monkeypatch.setattr(appadvisor, "api_factory", lambda prof, targets: seen.append(targets) or api)
    c = _client(tmp_path, monkeypatch)
    _login(c, "prep1", "pw-prep-123456")
    r = c.get("/advisor?customer=panotest")
    assert r.status_code == 200 and "Analyze (read-only)" in r.text and "App-ID advisor" in r.text
    r = c.post("/advisor/run", data={"customer": "panotest", "rules": "TST-TEST-PORT-LEGACY", "days": "500", "max_logs": "5000"},
               follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/advisor/panotest/adv-")
    assert seen == [["fw-2"]]
    page = c.get(r.headers["location"]).text
    assert "TST-TEST-PORT-LEGACY-TCP2222" in page and "last 90 day(s)" in page and "TST-FW-FAKE · SN LAB000000001" in page
    md = c.get(r.headers["location"] + "/changeplan.md")
    assert md.status_code == 200 and "## Backout Plan" in md.text
    assert api.writes == 0
    audit = (vm.data_dir("audit") / "audit.jsonl").read_text()
    assert '"action": "app_advisor"' in audit
    _login(c, "view1", "pw-view-123456")  # view: may read, may not run
    assert c.get(r.headers["location"]).status_code == 200
    assert c.post("/advisor/run", data={"customer": "panotest"}, follow_redirects=False).status_code == 403
    _login(c, "other", "pw-other-123456")  # customer out of scope
    assert c.get(r.headers["location"]).status_code == 403
    assert c.post("/advisor/run", data={"customer": "panotest"}, follow_redirects=False).status_code == 403
    _login(c, "scoped", "pw-scoped-12345")  # only the Panorama in device scope: no firewall to read
    assert c.post("/advisor/run", data={"customer": "panotest", "target": "fw-2"}, follow_redirects=False).status_code == 403
    r = c.post("/advisor/run", data={"customer": "panotest"}, follow_redirects=False)
    assert r.status_code == 303 and "no+firewall" in r.headers["location"].replace("%20", "+")




def test_combine_never_mixes_app_any_with_named_apps():
    """Rows without an app stay in their own rule (PAN-OS refuses [ssh, any]; it would also widen every port to any app)."""
    from panlab import combine

    g = {"rules": [{"name": n, "from": ["Trust"], "to": ["DMZ"], "source": ["H-1"], "destination": ["H-2"], "application": a,
                    "service": [s], "requests": [n], "request": n} for n, a, s in
                   (("R1", ["ssh"], "tcp-2222"), ("R2", ["any"], "tcp-3389"), ("R3", ["ssl"], "tcp-8443"), ("R4", ["any"], "tcp-2525"))]}
    combine._combine_group_rules(g, {}, True)
    assert sorted(sorted(r["application"]) for r in g["rules"]) == [["any"], ["ssh", "ssl"]]
