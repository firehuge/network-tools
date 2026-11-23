"""Site roles and the Production only scope in the trace page, the CLI and the saved per-customer roles. Synthetic data only."""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from panlab import flowmapper as fm  # noqa: E402
from panlab import siteroles  # noqa: E402
from panlab.web import flow_scope  # noqa: E402
from panlab.customers import load_profile  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
PANO = ROOT / "tests" / "fixtures" / "synthetic-prod-dr-panorama.xml"
FILES = [fm.ConfigFile(path=PANO, name="pano.xml")]
# prod LAN -> DR LAN (needs the DR firewall), and a flow that stays in production
CROSS = "10.10.1.50 -> 10.20.1.50 tcp/443"
LOCAL = "10.11.1.5 -> 10.30.1.5 tcp/443"


def test_parse_scope_words_and_errors():
    assert siteroles.parse_scope("production") == {"mode": "production", "sites": []}
    assert siteroles.parse_scope("ALL")["mode"] == "all"
    assert siteroles.parse_scope("sites=a, b") == {"mode": "custom", "sites": ["a", "b"]}
    with pytest.raises(siteroles.RolesError):
        siteroles.parse_scope("everything")
    with pytest.raises(siteroles.RolesError):
        siteroles.parse_scope("sites=")


def test_roles_file_ignores_junk_and_roundtrips():
    d = siteroles.normalize({"roles": [{"id": "Staging Env", "focus": True}, {"id": "dr"}, "x"],
                             "sites": {"a": "dr", "b": "nonsense"}, "devices": {"s1": "staging-env"},
                             "scope": {"mode": "bogus"}, "tokens": {"dr": ["ok", "no spaces!"]}})
    assert [r["id"] for r in d["roles"]] == ["staging-env"]
    assert d["sites"] == {"a": "dr"} and d["devices"] == {"s1": "staging-env"}
    assert d["scope"]["mode"] == "production" and d["tokens"] == {"dr": ["ok"]}
    assert siteroles.normalize(json.loads(json.dumps(d))) == d


def test_apply_form_sets_and_clears_overrides():
    d = siteroles.apply_form(siteroles.default(), {"scope_mode": "all", "site_role__x1": "dr", "fw_role__s9": "lab",
                                                  "new_role": "Staging", "new_focus": "1", "mirror_present": "1"})
    assert d["scope"]["mode"] == "all" and d["sites"] == {"x1": "dr"} and d["devices"] == {"s9": "lab"}
    assert d["roles"][0]["id"] == "staging" and d["roles"][0]["focus"] is True and d["mirror"]["enabled"] is False
    d = siteroles.apply_form(d, {"site_role__x1": "", "fw_role__s9": ""})
    assert d["sites"] == {} and d["devices"] == {}
    with pytest.raises(siteroles.RolesError):
        siteroles.apply_form(d, {"new_role": "Production"})


def test_production_only_hides_dr_and_lab_and_says_when_a_path_needs_them():
    r = fm.run_trace(FILES, CROSS + "\n" + LOCAL)  # default scope is Production only
    assert r["scope"]["mode"] == "production" and r["scope"]["hidden"] == 3
    assert r["scope"]["chip"] == "Scope: Production only, 3 firewalls hidden (2 DR, 1 Lab)"
    assert r["summary"]["devices"] == 3 and r["summary"]["devicesLoaded"] == 6
    hops = [h["hostname"] for row in r["rows"] for h in row["hops"]]
    assert hops and not any("dr" in h.split("-") or h.startswith("lab") for h in hops)
    via = r["rows"][0]["scope"]["viaHidden"]
    assert via and "only completes through" in via["text"] and via["fullStatus"] == "complete"
    assert "scope" in r["rows"][1]["scope"]["mode"] or r["rows"][1]["scope"]["mode"] == "production"


def test_all_sites_traces_everything():
    r = fm.run_trace(FILES, CROSS, scope="all")
    assert r["scope"]["hidden"] == 0 and r["summary"]["devices"] == 6
    assert [h["hostname"] for h in r["rows"][0]["hops"]] == ["dc1-prod-fw01", "dc2-dr-fw01"]
    assert r["rows"][0]["scope"]["viaHidden"] is None


def test_matching_rules_round_trip_and_first_match_wins():
    raw = {"rules": [
        {"field": "template-stack", "op": "contains", "value": "DC2-DR", "role": "dr"},
        {"field": "stack", "match": "contains", "value": "PROD", "role": "production"},
        {"field": "nope", "value": "x", "role": "lab"},
        {"field": "hostname", "match": "word", "value": "hq-fw01", "role": "production"},
    ]}
    d = siteroles.normalize(raw)
    assert len(d["rules"]) == 3 and d["rules"][0] == {"field": "stack", "match": "contains", "value": "DC2-DR", "role": "dr"}
    again = siteroles.normalize(json.loads(json.dumps(d)))
    assert again["rules"] == d["rules"]
    empty = siteroles.normalize({})
    assert empty["rules"] == []
    form = siteroles.apply_form(siteroles.default(), {
        "rules_present": "1",
        "rule_field__0": "stack", "rule_match__0": "contains", "rule_value__0": "DC2-DR", "rule_role__0": "dr",
        "rule_field__1": "stack", "rule_match__1": "contains", "rule_value__1": "PROD", "rule_role__1": "production",
    })
    assert [r["value"] for r in form["rules"]] == ["DC2-DR", "PROD"]
    r = fm.run_trace(FILES, CROSS, roles=form, scope="all")
    by = {f["name"]: f for f in r["roles"]["firewalls"]}
    assert by["dc2-dr-fw01"]["role"] == "dr" and by["dc2-dr-fw01"]["source"] == "rule"
    assert "Rule 1" in by["dc2-dr-fw01"]["why"] and "template stack contains" in by["dc2-dr-fw01"]["why"]
    assert by["dc1-prod-fw01"]["role"] == "production" and by["dc1-prod-fw01"]["source"] == "rule"
    assert by["lab-fw01"]["role"] == "lab" and by["lab-fw01"]["source"] == "guess"
    r2 = fm.run_trace(FILES, CROSS, roles=form)
    assert r2["scope"]["hidden"] == 3 and r2["scope"]["byRole"] == {"dr": 2, "lab": 1}


def test_apply_form_without_rules_present_keeps_saved_rules():
    cur = siteroles.normalize({"rules": [{"field": "stack", "match": "contains", "value": "HQ", "role": "test"}]})
    d = siteroles.apply_form(cur, {"scope_mode": "all", "site_role__x1": "dr"})
    assert d["rules"] == cur["rules"] and d["scope"]["mode"] == "all"


def test_scope_card_lists_matching_rules():
    roles = siteroles.apply_form(siteroles.default(), {
        "rules_present": "1",
        "rule_field__0": "stack", "rule_match__0": "contains", "rule_value__0": "DC2-DR", "rule_role__0": "dr",
    })
    r = fm.run_trace(FILES, CROSS, roles=roles, scope="all")
    html = flow_scope.scope_card("lab", "t1", r, roles)
    assert "Matching rules" in html and "rule_field__0" in html and "DC2-DR" in html
    assert "roles-fw-data" in html and "rule-add" in html and "roles-q" in html


def test_override_a_site_role_changes_what_is_hidden():
    roles = siteroles.apply_form(siteroles.default(), {"site_role__dc2-dr": "production"})
    r = fm.run_trace(FILES, CROSS, roles=roles)
    assert r["scope"]["hidden"] == 1 and r["scope"]["byRole"] == {"lab": 1}
    site = next(s for s in r["roles"]["sites"] if s["id"] == "dc2-dr")
    assert site["role"] == "production" and site["source"] == "site setting"
    # a firewall setting beats the site setting
    fw = next(f for f in r["roles"]["firewalls"] if f["name"] == "dc2-dr-fw02")
    roles = siteroles.apply_form(roles, {"fw_role__" + fw["key"]: "dr"})
    r = fm.run_trace(FILES, CROSS, roles=roles)
    assert r["scope"]["hidden"] == 2


def test_guess_is_explained_and_every_firewall_has_a_reason():
    r = fm.run_trace(FILES, CROSS, scope="all")
    by = {f["name"]: f for f in r["roles"]["firewalls"]}
    assert by["dc1-prod-fw01"]["role"] == "production" and by["dc2-dr-fw01"]["role"] == "dr"
    assert by["hq-fw01"]["role"] == "other"  # no words at all: never guessed, never hidden by a guess
    assert all(f["why"] for f in by.values())


def test_custom_set_and_all_hidden_fallback():
    r = fm.run_trace(FILES, CROSS, scope="sites=dc2-dr,hq")
    assert r["scope"]["mode"] == "custom" and r["scope"]["visible"] == 3
    lab_only = siteroles.apply_form(siteroles.default(), {"site_role__dc1-prod": "lab", "site_role__dc2-dr": "lab", "site_role__hq": "lab"})
    r = fm.run_trace(FILES, CROSS, roles=lab_only)
    assert r["summary"]["devices"] == 6 and "found no production firewalls" in r["scope"]["chip"]


def test_panorama_ha_pair_is_shown_separately_from_firewall_scope():
    r = fm.run_trace(FILES, CROSS)
    p = r["roles"]["panorama"]
    assert p["haEnabled"] and p["this"]["name"] == "pano-dc1-prod-01" and p["this"]["role"] == "production"
    assert p["peer"] and "never used to place or pair firewalls" in p["note"]
    # firewalls were not placed or paired by the Panorama HA settings
    assert all(f["site"] for f in r["roles"]["firewalls"]) and r["scope"]["hidden"] == 3


def test_dr_copy_advice_never_traces_dr():
    flow = "198.51.100.7 -> 10.10.1.10 tcp/443"  # internet to a production LAN: needs a rule on a production firewall
    r = fm.run_trace(FILES, flow)  # Production only: DR is hidden but the advice still names it
    mir = r["rows"][0]["drMirror"]
    assert mir and "DR copy likely needed on dc2-dr-fw01" in mir["text"] and "not traced" in mir["text"]
    assert all("dr" not in h["hostname"].split("-") for h in r["rows"][0]["hops"])
    off = siteroles.apply_form(siteroles.default(), {"mirror_present": "1"})
    assert not fm.run_trace(FILES, flow, roles=off)["rows"][0].get("drMirror")


def test_saved_roles_are_per_customer_and_private(tmp_path, monkeypatch):
    monkeypatch.setenv("PANLAB_DATA_DIR", str(tmp_path / "data"))
    prof = load_profile("example-pano")
    assert siteroles.load(prof)["scope"]["mode"] == "production"
    saved = siteroles.save(prof, siteroles.apply_form(siteroles.default(), {"scope_mode": "all", "site_role__x": "dr"}))
    assert siteroles.load(prof) == saved
    path = prof.data_dir("flowtraces") / siteroles.FILE_NAME
    assert oct(path.stat().st_mode & 0o777) == "0o600"


def test_cli_scope_and_roles_file(tmp_path, monkeypatch, capsys):
    from panlab import cli
    monkeypatch.setenv("PANLAB_DATA_DIR", str(tmp_path / "data"))
    fcr = tmp_path / "f.txt"
    fcr.write_text(CROSS + "\n")
    base = ["flowtrace", "--customer", "example-pano", "--config", str(PANO), "--fcr", str(fcr)]
    assert cli.main(base) == 0
    out = capsys.readouterr().out
    assert "Scope: Production only, 3 firewalls hidden" in out and "SCOPE:" in out
    assert cli.main(base + ["--scope", "all"]) == 0
    out = capsys.readouterr().out
    assert "nothing hidden" in out and "SCOPE:" not in out
    rf = tmp_path / "roles.json"
    rf.write_text(json.dumps({"sites": {"dc2-dr": "production"}}))
    assert cli.main(base + ["--roles", str(rf)]) == 0
    assert "1 firewall hidden" in capsys.readouterr().out
    assert cli.main(base + ["--scope", "nonsense"]) == 2
    assert cli.main(base + ["--roles", str(tmp_path / "missing.json")]) == 2


@pytest.fixture
def client(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("multipart")
    from fastapi.testclient import TestClient
    from panlab.web import auth
    from panlab.web.app import app
    monkeypatch.setenv("PANLAB_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PANLAB_USERS_FILE", str(tmp_path / "users.yaml"))
    monkeypatch.setenv("PANLAB_SESSION_KEY_FILE", str(tmp_path / "session.key"))
    monkeypatch.setenv("PANLAB_USER_AUDIT_FILE", str(tmp_path / "ua.jsonl"))
    auth.add_user("boss", "admin", "pw-boss-123456", tmp_path / "users.yaml")
    c = TestClient(app)
    assert c.post("/login", data={"username": "boss", "password": "pw-boss-123456"}, follow_redirects=False).status_code == 303
    return c


def test_page_chip_roles_editor_and_one_click_change(client):
    from panlab.uploads import store
    prof = load_profile("example-pano")
    rec = store(prof, PANO.read_bytes(), "pano.xml", uploaded_by="boss")
    assert "name='scope_mode'" in client.get("/flow").text
    r = client.post("/flow", data={"customer": "example-pano", "backups": rec["id"], "fcr": CROSS}, follow_redirects=True)
    assert r.status_code == 200
    t = r.text
    assert "Scope: Production only, 3 firewalls hidden (2 DR, 1 Lab)" in t
    assert "This flow needs a firewall the scope hides" in t and "Show: All sites" in t
    assert "Site roles" in t and "Panorama high availability" in t and "never used to place or pair firewalls" in t
    stem = re.search(r"/flow/example-pano/(ft-\d{8}-\d{6})/", t).group(1)
    # one click: All sites
    r = client.post(f"/flow/example-pano/{stem}/scope", data={"scope_mode": "all"}, follow_redirects=True)
    assert "nothing hidden" in r.text and "needs a firewall the scope hides" not in r.text
    assert siteroles.load(prof)["scope"]["mode"] == "all"
    # mark the DR site as production by hand
    stem2 = re.search(r"/flow/example-pano/(ft-\d{8}-\d{6})/", r.text).group(1)
    r = client.post(f"/flow/example-pano/{stem2}/scope",
                    data={"scope_mode": "production", "site_role__dc2-dr": "production", "incl_present": "1", "mirror_present": "1", "mirror": "yes"},
                    follow_redirects=True)
    assert "1 firewall hidden" in r.text
    assert client.get("/flow/example-pano/roles.json").json()["sites"] == {"dc2-dr": "production"}
    bad = client.post(f"/flow/example-pano/{stem2}/scope", data={"new_role": "Production"})
    assert bad.status_code == 400



def test_routing_rules_conflict_from_hidden_next_hop_is_explained():
    """Hiding the DR hop can flag a disagreement that is not present with every site — and the result says so."""
    files = [fm.ConfigFile(path=ROOT / "tests/fixtures" / n, name=n)
             for n in ("synthetic-scope-conflict-core-prod-fw.xml", "synthetic-scope-conflict-site-dr-fw.xml",
                       "synthetic-scope-conflict-alt-prod-fw.xml", "synthetic-scope-conflict-app-prod-fw.xml")]
    flow = "10.10.1.50 -> 10.30.1.10 tcp/443"
    all_sites = fm.run_trace(files, flow, scope="all")
    assert not all_sites["rows"][0].get("conflict")
    prod = fm.run_trace(files, flow)  # default Production only
    assert prod["scope"]["hidden"] == 1
    conf = prod["rows"][0].get("conflict")
    assert conf and conf["scopeCause"] == "hidden-routed-hop"
    assert "not, by itself, a stale rule" in (conf.get("scopeText") or "")
    assert "site-dr-fw" in (conf.get("scopeText") or "")


def test_no_site_specific_names_in_the_guess_logic_or_anywhere_we_ship():
    """Guessing uses only the generic words the engine ships. No customer or site name may appear in code, tests, docs or fixtures."""
    core = (ROOT / "vendor" / "flowmapper" / "core.js").read_text()
    sec = core[core.index("/* SCOPE:BEGIN */"):core.index("/* SCOPE:END */")]
    assert len(sec) > 5000
    m = re.search(r"const ROLE_TOKENS = (\{.*?\});", sec, re.S)
    assert m, "ROLE_TOKENS not found"
    toks = json.loads(re.sub(r"(\w+):", r'"\1":', m.group(1)))
    assert toks == {"production": ["prod", "prd", "production"],
                    "dr": ["dr", "drc", "cob", "bcp", "backup", "bkp", "failover", "recovery", "disaster"],
                    "lab": ["lab", "labs", "sandbox", "poc"],
                    "test": ["test", "tst", "qa", "uat", "dev", "stage", "staging", "stg", "preprod"]}
    bad = {"6b9cd7872ae634539ea1a99e1c4c16b41c9314c99192560ecf9c4bb846647655",
           "037d390cd4ef796e5d75407fa72cc4708aa8a1ba3c36ed88db6fd3a441b68503"}
    hits = []
    for p in ROOT.rglob("*"):
        if not p.is_file() or ".git" in p.parts or "node_modules" in p.parts or p.suffix not in {".py", ".js", ".md", ".html", ".json", ".xml", ".yaml", ".yml", ".txt", ".sh", ".css"}:
            continue
        for w in set(re.split(r"[^a-z]+", p.read_text(errors="ignore").lower())):
            if len(w) == 3 and hashlib.sha256(w.encode()).hexdigest() in bad:
                hits.append(str(p.relative_to(ROOT)))
    assert not hits, hits
