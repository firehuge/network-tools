# SPDX-License-Identifier: Apache-2.0
"""RS-44 parity with the offline FlowMapper page: diagrams and exports on /flow, the multi-place box, rule-order advice
and the on-firewall test commands. Synthetic fixtures only."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from panlab import flowmapper as fm
from panlab.customers import load_profile
from panlab.uploads import store

FIX = Path(__file__).parent / "fixtures"
HAIRPIN = FIX / "synthetic-hairpin-pano.xml"
MULTIVSYS = FIX / "synthetic-flow-multivsys.xml"

pytest.importorskip("fastapi")
pytest.importorskip("multipart")


@pytest.fixture
def client(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from panlab.web import auth
    from panlab.web.app import app

    monkeypatch.setenv("PANLAB_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PANLAB_USERS_FILE", str(tmp_path / "users.yaml"))
    monkeypatch.setenv("PANLAB_SESSION_KEY_FILE", str(tmp_path / "session.key"))
    monkeypatch.setenv("PANLAB_USER_AUDIT_FILE", str(tmp_path / "ua.jsonl"))
    uf = tmp_path / "users.yaml"
    auth.add_user("boss", "admin", "pw-boss-123456", uf)
    auth.add_user("viewer1", "viewer", "pw-viewer-12345", uf)
    return TestClient(app)


def _login(c, u, p):
    assert c.post("/login", data={"username": u, "password": p}, follow_redirects=False).status_code == 303


def _trace(client, path, flow):
    prof = load_profile("example-pano")
    rec = store(prof, path.read_bytes(), path.name, uploaded_by="boss")
    r = client.post("/flow", data={"customer": "example-pano", "backups": rec["id"], "fcr": flow})
    assert r.status_code == 200, r.text[:400]
    stem = re.search(r"/flow/example-pano/(ft-[0-9-]+)/changeset", r.text).group(1)
    return r, stem


def test_engine_returns_diagrams_places_and_rule_order():
    res = fm.run_trace([fm.ConfigFile(path=HAIRPIN, name="hp.xml")], "10.66.1.10 -> 10.66.3.10 tcp/443")
    row = res["rows"][0]
    assert row["diagram"].startswith("<svg") and row["diagram"].rstrip().endswith("</svg>")
    en = row["enforcement"]
    assert en["multi"] and en["level"] == "need" and "2 places" in en["text"]
    assert [p["needs"] for p in en["places"]] == [False, True]
    new = [i for i in row["plan"]["items"] if i["kind"] == "security" and not i["optional"]]
    assert new and new[0]["order"]["mode"] == "above" and new[0]["order"]["before"] == "DENY-A-C-IN"
    hop = row["filters"]["hops"][1]
    assert any(c.startswith("test security-policy-match") and "destination-port 443" in c for c in hop["testCli"])
    assert any(c.startswith("test routing fib-lookup virtual-router") for c in hop["testCli"])
    assert "(port.dst eq 443)" in row["filters"]["common"]
    vm = res["vsysMap"]
    assert vm["svg"].startswith("<svg") and vm["drawio"].startswith("<mxfile")




def test_environment_and_panorama_diagrams():
    f = [fm.ConfigFile(path=HAIRPIN, name="hp.xml")]
    site = fm.run_diagram(f, "site")
    assert site["svg"].startswith("<svg") and site["drawio"].startswith("<mxfile") and "firewalls" in site["summary"]
    pano = fm.run_diagram(f, "pano")
    assert pano["svg"].startswith("<svg") and pano["drawio"].startswith("<mxfile")
    with pytest.raises(fm.FlowMapperError):
        fm.run_diagram(f, "nope")


def test_trace_page_shows_diagram_box_exports_and_advice(client):
    _login(client, "boss", "pw-boss-123456")
    r, stem = _trace(client, HAIRPIN, "10.66.1.10 -> 10.66.3.10 tcp/443")
    t = r.text
    assert "Rule needed in more than one place!" in t and "Place 2:" in t and "needs an allow" in t and "already allowed" in t
    assert "Rule order:" in t and "above DENY-A-C-IN" in t
    assert "id='flow-diagram-1'" in t and "data-svg-export='png'" in t and "Export SVG" in t
    assert "id='vsys-map'" in t and f"/flow/example-pano/{stem}/vsys-map.drawio" in t
    assert "Check it after the push" in t and "test security-policy-match" in t
    assert f"/flow/example-pano/{stem}/export.csv" in t
    svg = client.get(f"/flow/example-pano/{stem}/flow-1.svg")
    assert svg.status_code == 200 and svg.headers["content-type"].startswith("image/svg+xml")
    assert svg.text.startswith("<?xml") and "<svg" in svg.text and "attachment" in svg.headers["content-disposition"]
    assert client.get(f"/flow/example-pano/{stem}/flow-9.svg").status_code == 404
    assert client.get(f"/flow/example-pano/{stem}/vsys-map.svg").status_code == 200
    dio = client.get(f"/flow/example-pano/{stem}/vsys-map.drawio")
    assert dio.status_code == 200 and dio.text.startswith("<mxfile")
    csv_ = client.get(f"/flow/example-pano/{stem}/export.csv")
    assert csv_.status_code == 200 and "Rule order" in csv_.text and "Places checked by security policy" in csv_.text
    assert "Place before" in csv_.text and "DENY-A-C-IN" in csv_.text
    js = client.get(f"/flow/example-pano/{stem}/export.json")
    assert "<svg" not in js.text and "<mxfile" not in js.text and json.loads(js.text)["result"]["rows"]
    md = client.get(f"/flow/example-pano/{stem}/export.md").text
    assert "Rule needed in more than one place" in md and "Rule order:" in md and "on the firewall:" in md


def test_environment_diagram_pages_and_roles(client):
    _login(client, "boss", "pw-boss-123456")
    _, stem = _trace(client, HAIRPIN, "10.66.1.10 -> 10.66.2.10 tcp/443")
    for kind in ("site", "pano"):
        page = client.get(f"/flow/example-pano/{stem}/diagram/{kind}")
        assert page.status_code == 200 and "id='env-diagram'" in page.text and "Export PNG" in page.text and "Export draw.io" in page.text
        assert client.get(f"/flow/example-pano/{stem}/diagram/{kind}.svg").text.startswith("<?xml")
        assert client.get(f"/flow/example-pano/{stem}/diagram/{kind}.drawio").text.startswith("<mxfile")
    assert client.get(f"/flow/example-pano/{stem}/diagram/other").status_code == 404
    client.get("/logout")
    # a viewer can open and export everything on the page (all of it is plan-only), and still cannot push
    _login(client, "viewer1", "pw-viewer-12345")
    assert client.get(f"/flow/example-pano/{stem}/diagram/site").status_code == 200
    assert client.get(f"/flow/example-pano/{stem}/flow-1.svg").status_code == 200
    assert client.get(f"/flow/example-pano/{stem}/export.csv").status_code == 200
    assert client.get(f"/push/example-pano/{stem}", follow_redirects=False).status_code == 403
    client.get("/logout")
    assert client.get(f"/flow/example-pano/{stem}/export.csv", follow_redirects=False).status_code in (302, 303, 401, 403)
    assert client.get(f"/flow/example-pano/{stem}/diagram/site", follow_redirects=False).status_code in (302, 303, 401, 403)


def test_single_place_flow_has_no_multi_place_box(client):
    _login(client, "boss", "pw-boss-123456")
    r, _ = _trace(client, HAIRPIN, "10.66.1.10 -> 10.66.1.20 tcp/443")
    assert "Rule needed in more than one place" not in r.text


def test_firewall_without_network_config_is_called_out(client):
    nonet = FIX / "synthetic-hairpin-pano-nonet.xml"
    res = fm.run_trace([fm.ConfigFile(path=nonet, name="x.xml")], "10.66.1.10 -> 10.66.3.10 tcp/443")
    assert [x["device"] for x in res["noNetwork"]] == ["FW-NO-NET"]
    _login(client, "boss", "pw-boss-123456")
    r, _ = _trace(client, nonet, "10.66.1.10 -> 10.66.3.10 tcp/443")
    assert "id='nonet-callout'" in r.text and "1 firewall has no network config" in r.text and "FW-NO-NET" in r.text
    r2, _ = _trace(client, HAIRPIN, "10.66.1.10 -> 10.66.3.10 tcp/443")
    assert "nonet-callout" not in r2.text
