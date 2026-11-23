"""Phase 1 quick wins: layers, Home, search, blast-radius, approval, API v1."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from fcr_factory import make_fcr  # noqa: E402

from panlab.web import approval, auth, layers, tokens  # noqa: E402
from panlab.web.blast_radius import summarize  # noqa: E402

pytest.importorskip("fastapi")
pytest.importorskip("multipart")


@pytest.fixture
def client(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from panlab.web.app import app

    monkeypatch.setenv("PANLAB_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PANLAB_USERS_FILE", str(tmp_path / "users.yaml"))
    monkeypatch.setenv("PANLAB_SESSION_KEY_FILE", str(tmp_path / "session.key"))
    monkeypatch.setenv("PANLAB_USER_AUDIT_FILE", str(tmp_path / "ua.jsonl"))
    monkeypatch.setenv("PANLAB_API_TOKENS_FILE", str(tmp_path / "tokens.yaml"))
    uf = tmp_path / "users.yaml"
    auth.add_user("boss", "admin", "pw-boss-123456", uf)
    auth.add_user("viewer1", "viewer", "pw-viewer-12345", uf)
    auth.add_user("requester", "viewer", "pw-req-1234567", uf,
                  permissions=["view", "urlfilter_request"], customers=["example-pano"])
    auth.add_user("approver", "viewer", "pw-apr-1234567", uf,
                  permissions=["view", "urlfilter_approve", "approve"], customers=["example-pano"])
    auth.add_user("builder", "prep", "pw-bld-1234567", uf, customers=["example-pano"])
    return TestClient(app)


def _login(c, u, p):
    r = c.post("/login", data={"username": u, "password": p}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/home"


def test_legacy_admin_and_viewer_labels():
    assert layers.layer_label(auth.Principal("a", {"role": "admin"})) == "Platform admin"
    assert layers.layer_label(auth.Principal("v", {"role": "viewer"})) == "Viewer"
    assert layers.layer_label(auth.Principal("e", {"role": "engineer"})) == "engineer"
    assert layers.layer_label(auth.Principal("p", {"role": "prep"})) == "prep"
    assert layers.match_layer(frozenset({"view", "urlfilter_request"}))["id"] == "requester"
    assert "approve" in auth.PERMS
    assert "approve" in auth.ROLE_PERMS["admin"]
    assert "approve" not in auth.ROLE_PERMS["engineer"]


def test_home_is_task_based_per_layer(client):
    _login(client, "viewer1", "pw-viewer-12345")
    t = client.get("/home").text
    assert "Plans and reports in your scope" in t
    assert "Saved change sets" in t
    assert "Upload FCRs" not in t
    assert "class='job'" in t
    assert "How this page works" in t
    assert "Search" in t
    client.get("/logout")
    _login(client, "requester", "pw-req-1234567")
    t = client.get("/home").text
    assert "Start a request" in t
    assert "Platform admin" not in t
    assert "Requester" in t
    client.get("/logout")
    _login(client, "boss", "pw-boss-123456")
    t = client.get("/home").text
    assert "The tool itself" in t
    assert "Platform admin" in t
    assert "Upload FCRs" in t


def test_users_page_has_layer_presets(client):
    _login(client, "boss", "pw-boss-123456")
    t = client.get("/users").text
    assert "Matches layer" in t
    assert "layer-preset" in t
    assert "Platform admin" in t
    assert "Approve FCR and push change plans" in t or "approve" in t


def test_search_finds_changeset_by_ticket(client, tmp_path):
    _login(client, "boss", "pw-boss-123456")
    f = make_fcr(tmp_path / "RITM0009001.xlsx", [("10.10.0.0/24", None, "10.20.1.10", None, "TCP", "8443", None, "", None)])
    r = client.post("/import", data={"customer": "example-pano", "combine_on": "yes"},
                    files=[("files", (f.name, f.read_bytes(), "application/octet-stream"))], headers={"accept": "text/html"})
    assert r.status_code == 200
    s = client.get("/search?q=RITM0009001")
    assert s.status_code == 200
    assert "RITM0009001" in s.text or "/changesets/example-pano/" in s.text
    empty = client.get("/search?q=NO-SUCH-TICKET-XYZ")
    assert empty.status_code == 200
    assert "No change sets" in empty.text


def test_changeplan_shows_stepper_and_blast_radius(client, tmp_path):
    _login(client, "boss", "pw-boss-123456")
    f = make_fcr(tmp_path / "RITM0009002.xlsx", [("10.10.0.0/24", None, "10.20.1.10", None, "TCP", "8443", None, "", None)])
    r = client.post("/import", data={"customer": "example-pano", "combine_on": "yes"},
                    files=[("files", (f.name, f.read_bytes(), "application/octet-stream"))], headers={"accept": "text/html"})
    assert r.status_code == 200
    assert "class='stepper'" in r.text
    assert "Blast radius" in r.text
    stem = client.get("/changesets").text.split("/changesets/example-pano/")[1].split("'")[0]
    p = client.get(f"/changesets/example-pano/{stem}/changeplan")
    assert p.status_code == 200
    assert "class='stepper'" in p.text
    assert "Blast radius" in p.text
    assert "Approval" in p.text


def test_two_person_rule_blocks_builder_and_prepare(client, tmp_path, monkeypatch):
    monkeypatch.setenv("PANLAB_CUSTOMER_OVERRIDE_DIR", str(tmp_path / "ovr"))
    (tmp_path / "ovr").mkdir()
    (tmp_path / "ovr" / "example-pano.yaml").write_text("two_person_approval: true\n")
    _login(client, "builder", "pw-bld-1234567")
    f = make_fcr(tmp_path / "RITM0009003.xlsx", [("10.10.0.0/24", None, "10.20.1.10", None, "TCP", "8443", None, "", None)])
    r = client.post("/import", data={"customer": "example-pano", "combine_on": "yes"},
                    files=[("files", (f.name, f.read_bytes(), "application/octet-stream"))], headers={"accept": "text/html"})
    assert r.status_code == 200
    stem = client.get("/changesets").text.split("/changesets/example-pano/")[1].split("'")[0]
    plan = client.get(f"/changesets/example-pano/{stem}/changeplan")
    assert "second person" in plan.text
    assert "You built this change" in plan.text
    denied = client.post(f"/changesets/example-pano/{stem}/approve",
                         data={"cr": "CHG0009003"}, follow_redirects=False)
    assert denied.status_code in (400, 403)
    client.get("/logout")
    _login(client, "approver", "pw-apr-1234567")
    ok = client.post(f"/changesets/example-pano/{stem}/approve",
                     data={"cr": "CHG0009003"}, follow_redirects=False)
    assert ok.status_code == 303
    page = client.get(f"/changesets/example-pano/{stem}/changeplan")
    assert "Approved by" in page.text and "approver" in page.text


def test_approval_required_before_prepare_when_flag_on(tmp_path, monkeypatch):
    from panlab.customers import load_profile

    monkeypatch.setenv("PANLAB_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PANLAB_CUSTOMER_OVERRIDE_DIR", str(tmp_path / "ovr"))
    (tmp_path / "ovr").mkdir()
    (tmp_path / "ovr" / "example-pano.yaml").write_text("two_person_approval: true\n")
    prof = load_profile("example-pano")
    assert prof.two_person_approval is True
    cs = {"created_by": "builder", "summary": {}}
    err = approval.check_push_allowed(prof, cs, "cs-missing", "boss")
    assert err and "second-person" in err
    approval.approve(prof, "cs-missing", actor="approver", cr="CHG1", created_by="builder")
    assert approval.check_push_allowed(prof, cs, "cs-missing", "boss") is None


def test_blast_radius_verdict_for_red_flags():
    cs = {
        "kind": "add",
        "summary": {"rules": 2, "new_objects": 1, "red_flags": 1, "needs_human": 1},
        "groups": [{
            "backend": "panorama", "target": "pano-1", "device_group": "DG-EXAMPLE",
            "also_targets": ["fw-2"],
            "rules": [{"name": "R1", "source": ["any"], "flags": [{"level": "red", "message": "too broad"}]}],
        }],
        "unplaced": [],
    }
    s = summarize(cs)
    assert s["level"] == "red"
    assert "pano-1" in s["targets"]
    assert "DG-EXAMPLE" in s["device_groups"]
    assert s["serial_limited"] is True


def test_api_v1_session_and_token(client, tmp_path):
    assert client.get("/api/v1/health").json()["status"] == "ok"
    assert client.get("/api/v1/me").status_code == 401
    _login(client, "viewer1", "pw-viewer-12345")
    me = client.get("/api/v1/me").json()
    assert me["name"] == "viewer1" and me["layer"] == "Viewer" and "view" in me["permissions"]
    spec = client.get("/api/v1/openapi.json").json()
    assert spec["openapi"].startswith("3.") and "/api/v1/me" in spec["paths"]
    listed = client.get("/api/v1/customers").json()
    assert "example-pano" in listed["customers"]
    client.get("/logout")
    # token for viewer1
    tok = tokens.create_token("viewer1", label="test")
    r = client.get("/api/v1/me", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200 and r.json()["name"] == "viewer1"
    # scoped requester cannot use a token to see nothing they shouldn't
    tok2 = tokens.create_token("requester", label="r")
    r2 = client.get("/api/v1/customers", headers={"Authorization": f"Bearer {tok2}"})
    assert r2.status_code == 200
    assert r2.json()["customers"] == ["example-pano"]


def test_api_v1_changeset_and_plan(client, tmp_path):
    _login(client, "boss", "pw-boss-123456")
    f = make_fcr(tmp_path / "RITM0009004.xlsx", [("10.10.0.0/24", None, "10.20.1.10", None, "TCP", "8443", None, "", None)])
    r = client.post("/import", data={"customer": "example-pano", "combine_on": "yes"},
                    files=[("files", (f.name, f.read_bytes(), "application/octet-stream"))], headers={"accept": "text/html"})
    assert r.status_code == 200
    stems = client.get("/api/v1/customers/example-pano/changesets").json()["changesets"]
    assert stems
    stem = stems[0]["stem"]
    one = client.get(f"/api/v1/customers/example-pano/changesets/{stem}").json()
    assert one["stem"] == stem and "blast_radius" in one and "changeset" in one
    plan = client.get(f"/api/v1/customers/example-pano/changesets/{stem}/plan").json()
    assert "plan" in plan and "blast_radius" in plan
    # viewer without that customer... requester is scoped, boss is all
    client.get("/logout")
    _login(client, "requester", "pw-req-1234567")
    assert client.get(f"/api/v1/customers/example-pano/changesets/{stem}").status_code == 200


def test_requester_layer_can_submit_fcrs_but_not_push(client, tmp_path):
    uf = tmp_path / "users.yaml"
    auth.add_user("req2", "viewer", "pw-req2-123456", uf,
                  permissions=sorted(layers.LAYERS[1]["perms"]), customers=["example-pano"])
    assert layers.LAYERS[1]["id"] == "requester" and "request" in layers.LAYERS[1]["perms"]
    _login(client, "req2", "pw-req2-123456")
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 200 and "action='/import'" in r.text
    assert "Upload FCRs" in client.get("/home").text
    assert client.get("/decom", follow_redirects=False).status_code == 403
    client.get("/logout")
    _login(client, "requester", "pw-req-1234567")  # legacy list without "request": still view-only
    assert client.get("/", follow_redirects=False).status_code == 303
