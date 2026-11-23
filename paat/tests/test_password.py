# SPDX-License-Identifier: Apache-2.0
"""GUI change-password and admin reset: hashing, validation, CSRF, audit (no secrets)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from panlab.web import auth


def _client(tmp_path, monkeypatch, extra=()):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from panlab.web.app import app

    uf = tmp_path / "users.yaml"
    af = tmp_path / "user-audit.jsonl"
    monkeypatch.setenv("PANLAB_USERS_FILE", str(uf))
    monkeypatch.setenv("PANLAB_USER_AUDIT_FILE", str(af))
    auth.add_user("viewer1", "viewer", "pw-viewer", uf)
    auth.add_user("eng1", "engineer", "pw-eng", uf)
    auth.add_user("admin1", "admin", "pw-admin", uf)
    for name, role, pw in extra:
        auth.add_user(name, role, pw, uf)
    return TestClient(app), uf, af


def _login(c, u, p):
    r = c.post("/login", data={"username": u, "password": p}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/home"
    return r


def test_change_password_requires_login_and_current(tmp_path, monkeypatch):
    c, uf, af = _client(tmp_path, monkeypatch)
    assert c.get("/password", follow_redirects=False).status_code == 303
    _login(c, "viewer1", "pw-viewer")
    page = c.get("/password")
    assert page.status_code == 200 and "Change password" in page.text and "Change password" in c.get("/changesets").text
    r = c.post("/password", data={"current": "nope", "new_password": "new-password-12", "confirm": "new-password-12"})
    assert "incorrect" in r.text.lower()
    assert auth.authenticate("viewer1", "pw-viewer") == "viewer"
    assert auth.authenticate("viewer1", "new-password-12") is None
    recs = [json.loads(x) for x in af.read_text().splitlines() if x.strip()]
    assert recs[-1]["action"] == "password_change" and recs[-1]["result"] == "denied"
    assert "new-password-12" not in af.read_text() and "pw-viewer" not in af.read_text()


def test_change_password_validates_and_updates_hash(tmp_path, monkeypatch):
    c, uf, af = _client(tmp_path, monkeypatch)
    _login(c, "eng1", "pw-eng")
    r = c.post("/password", data={"current": "pw-eng", "new_password": "short", "confirm": "short"})
    assert "at least 12" in r.text and auth.authenticate("eng1", "pw-eng") == "engineer"
    r = c.post("/password", data={"current": "pw-eng", "new_password": "new-password-12", "confirm": "mismatch-xxxxx"})
    assert "do not match" in r.text and auth.authenticate("eng1", "pw-eng") == "engineer"
    r = c.post("/password", data={"current": "pw-eng", "new_password": "new-password-12", "confirm": "new-password-12"})
    assert r.status_code == 200 and "Password changed" in r.text
    assert auth.authenticate("eng1", "pw-eng") is None
    assert auth.authenticate("eng1", "new-password-12") == "engineer"
    # same hashing scheme as panlab users add
    stored = auth.load_users(uf)["eng1"]["hash"]
    assert stored.startswith("pbkdf2_sha256$600000$") and auth.verify_password("new-password-12", stored)
    from fastapi.testclient import TestClient
    from panlab.web.app import app
    c2 = TestClient(app)
    _login(c2, "eng1", "new-password-12")
    recs = auth.read_user_audit()
    ok = [x for x in recs if x.get("action") == "password_change" and x.get("result") == "ok"]
    assert ok and ok[-1]["actor"] == "eng1" and ok[-1]["target"] == "eng1"
    blob = af.read_text()
    assert "new-password-12" not in blob and "pw-eng" not in blob
    assert "pbkdf2" not in blob


def test_admin_reset_typed_and_generated(tmp_path, monkeypatch):
    c, uf, af = _client(tmp_path, monkeypatch)
    _login(c, "eng1", "pw-eng")
    assert c.get("/users", follow_redirects=False).status_code == 403
    r = c.post("/users/reset", data={"username": "viewer1", "action": "set",
                                     "new_password": "reset-password-12", "confirm": "reset-password-12"})
    assert r.status_code == 403
    assert auth.authenticate("viewer1", "pw-viewer") == "viewer"

    _login(c, "admin1", "pw-admin")
    page = c.get("/users")
    assert page.status_code == 200 and "viewer1" in page.text and "Reset a password" in page.text
    r = c.post("/users/reset", data={"username": "viewer1", "action": "set",
                                     "new_password": "reset-password-12", "confirm": "reset-password-12"})
    assert r.status_code == 200 and "Password for viewer1 was reset" in r.text
    assert auth.authenticate("viewer1", "pw-viewer") is None
    assert auth.authenticate("viewer1", "reset-password-12") == "viewer"
    # generate random, shown once, not audited
    r = c.post("/users/reset", data={"username": "eng1", "action": "generate"})
    assert r.status_code == 200 and "Temporary password for eng1" in r.text
    # pull the one-time password out of the <code> tag for the test only
    import re
    m = re.search(r"<code>([^<]+)</code>", r.text)
    assert m and len(m.group(1)) >= 12
    gen = m.group(1)
    assert auth.authenticate("eng1", "pw-eng") is None
    assert auth.authenticate("eng1", gen) == "engineer"
    blob = af.read_text()
    assert gen not in blob and "reset-password-12" not in blob
    recs = auth.read_user_audit()
    resets = [x for x in recs if x.get("action") == "password_reset" and x.get("result") == "ok"]
    assert {x["target"] for x in resets} >= {"viewer1", "eng1"}
    assert all(x["actor"] == "admin1" for x in resets)


def test_password_posts_reject_cross_site_origin(tmp_path, monkeypatch):
    c, uf, af = _client(tmp_path, monkeypatch)
    _login(c, "admin1", "pw-admin")
    r = c.post(
        "/password",
        data={"current": "pw-admin", "new_password": "new-password-12", "confirm": "new-password-12"},
        headers={"Origin": "http://evil.example", "Host": "testserver"},
    )
    assert r.status_code == 403
    assert auth.authenticate("admin1", "pw-admin") == "admin"
    r = c.post(
        "/users/reset",
        data={"username": "viewer1", "action": "generate"},
        headers={"Origin": "http://evil.example", "Host": "testserver"},
    )
    assert r.status_code == 403
    assert auth.authenticate("viewer1", "pw-viewer") == "viewer"


def test_set_password_keeps_role_and_refuses_missing(tmp_path, monkeypatch):
    uf = tmp_path / "users.yaml"
    monkeypatch.setenv("PANLAB_USERS_FILE", str(uf))
    auth.add_user("alice", "prep", "old-password-12", uf)
    assert auth.set_password("alice", "new-password-12") is True
    assert auth.load_users(uf)["alice"]["role"] == "prep"
    assert auth.authenticate("alice", "new-password-12") == "prep"
    assert auth.set_password("nobody", "new-password-12") is False
    with pytest.raises(ValueError):
        auth.set_password("alice", "short")
