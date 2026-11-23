# SPDX-License-Identifier: Apache-2.0
"""Shared layout: Home dashboard, permission-filtered sidebar and top bar, breadcrumbs (synthetic data only)."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from fcr_factory import make_fcr  # noqa: E402

from panlab.web import auth  # noqa: E402

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
    uf = tmp_path / "users.yaml"
    auth.add_user("boss", "admin", "pw-boss-123456", uf)
    auth.add_user("viewer1", "viewer", "pw-viewer-12345", uf)
    auth.add_user("upg", "viewer", "pw-upg-1234567", uf, permissions=["upgrade_plan"], customers=["example-pano"])
    return TestClient(app)


def _login(c, u, p):
    r = c.post("/login", data={"username": u, "password": p}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/home"


def test_login_page_is_styled_and_home_requires_login(client):
    r = client.get("/login")
    assert r.status_code == 200 and "login-card" in r.text and "name='username'" in r.text and "name='password'" in r.text
    assert client.get("/home", follow_redirects=False).headers["location"] == "/login"


def test_home_tiles_and_nav_follow_permissions(client):
    _login(client, "boss", "pw-boss-123456")
    t = client.get("/home").text
    for label in ("Upload FCRs", "Trace a flow", "Decommission", "Saved change sets", "OS upgrades", "Users", "Backup destinations", "Push changes"):
        assert label in t
    assert "href='/home'" in t and "Log out" in t and "Change password" in t and "boss" in t
    client.get("/logout")
    _login(client, "viewer1", "pw-viewer-12345")
    t = client.get("/home").text
    assert "Saved change sets" in t and "Trace a flow" in t
    assert "OS upgrades" not in t and "Users" not in t and "Backup destinations" not in t and "Upload FCRs" not in t and "Push changes" not in t
    client.get("/logout")
    _login(client, "upg", "pw-upg-1234567")
    t = client.get("/home").text
    assert "OS upgrades" in t and "Saved change sets" not in t and "Administration" not in t


def test_current_page_is_highlighted_and_deep_pages_have_crumbs_and_home_link(client, tmp_path):
    _login(client, "boss", "pw-boss-123456")
    t = client.get("/upgrade").text
    assert "href='/upgrade' class='cur'" in t and "class='crumbs'" in t
    u = client.get("/users").text
    assert "href='/users' class='cur'" in u and "Administration" in u  # Users is current under the Administration group
    f = make_fcr(tmp_path / "RITM0009001.xlsx", [("10.10.0.0/24", None, "10.20.1.10", None, "TCP", "8443", None, "", None)])
    r = client.post("/import", data={"customer": "example-pano", "combine_on": "yes"},
                    files=[("files", (f.name, f.read_bytes(), "application/octet-stream"))], headers={"accept": "text/html"})
    assert r.status_code == 200
    assert "class='brand' href='/home'" in r.text and "Log out" in r.text and "&larr; Home" in r.text  # report page has the bar + Home
    stem = client.get("/changesets").text.split("/changesets/example-pano/")[1].split("'")[0]
    p = client.get(f"/changesets/example-pano/{stem}/changeplan").text
    assert "class='crumbs'" in p and "Saved change sets" in p and "href='/home'" in p
    e404 = client.get("/changesets/example-pano/nope", headers={"accept": "text/html"})
    assert e404.status_code == 404 and "Back to Home" in e404.text and "class='brand'" in e404.text


def test_sidebar_groups_icons_and_no_external_assets(client):
    _login(client, "boss", "pw-boss-123456")
    t = client.get("/home").text
    assert "class='sidebar'" in t and "Change requests" in t and "Operations" in t and "Administration" in t
    assert "<svg" in t and "id='pl-theme'" in t and "class='usermenu'" in t and "Platform admin" in t
    assert "<link rel='icon' type='image/svg+xml' href='/favicon.svg'>" in t  # the only link: same-origin favicon
    t = t.replace("<link rel='icon' type='image/svg+xml' href='/favicon.svg'>", "")
    for bad in ("http://", "https://", "<link ", "src='http", 'src="http'):
        assert bad not in t, bad  # offline fwtest server: no CDN, fonts or remote scripts
    client.get("/logout")
    _login(client, "viewer1", "pw-viewer-12345")
    t = client.get("/home").text
    assert "Administration" not in t and "href='/users'" not in t and "href='/upgrade'" not in t


def test_home_counts_and_changeset_status(client, tmp_path):
    _login(client, "boss", "pw-boss-123456")
    t = client.get("/home").text
    assert "Saved change sets" in t and "Awaiting approval" in t and "No change sets yet" in t
    f = make_fcr(tmp_path / "RITM0009002.xlsx", [("10.10.0.0/24", None, "10.20.1.10", None, "TCP", "8443", None, "", None)])
    client.post("/import", data={"customer": "example-pano", "combine_on": "yes"},
                files=[("files", (f.name, f.read_bytes(), "application/octet-stream"))], headers={"accept": "text/html"})
    t = client.get("/home").text
    assert "Recent change sets" in t and "class='badge" in t
    cs = client.get("/changesets").text
    assert "<th>Status</th>" in cs and "class='chip on'" in cs
    assert client.get("/changesets?status=Pushed").status_code == 200


def test_report_hides_traffic_log_lookup_link_from_viewers(client, tmp_path):
    _login(client, "boss", "pw-boss-123456")
    f = make_fcr(tmp_path / "RITM0009003.xlsx", [("10.10.0.0/24", None, "10.20.1.10", None, "TCP", "8443", None, "", None)])
    client.post("/import", data={"customer": "example-pano", "combine_on": "yes"},
                files=[("files", (f.name, f.read_bytes(), "application/octet-stream"))], headers={"accept": "text/html"})
    stem = client.get("/changesets").text.split("/changesets/example-pano/")[1].split("'")[0]
    assert "href='/denylog/example-pano'" in client.get(f"/changesets/example-pano/{stem}").text
    client.get("/logout")
    _login(client, "viewer1", "pw-viewer-12345")
    page = client.get(f"/changesets/example-pano/{stem}").text
    assert "href='/denylog/example-pano'" not in page  # the link would 403 for this role
    assert client.get("/denylog/example-pano", headers={"accept": "text/html"}).status_code == 403
