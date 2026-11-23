"""In-app help (/help): every role can read the manual, links stay inside it, nothing escapes the folder."""
from __future__ import annotations

import re

import pytest

from panlab.web import auth, layers
from panlab.web.help_routes import MANUAL, render


@pytest.fixture
def client(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from panlab.web.app import app

    monkeypatch.setenv("PANLAB_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PANLAB_USERS_FILE", str(tmp_path / "users.yaml"))
    monkeypatch.setenv("PANLAB_SESSION_KEY_FILE", str(tmp_path / "session.key"))
    monkeypatch.setenv("PANLAB_USER_AUDIT_FILE", str(tmp_path / "ua.jsonl"))
    for lay in layers.LAYERS:
        auth.add_user(f"u-{lay['id']}", "viewer", "pw-synthetic-1234", tmp_path / "users.yaml",
                      permissions=sorted(lay["perms"]), customers=["*"])
    return TestClient(app)


def _login(c, u):
    r = c.post("/login", data={"username": u, "password": "pw-synthetic-1234"}, follow_redirects=False)
    assert r.status_code in (302, 303)


def test_every_role_reads_the_manual_and_sees_help_in_the_top_bar(client):
    for lay in layers.LAYERS:
        _login(client, f"u-{lay['id']}")
        r = client.get("/help/trace-a-flow")
        assert r.status_code == 200, lay["id"]
        assert "On this page" in r.text
        assert "href='/help'" in client.get("/home").text
        assert client.get("/help").status_code == 200
        client.get("/logout")


def test_help_needs_login_and_rejects_bad_names(client):
    assert client.get("/help/trace-a-flow", follow_redirects=False).status_code == 303
    _login(client, "u-viewer")
    assert client.get("/help/..%2Fsecret", follow_redirects=False).status_code == 404
    assert client.get("/help/nope-page").status_code == 404
    assert client.get("/help/img/..%2F..%2Fpyproject.toml").status_code == 404


def test_manual_links_and_images_all_resolve(client):
    _login(client, "u-viewer")
    bad = []
    for md in sorted(MANUAL.glob("*.md")):
        _, body, _ = render(md.read_text(encoding="utf-8"))
        for url in re.findall(r"(?:href|src)='(/help/[^'#]+)", body):
            if client.get(url).status_code != 200:
                bad.append(f"{md.name}: {url}")
    assert not bad, bad


def test_renderer_escapes_html_and_builds_lists_and_tables():
    _, body, heads = render("# T\n\n<script>x</script>\n\n1. one\n2. two\n   - sub\n\n| a | b |\n|---|---|\n| `c` | **d** |\n")
    assert "<script>" not in body and "&lt;script&gt;" in body
    assert "<ol><li>one</li><li>two<ul><li>sub</li></ul></li></ol>" in body
    assert "<td><code>c</code></td><td><b>d</b></td>" in body
    assert heads[0][1] == "T"


def test_page_help_boxes_link_to_the_manual(client):
    _login(client, "u-viewer")
    t = client.get("/home").text
    assert "href='/help/navigation'" in t and "href='/help/index'" in t
