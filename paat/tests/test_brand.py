# SPDX-License-Identifier: Apache-2.0
"""PAAT branding: titles, logo, favicon, About page, OpenAPI title, CLI names, PAAT_* settings (synthetic only)."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from panlab import brand  # noqa: E402
from panlab.web import auth  # noqa: E402

pytest.importorskip("fastapi")
pytest.importorskip("multipart")


@pytest.fixture
def client(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from panlab.web.app import app

    for k, v in (("DATA_DIR", "data"), ("USERS_FILE", "users.yaml"), ("SESSION_KEY_FILE", "session.key"),
                 ("USER_AUDIT_FILE", "ua.jsonl")):
        monkeypatch.setenv("PANLAB_" + k, str(tmp_path / v))
    auth.add_user("boss", "admin", "pw-boss-123456", tmp_path / "users.yaml")
    return TestClient(app)


def test_name_keeps_trademark_out():
    assert brand.NAME == "PAAT" and brand.LONG_NAME == "Policy Automation and Analysis Tool"
    assert "palo alto" not in (brand.NAME + brand.LONG_NAME + brand.TAGLINE).lower()


def test_login_page_title_logo_and_footer(client):
    t = client.get("/login").text
    assert "<title>Log in · PAAT</title>" in t and "Sign in to PAAT" in t and "Policy Automation and Analysis Tool" in t
    assert "class='mark'" in t and "href='/favicon.svg'" in t and "panlab" not in t.lower()


def test_signed_in_pages_show_paat(client):
    client.post("/login", data={"username": "boss", "password": "pw-boss-123456"})
    t = client.get("/home").text
    assert "<b>PAAT</b>" in t and "· PAAT</title>" in t and "About PAAT" in t
    assert "panlab v" not in t and "PAN-OS change automation" not in t


def test_favicon_is_local_svg(client):
    for path in ("/favicon.svg", "/favicon.ico"):
        r = client.get(path)
        assert r.status_code == 200 and r.headers["content-type"].startswith("image/svg+xml") and "<svg" in r.text


def test_about_page_public_and_in_help(client):
    r = client.get("/about")
    assert r.status_code == 200 and "About PAAT" in r.text and "FlowMapper" in r.text
    client.post("/login", data={"username": "boss", "password": "pw-boss-123456"})
    r = client.get("/help/about")
    assert r.status_code == 200 and "same path-tracing engine" in r.text


def test_openapi_and_app_title(client):
    from panlab.web.app import app
    assert app.title.startswith("PAAT")
    client.post("/login", data={"username": "boss", "password": "pw-boss-123456"})
    assert client.get("/api/v1/openapi.json").json()["info"]["title"].startswith("PAAT API")


def test_paat_env_prefix_is_an_alias(tmp_path):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("PANLAB_", "PAAT_"))}
    env.update(PAAT_DATA_DIR=str(tmp_path / "d"), PAAT_ETC_DIR=str(tmp_path / "etc"), PANLAB_USERS_FILE=str(tmp_path / "u.yaml"),
               PAAT_USERS_FILE=str(tmp_path / "ignored.yaml"), PYTHONPATH=str(Path(__file__).parent.parent / "src"))
    code = ("from panlab.customers import data_root; from panlab.paths import etc_dir; from panlab.web import auth;"
            "print(data_root(), etc_dir(), auth.users_file())")
    out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, check=True).stdout.split()
    assert out[0] == str(tmp_path / "d") and out[1] == str(tmp_path / "etc")
    assert out[2] == str(tmp_path / "u.yaml")  # an explicit PANLAB_* value wins


def test_cli_names():
    from panlab.cli import build_parser
    old = sys.argv[0]
    try:
        for name in ("paat", "panlab"):
            sys.argv[0] = f"/usr/bin/{name}"
            assert build_parser().prog == name
    finally:
        sys.argv[0] = old
    assert "PAAT" in build_parser().description
