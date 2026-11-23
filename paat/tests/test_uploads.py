# SPDX-License-Identifier: Apache-2.0
"""Uploaded backup files: parse, store, expire, plan-only import, push refusal.

Synthetic fixtures only. Never reads real or scrambled customer configs.
"""

from __future__ import annotations

import io
import json
import tarfile
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest

from panlab.customers import load_profile
from panlab.paths import repo_root
from panlab.report import to_markdown
from panlab.uploads import (
    PLAN_ONLY,
    UploadError,
    attach_source,
    create_offline_customer,
    delete,
    expire,
    extract_xml,
    format_uploaded,
    is_plan_only,
    list_uploads,
    sanitize_filename,
    source_label,
    store,
    summarize_xml,
)
from fcr_factory import make_fcr

ROOT = repo_root()
FW = ROOT / "tests" / "fixtures" / "synthetic-fw-test.xml"
PANO = ROOT / "tests" / "fixtures" / "synthetic-panorama.xml"
TZ = ZoneInfo("America/Chicago")


def _env(tmp_path, monkeypatch):
    monkeypatch.setenv("PANLAB_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PANLAB_OFFLINE_CUSTOMERS_DIR", str(tmp_path / "offline"))
    return load_profile("fwtest")


def test_summarize_synthetic_firewall_and_panorama():
    fw = summarize_xml(FW)
    assert fw["kind"] == "firewall"
    assert fw["vsys"] >= 1
    assert fw["addresses"] >= 1
    assert fw["rules"] >= 1
    pano = summarize_xml(PANO)
    assert pano["kind"] == "panorama"
    assert pano["device_groups"] >= 1
    assert pano["template_stacks"] >= 1


def test_store_list_delete_and_sanitize(tmp_path, monkeypatch):
    prof = _env(tmp_path, monkeypatch)
    rec = store(prof, FW.read_bytes(), "../../../evil name (1).XML", uploaded_by="alice")
    assert rec["kind"] == "firewall"
    assert rec["original_name"] == "evil_name_1_.XML" or rec["original_name"].endswith(".XML")
    assert ".." not in rec["original_name"]
    assert rec["sha256"] and len(rec["sha256"]) == 64
    path = Path(rec["path"])
    assert path.is_file() and (path.stat().st_mode & 0o777) == 0o600
    assert tmp_path.resolve() in path.resolve().parents
    assert ROOT not in path.resolve().parents or not str(path).startswith(str(ROOT / "src"))
    try:
        path.resolve().relative_to(ROOT)
        # data dir must not be inside the repo in this test
        raise AssertionError("stored under the repo")
    except ValueError:
        pass
    listed = list_uploads(prof)
    assert listed and listed[0]["id"] == rec["id"]
    delete(prof, rec["id"], actor="alice")
    assert list_uploads(prof) == []
    assert not path.is_file()


def test_tgz_extracts_running_config(tmp_path, monkeypatch):
    prof = _env(tmp_path, monkeypatch)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo("folder/running-config.xml")
        data = PANO.read_bytes()
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
        # traversal member must be ignored
        bad = tarfile.TarInfo("../escape.xml")
        bad.size = 4
        tf.addfile(bad, io.BytesIO(b"<x/>"))
    rec = store(prof, buf.getvalue(), "pano-bundle.tgz", uploaded_by="bob")
    assert rec["kind"] == "panorama"
    assert extract_xml(buf.getvalue(), "pano-bundle.tgz").lstrip().startswith(b"<")


def test_xxe_is_refused(tmp_path, monkeypatch):
    prof = _env(tmp_path, monkeypatch)
    xxe = b"""<?xml version='1.0'?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<config version="1.0">&xxe;</config>
"""
    with pytest.raises(UploadError, match="refused|parse"):
        store(prof, xxe, "xxe.xml", uploaded_by="alice")


def test_size_limit(tmp_path, monkeypatch):
    prof = _env(tmp_path, monkeypatch)
    monkeypatch.setenv("PANLAB_MAX_BACKUP_BYTES", "64")
    with pytest.raises(UploadError, match="larger"):
        store(prof, b"<config>" + b"x" * 100, "big.xml", uploaded_by="alice")


def test_refuse_store_inside_repo(tmp_path, monkeypatch):
    inside = ROOT / "tests" / "fixtures" / "_tmp-data-must-not-commit"
    monkeypatch.setenv("PANLAB_DATA_DIR", str(inside))
    prof = load_profile("fwtest")
    with pytest.raises(UploadError, match="outside the git repository"):
        store(prof, FW.read_bytes(), "fwtest.xml", uploaded_by="alice")


def test_expiry(tmp_path, monkeypatch):
    prof = _env(tmp_path, monkeypatch)
    rec = store(prof, FW.read_bytes(), "old.xml", uploaded_by="alice")
    prof.config_retention_days = 7
    old = (datetime.now(TZ) - timedelta(days=10)).isoformat(timespec="seconds")
    man = json.loads((Path(rec["path"]).parent / "manifest.json").read_text())
    man["files"][0]["uploaded"] = old
    (Path(rec["path"]).parent / "manifest.json").write_text(json.dumps(man))
    gone = expire(prof)
    assert rec["id"] in gone
    assert list_uploads(prof) == []


def test_offline_customer_and_import_plan(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    prof, rec = create_offline_customer("offline-fw", FW.read_bytes(), "fw.xml", uploaded_by="alice",
                                        display_name="Offline fwtest fixture")
    assert prof.origin == "backup"
    assert prof.name == "offline-fw"
    assert rec["kind"] == "firewall"
    from panlab import uploads
    from panlab.changeset import build_changeset
    from panlab.changeplan import render_changeplan
    from panlab.fcr import read_fcr

    f = make_fcr(tmp_path / "RITM0008001.xlsx",
                 [("10.1.20.50", None, "10.1.20.60", None, "TCP", "443", None, "web", None)],
                 project="Web")
    reqs, meta = read_fcr(f, ticket_patterns=prof.tickets)
    envs, src = uploads.resolve_envs(prof, f"backup:{rec['id']}")
    cs = build_changeset(prof, envs, reqs, files=[meta])
    attach_source(cs, src)
    assert is_plan_only(cs)
    assert "Offline - from backup" in source_label(cs)
    md = to_markdown(cs)
    assert "plan only" in md.lower() and rec["sha256"][:8] in md
    plan = render_changeplan(cs)
    assert "Firewall Change Request" in plan
    assert PLAN_ONLY in plan
    assert rec["original_name"] in plan or rec["id"] in plan


def test_push_prepare_refuses_backup_changeset(tmp_path, monkeypatch):
    from panlab import pusher
    from panlab.pusher import PushError

    prof = _env(tmp_path, monkeypatch)
    rec = store(prof, FW.read_bytes(), "fw.xml", uploaded_by="alice")
    cs = {"customer": "fwtest", "plan_only": True,
          "config_source": {"kind": "backup", "id": rec["id"], "file": "fw.xml",
                            "sha256": rec["sha256"], "sha8": rec["sha256"][:8],
                            "uploaded": rec["uploaded"]}}
    with pytest.raises(PushError, match="plan only - built from a backup file"):
        pusher.prepare(prof, cs, "cs-test", actor="eng", cr="CHG0009999", dev=None, target_name="fw-1")


def test_cli_uploads_list_add_delete(tmp_path, monkeypatch, capsys):
    from panlab.cli import main

    _env(tmp_path, monkeypatch)
    assert main(["uploads", "add", str(FW), "--customer", "fwtest"]) == 0
    out = capsys.readouterr().out
    ident = out.split("\t")[0].strip()
    assert ident.startswith("cfg-")
    assert main(["uploads", "list", "--customer", "fwtest"]) == 0
    assert ident in capsys.readouterr().out
    assert main(["uploads", "delete", ident, "--customer", "fwtest"]) == 0


def test_gui_upload_delete_expiry_picker_and_push_refusal(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from panlab.web import auth
    from panlab.web.app import app

    prof = _env(tmp_path, monkeypatch)
    uf = tmp_path / "users.yaml"
    monkeypatch.setenv("PANLAB_USERS_FILE", str(uf))
    auth.add_user("prep1", "prep", "pw-prep-user-1", uf)
    auth.add_user("prep2", "prep", "pw-prep-user-2", uf)
    auth.add_user("admin1", "admin", "pw-admin-user1", uf)
    c = TestClient(app)
    # unauthenticated
    assert c.get("/backups", follow_redirects=False).status_code == 303
    r = c.post("/login", data={"username": "prep1", "password": "pw-prep-user-1"}, follow_redirects=False)
    assert r.status_code == 303
    page = c.get("/backups?customer=fwtest")
    assert page.status_code == 200 and "Backup files" in page.text
    up = c.post("/backups/upload", data={"customer": "fwtest"},
                files={"file": ("synthetic-fw-test.xml", FW.read_bytes(), "application/xml")})
    assert up.status_code == 200 and "Stored" in up.text
    ident = list_uploads(prof)[0]["id"]
    # import picker and decom picker mention uploaded backup
    home = c.get("/")
    assert home.status_code == 200 and "Config source" in home.text and ident in home.text
    decom = c.get("/decom")
    assert decom.status_code == 200 and "Config source" in decom.text
    # CSRF
    bad = c.post("/backups/upload", data={"customer": "fwtest"},
                 files={"file": ("x.xml", FW.read_bytes(), "application/xml")},
                 headers={"Origin": "http://evil.example", "Host": "testserver"})
    assert bad.status_code == 403
    # other prep cannot delete
    c.post("/login", data={"username": "prep2", "password": "pw-prep-user-2"}, follow_redirects=False)
    denied = c.post(f"/backups/fwtest/{ident}/delete", follow_redirects=False)
    assert denied.status_code == 403
    # uploader can delete? switch back to prep1
    c.post("/login", data={"username": "prep1", "password": "pw-prep-user-1"}, follow_redirects=False)
    # build a change set from the backup and refuse push
    fcr = make_fcr(tmp_path / "RITM0008002.xlsx",
                   [("10.1.20.50", None, "10.1.20.60", None, "TCP", "443", None, "web", None)],
                   project="Web")
    imp = c.post("/import", data={"customer": "fwtest", "config_source": f"backup:{ident}", "combine_on": "yes"},
                 files={"files": ("RITM0008002.xlsx", fcr.read_bytes(),
                                 "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")})
    assert imp.status_code == 200
    assert "Offline - from backup" in imp.text and "Push not available" in imp.text
    # find stem
    stems = list((Path(tmp_path / "data" / "fwtest" / "changesets")).glob("cs-*.json"))
    assert stems
    stem = stems[0].stem
    plan = c.get(f"/changesets/fwtest/{stem}/changeplan")
    assert plan.status_code == 200 and "Firewall Change Request" in plan.text and PLAN_ONLY in plan.text
    # engineer push page
    auth.add_user("eng1", "engineer", "pw-engineer-1", uf)
    c.post("/login", data={"username": "eng1", "password": "pw-engineer-1"}, follow_redirects=False)
    push = c.get(f"/push/fwtest/{stem}")
    assert push.status_code == 200 and PLAN_ONLY in push.text and "Prepare (backup" not in push.text
    prep = c.post(f"/push/fwtest/{stem}/prepare",
                  data={"cr": "CHG0009999", "approved": "yes", "target": "fw-1"})
    assert prep.status_code == 400 and PLAN_ONLY in prep.text
    # admin can delete
    c.post("/login", data={"username": "admin1", "password": "pw-admin-user1"}, follow_redirects=False)
    gone = c.post(f"/backups/fwtest/{ident}/delete")
    assert gone.status_code == 200 and "Deleted" in gone.text
    assert list_uploads(prof) == []


def test_gui_offline_customer(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from panlab.customers import list_customers
    from panlab.web import auth
    from panlab.web.app import app

    _env(tmp_path, monkeypatch)
    uf = tmp_path / "users.yaml"
    monkeypatch.setenv("PANLAB_USERS_FILE", str(uf))
    auth.add_user("prep1", "prep", "pw-prep-user-1", uf)
    c = TestClient(app)
    c.post("/login", data={"username": "prep1", "password": "pw-prep-user-1"}, follow_redirects=False)
    r = c.post("/backups/offline",
               data={"name": "adhoc-pano", "display_name": "Ad hoc Panorama"},
               files={"file": ("synthetic-panorama.xml", PANO.read_bytes(), "application/xml")})
    assert r.status_code == 200 and "Created offline customer" in r.text
    assert "adhoc-pano" in list_customers()
    prof = load_profile("adhoc-pano")
    assert prof.origin == "backup" and prof.targets[0].type == "panorama"


def test_sanitize_filename_helpers():
    assert sanitize_filename("/tmp/../foo bar.xml") == "foo_bar.xml"
    assert ".." not in sanitize_filename("....")
    assert format_uploaded("2026-11-17T10:38:00-06:00").endswith("CST")
