# SPDX-License-Identifier: Apache-2.0
"""GUI FCR import of several spreadsheets at once (synthetic files only)."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from fcr_factory import make_fcr  # noqa: E402

from panlab.customers import load_profile  # noqa: E402
from panlab.web import auth  # noqa: E402
from panlab.web.app import app  # noqa: E402

pytest.importorskip("fastapi")
pytest.importorskip("multipart")


@pytest.fixture(autouse=True)
def _env(tmp_path, monkeypatch):
    monkeypatch.setenv("PANLAB_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PANLAB_USERS_FILE", str(tmp_path / "users.yaml"))
    monkeypatch.setenv("PANLAB_SESSION_KEY_FILE", str(tmp_path / "session.key"))
    auth.add_user("prep1", "prep", "pw-password-1", tmp_path / "users.yaml")


def _client():
    from fastapi.testclient import TestClient
    c = TestClient(app)
    c.post("/login", data={"username": "prep1", "password": "pw-password-1"})
    return c


def _xlsx(path: Path, rows, project="Multi"):
    return make_fcr(path, rows, project=project)


def test_several_valid_files_become_one_changeset(tmp_path):
    a = _xlsx(tmp_path / "RITM0002001.xlsx", [
        ("10.10.0.0/24", None, "10.20.1.10", None, "TCP", "8443", None, "", None),
    ], project="Alpha")
    b = _xlsx(tmp_path / "RITM0002002.xlsx", [
        ("10.101.3.3", None, "10.102.4.4", None, "tcp", "3389", None, "", None),
    ], project="Beta")
    c = _client()
    r = c.post(
        "/import",
        data={"customer": "example-pano", "requester": "Web Tester", "combine_on": "yes"},
        files=[
            ("files", (a.name, a.read_bytes(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")),
            ("files", (b.name, b.read_bytes(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")),
        ],
        headers={"accept": "text/html"},
    )
    assert r.status_code == 200
    assert "RITM0002001.xlsx" in r.text and "RITM0002002.xlsx" in r.text
    assert "Some files could not be imported" not in r.text
    prof = load_profile("example-pano")
    stems = sorted(p.stem for p in prof.data_dir("changesets").glob("*.json"))
    assert stems
    import json
    cs = json.loads((prof.data_dir("changesets") / f"{stems[-1]}.json").read_text())
    names = [f.get("file") for f in cs["files"]]
    assert names == ["RITM0002001.xlsx", "RITM0002002.xlsx"]
    assert cs["summary"]["requests_in"] == 2


def test_one_bad_file_is_listed_and_the_good_file_still_builds_a_plan(tmp_path):
    good = _xlsx(tmp_path / "RITM0002003.xlsx", [
        ("10.10.0.0/24", None, "10.20.1.10", None, "TCP", "8443", None, "", None),
    ])
    c = _client()
    r = c.post(
        "/import",
        data={"customer": "example-pano", "combine_on": "yes"},
        files=[
            ("files", (good.name, good.read_bytes(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")),
            ("files", ("notes.txt", b"this is not a spreadsheet", "text/plain")),
        ],
        headers={"accept": "text/html"},
    )
    assert r.status_code == 200
    assert "Some files could not be imported" in r.text
    assert "notes.txt: use .xlsx or .csv" in r.text
    assert "RITM0002003.xlsx" in r.text
    import json
    prof = load_profile("example-pano")
    cs = json.loads(next(prof.data_dir("changesets").glob("*.json")).read_text())
    assert [f["file"] for f in cs["files"]] == ["RITM0002003.xlsx"]
    assert cs["file_errors"] == ["notes.txt: use .xlsx or .csv"]
    assert cs["summary"]["requests_in"] == 1


def test_all_bad_files_show_an_html_error_and_do_not_save_a_changeset(tmp_path):
    c = _client()
    r = c.post(
        "/import",
        data={"customer": "example-pano"},
        files=[
            ("files", ("notes.txt", b"nope", "text/plain")),
            ("files", ("also.csv", b"a,b\n1,2\n", "text/csv")),
        ],
        headers={"accept": "text/html"},
    )
    assert r.status_code == 400
    assert "text/html" in r.headers.get("content-type", "")
    assert "notes.txt: use .xlsx or .csv" in r.text
    assert "also.csv:" in r.text
    assert "Headers seen: a, b" in r.text
    assert "Looking for:" in r.text
    assert "<h2>" in r.text
    prof = load_profile("example-pano")
    assert list(prof.data_dir("changesets").glob("*.json")) == []


def test_same_filename_twice_keeps_both(tmp_path):
    a = _xlsx(tmp_path / "a.xlsx", [
        ("10.10.0.0/24", None, "10.20.1.10", None, "TCP", "8443", None, "", None),
    ], project="One")
    b = _xlsx(tmp_path / "b.xlsx", [
        ("10.101.3.3", None, "10.102.4.4", None, "tcp", "3389", None, "", None),
    ], project="Two")
    c = _client()
    r = c.post(
        "/import",
        data={"customer": "example-pano"},
        files=[
            ("files", ("rules.xlsx", a.read_bytes(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")),
            ("files", ("rules.xlsx", b.read_bytes(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")),
        ],
        headers={"accept": "text/html"},
    )
    assert r.status_code == 200
    import json
    prof = load_profile("example-pano")
    cs = json.loads(next(prof.data_dir("changesets").glob("*.json")).read_text())
    assert cs["summary"]["requests_in"] == 2
    assert len(cs["files"]) == 2


def test_unreadable_xlsx_is_a_visible_error_with_the_good_file(tmp_path):
    good = _xlsx(tmp_path / "RITM0002005.xlsx", [
        ("10.10.0.0/24", None, "10.20.1.10", None, "TCP", "8443", None, "", None),
    ])
    c = _client()
    r = c.post(
        "/import",
        data={"customer": "example-pano"},
        files=[
            ("files", (good.name, good.read_bytes(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")),
            ("files", ("broken.xlsx", b"not-a-zip", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")),
        ],
        headers={"accept": "text/html"},
    )
    assert r.status_code == 200
    assert "broken.xlsx:" in r.text
    assert "Some files could not be imported" in r.text
    assert "RITM0002005.xlsx" in r.text


def test_csv_upload_is_accepted(tmp_path):
    csv_body = b"Src,Dst,Service\n10.10.0.1,10.20.0.1,443\n"
    c = _client()
    r = c.post(
        "/import",
        data={"customer": "example-pano", "combine_on": "yes"},
        files=[("files", ("rules.csv", csv_body, "text/csv"))],
        headers={"accept": "text/html"},
    )
    assert r.status_code == 200
    assert "rules.csv" in r.text
    assert "source \u2190 Src" in r.text or "source ← Src" in r.text
    assert "non-standard format, check the mapping" in r.text
    import json
    prof = load_profile("example-pano")
    cs = json.loads(next(prof.data_dir("changesets").glob("*.json")).read_text())
    assert cs["files"][0]["mapping"]["source"] == "Src"
    assert cs["files"][0]["standard_template"] is False


def test_xls_upload_explains_save_as(tmp_path):
    c = _client()
    r = c.post(
        "/import",
        data={"customer": "example-pano"},
        files=[("files", ("old.xls", b"not-xls", "application/vnd.ms-excel"))],
        headers={"accept": "text/html"},
    )
    assert r.status_code == 400
    assert "save as .xlsx or .csv" in r.text
    assert ".xls is not supported" in r.text


def test_template_download_serves_the_request_form(tmp_path):
    import io

    import openpyxl
    c = _client()
    page = c.get("/", headers={"accept": "text/html"})
    assert "/fcr-template.xlsx" in page.text
    r = c.get("/fcr-template.xlsx")
    assert r.status_code == 200
    assert "attachment" in r.headers["content-disposition"] and "FCR-request-form.xlsx" in r.headers["content-disposition"]
    wb = openpyxl.load_workbook(io.BytesIO(r.content))
    assert wb.sheetnames[:2] == ["Instructions", "Firewall Rules"]
    assert wb["Firewall Rules"].data_validations.dataValidation


def test_template_download_needs_login():
    from fastapi.testclient import TestClient
    r = TestClient(app).get("/fcr-template.xlsx", follow_redirects=False)
    assert r.status_code in (303, 401, 403)
