# SPDX-License-Identifier: Apache-2.0
"""Opt-in live Panorama apply is off by default and works only when the flag is set."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from fcr_factory import make_fcr  # noqa: E402

from panlab.changeset import build_changeset  # noqa: E402
from panlab.customers import load_profile  # noqa: E402
from panlab.fcr import read_fcr  # noqa: E402
from panlab.sources import load_customer_envs  # noqa: E402

FIX = Path(__file__).parent / "fixtures"
PANOXML = FIX / "synthetic-panorama.xml"


class LivePanorama:
    """Records writes. commit / commit_all succeed. Tracks presence for verify."""

    def __init__(self, xml: str):
        self.xml = xml
        self.calls: list = []
        self.phase = "empty"

    def export_running(self):
        self.calls.append("export")
        return self.xml

    def set(self, xpath, element):
        self.calls.append(("set", xpath))
        self.phase = "applied"

    def delete(self, xpath):
        self.calls.append(("delete", xpath))
        self.phase = "rolled"

    def revert(self):
        self.calls.append("revert")

    def commit(self, description):
        self.calls.append(("commit", description))
        return {"jobid": "11", "success": True, "result": "OK", "messages": []}

    def commit_all(self, cmd):
        self.calls.append(("commit_all", cmd))
        assert "<commit-all>" in cmd and "include-template>no" in cmd
        return {"jobid": "12", "success": True, "result": "OK", "messages": []}

    def exists_running(self, xpath):
        return self.phase == "applied"

    def pending_changes(self):
        return False

    def policy_match(self, q):
        raise AssertionError("policy-match is not run against Panorama")


@pytest.fixture
def live_setup(tmp_path, monkeypatch):
    monkeypatch.setenv("PANLAB_DATA_DIR", str(tmp_path / "data"))
    prof = load_profile("example-pano")
    prof.allow_live_panorama_push = True
    envs = load_customer_envs(prof)
    f = make_fcr(tmp_path / "RITM0010009.xlsx", [
        ("10.10.1.0/24", None, "10.20.1.10", None, "tcp", "9443", None, "RITM0010009", None),
    ], project="X")
    reqs, meta = read_fcr(f, ticket_patterns=prof.tickets, requester="Jane Tester")
    cs = build_changeset(prof, envs, reqs, files=[meta])
    (prof.data_dir("changesets") / "cs-live.json").write_text(json.dumps(cs))
    dev = LivePanorama(PANOXML.read_text())
    return prof, cs, dev


def test_prepare_is_prepared_when_flag_is_on(live_setup):
    from panlab import pusher

    prof, cs, dev = live_setup
    s = pusher.prepare(prof, cs, "cs-live", actor="eng", cr="CHG0001234", dev=dev)
    assert s["status"] == "prepared" and s["live_panorama"] is True and not s["errors"]
    assert s.get("result") != pusher.PANORAMA_DRY_RUN
    assert any(o["kind"] == "rule" for o in s["ops"])
    assert s["push_plan"] and s["push_plan"][0]["step"] == "commit to Panorama"


def test_apply_commits_and_commit_all_then_rollback(live_setup):
    from panlab import pusher

    prof, cs, dev = live_setup
    s = pusher.prepare(prof, cs, "cs-live", actor="eng", cr="CHG0001234", dev=dev)
    s = pusher.apply(prof, cs, s["id"], actor="eng", confirm_target="pano-synth", dev=dev)
    assert s["status"] == "committed"
    kinds = [c[0] if isinstance(c, tuple) else c for c in dev.calls]
    assert "set" in kinds and "commit" in kinds and "commit_all" in kinds
    assert all(v["ok"] for v in s["verify"])
    # no policy-match checks on Panorama
    assert not any("policy-match" in v["check"] for v in s["verify"])
    s = pusher.rollback(prof, cs, s["id"], actor="eng", confirm_target="pano-synth", dev=dev)
    assert s["status"] == "rolled-back"
    assert any(isinstance(c, tuple) and c[0] == "commit_all" for c in dev.calls)
    md = (prof.data_dir("push") / f"{s['id']}-report.md").read_text()
    assert "commit-and-push plan (executed)" in md


def test_flag_off_still_refuses_even_if_session_was_tampered(live_setup, tmp_path, monkeypatch):
    from panlab import pusher

    # A different customer (flag off) must stay dry-run.
    monkeypatch.setenv("PANLAB_DATA_DIR", str(tmp_path / "data-off"))
    prof = load_profile("example-pano")
    assert prof.allow_live_panorama_push is False
    envs = load_customer_envs(prof)
    f = make_fcr(tmp_path / "off.xlsx", [
        ("10.10.1.0/24", None, "10.20.1.10", None, "tcp", "9443", None, "RITM0010009", None),
    ], project="X")
    reqs, meta = read_fcr(f, ticket_patterns=prof.tickets, requester="Jane Tester")
    cs = build_changeset(prof, envs, reqs, files=[meta])
    (prof.data_dir("changesets") / "cs-off.json").write_text(json.dumps(cs))
    dev = LivePanorama(PANOXML.read_text())
    s = pusher.prepare(prof, cs, "cs-off", actor="eng", cr="CHG0001234", dev=dev)
    assert s["status"] == "dry-run"
    with pytest.raises(pusher.PushError, match="dry-run only"):
        pusher.apply(prof, cs, s["id"], actor="eng", confirm_target="pano-synth", dev=dev)
    assert dev.phase == "empty" and not any(isinstance(c, tuple) and c[0] == "set" for c in dev.calls)


def test_gui_shows_apply_when_flag_is_on(live_setup, tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    import panlab.web.app as web
    from panlab.web import auth
    from panlab import pusher
    from panlab.customers import load_profile

    prof, cs, dev = live_setup
    uf = tmp_path / "users.yaml"
    monkeypatch.setenv("PANLAB_USERS_FILE", str(uf))
    auth.add_user("eng1", "engineer", "pw-eng", uf)

    def load_live(name):
        p = load_profile(name)
        if name == "example-pano":
            p.allow_live_panorama_push = True
        return p

    monkeypatch.setattr(web, "load_profile", load_live)
    web.device_factory = lambda p, t: dev
    c = TestClient(web.app)
    try:
        c.post("/login", data={"username": "eng1", "password": "pw-eng"})
        page = c.get("/push/example-pano/cs-live")
        assert page.status_code == 200
        assert "live apply opted in" in page.text
        assert "Dry run only (Panorama)" not in page.text
        r = c.post("/push/example-pano/cs-live/prepare",
                   data={"cr": "CHG0001234", "approved": "yes", "target": "pano-synth"})
        assert r.status_code == 200
        assert "Apply + commit to Panorama" in r.text
        assert "Dry run only (Panorama)" not in r.text
    finally:
        web.device_factory = pusher.connect_target
