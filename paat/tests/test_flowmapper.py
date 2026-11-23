# SPDX-License-Identifier: Apache-2.0
"""FlowMapper engine (vendored core.js) and the PAAT GUI trace page. Synthetic data only."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from panlab import flowmapper as fm  # noqa: E402
from panlab.changeset import build_changeset  # noqa: E402
from panlab.customers import load_profile  # noqa: E402
from panlab.uploads import store  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "synthetic-flow-multivsys.xml"


def test_vendored_engine_hash_matches_manifest():
    info = fm.verify_engine()
    assert tuple(int(x) for x in info["version"].split(".")[:2]) >= (1, 6)
    assert len(info["sha256"]) == 64
    man = json.loads((ROOT / "vendor" / "flowmapper" / "manifest.json").read_text())
    assert man["sha256"] == info["sha256"]
    assert man["source_repo"].endswith('(this repository)')


def test_sync_check_passes():
    import subprocess
    proc = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "sync-flowmapper.py"), "--check"],
        cwd=ROOT, capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr
    assert f"FlowMapper engine {fm.verify_engine()['version']}" in proc.stdout


def test_trace_two_vsys_hairpin_needs_a_rule_on_each_hop():
    files = [fm.ConfigFile(path=FIXTURE, name="fwtest-flow-fw.xml")]
    result = fm.run_trace(files, "10.10.1.50 -> 10.20.1.50 tcp/443")
    assert result["ok"] is True
    assert result["summary"]["devices"] == 1
    assert result["summary"]["vsys"] == 2
    assert len(result["rows"]) == 1
    row = result["rows"][0]
    hops = row["hops"]
    assert len(hops) == 2
    assert hops[0]["vsys"] == "left" and hops[0]["deny"] and hops[0]["hairpin"]
    assert hops[1]["vsys"] == "right" and hops[1]["deny"]
    assert row["why"]["vsysCount"] == 2 and row["why"]["hairpins"] == 1
    assert "later vsys can still deny" in row["why"]["text"]
    assert row["plan"]["required"] >= 2
    assert result["vsysMap"]["units"]
    assert result["vsysMap"]["layout"]["shapes"]


def test_csv_and_garbage_lines():
    files = [fm.ConfigFile(path=FIXTURE, name="fwtest-flow-fw.xml")]
    text = "source,destination,protocol,port\n10.10.1.50,10.20.1.50,tcp,443\nnot a flow\n"
    result = fm.run_trace(files, text)
    assert len(result["rows"]) == 1
    assert result["parseErrors"] and "source and destination" in (result["parseErrors"][0].get("error") or "")


def test_path_placements_build_a_changeset(tmp_path, monkeypatch):
    monkeypatch.setenv("PANLAB_DATA_DIR", str(tmp_path / "data"))
    prof = load_profile("example-pano")
    files = [fm.ConfigFile(path=FIXTURE, name="fwtest-flow-fw.xml")]
    result = fm.run_trace(files, "10.10.1.50 -> 10.20.1.50 tcp/443")
    reqs, placed = fm.requests_and_placements(result, target=prof.targets[0].name)
    assert len(reqs) == 1 and reqs[0].key() in placed
    assert len(placed[reqs[0].key()]) == 2
    from panlab.netmodel import load_environment
    envs = [load_environment(FIXTURE, target=prof.targets[0].name)]
    cs = build_changeset(prof, envs, reqs, path_placements=placed, require_profile_targets=False, combine=False)
    # Two vsys hops, both denied: two proposed allow rules (not already-allowed).
    rules = [r for g in cs["groups"] for r in g["rules"]]
    proposed = [r for r in rules if r.get("operation") != "already-allowed"]
    assert len(proposed) >= 2
    vsys = {td["vsys"] for r in proposed for td in r.get("target_devices") or []}
    assert "left" in vsys and "right" in vsys


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
    r = c.post("/login", data={"username": u, "password": p}, follow_redirects=False)
    assert r.status_code == 303


def test_trace_page_requires_login_and_is_open_to_viewers(client):
    assert client.get("/flow", follow_redirects=False).headers["location"] == "/login"
    _login(client, "viewer1", "pw-viewer-12345")
    home = client.get("/home").text
    assert "Trace a flow" in home and "href='/flow'" in home
    assert "Push changes" not in home
    page = client.get("/flow")
    assert page.status_code == 200
    assert "name='fcr'" in page.text
    assert "Create change set" not in page.text or "Trace" in page.text
    # Non-admins can see the planner, but cannot reach any push endpoint.
    r = client.get("/push/example-pano/cs-test", follow_redirects=False)
    assert r.status_code == 403
    for url, data in (
        ("/push/example-pano/cs-test/prepare", {"cr": "CHG0009999", "approved": "yes", "target": "example"}),
        ("/push/example-pano/session/s-test/apply", {"confirm_target": "example"}),
        ("/push/example-pano/session/s-test/rollback", {"confirm_target": "example"}),
    ):
        r = client.post(url, data=data, follow_redirects=False)
        assert r.status_code == 403, (url, r.status_code, r.text[:200])
    client.get("/logout")
    _login(client, "boss", "pw-boss-123456")
    home = client.get("/home").text
    assert "Trace a flow" in home and "href='/flow'" in home
    page = client.get("/flow")
    assert page.status_code == 200
    assert "href='/flow' class='cur'" in page.text
    assert "Paste a firewall change request" in page.text or "Trace a flow" in page.text
    assert "name='fcr'" in page.text


def test_gui_trace_and_change_set(client, tmp_path, monkeypatch):
    _login(client, "boss", "pw-boss-123456")
    prof = load_profile("example-pano")
    rec = store(prof, FIXTURE.read_bytes(), "fwtest-flow-fw.xml", uploaded_by="boss")
    r = client.post(
        "/flow",
        data={
            "customer": "example-pano",
            "backups": rec["id"],
            "fcr": "10.10.1.50 -> 10.20.1.50 tcp/443",
        },
        follow_redirects=False,
    )
    assert r.status_code == 200, r.text[:500]
    assert "fwtest-flow-fw" in r.text
    assert "later vsys can still deny" in r.text
    assert "hairpin" in r.text
    assert "Create change set" in r.text
    # stem is in the form action /flow/example-pano/ft-.../changeset
    assert "/flow/example-pano/ft-" in r.text
    action = re.search(r"/flow/example-pano/(ft-[0-9-]+)/changeset", r.text).group(1)
    cs = client.post(f"/flow/example-pano/{action}/changeset", follow_redirects=False)
    assert cs.status_code == 303, cs.text[:500]
    loc = cs.headers["location"]
    assert loc.startswith("/changesets/example-pano/cs-")
    page = client.get(loc)
    assert page.status_code == 200
    assert "left" in page.text and "right" in page.text
    # plan only: built from a backup; push area must refuse it
    assert "Offline" in page.text or "plan only" in page.text.lower() or "backup" in page.text.lower()
    exp = client.get(f"/flow/example-pano/{action}/export.json")
    assert exp.status_code == 200 and "rows" in exp.json()["result"]
    md = client.get(f"/flow/example-pano/{action}/export.md")
    assert md.status_code == 200 and b"Change plan" in md.content and b"Plan only" in md.content
    # A viewer can open the saved trace and export it, but still cannot push the change set.
    client.get("/logout")
    _login(client, "viewer1", "pw-viewer-12345")
    shown = client.get(f"/flow/example-pano/{action}")
    assert shown.status_code == 200 and "later vsys can still deny" in shown.text
    assert client.get(f"/flow/example-pano/{action}/export.md").status_code == 200
    stem = loc.rsplit("/", 1)[-1]
    assert client.get(f"/push/example-pano/{stem}", follow_redirects=False).status_code == 403
    assert client.post(f"/push/example-pano/{stem}/prepare", data={"cr": "CHG0009999", "approved": "yes", "target": "example"}, follow_redirects=False).status_code == 403



def test_viewer_live_snapshot_refresh_and_cannot_push(client, tmp_path, monkeypatch):
    """A viewer can refresh the live snapshot and trace against it; push stays forbidden."""
    from fake_panos import FakeBox, live_factory_for
    import panlab.liveconfig as liveconfig

    monkeypatch.setenv("EXAMPLE_PANO_HOST", "192.0.2.10")
    monkeypatch.setenv("EXAMPLE_PANO_API_KEY_RO", "readonly-key")
    monkeypatch.setenv("EXAMPLE_PANO_API_KEY", "admin-key")
    monkeypatch.setenv("PANLAB_LIVE_REFRESH_SECONDS", "60")
    pano = FakeBox("PANO-SYNTH", kind="panorama", serial="P100")
    fw = FakeBox("FW-SYNTH", serial="F100")
    pano.managed = [fw]
    pano.running_xml = FIXTURE.read_text()
    fw.running_xml = FIXTURE.read_text()
    fw.policy_matches["default"] = {"name": "interzone-default", "action": "deny"}
    monkeypatch.setattr(liveconfig, "device_factory", live_factory_for({"pano-synth": pano}))
    # example-pano profile has no api_key_ro_env; the admin key is the fallback.
    monkeypatch.delenv("EXAMPLE_PANO_API_KEY_RO", raising=False)

    _login(client, "viewer1", "pw-viewer-12345")
    page = client.get("/flow?customer=example-pano")
    assert page.status_code == 200
    assert "Live config" in page.text
    r = client.post("/flow/live/refresh", data={"customer": "example-pano"}, follow_redirects=False)
    assert r.status_code == 303
    page = client.get("/flow?customer=example-pano")
    assert "Last pulled" in page.text
    r = client.post(
        "/flow",
        data={
            "customer": "example-pano",
            "use_live": "yes",
            "live_check": "yes",
            "fcr": "10.10.1.50 -> 10.20.1.50 tcp/443",
        },
        follow_redirects=False,
    )
    assert r.status_code == 200, r.text[:800]
    assert "later vsys can still deny" in r.text
    assert "Live check" in r.text
    assert "Export plan" in r.text
    assert "/push/" not in r.text
    # Create a plan-only change set as the viewer, then prove push is refused.
    action = re.search(r"/flow/example-pano/(ft-[0-9-]+)/changeset", r.text).group(1)
    cs = client.post(f"/flow/example-pano/{action}/changeset", follow_redirects=False)
    assert cs.status_code == 303
    loc = cs.headers["location"]
    stem = loc.rsplit("/", 1)[-1]
    assert client.get(f"/push/example-pano/{stem}", follow_redirects=False).status_code == 403
    assert client.post(
        f"/push/example-pano/{stem}/prepare",
        data={"cr": "CHG0009999", "approved": "yes", "target": "pano-synth"},
        follow_redirects=False,
    ).status_code == 403


