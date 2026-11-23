"""RS-43: firewall downgrade inside a train, and the progress/result panels on the upgrade pages (fake device API only)."""

from __future__ import annotations

import pytest

from fake_panos import FakeBox, factory_for
from panlab.customers import load_profile
from panlab.upgrade import device as devmod
from panlab.upgrade import planner, runner
from panlab.upgrade.crplan import render_cr
from panlab.upgrade.versions import Available, is_downgrade, upgrade_path

AV = ["11.1.13-h9", "11.1.13-h17", "11.1.6-h32", "11.1.0", "11.0.6", "11.0.0"]


def av(cur="11.1.13-h17", down=("11.1.13-h9",)):
    return [Available(v, downloaded=v == cur or v in down, current=v == cur) for v in AV]


def test_downgrade_path_same_train_only_and_opt_in():
    assert is_downgrade("11.1.13-h17", "11.1.13-h9") and not is_downgrade("11.1.13-h9", "11.1.13-h17")
    steps, err = upgrade_path("11.1.13-h17", "11.1.13-h9", av(), allow_downgrade=True)
    assert not err and [(s.action, s.version, s.downgrade) for s in steps] == [("download", "11.1.13-h9", True), ("install", "11.1.13-h9", True)]
    assert "already downloaded" in steps[0].why
    steps, err = upgrade_path("11.1.13-h17", "11.1.6-h32", av(), allow_downgrade=True)  # earlier maintenance release, same train
    assert not err and steps[-1].version == "11.1.6-h32"
    _, err = upgrade_path("11.1.13-h17", "11.1.13-h9", av())  # default: refused
    assert err and "not offered" in err[0]
    _, err = upgrade_path("11.1.13-h17", "11.0.6", av(), allow_downgrade=True)  # across trains: refused with a reason
    assert err and "older feature train" in err[0]
    _, err = upgrade_path("11.1.13-h17", "11.1.13-h5", av(), allow_downgrade=True)  # not offered
    assert err and "not in this device" in err[0]


@pytest.fixture
def fwtest(tmp_path, monkeypatch):
    cdir = tmp_path / "customers" / "vlab"
    cdir.mkdir(parents=True)
    (cdir / "profile.yaml").write_text(
        "name: vlab\ntargets:\n  - {name: pano, type: panorama, host_env: X_H, api_key_env: X_K}\n"
        "  - {name: palo, type: firewall, host_env: Y_H, api_key_env: Y_K}\n")
    monkeypatch.setenv("PANLAB_CUSTOMERS_DIR", str(tmp_path / "customers"))
    monkeypatch.setenv("PANLAB_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PANLAB_UPGRADE_REFERENCE", str(tmp_path / "none.yaml"))
    monkeypatch.setenv("PANLAB_UPGRADE_EXECUTE", "1")
    pano = FakeBox("PANO", kind="panorama", version="11.1.13-h17", serial="P1", versions=AV)
    fw = FakeBox("FW", version="11.1.13-h17", serial="F1", versions=AV)
    pano.managed = [fw]
    fac = factory_for({"pano": pano, "palo": fw})
    monkeypatch.setattr(devmod, "device_factory", fac)
    return load_profile("vlab"), pano, fw, fac


def _run(prof, plan, fac):
    for _ in range(300):
        s = runner.next_step(plan)
        if s is None:
            break
        plan = runner.poll(prof, plan, factory=fac) if s["status"] == "running" else \
            runner.start_step(prof, plan, actor="op", confirm=s["hostname"], factory=fac)
        assert plan["status"] != "stopped", [x for x in plan["steps"] if x["status"] == "failed"]
    return plan


def test_plan_downgrade_is_yellow_and_panorama_downgrade_is_red(fwtest):
    prof, pano, fw, fac = fwtest
    snap = planner.discover_customer(prof, actor="t")
    plan = planner.build_plan(prof, snap, {"t:palo": "11.1.13-h9"})
    assert not plan["blocked"], plan["devices"]
    d = plan["devices"][0]
    path = next(c for c in d["checks"] if c["id"] == "path")
    assert path["level"] == "yellow" and "DOWNGRADE" in path["title"]
    assert any(c["id"] == "panorama-first" and c["level"] == "green" for c in d["checks"])  # older than Panorama is fine
    titles = [s["title"] for s in plan["steps"]]
    assert any(t.startswith("Downgrade FW") and t.endswith("to 11.1.13-h9") for t in titles)
    assert not any(t.startswith("Install ") for t in titles)
    dl = next(s for s in plan["steps"] if s["action"] == "download")
    assert "will be skipped" not in dl["explain"]  # Panorama path still runs its (fast) download job
    assert "# PAN-OS downgrade:" in render_cr(plan) and "downgrades" in render_cr(plan)
    # Panorama is never downgraded here
    plan = planner.build_plan(prof, snap, {"t:pano": "11.1.13-h9"})
    assert plan["blocked"]
    assert any(c["id"] == "path" and c["level"] == "red" and "never downgraded" in c["detail"]
               for c in plan["devices"][0]["checks"])


def test_live_downgrade_then_upgrade_back_through_panorama(fwtest):
    prof, pano, fw, fac = fwtest
    snap = planner.discover_customer(prof, actor="t")
    plan = planner.build_plan(prof, snap, {"t:palo": "11.1.13-h9"})
    with pytest.raises(runner.UpgradeRefused, match="yellow"):  # the downgrade must be acknowledged
        runner.arm(prof, plan, actor="op", cr="CHG1", approved=True, ack_yellow=False)
    plan = runner.arm(prof, plan, actor="op", cr="CHG1", approved=True, ack_yellow=True)
    plan = _run(prof, plan, fac)
    assert plan["status"] == "complete" and fw.version == "11.1.13-h9" and pano.version == "11.1.13-h17"
    assert any("<request><batch><software><upload-install>" in w and "11.1.13-h9" in w for w in pano.writes)
    assert not any("<software><install>" in w for w in fw.writes)  # still only through Panorama
    post = next(s for s in plan["steps"] if s["action"] == "postcheck")
    assert any(r["check"] == "version" and r["ok"] for r in post["results"])
    # And forward again, same wizard
    snap = planner.discover_customer(prof, actor="t")
    assert snap["devices"]["t:palo"]["recommended"]["version"] == "11.1.13-h17"
    plan = planner.build_plan(prof, snap, {"t:palo": "11.1.13-h17"})
    assert next(c for c in plan["devices"][0]["checks"] if c["id"] == "path")["level"] == "green"
    yellows = [c for c in plan["devices"][0]["checks"] if c["level"] == "yellow"]
    assert not any(c["id"] == "path" for c in yellows)  # going forward in the same train is not a warning
    plan = runner.arm(prof, plan, actor="op", cr="CHG2", approved=True, ack_yellow=bool(yellows))
    plan = _run(prof, plan, fac)
    assert plan["status"] == "complete" and fw.version == "11.1.13-h17"


def test_gui_picker_badges_progress_and_results(fwtest, tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from panlab.web import auth
    from panlab.web.app import app

    prof, pano, fw, fac = fwtest
    uf = tmp_path / "users.yaml"
    monkeypatch.setenv("PANLAB_USERS_FILE", str(uf))
    auth.add_user("op1", "viewer", "pw-op", uf, permissions=["view", "fcr", "upgrade_plan", "push", "upgrade_exec"], customers=["*"])
    c = TestClient(app)
    c.post("/login", data={"username": "op1", "password": "pw-op"})
    r = c.post("/upgrade/discover", data={"customer": "vlab", "refresh": "yes"}, follow_redirects=False)
    disc = r.headers["location"]
    page = c.get(disc).text
    assert "Older versions: DOWNGRADE (same 11.1 train only)" in page and "<option value='11.1.13-h9'>11.1.13-h9</option>" in page
    assert "<option value='11.1.6-h32'>" in page and "11.0.6" not in page  # same train only, no other train
    r = c.post(disc + "/plan", data={"pick": ["t:palo"], "v::t:palo": "11.1.13-h9"}, follow_redirects=False)
    plan_url = r.headers["location"]
    plan_page = c.get(plan_url).text
    assert "DOWNGRADE" in plan_page and "How to read this plan" in plan_page and "Downgrade FW" in plan_page
    r = c.post(plan_url + "/arm", data={"cr": "CHG9", "approved": "yes"})  # no ack for the yellow item
    assert "Refused" in r.text and "yellow" in r.text
    r = c.post(plan_url + "/arm", data={"cr": "CHG9", "approved": "yes", "ack": "yes"})
    run = plan_url.replace("/plan/", "/run/")
    assert "Progress: step 0 of" in r.text and "Pre-checks" in r.text and "Reboot and reconnect" in r.text
    pid = run.rsplit("/", 1)[1]
    plan = planner.load_plan(prof, pid)
    for _ in range(300):
        s = runner.next_step(plan)
        if s is None:
            break
        if s["status"] == "running":
            plan = runner.poll(prof, plan, factory=fac)
        else:
            if s["action"] == "wait":
                break
            plan = runner.start_step(prof, plan, actor="op1", confirm=s["hostname"], factory=fac)
    # now at the reboot wait: panel explains it
    plan = runner.start_step(prof, plan, actor="op1", confirm=s["hostname"], factory=fac)
    fw.down_polls = 5  # still rebooting
    page = c.get(run).text
    assert "Rebooting: waiting for the device to come back" in page and "10 to 25 minutes" in page
    assert "not answering yet" in page and "Reboot and reconnect" in page
    plan = _run(prof, planner.load_plan(prof, pid), fac)
    page = c.get(run).text
    assert "Progress: step" in page and "(100%)" in page and "Pre-check results" in page
    assert "<b>OK</b>" in page and "Before and after" in page and "11.1.13-h9" in page


def test_recommendation_never_goes_above_panorama(fwtest):
    prof, pano, fw, fac = fwtest
    items = [Available(v) for v in ["11.1.13-h9", "11.1.13-h17", "11.1.16-h5", "11.1.16"]]
    from panlab.upgrade.versions import recommend
    assert recommend("11.1.13-h9", items).version == "11.1.16-h5"
    r = recommend("11.1.13-h9", items, ceiling="11.1.13-h17")
    assert r.version == "11.1.13-h17" and r.latest_in_train == "11.1.16-h5"
    r = recommend("11.1.13-h17", items, ceiling="11.1.13-h17")
    assert r.version is None and "Panorama is on 11.1.13-h17" in r.why and "upgrade Panorama first" in r.why
    # through discovery: the firewall's card recommends within Panorama's version, the picker marks the rest blocked
    pano.versions.update({"11.1.16-h5": {"downloaded": False}})
    pano.device_versions.append("11.1.16-h5")
    fw.versions.update({"11.1.16-h5": {"downloaded": False}})
    snap = planner.discover_customer(prof, actor="t")
    assert snap["devices"]["t:palo"]["recommended"]["version"] is None
    from panlab.web.upgrade_routes import _picker
    html = _picker("t:palo", snap["devices"]["t:palo"], "11.1.13-h17")
    assert "11.1.16-h5 (blocked: newer than Panorama 11.1.13-h17)" in html


def test_postcheck_reports_panorama_sync_and_warns_when_out_of_sync(fwtest):
    prof, pano, fw, fac = fwtest
    pano.dgs = {"DG-X": [fw.serial]}
    for status, level in (("In Sync", "ok"), ("Out of Sync", "warn")):
        pano.sync_status = status
        snap = planner.discover_customer(prof, actor="t")
        plan = planner.build_plan(prof, snap, {"t:palo": "11.1.13-h9"})
        plan = runner.arm(prof, plan, actor="op", cr="CHG3", approved=True, ack_yellow=True)
        plan = _run(prof, plan, fac)
        assert plan["status"] == "complete"  # out of sync is shown, not failed
        post = next(s for s in plan["steps"] if s["action"] == "postcheck")
        sync = [r for r in post["results"] if "sync" in r["check"] and r["check"] != "ha sync"]
        assert {r["check"] for r in sync} == {"device group DG-X sync", "template TPL sync"}
        assert all(r["level"] == level and r["detail"].startswith(status) for r in sync)
        fw.version = "11.1.13-h17"  # put the fake back for the second round
        fw.versions["11.1.13-h9"]["downloaded"] = True
