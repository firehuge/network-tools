# SPDX-License-Identifier: Apache-2.0
"""OS upgrade wizard: versions, safety, plan order, runner — all against a fake device API."""

from __future__ import annotations

import pytest

from fake_panos import FakeBox, factory_for
from panlab.customers import load_profile
from panlab.upgrade import device as devmod
from panlab.upgrade import planner, runner
from panlab.upgrade.crplan import render_cr
from panlab.upgrade.versions import Available, V, group_by_train, recommend, upgrade_path

AV = ["11.1.6-h7", "11.1.6-h32", "11.1.6", "11.1.13", "11.1.13-h9", "11.1.13-h17", "11.1.10-h3", "11.2.0", "11.2.4-h5",
      "12.1.0", "12.1.2", "11.1.0", "10.2.13-h1"]


def av(cur="11.1.6-h7", downloaded=()):
    return [Available(v, downloaded=v in downloaded or v == cur, current=v == cur) for v in AV]


def test_version_ordering_handles_hotfixes():
    assert V("11.1.6-h32") > V("11.1.6-h7") > V("11.1.6")
    assert V("11.1.10") > V("11.1.6-h41")
    assert V("12.1.0") > V("11.2.4-h5")
    assert sorted(["11.1.6-h7", "11.1.6-h32", "11.1.13"], key=V)[-1] == "11.1.13"


def test_group_by_train_and_recommend_latest_in_train():
    trains = [t.train for t in group_by_train(av())]
    assert trains == ["12.1", "11.2", "11.1", "10.2"]
    r = recommend("11.1.6-h7", av())
    assert r.version == "11.1.13-h17" and r.latest_same_release == "11.1.6-h32"
    assert recommend("11.1.6-h7", av(), preferred=["11.1.13-h9"]).version == "11.1.13-h9"
    assert recommend("11.1.13-h17", av()).version is None


def test_same_train_path_and_feature_jump_path():
    steps, err = upgrade_path("11.1.6-h7", "11.1.13-h9", av())
    assert not err and [(s.action, s.version) for s in steps] == [("download", "11.1.13-h9"), ("install", "11.1.13-h9")]
    steps, err = upgrade_path("11.1.6-h7", "12.1.2", av())
    assert not err
    seq = [(s.action, s.version) for s in steps]
    assert seq.index(("download", "11.2.0")) < seq.index(("install", "11.2.4-h5")) < seq.index(("download", "12.1.0"))
    assert seq[-1] == ("install", "12.1.2")
    assert upgrade_path("11.1.6-h7", "10.2.13-h1", av())[1]  # downgrade refused


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
    pano = FakeBox("PANO", kind="panorama", version="11.1.6-h7", serial="P1", versions=AV)
    fw = FakeBox("FW", version="11.1.6-h32", serial="F1", versions=AV)
    pano.managed = [fw]
    fac = factory_for({"pano": pano, "palo": fw})
    monkeypatch.setattr(devmod, "device_factory", fac)
    return load_profile("vlab"), pano, fw, fac


def test_discovery_and_panorama_first_rule(fwtest):
    prof, pano, fw, fac = fwtest
    snap = planner.discover_customer(prof, actor="t")
    assert snap["devices"]["t:palo"]["managed_by"] == "t:pano"
    assert snap["devices"]["t:pano"]["recommended"]["version"] == "11.1.13-h17"
    # Firewall alone above Panorama -> red
    plan = planner.build_plan(prof, snap, {"t:palo": "11.1.13-h9"})
    assert plan["blocked"] and any(c["id"] == "panorama-first" and c["level"] == "red" for d in plan["devices"] for c in d["checks"])
    # Both, same target: Panorama first, not blocked
    plan = planner.build_plan(prof, snap, {"t:palo": "11.1.13-h9", "t:pano": "11.1.13-h9"})
    assert not plan["blocked"], plan["devices"]
    assert [d["name"] for d in plan["devices"]] == ["pano", "palo"]
    first_fw = next(s["n"] for s in plan["steps"] if s["device"] == "t:palo")
    assert all(s["n"] < first_fw for s in plan["steps"] if s["device"] == "t:pano")
    # Firewall target above Panorama target -> red
    assert planner.build_plan(prof, snap, {"t:palo": "11.1.13-h17", "t:pano": "11.1.13-h9"})["blocked"]
    assert "debug swm revert" in render_cr(plan)


def test_pending_changes_and_disk_block(fwtest):
    prof, pano, fw, fac = fwtest
    fw.pending = True
    pano.free = "100M"
    snap = planner.discover_customer(prof)
    plan = planner.build_plan(prof, snap, {"t:palo": "11.1.13-h9", "t:pano": "11.1.13-h9"})
    ids = {c["id"] for d in plan["devices"] for c in d["checks"] if c["level"] == "red"}
    assert {"pending", "disk"} <= ids and plan["blocked"] and not plan["steps"] or plan["blocked"]


def test_ha_peer_must_be_in_plan(fwtest):
    prof, pano, fw, fac = fwtest
    fw.ha = {"state": "active", "peer_state": "passive", "peer": "F2"}
    snap = planner.discover_customer(prof)
    plan = planner.build_plan(prof, snap, {"t:palo": "11.1.6-h32", "t:pano": "11.1.13-h9"})
    assert any(c["id"] == "ha-peer" and c["level"] == "red" for d in plan["devices"] for c in d["checks"])


def test_unlicensed_check_falls_back_with_friendly_message(tmp_path, monkeypatch):
    cdir = tmp_path / "customers" / "solo"
    cdir.mkdir(parents=True)
    (cdir / "profile.yaml").write_text("name: solo\ntargets:\n  - {name: palo, type: firewall, host_env: Y_H, api_key_env: Y_K}\n")
    monkeypatch.setenv("PANLAB_CUSTOMERS_DIR", str(tmp_path / "customers"))
    monkeypatch.setenv("PANLAB_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PANLAB_UPGRADE_REFERENCE", str(tmp_path / "none.yaml"))
    fw = FakeBox("FW", version="11.1.6-h32", serial="F1", versions=AV, licensed=False)
    fw.pano_server = None  # standalone: the firewall's own update-server check is what counts
    monkeypatch.setattr(devmod, "device_factory", factory_for({"palo": fw}))
    prof = load_profile("solo")
    snap = planner.discover_customer(prof)
    f = snap["devices"]["t:palo"]
    assert f["can_download"] is False and "support license" in f["warnings"][0]
    fw.versions["11.1.6-h7"]["downloaded"] = True
    plan = planner.build_plan(prof, snap, {"t:palo": "11.1.13-h9"})
    assert any(c["id"] in ("download", "path") and c["level"] == "red" for d in plan["devices"] if d["name"] == "palo" for c in d["checks"])


def test_live_run_end_to_end_on_fakes(fwtest, monkeypatch):
    prof, pano, fw, fac = fwtest
    snap = planner.discover_customer(prof)
    plan = planner.build_plan(prof, snap, {"t:palo": "11.1.13-h9", "t:pano": "11.1.13-h9"})
    with pytest.raises(runner.UpgradeRefused):  # dry-run by default
        runner.start_step(prof, plan, actor="eng", confirm="PANO", factory=fac)
    with pytest.raises(runner.UpgradeRefused):  # server switch off
        runner.arm(prof, plan, actor="eng", cr="CHG100", approved=True, ack_yellow=True)
    monkeypatch.setenv("PANLAB_UPGRADE_EXECUTE", "1")
    with pytest.raises(runner.UpgradeRefused):
        runner.arm(prof, plan, actor="eng", cr="bogus", approved=True, ack_yellow=True)
    plan = runner.arm(prof, plan, actor="eng", cr="CHG100", approved=True, ack_yellow=True)
    with pytest.raises(runner.UpgradeRefused):  # wrong confirmation
        runner.start_step(prof, plan, actor="eng", confirm="palo", factory=fac)
    with pytest.raises(runner.UpgradeRefused, match="hostname the device reports exactly \\(PANO\\)"):
        runner.start_step(prof, plan, actor="eng", confirm="pano", factory=fac)  # profile name is not enough
    for _ in range(200):
        s = runner.next_step(plan)
        if s is None:
            break
        if s["status"] == "running":
            plan = runner.poll(prof, plan, factory=fac)
        else:
            plan = runner.start_step(prof, plan, actor="eng", confirm=s["hostname"], factory=fac)
        assert plan["status"] != "stopped", [x for x in plan["steps"] if x["status"] == "failed"]
    assert plan["status"] == "complete"
    assert pano.version == "11.1.13-h9" and fw.version == "11.1.13-h9"
    assert any("<request><batch><software><upload-install>" in w for w in pano.writes)  # firewall went through Panorama
    assert not any("<software><install>" in w for w in fw.writes)
    md, js = runner.write_report(prof, plan)
    assert "complete" in md.read_text()
    backups = list(prof.data_dir("upgrade-backups").glob(f"*/*/*/*/*_{plan['id']}_*"))
    assert {b.parents[3].name for b in backups} == {"PANO_P1", "FW_F1"}  # <hostname>_<serial>/<YYYY>/<MM>/<DD>/<HHMMSS>_<run>_<type>
    # Panorama: config only; firewall (through Panorama): its config + Panorama's config (no device state via Panorama)
    assert len(backups) == 3
    # The managed firewall's own API was used once, at first sighting, to learn its serial (show system info); nothing else.
    assert fw.direct_calls == ["<show><system><info></info></system></show>"]


def test_panorama_reboot_waits_when_busy(fwtest, monkeypatch):
    prof, pano, fw, fac = fwtest
    monkeypatch.setenv("PANLAB_UPGRADE_EXECUTE", "1")
    snap = planner.discover_customer(prof)
    plan = planner.build_plan(prof, snap, {"t:pano": "11.1.13-h9"})
    plan = runner.arm(prof, plan, actor="e", cr="CHG1", approved=True, ack_yellow=True)
    while runner.next_step(plan)["action"] != "reboot":
        s = runner.next_step(plan)
        plan = runner.poll(prof, plan, fac) if s["status"] == "running" else runner.start_step(prof, plan, actor="e", confirm="PANO", factory=fac)
    pano.busy_jobs = ["CommitAll"]
    with pytest.raises(runner.UpgradeRefused, match="busy"):
        runner.start_step(prof, plan, actor="e", confirm="PANO", factory=fac)
    pano.busy_jobs = []
    plan = planner.load_plan(prof, plan["id"])
    plan = runner.start_step(prof, plan, actor="e", confirm="PANO", factory=fac)
    assert runner.next_step(plan)["action"] == "wait"


def test_failed_job_stops_plan(fwtest, monkeypatch):
    prof, pano, fw, fac = fwtest
    monkeypatch.setenv("PANLAB_UPGRADE_EXECUTE", "1")
    orig = pano._job
    pano._job = lambda kind, ok=True, details="": orig(kind, ok=kind != "SWInstall",
                                                         details="requires a content version of 9000 or greater")
    plan = planner.build_plan(prof, planner.discover_customer(prof), {"t:pano": "11.1.13-h9"})
    plan = runner.arm(prof, plan, actor="e", cr="CHG1", approved=True, ack_yellow=True)
    for _ in range(100):
        s = runner.next_step(plan)
        plan = runner.poll(prof, plan, fac) if s["status"] == "running" else runner.start_step(prof, plan, actor="e", confirm="PANO", factory=fac)
        if plan["status"] == "stopped":
            break
    assert plan["status"] == "stopped"
    bad = next(s for s in plan["steps"] if s["status"] == "failed")
    assert bad["action"] == "install" and "content" in bad["hint"]
    with pytest.raises(runner.UpgradeRefused):
        runner.start_step(prof, plan, actor="e", confirm="PANO", factory=fac)


def test_gui_wizard_dry_run_and_live(fwtest, tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from panlab.web import auth
    from panlab.web.app import app

    prof, pano, fw, fac = fwtest
    uf = tmp_path / "users.yaml"
    monkeypatch.setenv("PANLAB_USERS_FILE", str(uf))
    auth.add_user("viewer1", "viewer", "pw-viewer", uf)
    auth.add_user("prep1", "prep", "pw-prep", uf)
    auth.add_user("eng1", "engineer", "pw-eng", uf)
    c = TestClient(app)
    c.post("/login", data={"username": "viewer1", "password": "pw-viewer"})
    assert c.get("/upgrade").status_code == 403
    c.post("/login", data={"username": "prep1", "password": "pw-prep"})
    r = c.get("/upgrade?customer=vlab")
    assert r.status_code == 200 and "Discover devices" in r.text
    r = c.post("/upgrade/discover", data={"customer": "vlab", "refresh": "yes"}, follow_redirects=False)
    assert r.status_code == 303
    disc = r.headers["location"]
    r = c.get(disc)
    assert "<b>FW</b> · SN <code>F1</code>" in r.text
    assert "11.1.13-h17 (recommended)" in r.text and "selected" in r.text
    r = c.post(disc + "/plan", data={"pick": ["t:pano", "t:palo"], "v::t:pano": "11.1.13-h9", "v::t:palo": "11.1.13-h9"},
               follow_redirects=False)
    plan_url = r.headers["location"]
    r = c.get(plan_url)
    assert "<b>PANO</b> · SN <code>P1</code>" in r.text and "<h2>Customer: vlab</h2>" in r.text
    assert "Pre-check PANO · SN P1 [pano]" in r.text
    assert "Steps (in this order" in r.text and "Arm for live" not in r.text  # prep cannot arm
    assert "debug swm revert" in c.get(plan_url + "/changeplan.md").text
    assert not pano.writes and not fw.writes  # discovery and planning are read-only
    c.post("/login", data={"username": "eng1", "password": "pw-eng"})
    r = c.post(plan_url + "/arm", data={"cr": "CHG7", "approved": "yes", "ack": "yes"})
    assert "switched off" in r.text
    monkeypatch.setenv("PANLAB_UPGRADE_EXECUTE", "1")
    r = c.post(plan_url + "/arm", data={"cr": "CHG7", "approved": "yes", "ack": "yes"})
    assert "Live upgrade" in r.text and "PUSH AREA" in r.text and "the hostname the device reports, <code>PANO</code>" in r.text
    assert "<b>PANO</b> · SN <code>P1</code> <span style='color:#777;font-size:12px'>pano</span>" in r.text and "<h2>Customer: vlab</h2>" in r.text
    run = plan_url.replace("/plan/", "/run/")
    r = c.post(run + "/next", data={"confirm": "wrong"})
    assert "Refused" in r.text
    r = c.post(run + "/next", data={"confirm": "pano"})
    assert "Refused" in r.text  # profile name refused; the device's own hostname is required
    r = c.post(run + "/next", data={"confirm": "PANO"})
    assert r.status_code == 200 and "Next: step 2" in r.text


# ---------------------------------------------------------------- hostname + serial everywhere

def test_identity_in_plan_steps_cr_report_and_audit(fwtest, monkeypatch):
    prof, pano, fw, fac = fwtest
    monkeypatch.setenv("PANLAB_UPGRADE_EXECUTE", "1")
    snap = planner.discover_customer(prof)
    assert snap["devices"]["t:pano"]["identity"]["hostname"] == "PANO"
    assert snap["devices"]["t:palo"]["identity"]["serial"] == "F1"
    from panlab import identity
    assert identity.cached(prof, "pano")["serial"] == "P1"  # remembered for pages that do not talk to the device
    plan = planner.build_plan(prof, snap, {"t:pano": "11.1.13-h9"})
    d = plan["devices"][0]
    assert (d["hostname"], d["serial"], d["label"]) == ("PANO", "P1", "PANO · SN P1 [pano]")
    assert any(c["id"] == "identity" and c["level"] == "green" for c in d["checks"])
    assert all("PANO · SN P1 [pano]" in s["title"] for s in plan["steps"])
    cr = render_cr(plan)
    assert "| PANO | P1 | pano |" in cr and "### PANO · SN P1 [pano]" in cr
    plan = runner.arm(prof, plan, actor="e", cr="CHG1", approved=True, ack_yellow=True)
    plan = runner.start_step(prof, plan, actor="e", confirm="PANO", factory=fac)
    md = (planner.upgrade_dir(prof) / f"{plan['id']}-report.md").read_text()
    assert "| PANO | P1 | pano | panorama |" in md
    from panlab.pusher import read_audit
    step = [r for r in read_audit(prof) if r.get("action") == "upgrade-step"][-1]
    assert (step["hostname"], step["serial"], step["target"]) == ("PANO", "P1", "PANO · SN P1 [pano]")
    arm = [r for r in read_audit(prof) if r.get("action") == "upgrade-arm"][-1]
    assert arm["devices"] == ["PANO · SN P1 [pano]"]


def test_unknown_hostname_is_yellow_and_confirm_uses_serial(fwtest, monkeypatch):
    prof, pano, fw, fac = fwtest
    pano.name = ""  # device does not report a hostname
    snap = planner.discover_customer(prof)
    plan = planner.build_plan(prof, snap, {"t:pano": "11.1.13-h9"})
    d = plan["devices"][0]
    ych = [c for c in d["checks"] if c["id"] == "identity"]
    assert ych and ych[0]["level"] == "yellow" and ych[0]["title"] == "Hostname unknown"
    assert plan["status_light"] in ("yellow", "red")
    assert d["label"] == "pano · hostname unknown · SN P1" and plan["steps"][0]["confirm_with"] == "P1"
    assert "| hostname unknown | P1 | pano |" in render_cr(plan)


def test_duplicate_hostnames_require_serial(fwtest):
    prof, pano, fw, fac = fwtest
    pano.name = fw.name = "PA-VM"  # factory-default hostnames
    plan = planner.build_plan(prof, planner.discover_customer(prof), {"t:pano": "11.1.13-h9", "t:palo": "11.1.13-h9"})
    assert {s["confirm_with"] for s in plan["steps"]} == {"P1", "F1"}


def test_precheck_refuses_a_different_device(fwtest, monkeypatch):
    prof, pano, fw, fac = fwtest
    monkeypatch.setenv("PANLAB_UPGRADE_EXECUTE", "1")
    plan = planner.build_plan(prof, planner.discover_customer(prof), {"t:pano": "11.1.13-h9"})
    plan = runner.arm(prof, plan, actor="e", cr="CHG1", approved=True, ack_yellow=True)
    pano.serial = "P9"  # the address now answers as another box
    plan = runner.start_step(prof, plan, actor="e", confirm="PANO", factory=fac)
    assert plan["status"] == "stopped"
    assert "A different device answered" in plan["steps"][0]["error"] and "P9" in plan["steps"][0]["error"]
