"""Panorama-managed firewalls are upgraded only through Panorama; direct mode is for standalone firewalls.

All against the in-memory fake XML API (tests/fake_panos.py). Never touches a real device.
"""

from __future__ import annotations

import pytest

from fake_panos import FakeBox, factory_for
from panlab.customers import load_profile
from panlab.upgrade import device as devmod
from panlab.upgrade import discovery as D
from panlab.upgrade import paths, planner, runner
from panlab.upgrade.crplan import render_cr

AV = ["11.1.6-h32", "11.1.13", "11.1.13-h9", "11.1.13-h17"]
SYSINFO = "<show><system><info></info></system></show>"


def _profile(tmp_path, monkeypatch, fw_extra: str = "", extra: str = "", with_pano: bool = True):
    cdir = tmp_path / "customers" / "plab"
    cdir.mkdir(parents=True, exist_ok=True)
    pano = "  - {name: pano, type: panorama, host_env: X_H, api_key_env: X_K}\n" if with_pano else ""
    (cdir / "profile.yaml").write_text(
        f"name: plab\n{extra}targets:\n{pano}  - {{name: palo, type: firewall, host_env: Y_H, api_key_env: Y_K{fw_extra}}}\n")
    monkeypatch.setenv("PANLAB_CUSTOMERS_DIR", str(tmp_path / "customers"))
    monkeypatch.setenv("PANLAB_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PANLAB_UPGRADE_REFERENCE", str(tmp_path / "none.yaml"))
    monkeypatch.setenv("PANLAB_CUSTOMER_OVERRIDE_DIR", str(tmp_path / "etc"))
    return load_profile("plab")


@pytest.fixture
def boxes():
    pano = FakeBox("PANO", kind="panorama", version="11.1.13-h17", serial="P1", versions=AV)
    fw = FakeBox("FW", version="11.1.13-h9", serial="F1", versions=AV)
    fw.versions = {"11.1.13-h9": {"downloaded": True}}  # the firewall itself knows no newer image
    pano.managed = [fw]
    return pano, fw


def _run_all(prof, plan, fac):
    for _ in range(300):
        s = runner.next_step(plan)
        if s is None:
            return plan
        plan = runner.poll(prof, plan, fac) if s["status"] == "running" else \
            runner.start_step(prof, plan, actor="eng", confirm=s["confirm_with"], factory=fac)
        assert plan["status"] != "stopped", [x for x in plan["steps"] if x["status"] == "failed"]
    return plan


def test_access_field_validated(tmp_path, monkeypatch):
    with pytest.raises(ValueError, match="access must be one of"):
        _profile(tmp_path, monkeypatch, fw_extra=", access: sideways")
    prof = _profile(tmp_path, monkeypatch, fw_extra=", access: panorama")
    assert [t.access for t in prof.targets] == ["auto", "panorama"] and prof.allow_direct_managed is False


def test_managed_firewall_without_direct_credentials_goes_through_panorama(tmp_path, monkeypatch, boxes):
    """The tool has only Panorama's key. Discovery, plan and a full live run never touch the firewall's own API."""
    pano, fw = boxes
    prof = _profile(tmp_path, monkeypatch, fw_extra=", access: panorama")
    from panlab import identity
    identity.remember(prof, "palo", identity.make("FW", "F1"))  # seen before (e.g. from Panorama's list)
    fac = factory_for({"pano": pano, "palo": fw}, no_direct={"palo"})
    monkeypatch.setattr(devmod, "device_factory", fac)
    snap = planner.discover_customer(prof)
    f = snap["devices"]["t:palo"]
    assert f["reachable"] and f["connect"] == {"target": "pano", "serial": "F1"} and paths.mode_of(f) == paths.PANORAMA
    assert f["software_source"] == "panorama" and {a["version"] for a in f["available"]} >= {"11.1.13-h17"}
    assert "m:pano:F1" not in snap["devices"]  # one entry, not two
    plan = planner.build_plan(prof, snap, {"t:palo": "11.1.13-h17"})
    d = plan["devices"][0]
    assert not plan["blocked"], d["checks"]
    assert d["path_text"] == "via Panorama PANO · SN P1 [pano]"
    assert any(c["id"] == "access-path" and c["level"] == "green" for c in d["checks"])
    assert all(s["path_text"].startswith("via Panorama") for s in plan["steps"])
    assert "Upgrade path for FW · SN F1 [palo]: **via Panorama PANO · SN P1 [pano]**" in render_cr(plan)
    monkeypatch.setenv("PANLAB_UPGRADE_EXECUTE", "1")
    plan = runner.arm(prof, plan, actor="eng", cr="CHG1", approved=True, ack_yellow=True)
    plan = _run_all(prof, plan, fac)
    assert plan["status"] == "complete" and fw.version == "11.1.13-h17"
    assert fw.direct_calls == []  # never its own API
    cmds = [c for c in pano.writes if "<batch>" in c]
    assert [c.split("><")[2] for c in cmds] == ["content"] * 4 + ["software", "software", "reboot"], cmds
    assert any("<upload-install><file>PanOS_vm-11.1.13-h17</file><devices>F1</devices>" in c for c in cmds)
    bk = next(s for s in plan["steps"] if s["action"] == "backup")
    assert sorted(p.rsplit("_", 1)[-1] for p in bk["files"]) == ["panorama-running-config.xml", "running-config.xml"]
    assert any("panorama-running-config" in p for p in bk["files"]) and "through Panorama" in bk["note"]
    post = next(s for s in plan["steps"] if s["action"] == "postcheck")
    assert {r["check"] for r in post["results"]} >= {"connected to Panorama", "Panorama sees the new version"}


def test_first_sighting_reads_only_show_system_info_directly(tmp_path, monkeypatch, boxes):
    pano, fw = boxes
    prof = _profile(tmp_path, monkeypatch)
    fac = factory_for({"pano": pano, "palo": fw})
    monkeypatch.setattr(devmod, "device_factory", fac)
    snap = planner.discover_customer(prof)
    assert fw.direct_calls == [SYSINFO] and paths.mode_of(snap["devices"]["t:palo"]) == paths.PANORAMA
    fw.direct_calls.clear()
    planner.discover_customer(prof)  # serial now cached: zero direct calls
    assert fw.direct_calls == []


def test_no_direct_credentials_and_never_seen_lists_it_under_panorama(tmp_path, monkeypatch, boxes):
    pano, fw = boxes
    prof = _profile(tmp_path, monkeypatch)
    fac = factory_for({"pano": pano, "palo": fw}, no_direct={"palo"})
    monkeypatch.setattr(devmod, "device_factory", fac)
    snap = planner.discover_customer(prof)
    assert not snap["devices"]["t:palo"]["reachable"]
    assert any("listed under that Panorama" in x for x in snap["devices"]["t:palo"]["errors"])
    m = snap["devices"]["m:pano:F1"]
    assert m["reachable"] and paths.mode_of(m) == paths.PANORAMA and fw.direct_calls == []
    assert not planner.build_plan(prof, snap, {"m:pano:F1": "11.1.13-h17"})["blocked"]


def test_direct_mode_on_managed_firewall_refused_by_default(tmp_path, monkeypatch, boxes):
    pano, fw = boxes
    fw.versions = {v: {"downloaded": v == "11.1.13-h9"} for v in AV}
    prof = _profile(tmp_path, monkeypatch, fw_extra=", access: direct")
    fac = factory_for({"pano": pano, "palo": fw})
    monkeypatch.setattr(devmod, "device_factory", fac)
    snap = planner.discover_customer(prof)
    f = snap["devices"]["t:palo"]
    assert f["managed_by"] == "t:pano" and paths.is_managed_direct(f)
    plan = planner.build_plan(prof, snap, {"t:palo": "11.1.13-h17"})
    assert plan["blocked"] and any(c["id"] == "access-path" and c["level"] == "red" for c in plan["devices"][0]["checks"])
    with pytest.raises(runner.UpgradeRefused):
        runner.reader_for(prof, snap, "t:palo", fac)
    with pytest.raises(runner.UpgradeRefused):
        runner.driver_for(prof, snap, {"id": "t:palo"}, fac)


def test_direct_override_is_yellow_and_audited(tmp_path, monkeypatch, boxes):
    pano, fw = boxes
    fw.versions = {v: {"downloaded": v == "11.1.13-h9"} for v in AV}
    prof = _profile(tmp_path, monkeypatch, fw_extra=", access: direct")
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "plab.yaml").write_text("allow_direct_managed: true\n")  # server override wins
    prof = load_profile("plab")
    assert prof.allow_direct_managed is True
    fac = factory_for({"pano": pano, "palo": fw})
    monkeypatch.setattr(devmod, "device_factory", fac)
    snap = planner.discover_customer(prof)
    plan = planner.build_plan(prof, snap, {"t:palo": "11.1.13-h17"})
    d = plan["devices"][0]
    assert not plan["blocked"] and any(c["id"] == "access-path" and c["level"] == "yellow" for c in d["checks"])
    assert d["path_text"].startswith("DIRECT")
    assert isinstance(runner.driver_for(prof, snap, d, fac), runner.DirectDriver)
    monkeypatch.setenv("PANLAB_UPGRADE_EXECUTE", "1")
    runner.arm(prof, plan, actor="eng", cr="CHG2", approved=True, ack_yellow=True)
    from panlab.pusher import read_audit
    assert any(r.get("action") == "upgrade-direct-override" and r.get("cr") == "CHG2" for r in read_audit(prof))


def test_standalone_firewall_uses_direct_path(tmp_path, monkeypatch, boxes):
    _, fw = boxes
    fw.pano_server = None
    fw.versions = {v: {"downloaded": v == "11.1.13-h9"} for v in AV}
    prof = _profile(tmp_path, monkeypatch, with_pano=False)
    fac = factory_for({"palo": fw})
    monkeypatch.setattr(devmod, "device_factory", fac)
    snap = planner.discover_customer(prof)
    plan = planner.build_plan(prof, snap, {"t:palo": "11.1.13-h17"})
    d = plan["devices"][0]
    assert not plan["blocked"] and d["path_text"] == "direct to the firewall's own API (standalone firewall)"
    monkeypatch.setenv("PANLAB_UPGRADE_EXECUTE", "1")
    plan = _run_all(prof, runner.arm(prof, plan, actor="eng", cr="CHG3", approved=True, ack_yellow=True), fac)
    assert plan["status"] == "complete" and fw.version == "11.1.13-h17"
    assert any("<software><install><version>11.1.13-h17" in w for w in fw.writes)


def test_firewall_managed_by_unknown_panorama_is_red(tmp_path, monkeypatch, boxes):
    _, fw = boxes
    fw.versions = {v: {"downloaded": v == "11.1.13-h9"} for v in AV}
    prof = _profile(tmp_path, monkeypatch, with_pano=False)  # panorama-status shows 192.0.2.10, not in the profile
    monkeypatch.setattr(devmod, "device_factory", factory_for({"palo": fw}))
    snap = planner.discover_customer(prof)
    plan = planner.build_plan(prof, snap, {"t:palo": "11.1.13-h17"})
    reds = [c for c in plan["devices"][0]["checks"] if c["level"] == "red"]
    assert plan["blocked"] and any(c["id"] == "access-path" and "Add that Panorama" in c["detail"] for c in reds)


def test_managed_driver_jobs_are_polled_on_panorama(boxes):
    pano, fw = boxes
    from fake_panos import FakeHandle
    drv = runner.ManagedDriver(FakeHandle(pano), FakeHandle(pano, fw), "F1", "vm")
    jid = drv.download("11.1.13-h17")
    assert "<request><batch><software><download><file>PanOS_vm-11.1.13-h17</file>" in pano.writes[-1]
    assert drv.job(jid)["status"] in ("ACT", "FIN") and int(jid) in pano.jobs and not fw.jobs
    drv.reboot()
    assert pano.writes[-1] == "<request><batch><reboot><devices>F1</devices></reboot></batch></request>"
    assert fw.direct_calls == []


def test_batch_software_filtered_by_platform_family():
    import xml.etree.ElementTree as ET
    resp = ET.fromstring(
        "<response status='success'><result><sw-updates><versions>"
        "<entry><version>11.1.13-h17</version><filename>PanOS_vm-11.1.13-h17</filename><downloaded>yes</downloaded></entry>"
        "<entry><version>11.1.13-h17</version><filename>PanOS_400-11.1.13-h17</filename><downloaded>no</downloaded></entry>"
        "<entry><version>11.2.4</version><filename>PanOS_400-11.2.4</filename><downloaded>no</downloaded></entry>"
        "</versions></sw-updates></result></response>")
    rows = D.parse_batch_software(resp)
    assert len(rows) == 3
    vm = D.batch_available_for(rows, "vm", "11.1.13-h9")
    assert [(a.version, a.downloaded) for a in vm] == [("11.1.13-h17", True)]
    assert {a.version for a in D.batch_available_for(rows, "400", None)} == {"11.1.13-h17", "11.2.4"}
    assert D.batch_available_for(rows, "", None) == []


def test_backup_through_panorama_reads_the_firewall_config_not_panoramas(tmp_path, monkeypatch, boxes):
    """Real Panorama ignores target=<serial> on export and returns its own config; the tool uses show config running."""
    pano, fw = boxes
    prof = _profile(tmp_path, monkeypatch, fw_extra=", access: panorama")
    from panlab import identity
    identity.remember(prof, "palo", identity.make("FW", "F1"))
    fac = factory_for({"pano": pano, "palo": fw}, no_direct={"palo"})
    monkeypatch.setattr(devmod, "device_factory", fac)
    snap = planner.discover_customer(prof)
    plan = planner.build_plan(prof, snap, {"t:palo": "11.1.13-h17"})
    s = next(x for x in plan["steps"] if x["action"] == "backup")
    files = runner.backup(prof, plan, snap, s, fac)
    from pathlib import Path
    cfg = next(p for p in files if Path(p).name.endswith("_running-config.xml") and "panorama" not in Path(p).name)
    assert "via op" in open(cfg).read() and "device-group" not in open(cfg).read()
    pcfg = next(p for p in files if "panorama-running-config" in Path(p).name)
    assert "device-group" in open(pcfg).read()
    assert "Device state is not exportable through Panorama" in s["note"]
    assert runner._is_panorama_config(pano.export("configuration"))


def test_push_to_panorama_managed_firewall_is_refused():
    from pathlib import Path
    import tempfile
    from panlab.pusher import panorama_servers
    d = Path(tempfile.mkdtemp())
    managed = d / "m.xml"
    managed.write_text("<config><devices><entry><deviceconfig><system><panorama><local-panorama>"
                       "<panorama-server>192.0.2.10</panorama-server></local-panorama></panorama></system></deviceconfig>"
                       "</entry></devices></config>")
    old = d / "o.xml"
    old.write_text("<config><devices><entry><deviceconfig><system><panorama-server>192.0.2.11</panorama-server>"
                   "</system></deviceconfig></entry></devices></config>")
    solo = d / "s.xml"
    solo.write_text("<config><devices><entry><deviceconfig><system><hostname>x</hostname></system></deviceconfig></entry></devices></config>")
    assert panorama_servers(managed) == ["192.0.2.10"] and panorama_servers(old) == ["192.0.2.11"] and panorama_servers(solo) == []


def test_gui_shows_path_destinations_and_backup_download(tmp_path, monkeypatch, boxes):
    pytest.importorskip("fastapi")
    import io
    import zipfile

    from fastapi.testclient import TestClient

    from panlab.web import auth
    from panlab.web.app import app

    pano, fw = boxes
    prof = _profile(tmp_path, monkeypatch)
    fac = factory_for({"pano": pano, "palo": fw})
    monkeypatch.setattr(devmod, "device_factory", fac)
    monkeypatch.setenv("PANLAB_UPGRADE_EXECUTE", "1")
    monkeypatch.setenv("PANLAB_ETC_DIR", str(tmp_path / "etc-panlab"))
    uf = tmp_path / "users.yaml"
    monkeypatch.setenv("PANLAB_USERS_FILE", str(uf))
    auth.add_user("eng1", "engineer", "pw-eng", uf)
    c = TestClient(app)
    c.post("/login", data={"username": "eng1", "password": "pw-eng"})
    disc = c.post("/upgrade/discover", data={"customer": "plab"}, follow_redirects=False).headers["location"]
    assert "upgrade path: <b>via Panorama PANO · SN P1 [pano]</b>" in c.get(disc).text
    plan_url = c.post(disc + "/plan", data={"pick": ["t:palo"], "v::t:palo": "11.1.13-h17"}, follow_redirects=False).headers["location"]
    r = c.get(plan_url)
    assert "Upgrade path: <b>via Panorama PANO · SN P1 [pano]</b>" in r.text
    assert "never into git" not in r.text and "Backed up to: this server (customer backup folder)." in r.text
    assert "No off-box backup destination is configured" in r.text
    r = c.post(plan_url + "/arm", data={"cr": "CHG7", "approved": "yes", "ack": "yes"})
    run = plan_url.replace("/plan/", "/run/")
    assert "via Panorama PANO · SN P1 [pano]" in r.text
    for _ in range(2):  # pre-check, backup
        r = c.post(run + "/next", data={"confirm": "FW"})
    assert "Download backup</a>" in r.text and "/backup/2.zip" in r.text
    z = c.get(run + "/backup/2.zip")
    assert z.status_code == 200 and z.headers["content-type"] == "application/zip"
    names = zipfile.ZipFile(io.BytesIO(z.content)).namelist()
    assert len(names) == 2 and all(n.startswith("FW_F1/") for n in names)
    assert c.get(run + "/backup/1.zip").status_code == 404  # step 1 is the pre-check
    from panlab.pusher import read_audit
    assert any(a.get("action") == "upgrade-backup-download" and a.get("actor") == "eng1" for a in read_audit(prof))
    # Another customer's user cannot download it.
    auth.add_user("other", "engineer", "pw-o", uf, customers=["someone-else"])
    c2 = TestClient(app)
    c2.post("/login", data={"username": "other", "password": "pw-o"})
    assert c2.get(run + "/backup/2.zip").status_code == 403
    # With an off-box destination configured, the step names it.
    from panlab import offsite
    offsite.save_destination("plab", {"id": "fwtest-s3", "type": "s3", "name": "Lab S3", "enabled": True, "bucket": "b"}, {})
    r = c.get(run)
    assert "Backed up to: this server (customer backup folder), Lab S3 (S3)." in r.text
    assert "No off-box backup destination" not in r.text
