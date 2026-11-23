"""Off-box backup destinations: git (local bare repo), S3 (moto), SFTP and FTPS (in-memory fakes)."""

from __future__ import annotations

import io
import json
import stat
import subprocess
from datetime import datetime
from pathlib import Path

import pytest

from fake_panos import FakeBox, factory_for
from panlab import offsite
from panlab.customers import load_profile
from panlab.pusher import read_audit
from panlab.upgrade import device as devmod
from panlab.upgrade import planner, runner

WHEN = datetime(2026, 11, 18, 22, 30, 5, tzinfo=offsite.TZ)
IDENT = {"hostname": "FW-A", "serial": "SN-TEST-9", "model": "PA-VM"}


@pytest.fixture
def env(tmp_path, monkeypatch):
    cdir = tmp_path / "customers" / "vlab"
    cdir.mkdir(parents=True)
    (cdir / "profile.yaml").write_text(
        "name: vlab\ntargets:\n  - {name: pano, type: panorama, host_env: X_H, api_key_env: X_K}\n"
        "  - {name: palo, type: firewall, host_env: Y_H, api_key_env: Y_K}\n")
    monkeypatch.setenv("PANLAB_CUSTOMERS_DIR", str(tmp_path / "customers"))
    monkeypatch.setenv("PANLAB_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PANLAB_ETC_DIR", str(tmp_path / "etc"))
    monkeypatch.setenv("PANLAB_UPGRADE_REFERENCE", str(tmp_path / "none.yaml"))
    prof = load_profile("vlab")
    f = tmp_path / "cfg.xml"
    f.write_bytes(b"<config version='11.1.0'><devices/></config>\n")
    return prof, tmp_path, f


def _bare(tmp_path: Path) -> Path:
    b = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--quiet", "--bare", "-b", "main", str(b)], check=True)
    return b


def _show(bare: Path, path: str) -> bytes:
    return subprocess.run(["git", "--git-dir", str(bare), "show", f"main:{path}"], capture_output=True, check=True).stdout


def _ls(bare: Path) -> list[str]:
    return subprocess.run(["git", "--git-dir", str(bare), "ls-tree", "-r", "--name-only", "main"], capture_output=True,
                          text=True, check=True).stdout.split()


# ---------------------------------------------------------------- config + secrets

def test_config_secrets_are_600_and_separate(env):
    prof, tmp, _ = env
    d = offsite.save_destination("vlab", {"id": "s3a", "type": "s3", "bucket": "panlab-bk", "enabled": True},
                                 {"access_key": "AKIDTEST", "secret_key": "s3cr3t-value"})
    cfg, envf = offsite._cfg_path("vlab"), offsite._env_path("vlab")
    assert stat.S_IMODE(cfg.stat().st_mode) == 0o600 and stat.S_IMODE(envf.stat().st_mode) == 0o600
    assert "s3cr3t" not in cfg.read_text() and "s3cr3t-value" in envf.read_text()
    offsite.save_destination("vlab", {**d, "prefix": "x"}, {"secret_key": ""})  # blank keeps the stored secret
    assert offsite.secret("vlab", "s3a", "secret_key") == "s3cr3t-value"
    offsite.delete_destination("vlab", "s3a")
    assert offsite.load_config("vlab") == [] and "s3cr3t" not in envf.read_text()


@pytest.mark.parametrize("url", ["https://github.com/example-org/network-tools.git",
                                 "git@github.com:example-org/network-tools.git",
                                 "https://github.com/example-org/network-tools/",
                                 "https://github.com/example-org/PAAT.git",
                                 "git@github.com:example-org/PAAT.git",
                                 "https://github.com/example-org/paat/"])
def test_tool_repo_is_refused(env, url):
    with pytest.raises(offsite.OffsiteError, match="own repo"):
        offsite.save_destination("vlab", {"id": "g", "type": "git", "url": url, "enabled": True}, {})


def test_plain_ftp_not_offered(env):
    with pytest.raises(offsite.OffsiteError, match="plain FTP"):
        offsite.validate({"id": "f", "type": "ftp", "host": "h", "username": "u"})


def test_redaction():
    r = offsite._Redactor(["tok_ABCDEFGH123"])
    assert "tok_ABC" not in r("fatal: auth tok_ABCDEFGH123 failed; Authorization: Basic eHl6Cg==")
    assert "eHl6Cg" not in r("Authorization: Basic eHl6Cg==")


def test_layout():
    assert offsite.remote_name(IDENT, WHEN, "upg-1", "running-config", ".xml") == \
        "FW-A_SN-TEST-9/2026/11/18/223005_upg-1_running-config.xml"
    assert offsite.device_dir({}) == "hostname-unknown_serial-unknown"
    assert offsite.remote_name(IDENT, WHEN, "upg-1", "manifest", ".json", customer="vm lab") == \
        "vm_lab/FW-A_SN-TEST-9/2026/11/18/223005_upg-1_manifest.json"  # <customer>/<hostname>_<serial>/<YYYY>/<MM>/<DD>/<file>


# ---------------------------------------------------------------- git

def test_git_destination_layout_manifest_verify_audit(env):
    prof, tmp, f = env
    bare = _bare(tmp)
    offsite.save_destination("vlab", {"id": "g1", "type": "git", "url": str(bare), "enabled": True}, {})
    ok, msg = offsite.test_destination("vlab", "g1", prof.data_dir())
    assert ok, msg
    res = offsite.ship(prof, [offsite.Item(f, "running-config")], run_id="upg-1", kind="os-upgrade", ident=IDENT,
                       actor="admin1", cr="CHG1", when=WHEN, extra={"versions": {"running": "11.1.13-h9", "target": "11.1.13-h17"}})
    assert res[0]["ok"], res
    names = _ls(bare)
    assert names == ["vlab/FW-A_SN-TEST-9/2026/11/18/223005_upg-1_manifest.json",
                     "vlab/FW-A_SN-TEST-9/2026/11/18/223005_upg-1_running-config.xml"]
    assert _show(bare, names[1]) == f.read_bytes()
    man = json.loads(_show(bare, names[0]))
    assert man["cr"] == "CHG1" and man["user"] == "admin1" and man["versions"]["target"] == "11.1.13-h17"
    assert man["files"][0]["sha256"] == offsite.sha256(f.read_bytes()) and man["device"]["serial"] == "SN-TEST-9"
    lines = [r for r in read_audit(prof) if r["action"] == "backup-offsite"]
    assert len(lines) == 2 and all(r["verified"] and r["result"] == "ok" and r["hostname"] == "FW-A" for r in lines)
    # A second run appends to the same repo
    res = offsite.ship(prof, [offsite.Item(f, "running-config")], run_id="upg-2", kind="os-upgrade", ident=IDENT, when=WHEN)
    assert res[0]["ok"] and len(_ls(bare)) == 4


def test_failure_is_returned_not_raised(env):
    prof, tmp, f = env
    offsite.save_destination("vlab", {"id": "g1", "type": "git", "url": str(tmp / "missing.git"), "enabled": True}, {})
    res = offsite.ship(prof, [offsite.Item(f, "running-config")], run_id="r", kind="push", ident=IDENT)
    assert res[0]["ok"] is False and "git clone failed" in res[0]["error"]
    assert [r["result"] for r in read_audit(prof) if r["action"] == "backup-offsite"] == ["failed"]


def test_no_destinations_means_local_only(env):
    prof, tmp, f = env
    assert offsite.ship(prof, [offsite.Item(f, "running-config")], run_id="r", kind="push", ident=IDENT) == []


# ---------------------------------------------------------------- S3 (moto)

def test_s3_destination(env):
    moto = pytest.importorskip("moto")
    import boto3

    prof, tmp, f = env
    with moto.mock_aws():
        boto3.client("s3", region_name="us-east-1").create_bucket(Bucket="panlab-bk")
        offsite.save_destination("vlab", {"id": "s3a", "type": "s3", "bucket": "panlab-bk", "prefix": "panlab", "region": "us-east-1",
                                          "enabled": True}, {"access_key": "testing", "secret_key": "testing"})
        assert offsite.test_destination("vlab", "s3a")[0]
        res = offsite.ship(prof, [offsite.Item(f, "running-config")], run_id="upg-1", kind="os-upgrade", ident=IDENT, when=WHEN)
        assert res[0]["ok"], res
        keys = sorted(o["Key"] for o in boto3.client("s3", region_name="us-east-1").list_objects_v2(Bucket="panlab-bk")["Contents"])
        assert keys == ["panlab/vlab/FW-A_SN-TEST-9/2026/11/18/223005_upg-1_manifest.json",
                        "panlab/vlab/FW-A_SN-TEST-9/2026/11/18/223005_upg-1_running-config.xml"]


# ---------------------------------------------------------------- SFTP / FTPS fakes

class _FakeSftp:
    def __init__(self, store):
        self.store = store

    def get_channel(self):
        return type("C", (), {"settimeout": lambda *a: None})()

    def stat(self, p):
        if p in self.store or any(k.startswith(p.rstrip("/") + "/") for k in self.store) or p in self.store.get("__dirs__", set()):
            return type("S", (), {"st_size": len(self.store.get(p, b""))})()
        raise OSError(p)

    def mkdir(self, p):
        self.store.setdefault("__dirs__", set()).add(p)

    def putfo(self, fo, p, confirm=True):
        self.store[p] = fo.read()

    def getfo(self, p, fo):
        fo.write(self.store[p])

    def remove(self, p):
        del self.store[p]


def test_sftp_destination(env, monkeypatch):
    prof, tmp, f = env
    store: dict = {}

    class Cli:
        def open_sftp(self):
            return _FakeSftp(store)

        def close(self):
            pass
    monkeypatch.setattr(offsite.SftpBackend, "_connect", lambda self: Cli())
    offsite.save_destination("vlab", {"id": "sf", "type": "sftp", "host": "h", "username": "u", "base_dir": "bk",
                                      "host_key": "ssh-ed25519 AAAA", "enabled": True}, {"password": "pw-123456"})
    assert offsite.test_destination("vlab", "sf")[0]
    res = offsite.ship(prof, [offsite.Item(f, "running-config")], run_id="upg-1", kind="os-upgrade", ident=IDENT, when=WHEN)
    assert res[0]["ok"], res
    assert store["bk/vlab/FW-A_SN-TEST-9/2026/11/18/223005_upg-1_running-config.xml"] == f.read_bytes()


def test_sftp_needs_pinned_host_key(env):
    prof, tmp, f = env
    offsite.save_destination("vlab", {"id": "sf", "type": "sftp", "host": "h", "username": "u", "enabled": True}, {})
    res = offsite.ship(prof, [offsite.Item(f, "running-config")], run_id="r", kind="push", ident=IDENT)
    assert not res[0]["ok"] and "host key is not pinned" in res[0]["error"]


class _FakeFtps:
    store: dict = {}

    def __init__(self, context=None, timeout=None):
        self.prot = False

    def connect(self, host, port):
        pass

    def login(self, u, p):
        assert p == "pw-ftps"

    def prot_p(self):
        self.prot = True

    def mkd(self, p):
        pass

    def storbinary(self, cmd, fo):
        assert self.prot  # data channel encrypted
        self.store[cmd[5:]] = fo.read()

    def voidcmd(self, c):
        pass

    def size(self, p):
        return len(self.store[p])

    def retrbinary(self, cmd, cb):
        cb(self.store[cmd[5:]])

    def delete(self, p):
        del self.store[p]

    def quit(self):
        pass

    close = quit


def test_ftps_destination(env, monkeypatch):
    prof, tmp, f = env
    monkeypatch.setattr(offsite.FtpsBackend, "ftp_class", _FakeFtps)
    offsite.save_destination("vlab", {"id": "ft", "type": "ftps", "host": "h", "username": "u", "enabled": True},
                             {"password": "pw-ftps"})
    assert offsite.test_destination("vlab", "ft")[0]
    res = offsite.ship(prof, [offsite.Item(f, "running-config")], run_id="upg-1", kind="os-upgrade", ident=IDENT, when=WHEN)
    assert res[0]["ok"] and "vlab/FW-A_SN-TEST-9/2026/11/18/223005_upg-1_running-config.xml" in _FakeFtps.store


# ---------------------------------------------------------------- upgrade run integration

def _lab(monkeypatch):
    pano = FakeBox("PANO", kind="panorama", version="11.1.6-h7", serial="P1", versions=["11.1.13-h9"])
    fw = FakeBox("FW", version="11.1.6-h32", serial="F1", versions=["11.1.13-h9"])
    pano.managed = [fw]
    fac = factory_for({"pano": pano, "palo": fw})
    monkeypatch.setattr(devmod, "device_factory", fac)
    return fac


def _run_to_backup(prof, fac):
    plan = planner.build_plan(prof, planner.discover_customer(prof), {"t:pano": "11.1.13-h9"})
    plan = runner.arm(prof, plan, actor="eng", cr="CHG5", approved=True, ack_yellow=True)
    plan = runner.start_step(prof, plan, actor="eng", confirm="PANO", factory=fac)
    return runner.start_step(prof, plan, actor="eng", confirm="PANO", factory=fac)


def test_upgrade_backup_goes_offsite(env, monkeypatch):
    prof, tmp, _ = env
    monkeypatch.setenv("PANLAB_UPGRADE_EXECUTE", "1")
    fac = _lab(monkeypatch)
    bare = _bare(tmp)
    offsite.save_destination("vlab", {"id": "g1", "type": "git", "url": str(bare), "enabled": True}, {})
    plan = _run_to_backup(prof, fac)
    s = plan["steps"][1]
    assert s["action"] == "backup" and s["status"] == "ok" and s["offsite"][0]["ok"] and "offsite_warning" not in s
    names = _ls(bare)
    assert len(names) == 2 and all(n.startswith("vlab/PANO_P1/") for n in names)
    assert any(n.endswith(f"_{plan['id']}_running-config.xml") for n in names)
    man = json.loads(_show(bare, next(n for n in names if n.endswith("manifest.json"))))
    assert man["cr"] == "CHG5" and man["user"] == "eng" and man["versions"]["target"] == "11.1.13-h9"
    assert "Off-box copy OK" in "".join(open(runner.write_report(prof, plan)[0]).read())


def test_offsite_failure_is_yellow_and_run_continues(env, monkeypatch):
    prof, tmp, _ = env
    monkeypatch.setenv("PANLAB_UPGRADE_EXECUTE", "1")
    fac = _lab(monkeypatch)
    offsite.save_destination("vlab", {"id": "g1", "type": "git", "url": str(tmp / "nope.git"), "enabled": True}, {})
    plan = _run_to_backup(prof, fac)
    s = plan["steps"][1]
    assert s["status"] == "ok" and plan["status"] != "stopped" and "CHECK" in s["offsite_warning"]
    assert list(prof.data_dir("upgrade-backups").glob("PANO_P1/*/*/*/*_" + plan["id"] + "_running-config.xml"))  # local copy kept
    plan = runner.start_step(prof, plan, actor="eng", confirm="PANO", factory=fac)  # next step still runs
    assert plan["steps"][2]["status"] in ("running", "ok")


# ---------------------------------------------------------------- admin page

def test_admin_page_is_admin_only_and_never_shows_secrets(env, monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from panlab.web import auth
    from panlab.web.app import app

    prof, tmp, _ = env
    uf = tmp / "users.yaml"
    monkeypatch.setenv("PANLAB_USERS_FILE", str(uf))
    auth.add_user("eng1", "engineer", "pw-eng", uf)
    auth.add_user("adm1", "admin", "pw-adm", uf)
    c = TestClient(app)
    c.post("/login", data={"username": "eng1", "password": "pw-eng"})
    assert c.get("/admin/backup-destinations").status_code == 403
    from panlab import identity
    identity.remember(prof, "pano", identity.make("PANO-X", "SN-X1"))
    assert c.post("/admin/backup-destinations/vlab/save", data={"type": "git"}).status_code == 403
    c.post("/login", data={"username": "adm1", "password": "pw-adm"})
    page = c.get("/admin/backup-destinations?customer=vlab").text
    assert "<h2>Customer: vlab</h2>" in page and "<b>PANO-X</b> · SN <code>SN-X1</code>" in page and "PANO-X_SN-X1/" in page
    assert "<b>palo</b> · <span style='color:#9a6700'><b>hostname unknown</b></span>" in page  # never read: profile name + yellow
    r = c.post("/admin/backup-destinations/vlab/save",
               data={"type": "git", "id": "g1", "name": "own", "url": "git@github.com:example-org/network-tools.git",
                     "enabled": "yes"})
    assert "own repo" in r.text and offsite.load_config("vlab") == []
    bare = _bare(tmp)
    r = c.post("/admin/backup-destinations/vlab/save",
               data={"type": "git", "id": "g1", "name": "junk", "url": str(bare), "enabled": "yes", "sec_token": "ghp_SECRET123"})
    assert "Saved junk" in r.text and "ghp_SECRET123" not in r.text and "token set" in r.text
    r = c.post("/admin/backup-destinations/vlab/g1/test")
    assert "Test passed" in r.text and "ghp_SECRET123" not in r.text
    assert "ghp_SECRET123" not in json.dumps(read_audit(prof))
    assert any(x["action"] == "backup-destination-save" for x in read_audit(prof))
    r = c.post("/admin/backup-destinations/vlab/g1/delete")
    assert "Deleted" in r.text and offsite.load_config("vlab") == []


def test_private_key_loading(tmp_path):
    paramiko = pytest.importorskip("paramiko")
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(tmp_path / "k")], check=True)
    assert isinstance(offsite._load_pkey((tmp_path / "k").read_text()), paramiko.Ed25519Key)
    with pytest.raises(offsite.OffsiteError):
        offsite._load_pkey("not a key")


def test_git_ssh_url_host_port_and_known_hosts():
    from panlab.offsite import known_hosts_name, ssh_host_port, refuse_own_repo, OffsiteError
    assert ssh_host_port("git@github.com:owner/backups.git") == ("github.com", 22)
    assert ssh_host_port("ssh://git@ssh.github.com:443/owner/backups.git") == ("ssh.github.com", 443)
    assert ssh_host_port("ssh://git@host.example/owner/b.git") == ("host.example", 22)
    assert known_hosts_name("github.com", 22) == "github.com"
    assert known_hosts_name("ssh.github.com", 443) == "[ssh.github.com]:443"
    import pytest
    with pytest.raises(OffsiteError):
        refuse_own_repo("ssh://git@ssh.github.com:443/example-org/network-tools.git")
    with pytest.raises(OffsiteError):
        refuse_own_repo("ssh://git@ssh.github.com:443/example-org/PAAT.git")
    refuse_own_repo("git@github.com:example/paat-backups.git")  # last path component is not exactly PAAT
