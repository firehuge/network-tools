# SPDX-License-Identifier: Apache-2.0
"""Push area: re-validation, apply/commit/verify, rollback, audit, CR check, CLI guards, GUI login and roles."""

from __future__ import annotations

import copy
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from fcr_factory import make_fcr  # noqa: E402

from panlab import pusher  # noqa: E402
from panlab.changeset import build_changeset  # noqa: E402
from panlab.cli import main  # noqa: E402
from panlab.customers import load_profile  # noqa: E402
from panlab.fcr import read_fcr  # noqa: E402
from panlab.sources import load_customer_envs  # noqa: E402
from panlab.web import auth  # noqa: E402

FIX = Path(__file__).parent / "fixtures"
FWXML = FIX / "synthetic-fw-test.xml"
SEG = re.compile(r"([^/\[]+)(?:\[@name='([^']*)'\])?")


class FakeDevice:
    """In-memory firewall: candidate + running trees, XML-API-like set/delete/show."""

    def __init__(self, xml: str, commit_ok: bool = True):
        self.running = ET.fromstring(xml)
        self.candidate = copy.deepcopy(self.running)
        self.dirty, self.commit_ok, self.jobs = False, commit_ok, 0

    def _walk(self, root, xpath, create=False):
        parts = SEG.findall(xpath.strip("/"))
        assert parts[0][0] == "config"
        cur = root
        for tag, name in parts[1:]:
            nxt = next((c for c in cur if c.tag == tag and (name == "" or c.get("name") == name)), None)
            if nxt is None:
                if not create:
                    return None
                nxt = ET.SubElement(cur, tag, {"name": name} if name else {})
            cur = nxt
        return cur

    def export_running(self):
        return ET.tostring(self.running, encoding="unicode")

    def set(self, xpath, element):
        parent = self._walk(self.candidate, xpath, create=True)
        el = ET.fromstring(element)
        if el.tag == "member":
            text = (el.text or "").strip()
            if not any(c.tag == "member" and (c.text or "").strip() == text for c in parent):
                parent.append(el)
            self.dirty = True
            return
        if el.tag == "description":
            old = next((c for c in parent if c.tag == "description"), None)
            if old is not None:
                parent.remove(old)
            parent.append(el)
            self.dirty = True
            return
        old = next((c for c in parent if c.tag == el.tag and c.get("name") == el.get("name")), None)
        if old is not None and el.get("name") is None and len(el) and all(c.tag == "member" for c in el):
            # like PAN-OS: 'set' on a member list merges (adds) members, it never removes any
            have = {(c.text or "").strip() for c in old}
            for c in el:
                if (c.text or "").strip() not in have:
                    old.append(c)
            self.dirty = True
            return
        if old is not None:
            parent.remove(old)
        parent.append(el)
        self.dirty = True

    def move(self, xpath, where, dst=None):
        parent_xp, _, last = xpath.rpartition("/")
        parent = self._walk(self.candidate, parent_xp)
        tag, name = SEG.match(last).groups()
        el = next((c for c in parent if c.tag == tag and c.get("name") == name), None)
        if el is None:
            raise RuntimeError(f"move: no such node {xpath}")
        parent.remove(el)
        kids = list(parent)
        if where == "top":
            parent.insert(0, el)
        elif where == "bottom":
            parent.append(el)
        else:
            ref = next((i for i, c in enumerate(kids) if c.get("name") == dst), None)
            if ref is None:
                raise RuntimeError(f"move: no such rule {dst}")
            parent.insert(ref if where == "before" else ref + 1, el)
        self.dirty = True

    def delete(self, xpath):
        if "/member[text()=" in xpath:
            parent_xp, _, pred = xpath.rpartition("/")
            text = pred.split("'", 2)[1] if "'" in pred else pred.split('"', 2)[1]
            parent = self._walk(self.candidate, parent_xp)
            for c in list(parent if parent is not None else []):
                if c.tag == "member" and (c.text or "").strip() == text:
                    parent.remove(c)
            self.dirty = True
            return
        parent_xp, _, last = xpath.rpartition("/")
        parent = self._walk(self.candidate, parent_xp)
        tag, name = SEG.match(last).groups()
        for c in list(parent if parent is not None else []):
            if c.tag == tag and (name and c.get("name") == name or not name and c.tag == tag):
                parent.remove(c)
        self.dirty = True

    def exists_running(self, xpath):
        if "/member[text()=" in xpath:
            parent_xp, _, pred = xpath.rpartition("/")
            text = pred.split("'", 2)[1] if "'" in pred else pred.split('"', 2)[1]
            return self.member_exists(parent_xp, text)
        return self._walk(self.running, xpath) is not None

    def member_exists(self, list_xpath, member):
        parent = self._walk(self.running, list_xpath)
        if parent is None:
            return False
        return any(c.tag == "member" and (c.text or "").strip() == member for c in parent)

    def pending_changes(self):
        return self.dirty

    def revert(self):
        self.candidate, self.dirty = copy.deepcopy(self.running), False

    def commit(self, description):
        self.jobs += 1
        if not self.commit_ok:
            return {"jobid": str(self.jobs), "success": False, "messages": ["validation error"]}
        self.running, self.dirty = copy.deepcopy(self.candidate), False
        return {"jobid": str(self.jobs), "success": True, "messages": ["Configuration committed successfully"]}

    def policy_match(self, q):
        rules = self._walk(self.running, "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules")
        for r in (rules if rules is not None else []):
            if q["from"] in [m.text for m in r.find("from")] and q["to"] in [m.text for m in r.find("to")]:
                return r.get("name")
        return None


@pytest.fixture
def fwtest(tmp_path, monkeypatch):
    monkeypatch.setenv("PANLAB_DATA_DIR", str(tmp_path / "data"))
    prof = load_profile("fwtest")
    f = make_fcr(tmp_path / "RITM0000777.xlsx", [("10.200.1.5", None, "10.1.20.60", None, "TCP", "5432", None, "db", None)],
                 project="LAB push")
    reqs, meta = read_fcr(f, ticket_patterns=prof.tickets)
    cs = build_changeset(prof, load_customer_envs(prof, configs=[str(FWXML)]), reqs, files=[meta])
    d = prof.data_dir("changesets")
    (d / "cs-test.json").write_text(json.dumps(cs))
    return prof, cs, FakeDevice(FWXML.read_text())


def test_cr_format_checked(fwtest):
    prof, cs, dev = fwtest
    with pytest.raises(pusher.PushError, match="CR format"):
        pusher.prepare(prof, cs, "cs-test", actor="t", cr="RITM123", dev=dev)


def test_full_push_verify_rollback_and_audit(fwtest):
    prof, cs, dev = fwtest
    s = pusher.prepare(prof, cs, "cs-test", actor="eng", cr="CHG0001234", dev=dev)
    assert s["status"] == "prepared" and not s["errors"]
    assert any(l.startswith("+ rule ") for l in s["diff"]) and Path(s["backup"]).is_file()
    assert not dev.dirty  # prepare writes nothing
    with pytest.raises(pusher.PushError, match="typed target"):
        pusher.apply(prof, cs, s["id"], actor="eng", confirm_target="wrong", dev=dev)
    s = pusher.apply(prof, cs, s["id"], actor="eng", confirm_target="fw-1", dev=dev)
    assert s["status"] == "committed", s.get("result")
    assert all(v["ok"] for v in s["verify"]) and any("policy-match" in v["check"] for v in s["verify"])
    rule = cs["groups"][0]["rules"][0]["name"]
    assert rule in ET.tostring(dev.running, encoding="unicode")
    s = pusher.rollback(prof, cs, s["id"], actor="eng", confirm_target="fw-1", dev=dev)
    assert s["status"] == "rolled-back"
    run = ET.tostring(dev.running, encoding="unicode")
    assert rule not in run and "LAN-PRINTER" in run  # pre-existing object untouched
    assert 'name="TST-panlab"' in run and 'name="TST-RITM0000777"' not in run  # shared tag kept, ticket tag removed
    acts = [(a["action"], a["result"]) for a in pusher.read_audit(prof)]
    assert acts == [("prepare", "prepared"), ("apply", "committed"), ("rollback", "rolled-back")]
    a = pusher.read_audit(prof)[1]
    assert a["actor"] == "eng" and a["cr"] == "CHG0001234" and a["job_ids"] == ["1"] and a["target"] == "fw-1"
    p = prof.data_dir("audit") / "audit.jsonl"
    assert oct(p.stat().st_mode & 0o777) == "0o600"


def test_revalidate_catches_conflicts_and_missing_zones(fwtest):
    prof, cs, dev = fwtest
    bad = copy.deepcopy(cs)
    bad["groups"][0]["rules"][0]["to"] = ["TST-GONE"]
    rule = cs["groups"][0]["rules"][0]["name"]
    dev.set("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules",
            f'<entry name="{rule}"><action>deny</action></entry>')
    dev.commit("someone else")
    s = pusher.prepare(prof, bad, "cs-test", actor="eng", cr="CHG0001234", dev=dev)
    assert s["status"] == "blocked"
    assert any("zone TST-GONE" in x for x in s["errors"]) and any("already exists" in x for x in s["errors"])
    with pytest.raises(pusher.PushError, match="blocked"):
        pusher.apply(prof, bad, s["id"], actor="eng", confirm_target="fw-1", dev=dev)


def test_failed_commit_reverts_and_pending_changes_refused(fwtest):
    prof, cs, dev = fwtest
    dev.commit_ok = False
    s = pusher.prepare(prof, cs, "cs-test", actor="eng", cr="CHG0001234", dev=dev)
    s = pusher.apply(prof, cs, s["id"], actor="eng", confirm_target="fw-1", dev=dev)
    assert s["status"] == "failed" and not dev.dirty
    dev.commit_ok = True
    dev.dirty = True  # someone else's uncommitted work
    s2 = pusher.prepare(prof, cs, "cs-test", actor="eng", cr="CHG0001234", dev=dev)
    s2 = pusher.apply(prof, cs, s2["id"], actor="eng", confirm_target="fw-1", dev=dev)
    assert s2["status"] == "refused" and "uncommitted" in s2["result"]


def test_cli_push_requires_cr_and_both_flags(fwtest, tmp_path, capsys):
    prof, cs, _ = fwtest
    p = prof.data_dir("changesets") / "cs-test.json"
    assert main(["push", "--customer", "fwtest", "--changeset", str(p), "--apply", "--commit"]) == 2
    assert "--cr" in capsys.readouterr().err
    assert main(["push", "--customer", "fwtest", "--changeset", str(p), "--apply", "--cr", "CHG1"]) == 2
    assert main(["push", "--customer", "fwtest", "--changeset", str(p)]) == 0  # dry run still fine


def test_users_cli_and_password_file(tmp_path, capsys):
    uf, pf = tmp_path / "users.yaml", tmp_path / "pw"
    assert main(["users", "add", "admin1", "--role", "admin", "--password-file", str(pf), "--users-file", str(uf)]) == 0
    out = capsys.readouterr().out
    pw = re.search(r"password: (\S+)", pf.read_text()).group(1)
    assert pw not in out and pw not in uf.read_text()
    assert oct(pf.stat().st_mode & 0o777) == "0o600" and oct(uf.stat().st_mode & 0o777) == "0o600"
    assert auth.verify_password(pw, auth.load_users(uf)["admin1"]["hash"])
    assert main(["users", "add", "admin1", "--role", "admin", "--password-file", str(pf), "--users-file", str(uf)]) == 1
    assert main(["users", "remove", "admin1", "--users-file", str(uf)]) == 0 and auth.load_users(uf) == {}


def _client(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from panlab.web.app import app

    uf = tmp_path / "users.yaml"
    monkeypatch.setenv("PANLAB_USERS_FILE", str(uf))
    auth.add_user("viewer1", "viewer", "pw-viewer", uf)
    auth.add_user("eng1", "engineer", "pw-eng", uf)
    return TestClient(app)


def _login(c, u, p):
    r = c.post("/login", data={"username": u, "password": p}, follow_redirects=False)
    assert r.status_code == 303
    return r


def test_gui_login_roles_and_tamper(tmp_path, monkeypatch, fwtest):
    c = _client(tmp_path, monkeypatch)
    assert c.get("/changesets", follow_redirects=False).status_code == 303
    r = c.post("/login", data={"username": "eng1", "password": "nope"}, follow_redirects=False)
    assert "Wrong" in r.headers["location"]
    _login(c, "viewer1", "pw-viewer")
    assert c.get("/changesets").status_code == 200
    r = c.get("/", follow_redirects=False)  # no FCR permission: lands on change sets instead
    assert r.status_code == 303 and r.headers["location"] == "/changesets"
    assert c.get("/decom").status_code == 403  # FCR pages need the fcr permission
    assert c.get("/push/fwtest/cs-test").status_code == 403
    c.cookies.set(auth.COOKIE, c.cookies.get(auth.COOKIE)[:-2] + "00")
    assert c.get("/changesets", follow_redirects=False).status_code == 303


def test_gui_push_flow(tmp_path, monkeypatch, fwtest):
    prof, cs, dev = fwtest
    import panlab.web.app as web

    c = _client(tmp_path, monkeypatch)
    monkeypatch.setattr(web, "device_factory", lambda p, t: dev)
    _login(c, "eng1", "pw-eng")
    page = c.get("/push/fwtest/cs-test").text
    assert "PUSH AREA" in page and "Approved CR" in page
    assert c.post("/push/fwtest/cs-test/prepare", data={"cr": "bad", "approved": "yes", "target": "fw-1"}).status_code == 400
    r = c.post("/push/fwtest/cs-test/prepare", data={"cr": "CHG0009999", "approved": "yes", "target": "fw-1"})
    assert r.status_code == 200 and "Dry-run diff" in r.text and "Apply + commit" in r.text
    sid = re.search(r"push-\d{8}-\d{6}-[0-9a-f]{6}", r.text).group(0)
    r = c.post(f"/push/fwtest/session/{sid}/apply", data={"confirm_target": "nope"})
    assert "Refused" in r.text
    r = c.post(f"/push/fwtest/session/{sid}/apply", data={"confirm_target": "fw-1"})
    assert "committed" in r.text and "Run rollback" in r.text
    r = c.post(f"/push/fwtest/session/{sid}/rollback", data={"confirm_target": "fw-1"})
    assert "rolled-back" in r.text
    audit = c.get("/audit/fwtest").text
    assert "CHG0009999" in audit and "eng1" in audit


class _IdentDevice:
    """Wraps FakeDevice and answers `show system info` like a real firewall."""

    def __init__(self, dev, hostname="FW-REPORTED", serial="SN-TEST-1"):
        self._dev, self.hostname, self.serial = dev, hostname, serial

    def __getattr__(self, name):
        return getattr(self._dev, name)

    def op_xml(self, cmd):
        assert "<show><system><info>" in cmd  # identity read is read-only
        return ET.fromstring(f"<response status='success'><result><system><hostname>{self.hostname}</hostname>"
                             f"<serial>{self.serial}</serial><model>PA-VM</model></system></result></response>")


def test_gui_push_shows_and_requires_real_hostname(tmp_path, monkeypatch, fwtest):
    prof, cs, dev = fwtest
    import panlab.web.app as web

    idev = _IdentDevice(dev)
    c = _client(tmp_path, monkeypatch)
    monkeypatch.setattr(web, "device_factory", lambda p, t: idev)
    _login(c, "eng1", "pw-eng")
    assert "fw-1 · hostname unknown · SN unknown" in c.get("/push/fwtest/cs-test").text  # never read yet: says so
    r = c.post("/push/fwtest/cs-test/prepare", data={"cr": "CHG0009999", "approved": "yes", "target": "fw-1"})
    assert "<b>FW-REPORTED</b> · SN <code>SN-TEST-1</code> <span style='color:#777;font-size:12px'>fw-1</span>" in r.text and "<h2>Customer: fwtest</h2>" in r.text
    assert "the hostname the device reports, <code>FW-REPORTED</code>" in r.text
    sid = re.search(r"push-\d{8}-\d{6}-[0-9a-f]{6}", r.text).group(0)
    assert "FW-REPORTED · SN SN-TEST-1 [fw-1]" in c.get("/push/fwtest/cs-test").text  # cached for the form
    assert "- FW-REPORTED · SN SN-TEST-1 [fw-1] (firewall)" in c.get("/changesets/fwtest/cs-test/changeplan.md").text
    r = c.post(f"/push/fwtest/session/{sid}/apply", data={"confirm_target": "fw-1"})
    assert "Refused" in r.text and "committed" not in r.text  # profile name is not enough
    idev.serial = "SN-OTHER"
    r = c.post(f"/push/fwtest/session/{sid}/apply", data={"confirm_target": "FW-REPORTED"})
    assert "a different device answered" in r.text and not dev.jobs
    idev.serial = "SN-TEST-1"
    r = c.post(f"/push/fwtest/session/{sid}/apply", data={"confirm_target": "FW-REPORTED"})
    assert "committed" in r.text
    audit = c.get("/audit/fwtest").text
    assert "FW-REPORTED · SN SN-TEST-1" in audit and "device-identity (prepare)" in audit
    rep = (prof.data_dir("push") / f"{sid}-report.md").read_text()
    assert "Device (as it reported itself): FW-REPORTED · SN SN-TEST-1 [fw-1]" in rep
