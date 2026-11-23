"""URL filter self-service: validation, diff, stale detection, change plan, push gating, scope. Fake devices only."""
from __future__ import annotations

import copy
import re
import xml.etree.ElementTree as ET

import pytest

from panlab import urlfilter as uf
from panlab.customers import load_profile
from panlab.web import auth

CATS = ["gambling", "malware", "news", "phishing", "private-ip-addresses", "shopping", "unknown"]
SEG = re.compile(r"^([\w-]+)(?:\[@name='([^']*)'\])?$")


class FakeUrlDevice:
    """Candidate + running XML trees; ``edit`` replaces the node at an xpath, ``commit`` copies candidate to running."""

    def __init__(self, cats=CATS, kind="panorama"):
        self.cats, self.kind = list(cats), kind
        self.cand = ET.fromstring("<config/>")
        self.run = copy.deepcopy(self.cand)
        self.pending, self.commits, self.commit_alls, self.writes = False, [], [], []
        self.fail_commit = False

    def _walk(self, root, xpath, create=False):
        node = root
        segs = [s for s in xpath.split("/") if s][1:]  # drop 'config'
        for s in segs:
            tag, name = SEG.match(s).groups()
            nxt = next((c for c in node if c.tag == tag and (name is None or c.get("name") == name)), None)
            if nxt is None:
                if not create:
                    return None, None
                nxt = ET.SubElement(node, tag, {"name": name} if name else {})
            parent, node = node, nxt
        return parent, node

    def show(self, xpath):
        return copy.deepcopy(self._walk(self.run, xpath)[1])

    def predefined_categories(self):
        return list(self.cats)

    def edit(self, xpath, element):
        self.writes.append(("edit", xpath))
        parent, node = self._walk(self.cand, xpath, create=True)
        idx = list(parent).index(node)
        parent.remove(node)
        parent.insert(idx, ET.fromstring(element))

    def delete(self, xpath):
        self.writes.append(("delete", xpath))
        parent, node = self._walk(self.cand, xpath)
        if node is not None:
            parent.remove(node)

    def pending_changes(self):
        return self.pending

    def revert(self):
        self.cand = copy.deepcopy(self.run)

    def commit(self, description):
        self.commits.append(description)
        if self.fail_commit:
            return {"jobid": 9, "success": False, "messages": ["validation error"]}
        self.run = copy.deepcopy(self.cand)
        return {"jobid": len(self.commits), "success": True}

    def commit_all(self, cmd):
        self.commit_alls.append(cmd)
        return {"jobid": 100 + len(self.commit_alls), "success": True}

    def pushed_policy(self):  # firewall view: what Panorama last pushed for the DG
        return copy.deepcopy(self.run)

    def set_live(self, xpath, element):  # someone else changes the device outside the tool
        self.edit(xpath, element)
        self.commit("outside change")


@pytest.fixture
def env(tmp_path, monkeypatch):
    d = tmp_path / "customers"
    for cust, extra in (("acme", "allow_live_panorama_push: true\n"), ("globex", "")):
        (d / cust).mkdir(parents=True)
        (d / cust / "profile.yaml").write_text(
            f"name: {cust}\ntargets:\n  - {{name: pano, type: panorama, host_env: X_H, api_key_env: X_K}}\n"
            "  - {name: fw1, type: firewall, host_env: Y_H, api_key_env: Y_K}\n" + extra
            + "url_filter:\n  target: pano\n  device_group: DG-EDGE\n  verify_targets: [fw1]\n")
    monkeypatch.setenv("PANLAB_CUSTOMERS_DIR", str(d))
    monkeypatch.setenv("PANLAB_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PANLAB_CUSTOMER_OVERRIDE_DIR", str(tmp_path / "none"))
    return tmp_path


def _ctx(name="acme"):
    prof = load_profile(name)
    return prof, uf.config_for(prof)


# ---------------------------------------------------------------- pure parts

def test_config_defaults_and_validation(env):
    prof, cfg = _ctx()
    assert (cfg.profile, cfg.allow_category, cfg.block_category) == ("URL-acme", "URL-acme-ALLOW", "URL-acme-BLOCK")
    assert cfg.backend == "panorama" and cfg.profile_xpath().endswith("device-group/entry[@name='DG-EDGE']/profiles/url-filtering/entry[@name='URL-acme']")
    assert uf.live_allowed(prof, cfg) and not uf.live_allowed(*_ctx("globex"))
    prof.url_filter = {"target": "nope"}
    with pytest.raises(uf.UrlFilterError):
        uf.config_for(prof)
    prof.url_filter = {"target": "pano"}  # Panorama needs a device group
    with pytest.raises(uf.UrlFilterError):
        uf.config_for(prof)
    prof.url_filter = {}
    assert uf.config_for(prof) is None


@pytest.mark.parametrize("raw,ok", [("Example.com", "example.com"), ("*.example.com", "*.example.com"), ("example.com/path/x", "example.com/path/x"),
                                    ("10.1.2.3", "10.1.2.3"), ("http://example.com", None), ("example.com:8443", None), ("*.com", None),
                                    ("*", None), ("bad site.com", None), ("10.1.2.300", None), ("localhost", None)])
def test_custom_url_validation(raw, ok):
    v, why = uf.check_url(raw)
    assert v == ok and (why is None) == (ok is not None)


def test_recommendations_follow_pa_best_practice():
    for c in ("command-and-control", "malware", "phishing", "grayware", "dynamic-dns", "unknown", "parked",
              "newly-registered-domain", "copyright-infringement", "extremism", "proxy-avoidance-and-anonymizers"):
        assert uf.recommended(c) == "block"
    assert uf.recommended("news") == uf.recommended("gambling") == uf.recommended("high-risk") == "alert"
    assert uf.risk_group("gambling").startswith("Consider") and uf.risk_group("malware").startswith("Palo Alto")
    assert uf.risk_group("AI-code-assistant") == "Artificial intelligence"  # PAN-OS 11.1 spells the AI ids in capitals
    assert len(uf.CATALOG) == 90


def test_read_live_missing_profile_is_all_allow_and_rows_sorted_by_risk(env):
    _, cfg = _ctx()
    st = uf.read_live(FakeUrlDevice(), cfg)
    assert not st["exists"] and set(st["actions"].values()) == {"allow"}
    rows = uf.rows(st)
    assert [r["id"] for r in rows[:3]] == ["malware", "phishing", "unknown"]  # block-recommended first


def test_request_stores_only_real_changes_and_flags_deviations(env):
    prof, cfg = _ctx()
    st = uf.read_live(FakeUrlDevice(), cfg)
    with pytest.raises(uf.UrlFilterError, match="nothing to change"):
        uf.create_request(prof, cfg, st, actor="req1", desired={c: "allow" for c in CATS})
    with pytest.raises(uf.UrlFilterError, match="both"):
        uf.create_request(prof, cfg, st, actor="req1", desired={}, allow_add=["a.example.com"], block_add=["a.example.com"])
    with pytest.raises(uf.UrlFilterError, match="action"):
        uf.create_request(prof, cfg, st, actor="req1", desired={"news": "drop"})
    r = uf.create_request(prof, cfg, st, actor="req1", desired={"gambling": "block", "news": "allow", "malware": "alert"},
                          block_add=["blocked.example.com"], allow_add=["partner.example.com"], notes="ticket 1")
    assert r["status"] == "pending" and set(r["changes"]) == {"gambling", "malware"}
    assert r["changes"]["malware"] == {"from": "allow", "to": "alert"}
    dev = uf.deviations(r)
    assert any("malware" in d and "weaker" in d for d in dev) and any("gambling" in d for d in dev)
    assert any("partner.example.com" in d for d in dev)
    assert uf.load(prof, r["id"])["requester"] == "req1"
    assert (prof.data_dir("urlfilter") / f"{r['id']}.json").stat().st_mode & 0o777 == 0o600


# ---------------------------------------------------------------- review, stale, plan, push

def _first_push(prof, cfg, pano, fw):
    st = uf.read_live(pano, cfg)
    r = uf.create_request(prof, cfg, st, actor="req1", desired={"gambling": "block", "malware": "block", "news": "alert"},
                          block_add=["blocked.example.com"])
    uf.approve(prof, cfg, r, pano, actor="appr", cr="CHG0001234", comment="ok")
    return uf.push(prof, cfg, r, pano, actor="appr", confirm_target="pano", verify_devs={"fw1": fw})


def test_self_approval_cr_format_and_reject_need_a_reason(env):
    prof, cfg = _ctx()
    pano = FakeUrlDevice()
    r = uf.create_request(prof, cfg, uf.read_live(pano, cfg), actor="req1", desired={"gambling": "block"})
    with pytest.raises(uf.UrlFilterError, match="own request"):
        uf.approve(prof, cfg, r, pano, actor="req1", cr="CHG0001234")
    with pytest.raises(Exception, match="CR"):
        uf.approve(prof, cfg, r, pano, actor="appr", cr="not-a-cr")
    with pytest.raises(uf.UrlFilterError, match="why"):
        uf.reject(prof, r, actor="appr", comment=" ")
    uf.reject(prof, r, actor="appr", comment="use the block list instead")
    assert uf.load(prof, r["id"])["status"] == "rejected" and not pano.writes


def test_stale_request_must_be_re_reviewed(env):
    prof, cfg = _ctx()
    pano = FakeUrlDevice()
    r = uf.create_request(prof, cfg, uf.read_live(pano, cfg), actor="req1", desired={"gambling": "block", "news": "alert"})
    pano.set_live(cfg.profile_xpath(), '<entry name="URL-acme"><block><member>gambling</member></block></entry>')  # changed outside
    with pytest.raises(uf.StaleError):
        uf.approve(prof, cfg, r, pano, actor="appr", cr="CHG0001234")
    assert uf.load(prof, r["id"])["status"] == "stale"
    uf.rebase(prof, r, uf.read_live(pano, cfg), actor="appr")
    assert r["status"] == "pending" and set(r["changes"]) == {"news"}  # gambling is already block
    uf.approve(prof, cfg, r, pano, actor="appr", cr="CHG0001234")
    assert r["status"] == "approved"
    pano.set_live(cfg.profile_xpath(), '<entry name="URL-acme"><alert><member>gambling</member></alert></entry>')  # changed after approval
    with pytest.raises(uf.StaleError):
        uf.push(prof, cfg, r, pano, actor="appr", confirm_target="pano")
    assert r["status"] == "stale" and pano.commits == ["outside change", "outside change"]


def test_change_plan_has_cr_sections_cli_and_api(env):
    prof, cfg = _ctx()
    pano = FakeUrlDevice()
    r = uf.create_request(prof, cfg, uf.read_live(pano, cfg), actor="req1", desired={"gambling": "block"}, block_add=["blocked.example.com"])
    uf.approve(prof, cfg, r, pano, actor="appr", cr="CHG0001234")
    md = r["plan_md"]
    for s in ("# URL filter change: URL-acme (acme)", "- CR: CHG0001234", "## Implementation Plan", "## Verification", "## Backout Plan",
              "set device-group DG-EDGE profiles url-filtering URL-acme block [ gambling ]",
              'set device-group DG-EDGE profiles custom-url-category URL-acme-BLOCK type "URL List" list [ blocked.example.com ]',
              "type=commit&action=all", "does not exist yet"):
        assert s in md, s
    assert [o["what"] for o in r["ops"]][0].startswith("custom URL category") and r["ops"][-1]["what"].startswith("URL Filtering profile")
    assert not pano.writes  # approving writes nothing


def test_dry_run_customer_cannot_push(env):
    prof, cfg = _ctx("globex")
    pano = FakeUrlDevice()
    r = uf.create_request(prof, cfg, uf.read_live(pano, cfg), actor="req1", desired={"gambling": "block"})
    uf.approve(prof, cfg, r, pano, actor="appr", cr="CHG0001234")
    assert r["mode"] == "dry-run" and "## Implementation Plan" in r["plan_md"]
    with pytest.raises(uf.UrlFilterError, match="dry-run"):
        uf.push(prof, cfg, r, pano, actor="appr", confirm_target="pano")
    assert not pano.writes and not pano.commits


def test_push_commits_pushes_dg_verifies_and_rolls_back(env):
    prof, cfg = _ctx()
    pano, fw = FakeUrlDevice(), FakeUrlDevice(kind="firewall")
    fw.pushed_policy = lambda: copy.deepcopy(pano.run)  # the firewall sees what Panorama pushed
    r = _first_push(prof, cfg, pano, fw)
    assert r["status"] == "pushed", r.get("result")
    assert all(v["ok"] for v in r["verify"]) and len(r["verify"]) == 2
    assert pano.commits[0].startswith("panlab CHG0001234 urlfilter") and 'entry name="DG-EDGE"' in pano.commit_alls[0]
    live = uf.read_live(pano, cfg)
    assert live["actions"]["gambling"] == "block" and live["actions"]["news"] == "alert" and live["actions"]["shopping"] == "allow"
    assert live["custom"]["block"]["urls"] == ["blocked.example.com"] and live["custom_actions"]["block"] == "block"
    # second request edits the existing profile and keeps unmanaged settings
    el = pano.show(cfg.profile_xpath())
    ET.SubElement(el, "log-http-hdr-xff").text = "yes"
    pano.set_live(cfg.profile_xpath(), ET.tostring(el).decode())
    r2 = uf.create_request(prof, cfg, uf.read_live(pano, cfg), actor="req1", desired={"shopping": "continue"},
                           block_remove=["blocked.example.com"])
    uf.approve(prof, cfg, r2, pano, actor="appr", cr="CHG0001235")
    with pytest.raises(uf.UrlFilterError, match="typed target"):
        uf.push(prof, cfg, r2, pano, actor="appr", confirm_target="fw1")
    uf.push(prof, cfg, r2, pano, actor="appr", confirm_target="pano", verify_devs={"fw1": fw})
    assert r2["status"] == "pushed", r2.get("result")
    after = pano.show(cfg.profile_xpath())
    assert after.findtext("log-http-hdr-xff") == "yes" and pano.show(cfg.custom_xpath(cfg.block_category)) is None
    uf.rollback(prof, cfg, r2, pano, actor="appr", confirm_target="pano", verify_devs={"fw1": fw})
    assert r2["status"] == "rolled-back", r2.get("rollback_result")
    r2["status"] = "pushing"  # another click while a push runs
    with pytest.raises(uf.UrlFilterError):
        uf.push(prof, cfg, r2, pano, actor="appr", confirm_target="pano")
    with pytest.raises(uf.UrlFilterError):
        uf.rollback(prof, cfg, r2, pano, actor="appr", confirm_target="pano")
    r2["status"] = "rolled-back"
    back = uf.read_live(pano, cfg)
    assert back["actions"]["shopping"] == "allow" and back["custom"]["block"]["urls"] == ["blocked.example.com"]
    acts = [a["action"] for a in __import__("panlab.pusher", fromlist=["x"]).read_audit(prof)]
    assert {"urlfilter_request", "urlfilter_approve", "urlfilter_push", "urlfilter_rollback"} <= set(acts)


def test_push_refuses_pending_changes_and_reverts_failed_commit(env):
    prof, cfg = _ctx()
    pano = FakeUrlDevice()
    r = uf.create_request(prof, cfg, uf.read_live(pano, cfg), actor="req1", desired={"gambling": "block"})
    uf.approve(prof, cfg, r, pano, actor="appr", cr="CHG0001234")
    pano.pending = True
    uf.push(prof, cfg, r, pano, actor="appr", confirm_target="pano")
    assert r["status"] == "failed" and "uncommitted" in r["result"] and not pano.writes
    r["status"], pano.pending, pano.fail_commit = "approved", False, True
    uf.push(prof, cfg, r, pano, actor="appr", confirm_target="pano")
    assert r["status"] == "failed" and "reverted" in r["result"] and uf.read_live(pano, cfg)["exists"] is False
    assert pano.show(cfg.profile_xpath()) is None and ET.tostring(pano.cand) == ET.tostring(pano.run)


def test_attachment_check(env):
    _, cfg = _ctx()
    pano = FakeUrlDevice()
    assert uf.attachment(pano, cfg) == {"groups": [], "rules": [], "attached": False}
    base = cfg.base
    pano.set_live(f"{base}/profile-group/entry[@name='PG-ACME']",
                  "<entry name='PG-ACME'><url-filtering><member>URL-acme</member></url-filtering></entry>")
    att = uf.attachment(pano, cfg)
    assert att["groups"] == ["PG-ACME"] and not att["attached"]
    pano.set_live(f"{base}/pre-rulebase/security/rules/entry[@name='R1']",
                  "<entry name='R1'><profile-setting><group><member>PG-ACME</member></group></profile-setting></entry>")
    pano.set_live(f"{base}/pre-rulebase/security/rules/entry[@name='R2']",
                  "<entry name='R2'><disabled>yes</disabled><profile-setting><group><member>PG-ACME</member></group></profile-setting></entry>")
    att = uf.attachment(pano, cfg)
    assert att["attached"] and att["rules"] == [{"rule": "R1", "rulebase": "pre-rulebase", "via": "PG-ACME"}]


# ---------------------------------------------------------------- web: permissions and scope

@pytest.fixture
def web(env, monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from panlab.web import urlfilter_routes as ur
    from panlab.web.app import app

    uf_file = env / "users.yaml"
    monkeypatch.setenv("PANLAB_USERS_FILE", str(uf_file))
    monkeypatch.setenv("PANLAB_USER_AUDIT_FILE", str(env / "ua.jsonl"))
    auth.add_user("boss", "admin", "pw-boss-123456", uf_file)
    auth.add_user("req-acme", "viewer", "pw-req-1234567", uf_file, permissions=["urlfilter_request"], customers=["acme"])
    auth.add_user("req-globex", "viewer", "pw-req-1234567", uf_file, permissions=["urlfilter_request"], customers=["globex"])
    auth.add_user("appr-acme", "viewer", "pw-app-1234567", uf_file, permissions=["urlfilter_approve"], customers=["acme"])
    auth.add_user("req-otherdg", "viewer", "pw-req-1234567", uf_file, permissions=["urlfilter_request"], customers=["acme"],
                  devices={"acme": ["dg:DG-OTHER"]})
    auth.add_user("plain", "viewer", "pw-pla-1234567", uf_file, permissions=["view", "fcr"], customers=["*"])
    devs = {"pano": FakeUrlDevice(), "fw1": FakeUrlDevice(kind="firewall")}
    devs["fw1"].pushed_policy = lambda: copy.deepcopy(devs["pano"].run)
    monkeypatch.setattr(ur, "device_factory", lambda prof, t: devs[t])

    def client(user, pw):
        c = TestClient(app)
        assert c.post("/login", data={"username": user, "password": pw}, follow_redirects=False).status_code == 303
        return c
    return client, devs


def test_web_request_approve_push_flow_and_scope(web):
    client, devs = web
    rq = client("req-acme", "pw-req-1234567")
    page = rq.get("/urlfilter?customer=acme").text
    assert "URL filter self-service" in page and "Request a change" in page and "Not attached" in page
    form = rq.get("/urlfilter/acme/new").text
    assert "cat__gambling" in form and "PA recommended" in form
    assert rq.get("/urlfilter/globex/new").status_code == 403  # other customer
    bad = rq.post("/urlfilter/acme/new", data={"cat__gambling": "block", "block_add": "http://x.example.com"}, follow_redirects=False)
    assert "Fix+the+site+list" in bad.headers["location"] or "Fix%20the%20site%20list" in bad.headers["location"]
    r = rq.post("/urlfilter/acme/new", data={"cat__gambling": "block", "cat__news": "alert", "block_add": "blocked.example.com"},
                follow_redirects=False)
    rid = r.headers["location"].rsplit("/", 1)[1]
    assert re.match(r"url-\d{8}-\d{6}-[0-9a-f]{6}$", rid)
    view = rq.get(f"/urlfilter/acme/{rid}").text
    assert "gambling" in view and "Approve" not in view  # requester cannot approve
    assert rq.post(f"/urlfilter/acme/{rid}/approve", data={"cr": "CHG0001234"}).status_code == 403
    assert client("req-globex", "pw-req-1234567").get(f"/urlfilter/acme/{rid}").status_code == 403
    other = client("req-globex", "pw-req-1234567").get("/urlfilter").text
    assert "<option selected>globex</option>" in other and "<option>acme</option>" not in other and rid not in other
    assert client("req-otherdg", "pw-req-1234567").get("/urlfilter/acme/new").status_code == 403  # device scope
    assert client("plain", "pw-pla-1234567").get("/urlfilter").status_code == 403
    ap = client("appr-acme", "pw-app-1234567")
    assert "Approve" in ap.get(f"/urlfilter/acme/{rid}").text
    assert ap.get("/urlfilter/acme/new").status_code == 403  # approver-only cannot file requests
    ap.post(f"/urlfilter/acme/{rid}/approve", data={"cr": "CHG0001234", "comment": "ok"})
    v = ap.get(f"/urlfilter/acme/{rid}").text
    assert "Push (live)" in v and "CR change plan" in v
    ap.post(f"/urlfilter/acme/{rid}/push", data={"confirm_target": "pano"})
    v = ap.get(f"/urlfilter/acme/{rid}").text
    assert ">pushed<" in v and "PASS" in v and devs["pano"].commit_alls
    md = ap.get(f"/urlfilter/acme/{rid}/changeplan.md")
    assert md.status_code == 200 and "## Backout Plan" in md.text


def test_nav_home_and_users_page_show_url_filter_permissions(web):
    client, _ = web
    boss = client("boss", "pw-boss-123456")
    assert "URL filter: request changes" in boss.get("/users").text and "URL filter: approve &amp; push" in boss.get("/users").text
    assert "href='/urlfilter'" in boss.get("/home").text
    plain = client("plain", "pw-pla-1234567").get("/home").text
    assert "href='/urlfilter'" not in plain
    assert auth.Principal("boss", auth.load_users()["boss"]).can("urlfilter_approve")


def test_xapi_jobs_are_polled_until_finished(monkeypatch):
    """A slow commit-all (busy Panorama) is waited for by job id instead of being reported as failed."""
    monkeypatch.setattr(uf, "POLL_SECONDS", 0)

    class X:
        def __init__(self):
            self.polls, self.element_result, self.cmds = 0, None, []

        def commit(self, cmd, action=None):
            self.cmds.append((action, cmd))
            self.element_result = ET.fromstring("<result><job>59</job></result>")

        def op(self, cmd):
            self.polls += 1
            st = "FIN" if self.polls >= 3 else "ACT"
            self.element_result = ET.fromstring(f"<result><job><id>59</id><status>{st}</status><result>{'OK' if st == 'FIN' else 'PEND'}</result>"
                                                "<details><line>Push succeeded</line></details></job></result>")

    class D:
        fw = type("F", (), {"xapi": X()})()

    dev = uf.XapiUrlDevice(D())
    r = dev.commit_all(uf.commit_all_cmd(uf.Config(target="p", backend="panorama", device_group="DG-EDGE", profile="URL-a")))
    assert r == {"jobid": 59, "success": True, "messages": ["Push succeeded"]} and dev.x.polls == 3 and dev.x.cmds[0][0] == "all"
    dev.x.polls = 0
    assert dev.commit("panlab CHG1 <x>")["success"] and "&lt;x&gt;" in dev.x.cmds[1][1]
