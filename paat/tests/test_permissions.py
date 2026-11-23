"""Per-user permission checkboxes and customer/device scope (MSP/NOC model). Fake devices only."""

from __future__ import annotations

import pytest
import yaml

from fake_panos import FakeBox, factory_for
from panlab.upgrade import device as devmod
from panlab.web import auth

AV = ["11.1.6-h7", "11.1.6-h32", "11.1.13", "11.1.13-h9", "11.1.13-h17"]


# ---------------------------------------------------------------- model + migration

def test_role_records_map_to_the_same_access_and_migrate_losslessly(tmp_path):
    uf = tmp_path / "users.yaml"
    for r in auth.ROLES:
        auth.add_user(f"u-{r}", r, f"pw-{r}-123456", uf)
    before = {n: (auth.Principal(n, u).perms, auth.Principal(n, u)[1]) for n, u in auth.load_users(uf).items()}
    assert before["u-viewer"][0] == {"view"}
    assert before["u-prep"][0] == {"view", "fcr", "upgrade_plan", "upgrade_panorama"}
    assert before["u-engineer"][0] == before["u-prep"][0] | {"push", "upgrade_exec"}
    assert before["u-admin"][0] == set(auth.PERMS)
    done = auth.migrate_roles(uf)
    assert sorted(n for n, _, _ in done) == sorted(before)
    after = {n: (auth.Principal(n, u).perms, auth.Principal(n, u)[1]) for n, u in auth.load_users(uf).items()}
    assert after == before  # nobody gained or lost anything; labels still match the old role
    raw = yaml.safe_load(uf.read_text())["users"]
    assert raw["u-prep"]["customers"] == ["*"] and raw["u-prep"]["migrated_from_role"] == "prep" and "role" not in raw["u-prep"]
    assert auth.migrate_roles(uf) == []  # idempotent
    assert (uf.stat().st_mode & 0o777) == 0o600


def test_legacy_has_role_maps_to_permissions():
    p = auth.Principal("x", {"permissions": ["view", "upgrade_exec"], "customers": ["a"]})
    assert auth.has_role(p, "viewer") and not auth.has_role(p, "prep") and not auth.has_role(p, "engineer")
    assert p[1] == "custom" and p.sees_customer("a") and not p.sees_customer("b")
    assert auth.Principal("y", {"permissions": ["view"], "customers": []}).customers == []  # empty = none, not all


def test_device_scope_matching():
    pats = ["FW-A", "dg:DG-East", "0007001"]
    assert auth.device_in_scope(None, target="anything")
    assert auth.device_in_scope(pats, hostname="fw-a")
    assert auth.device_in_scope(pats, serial="0007001")
    assert auth.device_in_scope(pats, device_groups=["DG-East"])
    assert not auth.device_in_scope(pats, hostname="FW-B", serial="9", device_groups=["DG-West"])


# ---------------------------------------------------------------- web fixtures

@pytest.fixture
def msp(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from panlab.web.app import app

    for cust, prof in (("acme", "name: acme\ntargets:\n  - {name: pano, type: panorama, host_env: X_H, api_key_env: X_K}\n"),
                       ("globex", "name: globex\ntargets:\n  - {name: gfw, type: firewall, host_env: G_H, api_key_env: G_K}\n")):
        d = tmp_path / "customers" / cust
        d.mkdir(parents=True)
        (d / "profile.yaml").write_text(prof)
    monkeypatch.setenv("PANLAB_CUSTOMERS_DIR", str(tmp_path / "customers"))
    monkeypatch.setenv("PANLAB_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PANLAB_UPGRADE_REFERENCE", str(tmp_path / "none.yaml"))
    monkeypatch.setenv("PANLAB_USER_AUDIT_FILE", str(tmp_path / "user-audit.jsonl"))
    pano = FakeBox("ACME-PANO", kind="panorama", version="11.1.13-h9", serial="P100", versions=AV)
    fa = FakeBox("ACME-FW-A", version="11.1.6-h7", serial="F100", versions=AV)
    fb = FakeBox("ACME-FW-B", version="11.1.6-h7", serial="F200", versions=AV)
    pano.managed = [fa, fb]
    pano.dgs = {"DG-East": ["F100"], "DG-West": ["F200"]}
    gfw = FakeBox("GLOBEX-FW", version="11.1.6-h7", serial="G100", versions=AV)
    monkeypatch.setattr(devmod, "device_factory", factory_for({"pano": pano, "gfw": gfw}))
    uf = tmp_path / "users.yaml"
    monkeypatch.setenv("PANLAB_USERS_FILE", str(uf))
    auth.add_user("boss", "admin", "pw-boss-123456", uf)
    auth.add_user("eng", "engineer", "pw-eng-1234567", uf)
    # NOC tech: upgrades only, ACME only, only firewalls in DG-East; may not touch Panorama
    auth.add_user("noc", "viewer", "pw-noc-1234567", uf, permissions=["upgrade_plan", "upgrade_exec"],
                  customers=["acme"], devices={"acme": ["dg:DG-East"]})
    # customer self-service: view + FCRs for globex only
    auth.add_user("gcust", "viewer", "pw-gcust-123456", uf, permissions=["view", "fcr"], customers=["globex"])
    # a limited user admin for acme
    auth.add_user("acmeadm", "viewer", "pw-acmeadm-12345", uf, permissions=["view", "user_admin", "upgrade_plan"],
                  customers=["acme"])
    c = TestClient(app)
    return c, {"pano": pano, "fa": fa, "fb": fb, "gfw": gfw}


def login(c, u, pw):
    r = c.post("/login", data={"username": u, "password": pw}, follow_redirects=False)
    assert r.status_code == 303 and "Wrong" not in r.headers["location"], r.headers
    return r


def audit_lines():
    return auth.read_user_audit()


# ---------------------------------------------------------------- cross-customer denial

def test_customer_scope_hides_and_refuses_other_customers(msp):
    c, dev = msp
    login(c, "gcust", "pw-gcust-123456")
    r = c.get("/")
    assert r.status_code == 200 and "globex" in r.text and "acme" not in r.text  # FCR customer list scoped
    assert "OS upgrades" not in r.text  # no upgrade permission: no nav link
    assert c.get("/upgrade").status_code == 403
    assert c.get("/backups?customer=acme").status_code == 403
    assert c.get("/changesets/acme/whatever").status_code == 403
    assert c.get("/changesets/acme/whatever/changeplan").status_code == 403
    assert c.get("/push/acme/whatever").status_code == 403
    assert c.get("/audit/acme").status_code == 403
    r = c.post("/decom", data={"customer": "acme", "items": "10.0.0.1"})
    assert r.status_code == 403
    r = c.post("/backups/offline", data={"name": "newco"}, files={"file": ("x.xml", b"<config/>")})
    assert r.status_code == 403  # creating a customer needs all customers
    assert c.get("/users").status_code == 403 and c.get("/admin/backup-destinations").status_code == 403


def test_noc_upgrade_scope_device_groups_and_panorama(msp, monkeypatch):
    c, dev = msp
    login(c, "noc", "pw-noc-1234567")
    r = c.get("/", follow_redirects=False)
    assert r.headers["location"] == "/upgrade"  # lands on the area it may use
    r = c.get("/upgrade")
    assert "acme" in r.text and "globex" not in r.text
    assert c.post("/upgrade/discover", data={"customer": "globex"}).status_code == 403
    r = c.post("/upgrade/discover", data={"customer": "acme", "refresh": "yes"}, follow_redirects=False)
    disc = r.headers["location"]
    page = c.get(disc).text
    assert "ACME-FW-A" in page and "ACME-FW-B" not in page and "1 device(s) outside your scope are hidden" in page
    assert "read-only for you" in page and "value='t:pano'" not in page  # Panorama shown, not selectable
    r = c.post(disc + "/plan", data={"pick": ["m:pano:F200"], "v::m:pano:F200": "11.1.13-h9"})
    assert r.status_code == 403  # out-of-scope firewall refused server-side
    r = c.post(disc + "/plan", data={"pick": ["t:pano"], "v::t:pano": "11.1.13-h17"})
    assert r.status_code == 403  # Panorama needs upgrade_panorama
    r = c.post(disc + "/plan", data={"pick": ["m:pano:F100"], "v::m:pano:F100": "11.1.6-h32"}, follow_redirects=False)
    assert r.status_code == 303
    mine = r.headers["location"]
    assert c.get(mine).status_code == 200
    # a plan someone else built that includes Panorama and FW-B is invisible and refused for noc
    c2 = msp[0].__class__(c.app)
    login(c2, "eng", "pw-eng-1234567")
    r = c2.post(disc + "/plan", data={"pick": ["t:pano", "m:pano:F200"], "v::t:pano": "11.1.13-h17",
                                      "v::m:pano:F200": "11.1.6-h32"}, follow_redirects=False)
    theirs = r.headers["location"]
    assert c2.get(theirs).status_code == 200
    assert c.get(theirs).status_code == 403
    assert c.post(theirs + "/arm", data={"cr": "CHG1", "approved": "yes", "ack": "yes"}).status_code == 403
    assert c.get(theirs + "/changeplan.md").status_code == 403
    assert c.post(theirs.replace("/plan/", "/run/") + "/next", data={"confirm": "x"}).status_code == 403
    home = c.get("/upgrade?customer=acme").text
    assert mine.rsplit("/", 1)[-1] in home and theirs.rsplit("/", 1)[-1] not in home
    assert not dev["pano"].writes and not dev["fa"].writes and not dev["fb"].writes


def test_noc_can_execute_in_scope_plan(msp, monkeypatch):
    c, dev = msp
    monkeypatch.setenv("PANLAB_UPGRADE_EXECUTE", "1")
    login(c, "noc", "pw-noc-1234567")
    disc = c.post("/upgrade/discover", data={"customer": "acme"}, follow_redirects=False).headers["location"]
    plan = c.post(disc + "/plan", data={"pick": ["m:pano:F100"], "v::m:pano:F100": "11.1.6-h32"},
                  follow_redirects=False).headers["location"]
    r = c.post(plan + "/arm", data={"cr": "CHG0001234", "approved": "yes", "ack": "yes"})
    assert r.status_code == 200 and "Live upgrade" in r.text


# ---------------------------------------------------------------- escalation

def test_limited_user_admin_cannot_escalate(msp):
    c, _ = msp
    login(c, "acmeadm", "pw-acmeadm-12345")
    page = c.get("/users").text
    assert "value='push' " in page and "disabled" in page  # cannot tick what it does not hold
    # grant itself or someone a permission it lacks
    r = c.post("/users/access", data={"username": "noc", "perm": ["upgrade_plan", "push"], "customer": ["acme"]})
    assert r.status_code == 403
    # widen to another customer / all customers
    r = c.post("/users/access", data={"username": "noc", "perm": ["upgrade_plan"], "customer": ["acme", "globex"]})
    assert r.status_code == 403
    r = c.post("/users/access", data={"username": "acmeadm", "perm": ["view", "user_admin", "upgrade_plan"], "customer": ["*"]})
    assert r.status_code == 403
    # touch a more powerful user: edit, reset password, disable, delete
    assert c.post("/users/access", data={"username": "eng", "perm": ["view"], "customer": ["acme"]}).status_code == 403
    assert c.post("/users/reset", data={"username": "boss", "action": "generate"}).status_code == 403
    assert c.post("/users/disable", data={"username": "boss"}).status_code == 403
    assert c.post("/users/delete", data={"username": "eng"}).status_code == 403
    # create a user with more than it has
    assert c.post("/users/add", data={"username": "x1", "perm": ["push"], "customer": ["acme"]}).status_code == 403
    denied = [a for a in audit_lines() if a.get("result") == "denied"]
    assert len(denied) >= 8 and all(a["actor"] == "acmeadm" for a in denied)
    # what it holds, it may grant
    # (noc holds upgrade_exec, which acmeadm lacks, so acmeadm cannot edit noc at all)
    assert c.post("/users/access", data={"username": "noc", "perm": ["upgrade_plan"], "customer": ["acme"]}).status_code == 403
    r = c.post("/users/add", data={"username": "t2", "perm": ["view", "upgrade_plan"], "customer": ["acme"], "must_change": "yes"})
    assert r.status_code == 200 and "User t2 added" in r.text
    r = c.post("/users/access", data={"username": "t2", "perm": ["upgrade_plan"], "customer": ["acme"],
                                      "devices_acme": "ACME-FW-A\nF100"})
    assert r.status_code == 200 and "Saved permissions for t2" in r.text
    rec = auth.load_users()["t2"]
    assert rec["permissions"] == ["upgrade_plan"] and rec["devices"] == {"acme": ["ACME-FW-A", "F100"]}
    ok = [a for a in audit_lines() if a["action"] == "permissions_change" and a["result"] == "ok"][-1]
    assert ok["before"]["permissions"] == ["upgrade_plan", "view"] and ok["after"]["permissions"] == ["upgrade_plan"]
    assert "hash" not in str(ok) and "pw-" not in str(audit_lines())


def test_non_admin_cannot_reach_user_admin_routes(msp):
    c, _ = msp
    login(c, "eng", "pw-eng-1234567")
    for url, data in (("/users/access", {"username": "eng", "perm": list(auth.PERMS), "customer": ["*"]}),
                      ("/users/add", {"username": "evil", "perm": list(auth.PERMS), "customer": ["*"]}),
                      ("/users/delete", {"username": "boss"}), ("/users/disable", {"username": "boss"}),
                      ("/users/reset", {"username": "boss", "action": "generate"})):
        assert c.post(url, data=data).status_code == 403, url
    assert "user_admin" not in auth.effective_perms(auth.load_users()["eng"])
    assert "evil" not in auth.load_users()


# ---------------------------------------------------------------- users page lifecycle

def test_admin_creates_user_forced_change_disable_delete_and_guards(msp):
    c, _ = msp
    login(c, "boss", "pw-boss-123456")
    r = c.post("/users/add", data={"username": "night1", "new_password": "initial-pass-123", "confirm": "initial-pass-123",
                                   "must_change": "yes", "perm": ["upgrade_plan", "upgrade_exec"], "customer": ["acme"],
                                   "devices_acme": "dg:DG-East"})
    assert r.status_code == 200 and "User night1 added" in r.text and "initial-pass-123" not in r.text
    rec = auth.load_users()["night1"]
    assert rec["permissions"] == ["upgrade_exec", "upgrade_plan"] and rec["customers"] == ["acme"]
    assert rec["must_change_password"] is True
    r = c.post("/users/add", data={"username": "gen1", "perm": ["view"], "customer": ["globex"], "must_change": "yes"})
    assert "Temporary password for gen1" in r.text
    # forced change on first login
    n = c.__class__(c.app)
    login(n, "night1", "initial-pass-123")
    r = n.get("/upgrade", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/password")
    r = n.post("/password", data={"current": "initial-pass-123", "new_password": "my-own-pass-1234", "confirm": "my-own-pass-1234"})
    assert "Password changed" in r.text
    assert n.get("/upgrade").status_code == 200
    # admin reset forces a change again
    c.post("/users/reset", data={"username": "night1", "action": "generate"})
    assert auth.load_users()["night1"]["must_change_password"] is True
    # disable: login and existing session refused; enable again
    assert c.post("/users/disable", data={"username": "night1"}).status_code == 200
    assert n.get("/upgrade", follow_redirects=False).status_code == 303
    r = n.post("/login", data={"username": "night1", "password": "my-own-pass-1234"}, follow_redirects=False)
    assert "Wrong" in r.headers["location"]
    assert c.post("/users/enable", data={"username": "night1"}).status_code == 200
    # self and last-admin guards
    assert c.post("/users/delete", data={"username": "boss"}).status_code == 403
    assert c.post("/users/disable", data={"username": "boss"}).status_code == 403
    assert c.post("/users/access", data={"username": "boss", "perm": ["view"], "customer": ["*"]}).status_code == 403
    # acmeadm is also a user admin, but boss is the last one with everything; deleting acmeadm is fine
    assert c.post("/users/delete", data={"username": "acmeadm"}).status_code == 200
    assert "acmeadm" not in auth.load_users()
    # now boss is the only user admin: a second admin cannot remove boss's user_admin either
    c.post("/users/access", data={"username": "eng", "perm": sorted(auth.PERMS), "customer": ["*"]})
    e2 = c.__class__(c.app)
    login(e2, "eng", "pw-eng-1234567")
    assert e2.post("/users/delete", data={"username": "boss"}).status_code == 200  # two admins: allowed
    assert e2.post("/users/access", data={"username": "eng", "perm": ["view"], "customer": ["*"]}).status_code == 403  # self-demote
    acts = {(a["action"], a["result"]) for a in audit_lines()}
    for want in (("user_add", "ok"), ("user_disable", "ok"), ("user_enable", "ok"), ("user_delete", "ok"),
                 ("user_delete", "denied"), ("permissions_change", "ok"), ("password_reset", "ok")):
        assert want in acts, want


def test_last_admin_cannot_be_deleted_by_another_admin(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from panlab.web.app import app
    uf = tmp_path / "users.yaml"
    monkeypatch.setenv("PANLAB_USERS_FILE", str(uf))
    monkeypatch.setenv("PANLAB_USER_AUDIT_FILE", str(tmp_path / "a.jsonl"))
    monkeypatch.setenv("PANLAB_CUSTOMERS_DIR", str(tmp_path / "customers"))
    auth.add_user("a1", "admin", "pw-a1-123456789", uf)
    auth.add_user("a2", "admin", "pw-a2-123456789", uf)
    c = TestClient(app)
    login(c, "a1", "pw-a1-123456789")
    assert c.post("/users/disable", data={"username": "a2"}).status_code == 200
    # a2 is disabled, so a1 is the last enabled admin; a1 cannot demote itself
    assert c.post("/users/access", data={"username": "a1", "perm": ["view"], "customer": ["*"]}).status_code == 403


def test_push_target_device_scope(monkeypatch):
    pytest.importorskip("fastapi")
    from types import SimpleNamespace

    from panlab import identity
    import panlab.web.app as web
    monkeypatch.setattr(identity, "cached", lambda prof, t: {"fw1": {"hostname": "EDGE-1", "serial": "S1"}}.get(t))
    prof = SimpleNamespace(name="acme")
    scoped = auth.Principal("n", {"permissions": ["push"], "customers": ["acme"], "devices": {"acme": ["EDGE-1"]}})
    free = auth.Principal("m", {"permissions": ["push"], "customers": ["acme"]})
    assert web._target_ok(scoped, prof, "fw1") and not web._target_ok(scoped, prof, "fw2")
    assert web._target_ok(free, prof, "fw2")


def test_cli_migrate_backs_up_and_keeps_access(tmp_path, monkeypatch, capsys):
    from panlab.cli import main
    uf = tmp_path / "users.yaml"
    monkeypatch.setenv("PANLAB_USER_AUDIT_FILE", str(tmp_path / "a.jsonl"))
    auth.add_user("p1", "prep", "pw-p1-123456789", uf)
    auth.add_user("a1", "admin", "pw-a1-123456789", uf)
    before = uf.read_text()
    assert main(["users", "migrate", "--users-file", str(uf)]) == 0
    baks = list(tmp_path.glob("users.yaml.bak-*"))
    assert len(baks) == 1 and baks[0].read_text() == before and (baks[0].stat().st_mode & 0o777) == 0o600
    out = capsys.readouterr().out
    assert "p1: role prep -> fcr upgrade_panorama upgrade_plan view" in out
    assert {a["target"] for a in auth.read_user_audit()} == {"p1", "a1"}
    assert auth.Principal("p1", auth.load_users(uf)["p1"])[1] == "prep"


# ---------------------------------------------------------------- EDL access for existing admins

def _pre_edl_admin_perms():
    return sorted(set(auth.PERMS) - auth.ADMIN_ADDED_PERMS)


def test_existing_platform_admins_get_edl_without_a_re_tick(tmp_path):
    """Checkbox lists saved before EDL (and before request/approve) still get EDL admin."""
    held = _pre_edl_admin_perms()
    assert "user_admin" in held and not set(auth.EDL_PERMS) & set(held)
    rec = {"permissions": held, "customers": ["*"], "devices": {}}
    got = auth.effective_perms(rec)
    assert auth.EDL_PERMS <= got
    assert set(held) <= got
    # request and approve stay as stored (not silently added)
    assert "request" not in got and "approve" not in got
    assert layers_label(rec) == "Platform admin"
    # a limited user admin must not gain EDL
    limited = {"permissions": ["view", "user_admin", "upgrade_plan"], "customers": ["acme"]}
    assert auth.EDL_PERMS.isdisjoint(auth.effective_perms(limited))
    assert not auth.is_legacy_platform_admin(frozenset(limited["permissions"]))


def layers_label(rec):
    from panlab.web import layers
    return layers.layer_label(auth.Principal("x", rec))


def test_grant_edl_to_admins_persists_only_edl_and_never_touches_passwords(tmp_path):
    uf = tmp_path / "users.yaml"
    auth.add_user("admin1", "admin", "pw-admin1-keep-me-12", uf, permissions=_pre_edl_admin_perms(), customers=["*"])
    auth.add_user("limited", "viewer", "pw-limited-12345", uf, permissions=["view", "user_admin"], customers=["acme"])
    auth.add_user("viewer1", "viewer", "pw-viewer-123456", uf)
    before = uf.read_text()
    hashes = {n: u["hash"] for n, u in auth.load_users(uf).items() if "hash" in u or True}
    # load_users strips nothing; hash is in the raw file
    import yaml
    raw = yaml.safe_load(before)["users"]
    hashes = {n: raw[n]["hash"] for n in raw}
    done = auth.grant_edl_to_admins(uf)
    assert done == ["admin1"]
    after = yaml.safe_load(uf.read_text())["users"]
    assert after["admin1"]["hash"] == hashes["admin1"]
    assert after["limited"]["hash"] == hashes["limited"]
    assert after["viewer1"]["hash"] == hashes["viewer1"]
    assert auth.EDL_PERMS <= set(after["admin1"]["permissions"])
    assert "user_admin" in after["admin1"]["permissions"]
    assert "edl_admin" not in after["limited"]["permissions"]
    assert "permissions" not in after["viewer1"]
    assert auth.grant_edl_to_admins(uf) == []  # idempotent
    assert {n: yaml.safe_load(uf.read_text())["users"][n]["hash"] for n in after} == hashes
    assert (uf.stat().st_mode & 0o777) == 0o600


def test_existing_admin_sees_edl_in_nav_and_home(msp):
    from panlab.web import layers
    uf = auth.users_file()
    auth.add_user("admin1-old", "viewer", "pw-admin1-old-1234", uf, permissions=_pre_edl_admin_perms(), customers=["*"])
    rec = auth.load_users(uf)["admin1-old"]
    assert auth.EDL_PERMS <= auth.effective_perms(rec)
    assert layers.layer_label(auth.Principal("admin1-old", rec)) == "Platform admin"
    from fastapi.testclient import TestClient
    from panlab.web.app import app
    c = TestClient(app)
    r = c.post("/login", data={"username": "admin1-old", "password": "pw-admin1-old-1234"}, follow_redirects=False)
    assert r.status_code == 303
    home = c.get("/home").text
    assert "External dynamic lists" in home
    assert "href='/edls'" in home
    assert "Operations" in home
    edl = c.get("/edls")
    assert edl.status_code == 200 and "External dynamic lists" in edl.text
    assert "href='/edls' class='cur'" in edl.text or "href='/edls'" in edl.text


def test_cli_grant_edl_admins_backs_up_and_leaves_passwords(tmp_path, monkeypatch, capsys):
    from panlab.cli import main
    import yaml
    uf = tmp_path / "users.yaml"
    monkeypatch.setenv("PANLAB_USER_AUDIT_FILE", str(tmp_path / "a.jsonl"))
    auth.add_user("admin1", "admin", "pw-admin1-keep-me-12", uf, permissions=_pre_edl_admin_perms(), customers=["*"])
    before = uf.read_text()
    hash_before = yaml.safe_load(before)["users"]["admin1"]["hash"]
    assert main(["users", "grant-edl-admins", "--users-file", str(uf)]) == 0
    baks = list(tmp_path.glob("users.yaml.bak-*"))
    assert len(baks) == 1 and baks[0].read_text() == before
    out = capsys.readouterr().out
    assert "admin1: granted edl_view edl_edit edl_approve edl_admin" in out
    assert "passwords unchanged" in out
    raw = yaml.safe_load(uf.read_text())["users"]["admin1"]
    assert raw["hash"] == hash_before
    assert auth.EDL_PERMS <= set(raw["permissions"])
    assert main(["users", "grant-edl-admins", "--users-file", str(uf)]) == 0  # idempotent
    assert "0 admin(s) updated" in capsys.readouterr().out
    assert yaml.safe_load(uf.read_text())["users"]["admin1"]["hash"] == hash_before
