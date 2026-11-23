"""Customer scope must be honored for users created from a legacy role, not only from explicit checkboxes.

Regression: ``auth.add_user(name, role, pw, customers=[...])`` used to drop ``customers``/``devices`` for a
role record, so the user silently became an all-customers user. Fake customers and devices only.
"""
from __future__ import annotations

import pytest
import yaml

from panlab.web import auth
from test_permissions import login, msp  # noqa: F401  (msp is a fixture)


# ---------------------------------------------------------------- model

def test_role_with_scope_is_stored_explicitly_and_scoped(tmp_path):
    uf = tmp_path / "users.yaml"
    auth.add_user("scoped-eng", "engineer", "pw-scoped-12345", uf, customers=["globex"])
    rec = yaml.safe_load(uf.read_text())["users"]["scoped-eng"]
    assert rec["customers"] == ["globex"] and set(rec["permissions"]) == set(auth.ROLE_PERMS["engineer"]) and "role" not in rec
    p = auth.Principal("scoped-eng", auth.load_users(uf)["scoped-eng"])
    assert p.customers == ["globex"] and p[1] == "engineer"  # same label, same permissions, narrower scope
    assert p.sees_customer("globex") and not p.sees_customer("acme")
    assert (uf.stat().st_mode & 0o777) == 0o600


def test_role_with_device_limit_only_keeps_all_customers_but_the_device_limit(tmp_path):
    uf = tmp_path / "users.yaml"
    auth.add_user("dev-limited", "prep", "pw-dev-1234567", uf, devices={"acme": ["dg:DG-East"]})
    p = auth.Principal("dev-limited", auth.load_users(uf)["dev-limited"])
    assert p.all_customers() and p.device_scope("acme") == ["dg:DG-East"]


def test_plain_role_record_is_unchanged_and_all_customers(tmp_path):
    uf = tmp_path / "users.yaml"
    auth.add_user("old-style", "admin", "pw-old-1234567", uf)
    rec = yaml.safe_load(uf.read_text())["users"]["old-style"]
    assert rec["role"] == "admin" and "customers" not in rec
    p = auth.Principal("old-style", auth.load_users(uf)["old-style"])
    assert p.all_customers() and p.perms == frozenset(auth.PERMS) and p[1] == "admin"


def test_explicit_permissions_without_a_customer_list_fail_closed():
    p = auth.Principal("x", {"permissions": ["view", "push"]})  # hand-edited record, no customers key
    assert p.customers == [] and not p.sees_customer("acme") and not p.all_customers()
    assert auth.Principal("y", {"permissions": ["view"], "customers": ["*"]}).all_customers()


def test_unknown_permission_is_rejected_when_adding(tmp_path):
    with pytest.raises(ValueError):
        auth.add_user("bad", "viewer", "pw-bad-1234567", tmp_path / "u.yaml", permissions=["view", "root"], customers=["a"])


def test_cli_users_add_customer_option(tmp_path, monkeypatch):
    from panlab import cli
    uf = tmp_path / "users.yaml"
    monkeypatch.setenv("PANLAB_USERS_FILE", str(uf))
    pf = tmp_path / "pw.txt"
    rc = cli.main(["users", "add", "clistaff", "--role", "engineer", "--customer", "globex", "--password-file", str(pf)])
    assert rc == 0
    p = auth.Principal("clistaff", auth.load_users(uf)["clistaff"])
    assert p.customers == ["globex"] and p[1] == "engineer"


# ---------------------------------------------------------------- every scoped route, role-created user

SCOPED_GET = ["/changesets/acme/x", "/changesets/acme/x/changeplan", "/changesets/acme/x/changeplan.md", "/push/acme/x",
              "/push/acme/session/s1", "/audit/acme", "/denylog/acme", "/backups?customer=acme", "/advisor?customer=acme",
              "/advisor/acme/a1", "/upgrade/acme/disc/d1", "/upgrade/acme/plan/p1", "/upgrade/acme/run/p1"]
SCOPED_POST = [("/import", {"customer": "acme"}), ("/decom", {"customer": "acme", "items": "10.0.0.1"}),
               ("/backups/offline", {"name": "acme"}), ("/backups/upload", {"customer": "acme"}), ("/advisor/run", {"customer": "acme"}),
               ("/upgrade/discover", {"customer": "acme"}), ("/push/acme/x/prepare", {"cr": "CHG1", "approved": "yes", "target": "pano"}),
               ("/push/acme/session/s1/run", {"confirm_target": "pano"}),
               ("/denylog/acme", {"src": "10.0.0.1", "dst": "10.0.0.2", "port": "443"}), ("/upgrade/acme/disc/d1/plan", {}),
               ("/upgrade/acme/plan/p1/arm", {}), ("/upgrade/acme/run/p1/next", {}),
               ("/admin/backup-destinations/acme/x/test", {}), ("/admin/backup-destinations/acme/save", {"type": "git"})]


@pytest.mark.parametrize("role", ["viewer", "prep", "engineer", "admin"])
def test_role_created_scoped_user_cannot_reach_other_customers(msp, tmp_path, role):  # noqa: F811
    c, _dev = msp
    auth.add_user("rolescoped", role, "pw-rolescoped-123", auth.users_file(), customers=["globex"])
    login(c, "rolescoped", "pw-rolescoped-123")
    for url in SCOPED_GET:
        r = c.get(url, follow_redirects=False)
        assert r.status_code == 403, (role, url, r.status_code)
    for url, data in SCOPED_POST:
        r = c.post(url, data=data, files=[("files", ("a.csv", b"x")), ("file", ("a.xml", b"<config/>"))], follow_redirects=False)
        assert r.status_code == 403, (role, url, r.status_code)
    # customer pickers only list the permitted customer
    for url in ("/", "/changesets", "/decom", "/backups", "/advisor", "/home"):
        r = c.get(url, follow_redirects=True)
        if r.status_code == 200:
            assert "acme" not in r.text, (role, url)
    # the top-bar scope label shows the one customer
    home = c.get("/home").text
    assert "globex" in home and "All customers" not in home


def test_role_created_scoped_user_still_works_inside_their_customer(msp):  # noqa: F811
    c, _dev = msp
    auth.add_user("rolescoped2", "engineer", "pw-rolescoped-456", auth.users_file(), customers=["globex"])
    login(c, "rolescoped2", "pw-rolescoped-456")
    assert c.get("/upgrade").status_code == 200 and "globex" in c.get("/upgrade").text
    assert c.get("/backups?customer=globex").status_code == 200
    assert c.get("/audit/globex").status_code == 200
    assert c.get("/advisor?customer=globex").status_code == 200


def test_scope_label_for_no_customers_and_all():
    from panlab.web import theme
    assert theme.scope_text(auth.Principal("n", {"permissions": ["view"], "customers": []})) == "No customers"
    assert theme.scope_text(auth.Principal("a", {"role": "admin"})) == "All customers"


def test_admin_users_page_create_and_edit_keep_scope(msp):  # noqa: F811
    c, _dev = msp
    login(c, "boss", "pw-boss-123456")
    r = c.post("/users/add", data={"username": "newscoped", "new_password": "pw-newscoped-12345", "confirm": "pw-newscoped-12345",
                                   "perm": ["view", "push"], "customer": ["globex"]})
    assert r.status_code == 200
    p = auth.Principal("newscoped", auth.load_users()["newscoped"])
    assert p.customers == ["globex"] and not p.sees_customer("acme")
    c.post("/users/access", data={"username": "newscoped", "perm": ["view"], "customer": ["acme"]})
    p = auth.Principal("newscoped", auth.load_users()["newscoped"])
    assert p.customers == ["acme"] and p.perms == {"view"}
    c.post("/users/access", data={"username": "newscoped", "perm": ["view"]})  # no customer ticked = none, not all
    p = auth.Principal("newscoped", auth.load_users()["newscoped"])
    assert p.customers == [] and not p.sees_customer("acme") and not p.sees_customer("globex")
