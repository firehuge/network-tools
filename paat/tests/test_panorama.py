"""Panorama: device-group hierarchy, template route callouts, change plan and dry-run push (synthetic only)."""

from __future__ import annotations

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


@pytest.fixture
def pano_cs(tmp_path):
    prof = load_profile("example-pano")
    envs = load_customer_envs(prof)
    f = make_fcr(tmp_path / "a.xlsx", [
        ("10.10.1.0/24", None, "10.77.7.7", None, "tcp", "9443", None, "RITM0010009", None),
        ("10.101.1.0/24", None, "10.77.7.7", None, "tcp", "9443", None, "RITM0010009", None),
        ("10.20.1.0/24", None, "10.101.5.0/24", None, "tcp", "9100", None, "RITM0010009", None),
    ], project="X")
    return prof, envs, build_changeset(prof, envs, read_fcr(f, ticket_patterns=prof.tickets, requester="Jane Tester")[0])


def test_rule_names_unique_across_dg_hierarchy(pano_cs):
    _, envs, cs = pano_cs
    names = [r["name"] for g in cs["groups"] for r in g["rules"]]
    assert len(names) == len(set(names))
    existing = {n for dg in envs[0].device_groups.values() for n in dg.scope.rule_names}
    assert not existing & set(names)


def test_child_dg_reuses_its_own_object_parent_does_not_see_it(pano_cs):
    _, _, cs = pano_cs
    g = {x["device_group"]: x for x in cs["groups"]}
    edge = next(r for r in g["DG-EDGE"]["rules"] if "tcp-9100" in r["service"])
    assert edge["destination"] == ["BR-A-PRINTERS"]
    dc = next(r for r in g["DG-DC"]["rules"] if "tcp-9100" in r["service"])
    assert dc["destination"] != ["BR-A-PRINTERS"]  # DG-DC cannot see a child-DG object


def test_common_parent_callout(pano_cs):
    _, _, cs = pano_cs
    g = {x["device_group"]: x for x in cs["groups"]}
    r = next(r for r in g["DG-EDGE"]["rules"] if "tcp-9443" in r["service"])
    m = next(f["message"] for f in r["flags"] if f["code"] == "dg-common-parent")
    assert "only in DG-DC" in m and "10.77.7.7" in m


def test_new_object_name_avoids_descendant_names():
    from panlab.changeset import _Ctx
    prof = load_profile("example-pano")
    env = load_customer_envs(prof)[0]
    ctx = _Ctx(prof, [env.device_groups["DG-DC"].scope, env.shared], "device-group")
    ctx.taken_below = {"BR-A-PRINTERS"}
    assert "BR-A-PRINTERS" in ctx._existing_names()


def test_changeplan_has_panorama_commit_and_push(pano_cs):
    from panlab.changeplan import render_changeplan

    _, _, cs = pano_cs
    t = render_changeplan(cs)
    assert "## Commit and push plan" in t and "$commit_push" not in t and "$rollback_push" not in t
    assert "**Commit to Panorama**" in t and "Push to Devices** for device group `DG-EDGE`" in t
    assert '<entry name="DG-EDGE"><devices><entry name="000000000201"/></devices>' in t
    assert "Include Device and Network Templates **unticked**" in t
    assert "commit-all template-stack ST-BRANCH" in t  # route callout hinted a template change
    rb = t[t.index("## Rollback"):]
    assert "Do step 1 for the rollback" in rb and "delete device-group DG-EDGE pre-rulebase security rules" in rb
    assert "set template TPL-BRANCH config network virtual-router" in t


# ---------------------------------------------------------------- fake Panorama, forced dry run

PANOXML = FIX / "synthetic-panorama.xml"


class FakePanorama:
    """Records every call; any write or commit fails the test."""

    def __init__(self, xml: str):
        self.xml, self.calls = xml, []

    def export_running(self):
        self.calls.append("export")
        return self.xml

    def _write(self, *a, **k):
        raise AssertionError("Panorama dry run must never write")

    set = delete = revert = commit = _write

    def exists_running(self, xpath):
        return False

    def pending_changes(self):
        return False

    def policy_match(self, q):
        return None


@pytest.fixture
def pano_push(tmp_path, monkeypatch):
    monkeypatch.setenv("PANLAB_DATA_DIR", str(tmp_path / "data"))
    prof = load_profile("example-pano")
    envs = load_customer_envs(prof)
    f = make_fcr(tmp_path / "RITM0010009.xlsx", [
        ("10.10.1.0/24", None, "10.20.1.10", None, "tcp", "9443", None, "RITM0010009", None),
        ("10.20.1.0/24", None, "10.101.5.0/24", None, "tcp", "9100", None, "RITM0010009", None),
    ], project="X")
    reqs, meta = read_fcr(f, ticket_patterns=prof.tickets, requester="Jane Tester")
    cs = build_changeset(prof, envs, reqs, files=[meta])
    (prof.data_dir("changesets") / "cs-pano.json").write_text(__import__("json").dumps(cs))
    return prof, cs, FakePanorama(PANOXML.read_text())


def test_panorama_prepare_is_dry_run_with_dg_ops_and_push_plan(pano_push):
    from panlab import pusher

    prof, cs, dev = pano_push
    s = pusher.prepare(prof, cs, "cs-pano", actor="eng", cr="CHG0001234", dev=dev)
    assert s["status"] == "dry-run" and not s["errors"] and dev.calls == ["export"]
    rule_ops = [o for o in s["ops"] if o["kind"] == "rule"]
    assert rule_ops and all("/device-group/entry[@name='DG-" in o["xpath"] and o["xpath"].endswith("/pre-rulebase/security/rules")
                            for o in rule_ops)
    edge = next(o for o in rule_ops if "DG-EDGE" in o["xpath"])
    assert '<target><devices><entry name="000000000201"><vsys><entry name="vsys1"/>' in edge["element"]
    assert "BR-A-PRINTERS" in edge["element"]  # child DG object reused
    assert all("pre-rulebase" in o["xpath"] for o in s["rollback_ops"] if o["kind"] == "rule")
    steps = [p["step"] for p in s["push_plan"]]
    assert steps[0] == "commit to Panorama" and any("DG-EDGE to 000000000201" in x for x in steps)
    assert "<include-template>no</include-template>" in s["push_plan"][1]["cmd"]
    md = (prof.data_dir("push") / f"{s['id']}-report.md").read_text()
    assert "dry run: NOT executed" in md and "dry-run" in md


def test_panorama_apply_and_rollback_always_refuse(pano_push):
    from panlab import pusher

    prof, cs, dev = pano_push
    s = pusher.prepare(prof, cs, "cs-pano", actor="eng", cr="CHG0001234", dev=dev)
    for fn in (pusher.apply, pusher.rollback):
        with pytest.raises(pusher.PushError, match="dry-run only"):
            fn(prof, cs, s["id"], actor="eng", confirm_target="pano-synth", dev=dev)
    acts = [(a["action"], a["result"]) for a in pusher.read_audit(prof)]
    assert ("apply", "refused") in acts and ("rollback", "refused") in acts


def test_panorama_revalidate_catches_hierarchy_problems(pano_push):
    import copy

    from panlab import pusher

    prof, cs, dev = pano_push
    tgt = prof.targets[0]
    cfg = PANOXML
    bad = copy.deepcopy(cs)
    g = {x["device_group"]: x for x in bad["groups"]}
    g["DG-EDGE"]["rules"][0]["name"] = "allow-users-web"  # existing rule in the parent DG
    g["DG-EDGE"]["rules"][0]["to"] = ["NO-SUCH-ZONE"]
    g["DG-EDGE"]["rules"][0]["target_devices"].append({"device": "FW-CORE-1", "serial": "000000000101", "vsys": "vsys1"})
    g["DG-DC"]["objects"]["reused"].append({"kind": "address", "name": "BR-A-PRINTERS", "scope": "DG-EDGE"})
    g["DG-DC"]["objects"]["new"].append({"kind": "address", "name": "BR-A-PRINTERS", "type": "ip-netmask",
                                         "value": "10.9.9.0/24", "location": "device-group", "device_group": "DG-DC"})
    errors, _, _ = pusher.revalidate(bad, cfg, tgt)
    text = "\n".join(errors)
    assert "allow-users-web already exists in the device-group hierarchy" in text
    assert "zone NO-SUCH-ZONE does not exist on FW-BR-A/vsys1" in text
    assert "FW-CORE-1/vsys1 is not in device group DG-EDGE" in text
    assert "reused address BR-A-PRINTERS is not visible from DG-DC" in text
    assert "already exists in child device group DG-EDGE" in text
    gone = copy.deepcopy(cs)
    gone["groups"][0]["device_group"] = "DG-GONE"
    assert any("DG-GONE does not exist" in x for x in pusher.revalidate(gone, cfg, tgt)[0])


def test_panorama_offline_dry_run_from_cli_and_gui(pano_push, tmp_path, monkeypatch, capsys):
    from panlab.cli import main

    prof, cs, _ = pano_push
    monkeypatch.delenv("EXAMPLE_PANO_HOST", raising=False)
    p = prof.data_dir("changesets") / "cs-pano.json"
    assert main(["push", "--customer", "example-pano", "--changeset", str(p), "--apply", "--commit", "--cr", "CHG0004321"]) == 0
    out = capsys.readouterr().out
    assert "dry-run: Panorama push is dry-run only" in out and "commit-all" in out and "+ rule X-" in out

    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    import panlab.web.app as web
    from panlab.web import auth

    uf = tmp_path / "users.yaml"
    monkeypatch.setenv("PANLAB_USERS_FILE", str(uf))
    auth.add_user("eng1", "engineer", "pw-eng", uf)
    c = TestClient(web.app)
    c.post("/login", data={"username": "eng1", "password": "pw-eng"})
    assert "dry run only" in c.get("/push/example-pano/cs-pano").text
    r = c.post("/push/example-pano/cs-pano/prepare", data={"cr": "CHG0004321", "approved": "yes", "target": "pano-synth"})
    assert r.status_code == 200 and "Dry run only (Panorama)" in r.text and "Apply + commit" not in r.text
    assert "commit-all" in r.text


def test_firewall_in_no_device_group_is_red_and_blocks_dry_run(tmp_path):
    from panlab import pusher
    from panlab.netmodel import load_environment

    lines = PANOXML.read_text().splitlines()
    lines[61] = lines[61].replace('<entry name="000000000202"/>', "")  # drop FW-BR-B from DG-EDGE
    cfg = tmp_path / "pano-nodg.xml"
    cfg.write_text("\n".join(lines))
    prof = load_profile("example-pano")
    env = load_environment(cfg, target="pano-synth")
    f = make_fcr(tmp_path / "a.xlsx", [("10.102.1.0/24", None, "10.20.1.10", None, "tcp", "8443", None, "RITM0010010", None)],
                 project="X")
    cs = build_changeset(prof, [env], read_fcr(f, ticket_patterns=prof.tickets)[0])
    nodg = [r for g in cs["groups"] if not g["device_group"] for r in g["rules"]]
    assert nodg and all(any(fl["code"] == "no-device-group" and fl["level"] == "red" for fl in r["flags"]) for r in nodg)
    errors, _, _ = pusher.revalidate(cs, cfg, prof.targets[0])
    assert any("in no device group" in e for e in errors)
