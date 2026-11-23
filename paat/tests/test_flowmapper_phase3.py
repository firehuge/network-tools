# SPDX-License-Identifier: Apache-2.0
"""FlowMapper 1.6.0 in the fwtest: BGP-inferred labels, pasted route tables, shared-IP picker,
pins and saved next-hop links, on /flow and in `panlab flowtrace`. Synthetic configs only."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from panlab import flowmapper as fm  # noqa: E402
from panlab.customers import load_profile  # noqa: E402
from panlab.uploads import store  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
FX = ROOT / "tests" / "fixtures"  # synthetic-fm3-*: copied from the FlowMapper samples (synthetic only)
DC1, DC2, CLONED = FX / "synthetic-fm3-fw-are-bgp-dc1.xml", FX / "synthetic-fm3-fw-are-bgp-dc2.xml", FX / "synthetic-fm3-panorama-cloned-dc.xml"
RT = FX / "synthetic-fm3-dc2-show-advanced-routing-route.txt"
BGP_FLOW = "10.20.1.50 -> 10.10.1.20 tcp/443"
SHARED_FLOW = "10.1.1.10 -> 10.50.1.20 tcp/443"


def _cf(*paths):
    return [fm.ConfigFile(path=p, name=p.name) for p in paths]


def test_engine_is_1_6_0():
    assert tuple(int(x) for x in fm.verify_engine()["version"].split(".")[:2]) >= (1, 6)


def test_bgp_inferred_label_and_reason():
    res = fm.run_trace(_cf(DC1, DC2), BGP_FLOW)
    ps = res["rows"][0]["pathStatus"]
    assert ps["status"] == "suggested" and ps["label"] == "Suggested (BGP-inferred)" and ps["bgpInferred"]
    what = " ".join(a["what"] for a in ps["assumptions"])
    assert "Why: dc1-core-fw aggregates" in what and "summary only" in what
    assert any("show advanced-routing route" in (a["confirm"] or "") for a in ps["assumptions"])
    engines = {b["vr"]: b["engine"] for b in res["bgp"]}
    assert engines == {"LR-CORE": "advanced"} and len(res["bgp"]) == 2


def test_pasted_route_table_wins_over_inference():
    t = fm.RouteTable(device="dc2-core-fw", text=RT.read_text(), label="dc2 table")
    res = fm.run_trace(_cf(DC1, DC2), BGP_FLOW, route_tables=[t])
    ps = res["rows"][0]["pathStatus"]
    assert ps["status"] == "complete" and ps["label"] == "Complete (pasted route table)"
    rep = res["routeTables"][0]
    assert rep["matched"] and rep["format"] == "advanced" and rep["routes"] == 3
    obs = [b for b in res["bgp"] if b.get("observed")]
    assert len(obs) == 1 and obs[0]["hostname"] is None  # local backup: name is already the hostname


def test_split_route_paste_and_specs(tmp_path):
    tabs = fm.split_route_paste("# device: fw-a\n1.0.0.0/8 2.2.2.2 e1 bgp\n# device: fw-b\n3.0.0.0/8 4.4.4.4 e1 bgp\n")
    assert [t.device for t in tabs] == ["fw-a", "fw-b"]
    with pytest.raises(fm.FlowMapperError):
        fm.split_route_paste("1.0.0.0/8 2.2.2.2 e1 bgp\n")
    p = tmp_path / "r.txt"
    p.write_text("x")
    assert fm.parse_route_spec(f"{p}@fw-a").device == "fw-a"
    link = fm.parse_link_spec("edge-dal-fw:ethernet1/1:10.99.0.2=core-dc2-fw")
    assert link["from"] == {"device": "edge-dal-fw", "iface": "ethernet1/1", "nexthop": "10.99.0.2"}
    assert link["to"]["device"] == "core-dc2-fw"


def test_shared_ip_needs_choice_never_silent():
    res = fm.run_trace(_cf(CLONED), SHARED_FLOW)
    ps = res["rows"][0]["pathStatus"]
    assert ps["status"] == "incomplete" and ps["label"] == "Needs your choice"
    nh = ps["choices"][0]
    assert nh["kind"] == "next-hop" and not nh["pinned"]
    hosts = sorted(c["hostname"] for c in nh["candidates"])
    assert hosts == ["core-dc1-fw", "core-dc2-fw"]
    assert {c["serial"] for c in nh["candidates"]} == {"009940000002", "009940000003"}
    assert all(c["stack"] and c["site"] and c["reason"] for c in nh["candidates"])
    ov = res["overlap"]
    assert ov["total"] >= 2 and "10.99.0.2" in [x["ip"] for x in ov["sharedIps"]]
    assert "different template stacks" in ov["cloned"][0]["notHa"]


def test_pick_and_link_pin_the_choice():
    first = fm.run_trace(_cf(CLONED), SHARED_FLOW)
    pins = fm.pins_from_picks(first, ["1.1=core-dc2-fw"])
    res = fm.run_trace(_cf(CLONED), SHARED_FLOW, pins=pins)
    row = res["rows"][0]
    assert row["pathStatus"]["status"] == "complete"
    assert row["hops"][-1]["hostname"] == "core-dc2-fw"
    assert all(c["pinned"] for c in row["pathStatus"]["choices"])
    with pytest.raises(fm.FlowMapperError):
        fm.pins_from_picks(first, ["1.1=not-a-firewall"])
    link = fm.parse_link_spec("edge-dal-fw:ethernet1/1:10.99.0.2=core-dc1-fw")
    res = fm.run_trace(_cf(CLONED), SHARED_FLOW, links=[link])
    row = res["rows"][0]
    assert row["hops"][-1]["hostname"] == "core-dc1-fw" and row["pathStatus"]["status"] == "complete"
    assert row["pathStatus"]["choices"][0]["pinBy"] == "a saved link"


def test_cli_flowtrace_routes_and_pick():
    env = {"PYTHONPATH": str(ROOT / "src")}
    import os
    env = dict(os.environ, **env)
    base = [sys.executable, "-m", "panlab.cli", "flowtrace", "--customer", "fwtest"]
    out = subprocess.run(base + ["--config", str(CLONED)], input=SHARED_FLOW, capture_output=True, text=True, env=env, cwd=ROOT)
    assert out.returncode == 0, out.stderr
    assert "path=Needs your choice" in out.stdout and "choice 1.1 next-hop" in out.stdout
    assert "core-dc2-fw · serial 009940000003 · stack ST-DC2 · site core-dc2" in out.stdout
    assert "--pick 1.1=" in out.stdout and "not HA (different template stacks" in out.stdout
    out = subprocess.run(base + ["--config", str(CLONED), "--pick", "1.1=core-dc2-fw"], input=SHARED_FLOW, capture_output=True, text=True, env=env, cwd=ROOT)
    assert "path=Complete" in out.stdout and "pinned to core-dc2-fw (your choice)" in out.stdout
    out = subprocess.run(base + ["--config", str(DC1), "--config", str(DC2)], input=BGP_FLOW, capture_output=True, text=True, env=env, cwd=ROOT)
    assert "path=Suggested (BGP-inferred)" in out.stdout and "Why: dc1-core-fw aggregates" in out.stdout
    out = subprocess.run(base + ["--config", str(DC1), "--config", str(DC2), "--routes", f"{RT}@dc2-core-fw"], input=BGP_FLOW, capture_output=True, text=True, env=env, cwd=ROOT)
    assert "path=Complete (pasted route table)" in out.stdout and "advanced, 3 route(s) used" in out.stdout


@pytest.fixture
def client(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from panlab.web import auth
    from panlab.web.app import app

    monkeypatch.setenv("PANLAB_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PANLAB_USERS_FILE", str(tmp_path / "users.yaml"))
    monkeypatch.setenv("PANLAB_SESSION_KEY_FILE", str(tmp_path / "session.key"))
    monkeypatch.setenv("PANLAB_USER_AUDIT_FILE", str(tmp_path / "ua.jsonl"))
    auth.add_user("viewer1", "viewer", "pw-viewer-12345", tmp_path / "users.yaml")
    c = TestClient(app)
    r = c.post("/login", data={"username": "viewer1", "password": "pw-viewer-12345"}, follow_redirects=False)
    assert r.status_code == 303
    return c


def _stem_of(text: str) -> str:
    return text.split("/flow/example-pano/")[1].split("/")[0]


def test_web_route_table_paste_and_bgp_label(client):
    page = client.get("/flow?customer=example-pano").text
    assert "name='route_tables'" in page and "show advanced-routing route" in page
    prof = load_profile("example-pano")
    ids = [store(prof, p.read_bytes(), p.name, uploaded_by="viewer1")["id"] for p in (DC1, DC2)]
    r = client.post("/flow", data={"customer": "example-pano", "backups": ids, "fcr": BGP_FLOW})
    assert r.status_code == 200, r.text[:400]
    assert "data-label='Suggested (BGP-inferred)'" in r.text and "Why: dc1-core-fw aggregates" in r.text
    assert "BGP in the loaded configs (2 router(s))" in r.text
    r = client.post("/flow", data={"customer": "example-pano", "backups": ids, "fcr": BGP_FLOW,
                                   "rt_device": "dc2-core-fw", "route_tables": RT.read_text()})
    assert "data-label='Complete (pasted route table)'" in r.text and "Route tables used" in r.text
    r = client.post("/flow", data={"customer": "example-pano", "backups": ids, "fcr": BGP_FLOW},
                    files=[("rt_files", ("dc2.txt", RT.read_bytes(), "text/plain"))])
    assert r.status_code == 400  # uploaded table without a firewall name is refused, never guessed
    r = client.post("/flow", data={"customer": "example-pano", "backups": ids, "fcr": BGP_FLOW, "rt_device": "dc2-core-fw"},
                    files=[("rt_files", ("dc2.txt", RT.read_bytes(), "text/plain"))])
    assert "data-label='Complete (pasted route table)'" in r.text and "dc2.txt" in r.text


def test_web_shared_ip_picker_pin_and_link(client):
    prof = load_profile("example-pano")
    bid = store(prof, CLONED.read_bytes(), CLONED.name, uploaded_by="viewer1")["id"]
    r = client.post("/flow", data={"customer": "example-pano", "backups": bid, "fcr": SHARED_FLOW})
    assert "data-label='Needs your choice'" in r.text and "id='overlap-callout'" in r.text
    assert "Pick one: next hop 10.99.0.2" in r.text and "009940000003" in r.text and "ST-DC2" in r.text
    assert "Use for this trace" in r.text and "Save as link" in r.text
    stem = _stem_of(r.text)
    res = json.loads((prof.data_dir("flowtraces") / f"{stem}.json").read_text())["result"]
    cand = {c["hostname"]: c["devId"] for c in res["rows"][0]["pathStatus"]["choices"][0]["candidates"]}
    p = client.post(f"/flow/example-pano/{stem}/pin", data={"row": 1, "choice": 1, "device": cand["core-dc2-fw"], "action": "pin"}, follow_redirects=False)
    assert p.status_code == 303
    shown = client.get(p.headers["location"]).text
    assert "data-label='Complete'" in shown and "Pinned: next hop 10.99.0.2" in shown and "your choice" in shown
    assert not (prof.data_dir("flowtraces") / "links.json").exists()  # a pin is for this trace only
    bad = client.post(f"/flow/example-pano/{stem}/pin", data={"row": 1, "choice": 1, "device": "nope", "action": "pin"})
    assert bad.status_code == 400
    p = client.post(f"/flow/example-pano/{stem}/pin", data={"row": 1, "choice": 1, "device": cand["core-dc1-fw"], "action": "link"}, follow_redirects=False)
    assert p.status_code == 303
    links = json.loads((prof.data_dir("flowtraces") / "links.json").read_text())
    assert len(links) == 1 and links[0]["from"]["nexthop"] == "10.99.0.2"
    form = client.get("/flow?customer=example-pano").text
    assert "Saved next-hop links" in form
    again = client.post("/flow", data={"customer": "example-pano", "backups": bid, "fcr": SHARED_FLOW})
    assert "data-label='Complete'" in again.text and "a saved link" in again.text
    d = client.post("/flow/example-pano/links/delete", data={"index": 0}, follow_redirects=False)
    assert d.status_code == 303 and json.loads((prof.data_dir("flowtraces") / "links.json").read_text()) == []


# RS-42 live BGP test (fwtest PA-VM, PAN-OS 11.1): legacy import/export rules deny what no rule matches,
# and route flags print run together ("A?B"). Synthetic Panorama export, no customer data.
LEGACY = FX / "synthetic-fm3-panorama-legacy-bgp.xml"
ALLOW_REST = '<entry name="allow-rest"><enable>yes</enable><used-by><member>BRANCHES</member></used-by><match/><action><allow><update/></allow></action></entry>'
BRANCH_FLOW = "10.40.1.10 -> 10.30.1.10 tcp/443"


def _legacy_variant(tmp_path, drop_allow: bool):
    text = LEGACY.read_text()
    assert ALLOW_REST in text
    p = tmp_path / ("deny-only.xml" if drop_allow else "deny-allow.xml")
    p.write_text(text.replace(ALLOW_REST, "") if drop_allow else text)
    return p


def test_legacy_export_rules_implicit_deny(tmp_path):
    ok = fm.run_trace(_cf(_legacy_variant(tmp_path, False)), BRANCH_FLOW)["rows"][0]
    assert ok["pathStatus"]["label"] == "Suggested (BGP-inferred)"
    bad = fm.run_trace(_cf(_legacy_variant(tmp_path, True)), BRANCH_FLOW)["rows"][0]
    assert bad["pathStatus"]["label"] != "Suggested (BGP-inferred)" and bad["status"] != "delivered"


def test_pasted_live_table_with_run_together_flags(tmp_path):
    xml = ('<response status="success"><result><entry><virtual-router>default</virtual-router><destination>10.30.1.0/24</destination>'
           '<nexthop>10.201.0.1</nexthop><metric/><flags>A?B   </flags><age>310</age><interface/></entry>'
           '<entry><virtual-router>default</virtual-router><destination>10.30.2.0/24</destination><nexthop>10.201.0.1</nexthop>'
           '<flags> ?B   </flags></entry></result></response>')
    t = fm.RouteTable(device="009930000002", text=xml, label="live")
    res = fm.run_trace(_cf(_legacy_variant(tmp_path, True)), BRANCH_FLOW, route_tables=[t])
    rep = res["routeTables"][0]
    assert rep["matched"] and rep["routes"] == 1 and rep["skipped"] == 1
    ps = res["rows"][0]["pathStatus"]
    assert ps["status"] == "complete" and ps["label"] == "Complete (pasted route table)"
