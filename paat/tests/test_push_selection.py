"""Tick a subset of planned rules on the gated Push page and prepare only those."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from test_two_places import FIX, _cs  # noqa: E402
from test_push import FakeDevice, _client, _login  # noqa: E402

from panlab import pusher  # noqa: E402
from panlab.changeplan import assumes_outside_hop, enforcement_lines  # noqa: E402
from panlab.customers import load_profile  # noqa: E402
from panlab.web.multiplace import banner_html  # noqa: E402


def test_filter_changeset_keeps_one_rule_and_rejects_empty():
    cs = _cs({"src": "10.66.1.10", "dst": "10.66.2.10", "proto": "udp", "port": "500"})
    items = [it for it in pusher.selectable_items(cs) if it["kind"] == "rule"]
    assert len(items) == 2
    one = pusher.filter_changeset(cs, [items[0]["token"]])
    names = [r["name"] for g in one["groups"] for r in g["rules"]]
    assert names == [items[0]["name"]]
    assert one["summary"]["rules"] == 1
    assert pusher.filter_changeset(cs, None) is cs
    with pytest.raises(pusher.PushError, match="at least one"):
        pusher.filter_changeset(cs, [])
    with pytest.raises(pusher.PushError, match="None of the ticked"):
        pusher.filter_changeset(cs, ["rule:9:nope"])


def test_wording_needs_n_rules_and_assumes_outside_hop_when_hairpin_is_noted():
    cs = _cs({"src": "10.66.1.10", "dst": "10.66.2.10", "proto": "udp", "port": "500"})
    lines = "\n".join(enforcement_lines(cs))
    assert "needs 2 rules across 2 vsys/firewalls" in lines
    assert "RULE NEEDED IN 2 PLACES" in lines
    assert "assumes the suggested outside hop" not in lines
    assert assumes_outside_hop(cs) is False
    cs["requests"][0]["placements"][0].setdefault("notes", []).append(
        "re-enters through an unknown network (hairpin)")
    assert assumes_outside_hop(cs) is True
    assert "The count assumes the suggested outside hop." in "\n".join(enforcement_lines(cs))
    h = banner_html(cs)
    assert "Rule needed in more than one place" in h
    assert "needs 2 rules across 2 vsys/firewalls" in h
    assert "The count assumes the suggested outside hop." in h


def test_prepare_subset_hashes_the_original_and_builds_ops_for_only_those_rules(tmp_path, monkeypatch):
    monkeypatch.setenv("PANLAB_DATA_DIR", str(tmp_path / "data"))
    prof = load_profile("example-pano")
    prof.allow_live_panorama_push = True
    cs = _cs({"src": "10.66.1.10", "dst": "10.66.2.10", "proto": "udp", "port": "500"}, prof=prof)
    (prof.data_dir("changesets") / "cs-sel.json").write_text(json.dumps(cs))
    items = [it for it in pusher.selectable_items(cs) if it["kind"] == "rule"]
    first = items[0]["token"]
    dev = FakeDevice(FIX.read_text())
    # FakeDevice is a firewall stand-in; this profile target is Panorama. Use a recorder instead.
    from test_panorama_live_push import LivePanorama

    dev = LivePanorama(FIX.read_text())
    s = pusher.prepare(prof, cs, "cs-sel", actor="eng", cr="CHG0001234", dev=dev,
                       selected=[first])
    assert s["status"] == "prepared" and s["selected"] == [first]
    assert pusher.cs_hash(cs) == s["changeset_hash"]
    rule_ops = [o for o in s["ops"] if o.get("kind") in ("rule", "deny-rule", "rule-move")]
    assert rule_ops and all(items[0]["name"] in (o.get("name") or "") for o in rule_ops)
    assert items[1]["name"] not in json.dumps(s["ops"])
    # Apply is the same session ops; a full apply is covered by the live-push tests. This
    # Fake/Live panorama stand-in cannot move rules, so we stop after prepare.


def test_gui_push_page_lists_rules_and_prepare_honours_the_ticks(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    monkeypatch.setenv("PANLAB_DATA_DIR", str(tmp_path / "data"))
    prof = load_profile("example-pano")
    prof.allow_live_panorama_push = True
    cs = _cs({"src": "10.66.1.10", "dst": "10.66.2.10", "proto": "udp", "port": "500"}, prof=prof)
    (prof.data_dir("changesets") / "cs-sel.json").write_text(json.dumps(cs))
    items = [it for it in pusher.selectable_items(cs) if it["kind"] == "rule"]
    import panlab.web.app as web
    from test_panorama_live_push import LivePanorama

    dev = LivePanorama(FIX.read_text())
    c = _client(tmp_path, monkeypatch)
    monkeypatch.setattr(web, "device_factory", lambda p, t: dev)
    _login(c, "eng1", "pw-eng")
    page = c.get("/push/example-pano/cs-sel").text
    assert "Rules to include in this prepare" in page
    assert 'name="item"' in page or "name='item'" in page
    assert "have_selection" in page and items[0]["token"] in page and items[1]["token"] in page
    r = c.post("/push/example-pano/cs-sel/prepare", data={
        "cr": "CHG0001234", "approved": "yes", "target": "pano-synth",
        "have_selection": "yes", "item": [items[0]["token"]],
    })
    assert r.status_code == 200 and items[0]["name"] in r.text
    assert items[1]["name"] not in r.text or "subset of the plan" in r.text
    assert items[0]["token"] in r.text
    r_bad = c.post("/push/example-pano/cs-sel/prepare", data={
        "cr": "CHG0001234", "approved": "yes", "target": "pano-synth",
        "have_selection": "yes",
    })
    assert r_bad.status_code == 400
