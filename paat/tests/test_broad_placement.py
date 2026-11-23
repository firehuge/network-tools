# SPDX-License-Identifier: Apache-2.0
"""Broad-route placement, named-vsys device-group binding, and visible no-rule-needed callouts.

All names, serials, and addresses are synthetic (RFC 1918 / RFC 5737).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from fcr_factory import make_fcr  # noqa: E402

from panlab.changeset import build_changeset  # noqa: E402
from panlab.customers import load_profile  # noqa: E402
from panlab.fcr import read_fcr  # noqa: E402
from panlab.netmodel import _dg_match_named_vsys, dg_for_vsys_name, load_environment  # noqa: E402
from panlab.placement import place  # noqa: E402
from panlab.report import to_html, to_markdown  # noqa: E402

FIX = Path(__file__).parent / "fixtures"
BROAD = FIX / "synthetic-broad-routes.xml"
ONLY = FIX / "synthetic-broad-only.xml"
PANO = FIX / "synthetic-panorama.xml"


@pytest.fixture(autouse=True)
def _data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("PANLAB_DATA_DIR", str(tmp_path / "data"))


@pytest.fixture(scope="module")
def env():
    return load_environment(BROAD, target="pano-broad")


@pytest.fixture(scope="module")
def only():
    return load_environment(ONLY, target="pano-synth")


def test_named_vsys_binds_to_device_group(env):
    names = {d.name: d for d in env.devices}
    app = names["FW-APP"]
    assert "VSYS_DC_APP" in app.vsys
    assert app.vsys["VSYS_DC_APP"].device_group == "DG_TIER_APP"
    mpls = names["FW-MPLS"]
    assert "VSYS_MPLS_COMMON" in mpls.vsys
    assert mpls.vsys["VSYS_MPLS_COMMON"].device_group == "DG_MPLS_COMMON"
    lan = names["FW-LAN"]
    assert lan.vsys["vsys1"].device_group == "DG_LAN"
    assert lan.vsys["vsys1"].intrazone_default == "deny"
    assert names["FW-EDGE-PHX"].vsys["vsys1"].device_group == "DG-EDGE-PHX"
    assert names["FW-EDGE-PHX"].vsys["vsys1"].intrazone_default == "allow"


def test_name_matcher_is_conservative():
    dgs = {"vsys5": "DG_TIER_APP", "vsys9": "DG_MPLS_COMMON", "vsys8": "DG_ATL_MPLS_COMMON"}
    assert dg_for_vsys_name("vsys5", dgs) == "DG_TIER_APP"
    assert _dg_match_named_vsys("VSYS_DC_APP", dgs) == "DG_TIER_APP"
    # Without site codes, "common" ties DG_MPLS_COMMON and DG_ATL_MPLS_COMMON, so no guess.
    assert _dg_match_named_vsys("VSYS_MPLS_COMMON", dgs) is None
    # The customer's site codes (here a made-up "atl") let the matcher drop the other site's DG.
    assert _dg_match_named_vsys("VSYS_MPLS_COMMON", dgs, site_codes=["atl"]) == "DG_MPLS_COMMON"
    assert _dg_match_named_vsys("VSYS_ATL_MPLS_COMMON", dgs, site_codes=["atl"]) == "DG_ATL_MPLS_COMMON"
    # Overlap still prefers the longer name match even with no site codes.
    assert _dg_match_named_vsys("VSYS_ATL_MPLS_COMMON", dgs) == "DG_ATL_MPLS_COMMON"
    # last token does not appear in any DG
    assert _dg_match_named_vsys("VSYS_DC_OTHER", dgs) is None
    # tie: last token APP is in two DGs with the same overlap
    tied = {"vsys1": "DG_TIER_APP", "vsys2": "DG_DC_APP"}
    assert _dg_match_named_vsys("VSYS_APP", tied) is None


def test_prefers_firewalls_with_specific_routes(env):
    r = place([env], "10.30.0.0/18", "10.20.20.10")
    devices = {p.device for p in r.placements}
    assert "FW-APP" in devices
    assert "FW-MPLS" in devices
    assert not any(p.device.startswith("FW-EDGE") for p in r.placements)
    app = next(p for p in r.placements if p.device == "FW-APP")
    assert app.vsys == "VSYS_DC_APP"
    assert app.device_group == "DG_TIER_APP"
    assert app.from_zone == "SZ_APP_CORE" and app.to_zone == "SZ_APP_DEV"
    assert app.rule_needed is True
    assert app.role == "destination-owner"
    mpls = next(p for p in r.placements if p.device == "FW-MPLS")
    assert mpls.vsys == "VSYS_MPLS_COMMON"
    assert mpls.device_group == "DG_MPLS_COMMON"
    assert mpls.from_zone == "SZ_MPLS" and mpls.to_zone == "SZ_TRANSIT"
    assert mpls.rule_needed is True
    assert mpls.role == "source-owner"


def test_broad_same_zone_proposes_rule_and_yellow_callout(only):
    r = place([only], "10.30.0.0/18", "10.20.20.10")
    assert r.placements
    assert {p.device for p in r.placements} == {"FW-SUM-A", "FW-SUM-B"}
    for p in r.placements:
        assert p.intrazone
        assert p.rule_needed is True
        assert p.needs_human is True
        assert p.confidence == "low"
        assert p.from_zone == p.to_zone == "External-Transit"
        assert any(c["code"] == "broad-same-zone" and c["level"] == "yellow" for c in p.callouts)
        assert any("both sides follow the same broad route via ethernet1/4" in (c["message"] + " ".join(p.notes))
                   for c in p.callouts)
        assert "real path likely goes through another firewall or a transit" in " ".join(p.notes)


def test_intrazone_deny_still_needs_a_rule(env):
    r = place([env], "10.40.1.10", "10.40.2.20")
    assert len(r.placements) == 1
    p = r.placements[0]
    assert p.device == "FW-LAN" and p.intrazone and p.from_zone == "LAN"
    assert p.rule_needed is True
    assert "default intrazone action is deny" in " ".join(p.notes)


def test_connected_intrazone_allow_still_skips(pano_env=None):
    pano = load_environment(PANO, target="pano-synth")
    r = place([pano], "10.10.1.1", "10.10.2.2")
    assert len(r.placements) == 1
    p = r.placements[0]
    assert p.intrazone and p.rule_needed is False


def _cs_for(tmp_path, env, src, dst, customer="example-pano"):
    prof = load_profile(customer)
    f = make_fcr(tmp_path / "RITM0000888.xlsx", [
        (src, None, dst, None, "tcp", "443", None, "", "ssl"),
    ], project="broad")
    reqs, meta = read_fcr(f, ticket_patterns=prof.tickets)
    return build_changeset(prof, [env], reqs, files=[meta])


def test_changeset_proposes_rules_for_broad_same_zone(tmp_path, only):
    cs = _cs_for(tmp_path, only, "10.30.0.0/18", "10.20.20.10")
    rules = [r for g in cs["groups"] for r in g["rules"]]
    skipped = [x for g in cs["groups"] for x in g["skipped"]]
    assert rules and not skipped
    assert cs["summary"]["rules"] >= 1
    assert cs["summary"]["skipped_intrazone"] == 0
    assert any(
        f.get("code") == "broad-same-zone"
        for r in rules
        for f in r["flags"]
    )
    html = to_html(cs)
    assert "both sides follow the same broad route via ethernet1/4" in html
    assert "real path likely goes through another firewall or a transit" in html


def test_html_shows_yellow_callout_for_no_rule_needed(tmp_path):
    pano = load_environment(PANO, target="pano-synth")
    cs = _cs_for(tmp_path, pano, "10.10.1.1", "10.10.2.2")
    assert cs["summary"]["rules"] == 0
    assert cs["summary"]["skipped_intrazone"] >= 1
    skipped = [x for g in cs["groups"] for x in g["skipped"]]
    assert skipped
    html = to_html(cs)
    assert "No rule needed (intrazone default allow)" in html
    assert "yellow" in html
    assert any(x.get("request") in html for x in skipped)
    md = to_markdown(cs)
    assert "No rule needed (intrazone default allow)" in md

def test_site_codes_reject_a_cross_site_name_match():
    """A vsys that names one configured site must not land in another site's device group."""
    dgs = {"vsys1": "DG_DC1_APP", "vsys2": "DG_DC2_APP"}
    assert _dg_match_named_vsys("VSYS_DC1_APP", dgs, site_codes=["dc1", "dc2"]) == "DG_DC1_APP"
    assert _dg_match_named_vsys("VSYS_DC2_APP", dgs, site_codes=["dc1", "dc2"]) == "DG_DC2_APP"
    # Without codes, unique token overlap still picks the right DG (dc1+app vs dc2+app).
    assert _dg_match_named_vsys("VSYS_DC1_APP", dgs) == "DG_DC1_APP"


def test_site_codes_come_from_the_customer_profile(tmp_path, monkeypatch):
    """Shipped profiles have no site codes. A local override (never committed) can add them."""
    assert load_profile("fwtest").site_codes == []
    monkeypatch.setenv("PANLAB_CUSTOMER_OVERRIDE_DIR", str(tmp_path))
    (tmp_path / "fwtest.yaml").write_text("site_codes: [dc1, DC2, 'no spaces!']\n")
    assert load_profile("fwtest").site_codes == ["dc1", "dc2"]
    from panlab.sources import load_customer_envs
    from panlab import netmodel
    seen: list = []
    real = netmodel.load_environment
    def wrap(*a, **k):
        seen.append(k.get("site_codes"))
        return real(*a, **k)
    monkeypatch.setattr("panlab.sources.load_environment", wrap)
    # example-pano has an offline_config; the override adds site codes
    (tmp_path / "example-pano.yaml").write_text("site_codes: [dc1]\n")
    load_customer_envs(load_profile("example-pano"))
    assert seen and seen[0] == ["dc1"]

