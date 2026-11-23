# SPDX-License-Identifier: Apache-2.0
"""Candidate pruning, multi-hop stitching, Panorama collapse, and the needs-local-backup note."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from panlab.netmodel import load_environment  # noqa: E402
from panlab.placement import place  # noqa: E402

FIX = Path(__file__).parent / "fixtures"
GW = "<nexthop><ip-address>$wan-gw</ip-address></nexthop></entry>"


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    xml = (FIX / "synthetic-panorama.xml").read_text()
    assert xml.count(GW) == 1
    # both branches get a specific route to 10.21/16 (unknown to the core) -> route-only candidates
    xml = xml.replace(GW, GW + '\n<entry name="to-lab21"><destination>10.21.0.0/16</destination>' + GW)
    # a firewall managed by Panorama but without template network config
    xml = xml.replace('<entry name="000000000202"><hostname>FW-BR-B</hostname></entry>',
                      '<entry name="000000000202"><hostname>FW-BR-B</hostname></entry>'
                      '<entry name="000000000301"><hostname>FW-NONET</hostname></entry>')
    xml = xml.replace('<entry name="000000000202"/>', '<entry name="000000000202"/><entry name="000000000301"/>')
    p = tmp_path_factory.mktemp("prune") / "pano.xml"
    p.write_text(xml)
    return load_environment(str(p), "pano-synth", "synthetic")


def devs(ps):
    return {(p.device, p.vsys) for p in ps}


def test_owner_beats_route_only(env):
    r = place([env], "10.10.1.1", "10.21.0.5")
    # CORE owns the source on a connected /16; branches own the destination
    # on a specific static /16. Both kinds of ownership are kept.
    assert ("FW-CORE-1", "vsys1") in devs(r.placements)
    roles = {p.device: p.role for p in r.placements}
    assert roles.get("FW-CORE-1") in {"source-owner", "owner-both"}
    branch = next(p for p in r.placements if p.device in {"FW-BR-A", "FW-BR-B"})
    assert branch.role == "destination-owner"
    covered = {branch.device} | {t["device"] for t in branch.also_targets}
    assert {"FW-BR-A", "FW-BR-B"} <= covered


def test_stitched_transit_kept(env):
    r = place([env], "10.101.1.1", "10.102.1.1")
    roles = {(p.device, p.role) for p in r.placements}
    assert ("FW-BR-A", "source-owner") in roles and ("FW-BR-B", "destination-owner") in roles
    # CORE has specific /16 statics for both sides, so it is an owner, not
    # merely a stitched transit hop.
    assert any(d == "FW-CORE-1" and role in {"owner-both", "source-owner", "destination-owner", "transit"}
               for d, role in roles)


def test_same_dg_same_zones_collapse(env):
    r = place([env], "10.21.0.5", "8.8.8.8")
    assert len(r.placements) == 1
    p = r.placements[0]
    assert p.device_group == "DG-EDGE" and len(p.also_targets) == 1
    assert {p.device, p.also_targets[0]["device"]} == {"FW-BR-A", "FW-BR-B"}


def test_owner_first_and_at_most_three(env):
    r = place([env], "10.10.1.1", "10.20.1.10")
    assert r.placements[0].role in ("source-owner", "destination-owner", "owner-both")
    assert len(r.placements) <= 3


def test_needs_local_backup_note(env):
    nonet = next(d for d in env.devices if d.name == "FW-NONET")
    assert nonet.no_network
    r = place([env], "10.77.0.1", "10.78.0.1")
    # Only broad/default matches exist: still propose a rule, and flag firewalls
    # that have no network config in this export (they might actually own it).
    assert r.placements and all(p.rule_needed and p.needs_human for p in r.placements)
    assert r.needs_local_backup == ["FW-NONET"]
    assert any("needs local backup" in n for n in r.notes)
    r2 = place([env], "10.101.1.1", "10.102.1.1")
    assert r2.needs_local_backup == []  # owners found, no note
