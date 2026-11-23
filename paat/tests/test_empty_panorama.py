"""A brand-new Panorama export has no device groups or templates yet."""
from __future__ import annotations

from pathlib import Path

from panlab.netmodel import load_environment

FIX = Path(__file__).parent / "fixtures"
PANO = FIX / "synthetic-panorama.xml"
LABFW = FIX / "synthetic-fw-test.xml"

# Management-only tree shaped like a fresh Panorama running-config: no
# device-group, template, or template-stack, and no vsys/network under
# localhost.localdomain. Serial and hostname are invented.
EMPTY_PANO = """<?xml version="1.0"?>
<config version="11.1.0" detail-version="11.1.0">
  <mgt-config>
    <devices>
      <entry name="000000000000001">
        <hostname>SYNTH-FW</hostname>
      </entry>
    </devices>
  </mgt-config>
  <shared/>
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig>
        <system>
          <hostname>SYNTH-PANO</hostname>
        </system>
      </deviceconfig>
    </entry>
  </devices>
</config>
"""


def test_empty_panorama_without_dgs_or_templates_is_panorama():
    env = load_environment(EMPTY_PANO, target="pano-1")
    assert env.kind == "panorama"
    assert env.hostname == "SYNTH-PANO"
    assert env.device_groups == {}
    assert env.stacks == {}
    assert [d.name for d in env.devices] == ["SYNTH-FW"]
    assert env.devices[0].serial == "000000000000001"
    assert env.devices[0].no_network is True


def test_existing_fixtures_keep_their_kinds():
    assert load_environment(PANO, target="pano-synth").kind == "panorama"
    assert load_environment(LABFW, target="fw-1").kind == "firewall"
