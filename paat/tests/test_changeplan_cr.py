# SPDX-License-Identifier: Apache-2.0
"""CR-template change plans, profile overrides, and standalone vs Panorama wording."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from test_callouts import _fw_cs  # noqa: E402
from test_phase2 import _cs  # noqa: E402

from panlab.changeplan import changeplan_sections, render_changeplan  # noqa: E402
from panlab.customers import load_profile  # noqa: E402


@pytest.fixture(autouse=True)
def _data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("PANLAB_DATA_DIR", str(tmp_path / "data"))


def test_panorama_plan_matches_cr_layout(tmp_path):
    text = render_changeplan(_cs(tmp_path))
    assert text.startswith("# Panorama Change Request")
    assert "**RITM:** RITM0010001" in text
    assert "## Implementation Plan" in text
    assert text.index("### Add Address Object") < text.index("### Add Policy")
    for label in (
        "#### General", "#### Source", "#### Destination", "#### Application",
        "#### Service/URL Category", "#### Actions", "#### Target",
        "Log at Session Start", "Log at Session End", "Log Forwarding",
        "Profile Type: Group", "Group Profile", "URL Category: `any`",
        "Audit Comment",
    ):
        assert label in text, label
    assert "LOG-FWD-DEFAULT" in text and "PROFILE-GROUP-DEFAULT" in text
    assert "the network team" in text
    assert "Navigate to: Commit > Commit to Panorama" in text
    assert "- Commit Summary" in text and "- Validate" in text and "- Commit" in text
    for h in ("## Impact Analysis Statement", "## Backout Plan", "## Validation Plan", "## Communications Plan"):
        assert h in text
    assert "## Implementation (CLI)" in text and text.index("## Implementation Plan") < text.index("## Implementation (CLI)")
    parts = changeplan_sections(_cs(tmp_path))
    assert "### Add Policy" in parts["cr"] and "set device-group" in parts["cli"]
    assert "delete device-group" in parts["rollback"]
    assert "test security-policy-match" in parts["verify"]


def test_standalone_plan_uses_firewall_paths(tmp_path):
    cs = _fw_cs(tmp_path, [("10.1.20.5", None, "8.8.8.8", None, "TCP", "22", None, "z", None)])
    text = render_changeplan(cs)
    assert text.startswith("# Firewall Change Request")
    assert "Policies > Security > Pre Rules" not in text
    assert "Navigate to: Policies > Security" in text
    assert "Device > Setup > Operations > Load configuration version" in text
    assert "Commit > Commit to Panorama" not in text
    assert "Navigate to: Commit\n" in text or "Navigate to: Commit\r\n" in text or "Navigate to: Commit\n\n" in text


def test_edit_policy_bullets(tmp_path):
    cs = _cs(tmp_path)
    rule = cs["groups"][0]["rules"][0]
    rule["operation"] = "edit"
    rule["edits"] = [{"action": "Add source address", "values": ["TST-H-10.0.0.1", "TST-H-10.0.0.2"]}]
    text = render_changeplan(cs)
    assert "### Edit Policy" in text
    assert "- Rule: `" + rule["name"] + "`" in text
    assert "- Add source address:" in text
    assert "  - `TST-H-10.0.0.1`" in text
    assert "### Add Policy\n\nNavigate to: Policies > Security > Pre Rules (Device Group: " + cs["groups"][0]["device_group"] + ")\n\n#### General\n- Name: `" + rule["name"] + "`" not in text


def test_change_plan_local_override(tmp_path, monkeypatch):
    import shutil

    src = Path(__file__).resolve().parents[1] / "tests" / "customers"
    cdir = tmp_path / "customers"
    shutil.copytree(src, cdir)
    (cdir / "fwtest" / "profile.local.yaml").write_text(
        "change_plan:\n  log_forwarding: LOG-FWD-TST-TEST\n  team_name: the fwtest operators\n",
        encoding="utf-8",
    )
    odir = tmp_path / "overrides"
    odir.mkdir()
    (odir / "fwtest.yaml").write_text(
        "change_plan:\n  profile_group: PROFILE-GROUP-TST-TEST\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("PANLAB_CUSTOMERS_DIR", str(cdir))
    monkeypatch.setenv("PANLAB_CUSTOMER_OVERRIDE_DIR", str(odir))
    cfg = load_profile("fwtest").change_plan
    assert cfg["log_forwarding"] == "LOG-FWD-TST-TEST"
    assert cfg["profile_group"] == "PROFILE-GROUP-TST-TEST"
    assert cfg["team_name"] == "the fwtest operators"
    assert "the fwtest operators will notify" in cfg["communications_plan"]
    cs = _fw_cs(tmp_path, [("10.1.20.5", None, "8.8.8.8", None, "TCP", "22", None, "z", None)])
    text = render_changeplan(cs)
    assert "LOG-FWD-TST-TEST" in text and "PROFILE-GROUP-TST-TEST" in text
    assert "LOG-FWD-DEFAULT" not in text
    assert "the fwtest operators" in text


def test_committed_profiles_stay_generic():
    for name in ("fwtest", "example-pano"):
        cfg = load_profile(name).change_plan
        assert cfg["log_forwarding"] == "LOG-FWD-DEFAULT"
        assert cfg["profile_group"] == "PROFILE-GROUP-DEFAULT"
        assert cfg["team_name"] == "the network team"


def test_empty_changeset_explains_missing_steps():
    cs = {
        "customer": "fwtest", "created": "2026-11-17T09:00:00-06:00",
        "files": [{"tickets": {"ritm": [], "sctask": [], "cr": []}}],
        "groups": [], "requests": [], "unplaced": ["R001"],
        "summary": {"rules": 0, "new_objects": 0, "reused_objects": 0, "red_flags": 0, "needs_human": 1},
        "default_tags": [],
    }
    from panlab.changeplan import open_items, render_changeplan
    # open_items on this stub may only show none; still require the empty-plan wording
    text = render_changeplan(cs)
    assert "No policies or objects were placed" in text
    assert "No set commands: no rules or objects were placed" in text
