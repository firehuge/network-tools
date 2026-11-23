"""Read-only live snapshot, rate limit, and RO-key preference. Synthetic devices only."""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest
import yaml

from fake_panos import FakeBox, live_factory_for
from panlab.customers import load_profile
from panlab.liveconfig import (
    cache_status,
    can_live_pull,
    rate_limited,
    refresh_snapshot,
    settings_for_read,
)
import panlab.liveconfig as liveconfig


@pytest.fixture
def fwtest(tmp_path, monkeypatch):
    d = tmp_path / "customers" / "acme"
    d.mkdir(parents=True)
    (d / "profile.yaml").write_text(
        "name: acme\n"
        "targets:\n"
        "  - name: pano\n"
        "    type: panorama\n"
        "    host_env: ACME_PANO_HOST\n"
        "    api_key_env: ACME_PANO_API_KEY\n"
        "    api_key_ro_env: ACME_PANO_API_KEY_RO\n"
        "  - name: fw\n"
        "    type: firewall\n"
        "    host_env: ACME_FW_HOST\n"
        "    api_key_env: ACME_FW_API_KEY\n"
        "    api_key_ro_env: ACME_FW_API_KEY_RO\n"
    )
    monkeypatch.setenv("PANLAB_CUSTOMERS_DIR", str(tmp_path / "customers"))
    monkeypatch.setenv("PANLAB_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("ACME_PANO_HOST", "192.0.2.10")
    monkeypatch.setenv("ACME_FW_HOST", "192.0.2.20")
    monkeypatch.setenv("PANLAB_LIVE_REFRESH_SECONDS", "60")
    pano = FakeBox("ACME-PANO", kind="panorama", serial="P100")
    fw = FakeBox("ACME-FW", serial="F100")
    pano.managed = [fw]
    pano.running_xml = "<config version='11.1.0'><devices><entry name='localhost.localdomain'><device-group/></entry></devices></config>"
    pano.candidate_xml = "<config version='11.1.0'><devices><entry name='localhost.localdomain'><device-group><entry name='DG-NEW'/></device-group></entry></devices></config>"
    fw.running_xml = "<config version='11.1.0'><devices><entry name='localhost.localdomain'><vsys><entry name='vsys1'/></vsys></entry></devices></config>"
    monkeypatch.setattr(liveconfig, "device_factory", live_factory_for({"pano": pano, "fw": fw}))
    return load_profile("acme"), {"pano": pano, "fw": fw}


def test_prefers_read_only_key(fwtest, monkeypatch):
    prof, _ = fwtest
    monkeypatch.setenv("ACME_PANO_API_KEY", "admin-secret-key")
    monkeypatch.setenv("ACME_PANO_API_KEY_RO", "readonly-secret-key")
    st, mode = settings_for_read(prof, prof.targets[0])
    assert mode == "readonly"
    assert st.api_key == "readonly-secret-key"
    # Admin key is used only when no RO key is set.
    monkeypatch.delenv("ACME_PANO_API_KEY_RO")
    st, mode = settings_for_read(prof, prof.targets[0])
    assert mode == "admin" and st.api_key == "admin-secret-key"


def test_can_live_pull_with_either_key(fwtest, monkeypatch):
    prof, _ = fwtest
    assert can_live_pull(prof) is False
    monkeypatch.setenv("ACME_PANO_API_KEY_RO", "readonly-secret-key")
    assert can_live_pull(prof) is True


def test_snapshot_pulls_running_candidate_and_managed_firewall(fwtest, monkeypatch):
    prof, boxes = fwtest
    monkeypatch.setenv("ACME_PANO_API_KEY_RO", "readonly-secret-key")
    monkeypatch.setenv("ACME_FW_API_KEY_RO", "readonly-fw-key")
    snap = refresh_snapshot(prof)
    assert snap.rate_limited is False
    roles = {(f["role"], f.get("serial") or f["target"]) for f in snap.meta["files"] if f["role"] in {"running", "candidate"}}
    assert ("running", "pano") in roles
    assert ("candidate", "pano") in roles
    assert ("running", "F100") in roles
    # Candidate differs from running on Panorama.
    cand = next(f for f in snap.meta["files"] if f["role"] == "candidate" and f["target"] == "pano")
    assert cand.get("differs") is True
    assert snap.meta["credential_mode"] == "readonly"
    assert snap.meta["used_admin_key"] is False
    paths = snap.config_files()
    names = [p.name for p in paths]
    assert any("candidate" in n for n in names)
    assert any("F100" in n or n.startswith("fw-") for n in names)
    # Policy comes from Panorama; skip the managed firewall's non-serial
    # export (local-only, no pushed policy) when a serial-named pull exists.
    assert snap.meta.get("policy_source") == "panorama"
    assert not any(n == "fw-running.xml" for n in names)
    assert any(n.startswith("pano-") and n.endswith("-running.xml") for n in names)
    st = cache_status(prof)
    assert st["file_count"] >= 3
    assert st["used_admin_key"] is False
    # Secrets never land in the cache metadata.
    raw = (Path(snap.meta["files"][0]["path"]).parent / "meta.json").read_text()
    assert "readonly-secret-key" not in raw and "admin-secret" not in raw


def test_admin_key_fallback_is_recorded(fwtest, monkeypatch):
    prof, _ = fwtest
    monkeypatch.setenv("ACME_PANO_API_KEY", "admin-secret-key")
    monkeypatch.setenv("ACME_FW_API_KEY", "admin-fw-key")
    snap = refresh_snapshot(prof)
    assert snap.meta["used_admin_key"] is True
    assert snap.meta["credential_mode"] in {"admin", "password"}


def test_rate_limit_returns_cached_snapshot(fwtest, monkeypatch):
    prof, _ = fwtest
    monkeypatch.setenv("ACME_PANO_API_KEY_RO", "readonly-secret-key")
    monkeypatch.setenv("ACME_FW_API_KEY_RO", "readonly-fw-key")
    first = refresh_snapshot(prof)
    t0 = first.pulled_at
    limited, wait = rate_limited(prof)
    assert limited and wait > 0
    second = refresh_snapshot(prof)  # force=False
    assert second.rate_limited is True
    assert second.pulled_at.replace(microsecond=0) == t0.replace(microsecond=0)
    # After the window, a new pull runs.
    monkeypatch.setattr(liveconfig, "now", lambda: t0 + timedelta(seconds=61))
    limited, wait = rate_limited(prof)
    assert limited is False
    third = refresh_snapshot(prof)
    assert third.rate_limited is False
    assert third.pulled_at > t0


def test_no_secrets_in_profile_yaml():
    # Guard: profiles mention only env var names.
    root = Path(__file__).resolve().parents[1]
    for p in (root / "tests" / "customers").glob("*/profile.yaml"):
        raw = p.read_text()
        assert "api_key:" not in raw or "api_key_env:" in raw
        data = yaml.safe_load(raw)
        for t in data.get("targets") or []:
            assert "api_key" not in t and "api_key_ro" not in t and "password" not in t
