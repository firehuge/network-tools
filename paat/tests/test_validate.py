from pathlib import Path

import pytest

from panlab import PANORAMA_NOT_IMPLEMENTED
from panlab.cli import main
from panlab.validate import validate_request


def test_example_request_is_valid(example_request: Path, config_xml: Path) -> None:
    result = validate_request(example_request, config=config_xml)
    assert result.ok, [i.message for i in result.errors]
    codes = {i.code for i in result.issues}
    assert "duplicate-rule" not in codes
    assert "object-conflict" not in codes
    # fwtest-user-subnet is reused; fwtest-app-server is new (10.20.20.11 vs existing web .10)
    assert any(i.code == "reuse-object" and "fwtest-user-subnet" in i.message for i in result.issues)


def test_schema_rejects_missing_fields(tmp_path: Path) -> None:
    bad = tmp_path / "empty.yaml"
    bad.write_text("requester: fwtest-operator\n", encoding="utf-8")
    result = validate_request(bad)
    assert not result.ok
    assert any(i.code == "schema" for i in result.errors)


def test_bad_cidr(fixtures: Path, config_xml: Path) -> None:
    result = validate_request(fixtures / "bad-cidr.yaml", config=config_xml)
    assert not result.ok
    assert any(i.code == "cidr" for i in result.errors)


def test_bad_rule_name_is_schema_error(fixtures: Path) -> None:
    result = validate_request(fixtures / "bad-name.yaml")
    assert not result.ok
    assert any(i.code == "schema" and "rule.name" in (i.path or "") for i in result.errors)


def test_duplicate_rule_name(fixtures: Path, config_xml: Path) -> None:
    result = validate_request(fixtures / "duplicate-rule.yaml", config=config_xml)
    assert not result.ok
    assert any(i.code == "duplicate-rule" for i in result.errors)


def test_object_conflict(fixtures: Path, config_xml: Path) -> None:
    result = validate_request(fixtures / "object-conflict.yaml", config=config_xml)
    assert not result.ok
    assert any(i.code == "object-conflict" and "fwtest-web-server" in i.message for i in result.errors)


def test_overlap_warning(fixtures: Path, config_xml: Path) -> None:
    result = validate_request(fixtures / "overlap-request.yaml", config=config_xml)
    assert result.ok
    assert any(i.code == "overlap" and "TST-allow-users-to-web" in i.message for i in result.warnings)


def test_non_overlapping_existing_rule_is_silent(example_request: Path, config_xml: Path) -> None:
    result = validate_request(example_request, config=config_xml)
    overlap = [i for i in result.warnings if i.code == "overlap" and "TST-allow-mgmt-to-dns" in i.message]
    assert overlap == []


def test_host_bits_warning(fixtures: Path, config_xml: Path) -> None:
    result = validate_request(fixtures / "host-bits.yaml", config=config_xml)
    assert result.ok
    assert any(i.code == "host-bits" and "10.10.10.5/24" in i.message for i in result.warnings)


def test_unknown_zone_warning(tmp_path: Path, config_xml: Path) -> None:
    path = tmp_path / "req.yaml"
    path.write_text(
        """
requester: fwtest-operator
ticket: TST-009
target:
  type: firewall
  firewall: fw-1
  vsys: vsys1
rule:
  name: TST-unknown-zone
  from_zones: [trust]
  to_zones: [not-a-real-zone]
  source_addresses: [10.10.10.0/24]
  destination_addresses: [10.20.20.11/32]
  applications: [ssl]
  services: [application-default]
  action: allow
""",
        encoding="utf-8",
    )
    result = validate_request(path, config=config_xml)
    assert result.ok
    assert any(i.code == "unknown-zone" and "not-a-real-zone" in i.message for i in result.warnings)


def test_panorama_is_schema_valid_but_stubbed(fixtures: Path) -> None:
    result = validate_request(fixtures / "panorama-request.yaml")
    assert result.ok
    assert any(i.code == "panorama-stub" for i in result.warnings)
    assert any(PANORAMA_NOT_IMPLEMENTED[:40] in i.message for i in result.warnings)


def test_cli_validate_example_exits_zero(example_request: Path, config_xml: Path) -> None:
    assert main(["validate", str(example_request), "--config", str(config_xml)]) == 0


def test_cli_validate_bad_cidr_exits_one(fixtures: Path, config_xml: Path) -> None:
    assert main(["validate", str(fixtures / "bad-cidr.yaml"), "--config", str(config_xml)]) == 1





def test_layer3_to_virtual_wire_is_an_error(repo_root: Path, tmp_path: Path) -> None:
    path = tmp_path / "mismatch.yaml"
    path.write_text(
        """
requester: fwtest-operator
ticket: TST-ZONE-TYPE
target:
  type: firewall
  firewall: fw-1
  vsys: vsys1
rule:
  name: TST-bad-zone-types
  from_zones: [LAN]
  to_zones: [untrust]
  source_addresses: [192.0.2.0/24]
  destination_addresses: [192.0.2.80/32]
  applications: [ssl]
  services: [service-https]
  action: allow
""",
        encoding="utf-8",
    )
    cfg = tmp_path / "cfg.xml"
    cfg.write_text((repo_root / "tests" / "fixtures" / "synthetic-fw-test.xml").read_text(encoding="utf-8").replace(
        '<entry name="untrust"><network><layer3>', '<entry name="untrust"><network><virtual-wire>').replace(
        "<member>ethernet1/1</member></layer3></network></entry>", "<member>ethernet1/1</member></virtual-wire></network></entry>", 1),
        encoding="utf-8")
    result = validate_request(path, config=cfg)
    assert not result.ok
    assert any(i.code == "zone-type-mismatch" for i in result.errors)
