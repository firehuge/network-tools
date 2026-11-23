from pathlib import Path

import pytest

from panlab import PANORAMA_NOT_IMPLEMENTED
from panlab.cli import main
from panlab.plan import build_plan, render_plan
from panlab.push import push_request


def test_plan_creates_new_object_and_reuses_existing(example_request: Path, config_xml: Path) -> None:
    plan = build_plan(example_request, config=config_xml)
    assert plan.ok
    assert plan.supported
    by_name = {obj.name: obj for obj in plan.objects}
    assert by_name["fwtest-app-server"].action == "create"
    assert by_name["fwtest-app-server"].value == "10.20.20.11/32"
    assert by_name["fwtest-user-subnet"].action == "reuse"
    assert plan.rule is not None
    assert plan.rule.action == "create"
    assert plan.rule.name == "TST-allow-trust-to-app"
    assert plan.rule.source == ["fwtest-user-subnet"]
    assert plan.rule.destination == ["fwtest-app-server"]


def test_plan_render_includes_xml_snippet(example_request: Path, config_xml: Path) -> None:
    text = render_plan(build_plan(example_request, config=config_xml))
    assert "fwtest-app-server = 10.20.20.11/32" in text
    assert "+ create" in text
    assert "= reuse" in text
    assert 'entry name="TST-allow-trust-to-app"' in text
    assert "<member>trust</member>" in text
    assert "fwtest-user-subnet" in text


def test_plan_existing_rule_is_flagged(fixtures: Path, config_xml: Path) -> None:
    plan = build_plan(fixtures / "duplicate-rule.yaml", config=config_xml)
    assert not plan.ok
    assert plan.rule is not None
    assert plan.rule.action == "exists"


def test_plan_object_conflict(fixtures: Path, config_xml: Path) -> None:
    plan = build_plan(fixtures / "object-conflict.yaml", config=config_xml)
    assert not plan.ok
    conflict = next(obj for obj in plan.objects if obj.name == "fwtest-web-server")
    assert conflict.action == "conflict"
    assert "10.20.20.10/32" in conflict.note


def test_plan_overlap_warning_in_render(fixtures: Path, config_xml: Path) -> None:
    plan = build_plan(fixtures / "overlap-request.yaml", config=config_xml)
    assert plan.ok
    text = render_plan(plan)
    assert "overlap" in text
    assert "TST-allow-users-to-web" in text
    # Literal CIDRs are used as members when no object is named.
    assert "10.10.10.0/24" in text
    assert "10.20.20.10/32" in text


def test_plan_refuses_panorama(fixtures: Path) -> None:
    plan = build_plan(fixtures / "panorama-request.yaml")
    assert not plan.supported
    assert plan.rule is None
    assert plan.objects == []
    text = render_plan(plan)
    assert "device_group" in text
    assert PANORAMA_NOT_IMPLEMENTED in text


def test_push_default_is_dry_run(example_request: Path, config_xml: Path) -> None:
    result = push_request(example_request, config=config_xml)
    assert result.dry_run is True
    assert result.applied is False
    assert result.committed is False
    assert result.backup_path is None
    assert "fwtest-app-server" in result.created_objects
    assert "fwtest-user-subnet" in result.reused_objects
    assert "Dry-run only" in result.message


def test_push_refuses_panorama(fixtures: Path) -> None:
    with pytest.raises(RuntimeError, match="not implemented yet"):
        push_request(fixtures / "panorama-request.yaml", apply=True)


def test_push_refuses_conflicts(fixtures: Path, config_xml: Path) -> None:
    with pytest.raises(RuntimeError, match="already exists"):
        push_request(fixtures / "object-conflict.yaml", config=config_xml, apply=True)


def test_cli_plan_and_push_dry_run(example_request: Path, config_xml: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["plan", str(example_request), "--config", str(config_xml)]) == 0
    out = capsys.readouterr().out
    assert "TST-allow-trust-to-app" in out
    assert main(["push", str(example_request), "--config", str(config_xml)]) == 0
    out = capsys.readouterr().out
    assert "Dry-run only" in out


def test_cli_plan_panorama_exits_two(fixtures: Path) -> None:
    assert main(["plan", str(fixtures / "panorama-request.yaml")]) == 2


