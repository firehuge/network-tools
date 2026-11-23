# SPDX-License-Identifier: Apache-2.0
"""Render a dry-run plan: objects and rules that would be created versus an offline config."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from panlab import PANORAMA_NOT_IMPLEMENTED
from panlab.addresses import normalize_spec
from panlab.configxml import ParsedConfig, parse_config
from panlab.validate import Issue, ValidationResult, validate_request


@dataclass
class PlannedObject:
    name: str
    value: str
    addr_type: str
    action: str  # create, reuse, conflict, skip
    description: str = ""
    note: str = ""


@dataclass
class PlannedRule:
    name: str
    action: str  # create, exists, skip
    from_zones: list[str]
    to_zones: list[str]
    source: list[str]
    destination: list[str]
    applications: list[str]
    services: list[str]
    rule_action: str
    description: str = ""
    log_start: bool = False
    log_end: bool = True
    disabled: bool = False


@dataclass
class Plan:
    target: dict[str, Any]
    objects: list[PlannedObject]
    rule: PlannedRule | None
    issues: list[Issue]
    supported: bool = True
    message: str = ""

    @property
    def ok(self) -> bool:
        return self.supported and not any(i.severity == "error" for i in self.issues)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "supported": self.supported,
            "message": self.message,
            "target": self.target,
            "objects": [asdict(o) for o in self.objects],
            "rule": asdict(self.rule) if self.rule else None,
            "issues": [asdict(i) for i in self.issues],
        }


def _member_name(spec: Any) -> str:
    normalized = normalize_spec(spec)
    return normalized.get("name") or normalized.get("value") or "?"


def _collect_objects(rule: dict[str, Any], config: ParsedConfig | None) -> list[PlannedObject]:
    planned: list[PlannedObject] = []
    seen: set[str] = set()
    for spec in rule["source_addresses"] + rule["destination_addresses"]:
        normalized = normalize_spec(spec)
        name = normalized.get("name")
        value = normalized.get("value")
        addr_type = normalized.get("type") or "ip-netmask"
        if not name or name == "any" or normalized.get("literal"):
            continue
        if name in seen:
            continue
        seen.add(name)
        if not value or addr_type == "object":
            if config is not None and name in config.addresses:
                existing = config.addresses[name]
                planned.append(
                    PlannedObject(
                        name=name,
                        value=existing.value,
                        addr_type=existing.addr_type,
                        action="reuse",
                        note="existing object referenced by name",
                    )
                )
            else:
                planned.append(
                    PlannedObject(
                        name=name,
                        value=value or "",
                        addr_type=addr_type,
                        action="skip",
                        note="referenced by name only; no value provided to create",
                    )
                )
            continue
        description = normalized.get("description") or ""
        if config is not None and name in config.addresses:
            existing = config.addresses[name]
            if existing.value == value and existing.addr_type == addr_type:
                planned.append(
                    PlannedObject(
                        name=name,
                        value=value,
                        addr_type=addr_type,
                        action="reuse",
                        description=description,
                        note=f"already present as {existing.addr_type} {existing.value}",
                    )
                )
            else:
                planned.append(
                    PlannedObject(
                        name=name,
                        value=value,
                        addr_type=addr_type,
                        action="conflict",
                        description=description,
                        note=f"exists as {existing.addr_type} {existing.value}",
                    )
                )
        else:
            planned.append(
                PlannedObject(
                    name=name,
                    value=value,
                    addr_type=addr_type,
                    action="create",
                    description=description,
                )
            )
    return planned


def _planned_rule(rule: dict[str, Any], config: ParsedConfig | None) -> PlannedRule:
    action = "create"
    if config is not None and any(r.name == rule["name"] for r in config.rules):
        action = "exists"
    return PlannedRule(
        name=rule["name"],
        action=action,
        from_zones=list(rule["from_zones"]),
        to_zones=list(rule["to_zones"]),
        source=[_member_name(s) for s in rule["source_addresses"]],
        destination=[_member_name(s) for s in rule["destination_addresses"]],
        applications=list(rule["applications"]),
        services=list(rule["services"]),
        rule_action=rule["action"],
        description=rule.get("description") or "",
        log_start=bool(rule.get("log_start", False)),
        log_end=bool(rule.get("log_end", True)),
        disabled=bool(rule.get("disabled", False)),
    )


def build_plan(
    request: dict[str, Any] | Path | str,
    *,
    config: ParsedConfig | Path | str | None = None,
    schema: dict[str, Any] | Path | str | None = None,
) -> Plan:
    result: ValidationResult = validate_request(request, config=config, schema=schema)
    data = result.request
    target = data.get("target") or {}
    if target.get("type") == "panorama":
        return Plan(
            target=target,
            objects=[],
            rule=None,
            issues=result.issues,
            supported=False,
            message=PANORAMA_NOT_IMPLEMENTED,
        )

    parsed_config: ParsedConfig | None
    if isinstance(config, ParsedConfig):
        parsed_config = config
    elif config is not None and target.get("type") == "firewall":
        try:
            parsed_config = parse_config(config, target.get("vsys") or "vsys1")
        except (OSError, ValueError):
            parsed_config = None
    else:
        parsed_config = None

    rule = data.get("rule") or {}
    objects = _collect_objects(rule, parsed_config) if rule else []
    planned_rule = _planned_rule(rule, parsed_config) if rule else None
    return Plan(
        target=target,
        objects=objects,
        rule=planned_rule,
        issues=result.issues,
        supported=True,
        message="",
    )


def render_plan(plan: Plan) -> str:
    lines: list[str] = []
    target = plan.target
    title = "Plan"
    ticket = ""
    if target:
        if target.get("type") == "firewall":
            title = f"Plan for firewall {target.get('firewall')} / {target.get('vsys') or 'vsys1'}"
        elif target.get("type") == "panorama":
            title = (
                f"Plan for panorama {target.get('panorama')} / "
                f"device_group {target.get('device_group')}"
            )
    lines.append(title)
    lines.append("=" * len(title))

    if not plan.supported:
        lines.append("")
        lines.append(plan.message or PANORAMA_NOT_IMPLEMENTED)
        if plan.issues:
            lines.append("")
            lines.extend(_render_issues(plan.issues))
        return "\n".join(lines) + "\n"

    lines.append("")
    lines.append("Address objects:")
    if not plan.objects:
        lines.append("  (none to create or reuse)")
    for obj in plan.objects:
        marker = {"create": "+", "reuse": "=", "conflict": "!", "skip": "?"}.get(obj.action, "-")
        extra = f"  ({obj.note})" if obj.note else ""
        lines.append(f"  {marker} {obj.action:8} {obj.name} = {obj.value} [{obj.addr_type}]{extra}")

    lines.append("")
    lines.append("Security rule:")
    if plan.rule is None:
        lines.append("  (none)")
    else:
        rule = plan.rule
        marker = {"create": "+", "exists": "!"}.get(rule.action, "-")
        lines.append(f"  {marker} {rule.action} {rule.name}")
        lines.append(f"      from:        {', '.join(rule.from_zones)}")
        lines.append(f"      to:          {', '.join(rule.to_zones)}")
        lines.append(f"      source:      {', '.join(rule.source)}")
        lines.append(f"      destination: {', '.join(rule.destination)}")
        lines.append(f"      app:         {', '.join(rule.applications)}")
        lines.append(f"      service:     {', '.join(rule.services)}")
        lines.append(f"      action:      {rule.rule_action}")
        lines.append(f"      log_end:     {rule.log_end}")
        if rule.description:
            lines.append(f"      description: {rule.description}")
        lines.append("")
        lines.append("Candidate XML (illustrative, not pushed):")
        lines.append(_rule_xml_snippet(rule))

    if plan.issues:
        lines.append("")
        lines.extend(_render_issues(plan.issues))
    elif plan.ok:
        lines.append("")
        lines.append("No errors or warnings.")
    return "\n".join(lines) + "\n"


def _render_issues(issues: list[Issue]) -> list[str]:
    lines = ["Issues:"]
    for issue in issues:
        location = f" @ {issue.path}" if issue.path else ""
        lines.append(f"  [{issue.severity}] {issue.code}{location}: {issue.message}")
    return lines


def _rule_xml_snippet(rule: PlannedRule) -> str:
    def members(tag: str, values: list[str]) -> str:
        inner = "".join(f"<member>{_escape(v)}</member>" for v in values)
        return f"    <{tag}>{inner}</{tag}>"

    lines = [
        f'  <entry name="{_escape(rule.name)}">',
        members("from", rule.from_zones),
        members("to", rule.to_zones),
        members("source", rule.source),
        members("destination", rule.destination),
        members("application", rule.applications),
        members("service", rule.services),
        f"    <action>{_escape(rule.rule_action)}</action>",
        f"    <log-end>{'yes' if rule.log_end else 'no'}</log-end>",
    ]
    if rule.log_start:
        lines.append("    <log-start>yes</log-start>")
    if rule.description:
        lines.append(f"    <description>{_escape(rule.description)}</description>")
    if rule.disabled:
        lines.append("    <disabled>yes</disabled>")
    lines.append("  </entry>")
    return "\n".join(lines)


def _escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
