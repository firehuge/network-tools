"""Validate a rule request against the schema, naming rules, and an optional offline config."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from xml.etree.ElementTree import ParseError

import jsonschema
import yaml

from panlab import PANORAMA_NOT_IMPLEMENTED
from panlab.addresses import (
    OBJECT_NAME_RE,
    RULE_NAME_RE,
    ZONE_NAME_RE,
    host_bits_set,
    looks_like_ip_literal,
    networks_overlap,
    normalize_spec,
    parse_address_value,
)
from panlab.configxml import ParsedConfig, parse_config, resolve_member
from panlab.paths import schema_path

SPECIAL_ADDRESSES = {"any"}
SPECIAL_SERVICES = {"any", "application-default"}
SPECIAL_APPS = {"any"}


@dataclass
class Issue:
    severity: str  # error, warning, info
    code: str
    message: str
    path: str | None = None


@dataclass
class ValidationResult:
    ok: bool
    issues: list[Issue] = field(default_factory=list)
    request: dict[str, Any] = field(default_factory=dict)

    @property
    def errors(self) -> list[Issue]:
        return [i for i in self.issues if i.severity == "error"]

    @property
    def warnings(self) -> list[Issue]:
        return [i for i in self.issues if i.severity == "warning"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "issues": [asdict(i) for i in self.issues],
            "request": self.request,
        }


def load_yaml(path: Path | str) -> dict[str, Any]:
    with Path(path).open(encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, dict):
        raise ValueError("request file must contain a YAML mapping")
    return data


def load_schema(path: Path | str | None = None) -> dict[str, Any]:
    with (Path(path) if path else schema_path()).open(encoding="utf-8") as handle:
        return json.load(handle)


def _issue(issues: list[Issue], severity: str, code: str, message: str, path: str | None = None) -> None:
    issues.append(Issue(severity=severity, code=code, message=message, path=path))


def _schema_issues(request: dict[str, Any], schema: dict[str, Any]) -> list[Issue]:
    issues: list[Issue] = []
    validator = jsonschema.Draft202012Validator(schema)
    for error in sorted(validator.iter_errors(request), key=lambda e: list(e.path)):
        path = ".".join(str(p) for p in error.absolute_path) or "$"
        _issue(issues, "error", "schema", error.message, path)
    return issues


def _validate_named(value: str, pattern, path: str, issues: list[Issue], kind: str) -> None:
    if not pattern.match(value):
        _issue(
            issues,
            "error",
            "naming",
            f"invalid {kind} {value!r}: must start with a letter and use only letters, "
            "digits, dot, underscore, or hyphen (max 63 characters)",
            path,
        )


def _check_address_spec(spec: Any, path: str, issues: list[Issue]) -> dict[str, Any] | None:
    try:
        normalized = normalize_spec(spec)
    except ValueError as exc:
        _issue(issues, "error", "address", str(exc), path)
        return None

    name = normalized.get("name")
    if name and name not in SPECIAL_ADDRESSES:
        _validate_named(name, OBJECT_NAME_RE, f"{path}.name" if not isinstance(spec, str) else path, issues, "object name")

    value = normalized.get("value")
    addr_type = normalized.get("type") or "ip-netmask"

    if normalized.get("literal") or (value and addr_type in {"ip-netmask", "ip-range", "fqdn"}):
        if not value:
            _issue(issues, "error", "address", "address object is missing a value", path)
            return normalized
        try:
            parse_address_value(value, "ip-netmask" if addr_type == "object" else addr_type)
        except ValueError as exc:
            _issue(issues, "error", "cidr", f"{exc}", path)
            return normalized
        if addr_type in {"ip-netmask", "object"} and looks_like_ip_literal(value) and host_bits_set(value):
            _issue(
                issues,
                "warning",
                "host-bits",
                f"{value} has host bits set; PAN-OS will accept it, but the covering network "
                f"is {parse_address_value(value, 'ip-netmask').networks[0]}",
                path,
            )
    return normalized


def _resolved_from_spec(spec: dict[str, Any], config: ParsedConfig | None) -> list:
    value = spec.get("value")
    addr_type = spec.get("type") or "ip-netmask"
    name = spec.get("name")
    parsed = []
    if value and addr_type in {"ip-netmask", "ip-range", "fqdn", "any"}:
        try:
            parsed.append(parse_address_value(value, addr_type if addr_type != "any" else "ip-netmask"))
        except ValueError:
            pass
        return parsed
    if name:
        resolved = resolve_member(name, config)
        if resolved is not None:
            parsed.append(resolved)
    return parsed


def _members_overlap(left: list, right: list) -> bool | None:
    known = False
    for a in left:
        for b in right:
            result = networks_overlap(a, b)
            if result is True:
                return True
            if result is False:
                known = True
    if known and left and right:
        return False
    return None


def _sets_overlap(left: list[str], right: list[str], any_values: set[str]) -> bool:
    left_s = {x.lower() for x in left}
    right_s = {x.lower() for x in right}
    if left_s & any_values or right_s & any_values:
        return True
    return bool(left_s & right_s)


def _rule_overlap(request_rule: dict[str, Any], existing, src_resolved, dst_resolved, config: ParsedConfig) -> bool:
    if not _sets_overlap(request_rule["from_zones"], existing.from_zones, {"any"}):
        return False
    if not _sets_overlap(request_rule["to_zones"], existing.to_zones, {"any"}):
        return False
    if not _sets_overlap(request_rule["applications"], existing.applications, SPECIAL_APPS):
        return False
    # application-default is service-shaped, not a real port; treat name intersection
    # and "any" as overlap. application-default vs a named service is uncertain, so
    # keep the check at "possible" when apps already overlap.
    if not (
        _sets_overlap(request_rule["services"], existing.services, SPECIAL_SERVICES)
        or "application-default" in {s.lower() for s in request_rule["services"] + existing.services}
    ):
        return False
    existing_src = [p for m in existing.source if (p := resolve_member(m, config)) is not None]
    existing_dst = [p for m in existing.destination if (p := resolve_member(m, config)) is not None]
    src = _members_overlap(src_resolved, existing_src)
    dst = _members_overlap(dst_resolved, existing_dst)
    if src is False or dst is False:
        return False
    # If we cannot resolve IPs, still warn when zone/app/service and member names overlap.
    if src is None and dst is None:
        return bool(
            set(request_rule.get("_source_names", [])) & set(existing.source)
            or set(request_rule.get("_dest_names", [])) & set(existing.destination)
            or "any" in {m.lower() for m in existing.source + existing.destination}
        )
    return True


def validate_request(
    request: dict[str, Any] | Path | str,
    *,
    config: ParsedConfig | Path | str | None = None,
    schema: dict[str, Any] | Path | str | None = None,
) -> ValidationResult:
    issues: list[Issue] = []
    if isinstance(request, (Path, str)):
        try:
            request = load_yaml(request)
        except (OSError, yaml.YAMLError, ValueError) as exc:
            return ValidationResult(ok=False, issues=[Issue("error", "load", str(exc), str(request))])

    schema_data = load_schema(schema) if not isinstance(schema, dict) else schema
    issues.extend(_schema_issues(request, schema_data))
    if any(i.code == "schema" and i.severity == "error" for i in issues):
        return ValidationResult(ok=False, issues=issues, request=request)

    target = request["target"]
    if target.get("type") == "panorama":
        _issue(issues, "warning", "panorama-stub", PANORAMA_NOT_IMPLEMENTED, "target")

    rule = request["rule"]
    _validate_named(rule["name"], RULE_NAME_RE, "rule.name", issues, "rule name")
    for index, zone in enumerate(rule["from_zones"]):
        _validate_named(zone, ZONE_NAME_RE, f"rule.from_zones[{index}]", issues, "zone name")
    for index, zone in enumerate(rule["to_zones"]):
        _validate_named(zone, ZONE_NAME_RE, f"rule.to_zones[{index}]", issues, "zone name")

    if set(rule["from_zones"]) == set(rule["to_zones"]) and "any" not in {z.lower() for z in rule["from_zones"]}:
        _issue(
            issues,
            "info",
            "intrazone",
            "from and to zones are the same; this is an intrazone rule",
            "rule",
        )

    source_specs = []
    dest_specs = []
    for index, spec in enumerate(rule["source_addresses"]):
        normalized = _check_address_spec(spec, f"rule.source_addresses[{index}]", issues)
        if normalized:
            source_specs.append(normalized)
    for index, spec in enumerate(rule["destination_addresses"]):
        normalized = _check_address_spec(spec, f"rule.destination_addresses[{index}]", issues)
        if normalized:
            dest_specs.append(normalized)

    parsed_config: ParsedConfig | None = None
    if config is not None:
        vsys = target.get("vsys") or "vsys1"
        if isinstance(config, ParsedConfig):
            parsed_config = config
        else:
            try:
                parsed_config = parse_config(config, vsys)
            except (OSError, ParseError, ValueError) as exc:
                _issue(issues, "error", "config", f"could not parse offline config: {exc}", str(config))
                return ValidationResult(ok=False, issues=issues, request=request)

        if parsed_config:
            for index, zone in enumerate(rule["from_zones"] + rule["to_zones"]):
                if zone.lower() != "any" and parsed_config.zones and zone not in parsed_config.zones:
                    side = "from_zones" if index < len(rule["from_zones"]) else "to_zones"
                    _issue(
                        issues,
                        "warning",
                        "unknown-zone",
                        f"zone {zone!r} was not found in vsys {parsed_config.vsys} "
                        f"(known: {', '.join(parsed_config.zones)})",
                        f"rule.{side}",
                    )

            from_types = {
                parsed_config.zone_types.get(z, "unknown")
                for z in rule["from_zones"]
                if z.lower() != "any"
            }
            to_types = {
                parsed_config.zone_types.get(z, "unknown")
                for z in rule["to_zones"]
                if z.lower() != "any"
            }
            from_types.discard("unknown")
            to_types.discard("unknown")
            if from_types and to_types and from_types != to_types:
                _issue(
                    issues,
                    "error",
                    "zone-type-mismatch",
                    "from and to zones are incompatible types: "
                    f"from {sorted(from_types)} vs to {sorted(to_types)}. "
                    "PAN-OS cannot mix layer3 and virtual-wire (or other unlike "
                    "zone types) in one security rule",
                    "rule",
                )

            existing_names = {r.name for r in parsed_config.rules}
            if rule["name"] in existing_names:
                _issue(
                    issues,
                    "error",
                    "duplicate-rule",
                    f"a security rule named {rule['name']!r} already exists in vsys {parsed_config.vsys}",
                    "rule.name",
                )

            for spec in source_specs + dest_specs:
                name = spec.get("name")
                value = spec.get("value")
                addr_type = spec.get("type") or "ip-netmask"
                if not name or name in SPECIAL_ADDRESSES:
                    continue
                current = parsed_config.addresses.get(name)
                if current is None:
                    if not value:
                        _issue(
                            issues,
                            "warning",
                            "unknown-object",
                            f"address object {name!r} is referenced by name but was not found "
                            f"in vsys {parsed_config.vsys} and no value was given to create it",
                            "rule",
                        )
                    continue
                if not value or (current.value == value and (addr_type in {current.addr_type, "object"})):
                    _issue(
                        issues,
                        "info",
                        "reuse-object",
                        f"address object {name!r} already exists with value {current.value}",
                        "rule",
                    )
                else:
                    _issue(
                        issues,
                        "error",
                        "object-conflict",
                        f"address object {name!r} already exists as {current.addr_type} {current.value}, "
                        f"not {addr_type} {value}",
                        "rule",
                    )

            src_resolved: list = []
            dst_resolved: list = []
            source_names = []
            dest_names = []
            for spec in source_specs:
                src_resolved.extend(_resolved_from_spec(spec, parsed_config))
                source_names.append(spec.get("name") or spec.get("value"))
            for spec in dest_specs:
                dst_resolved.extend(_resolved_from_spec(spec, parsed_config))
                dest_names.append(spec.get("name") or spec.get("value"))
            overlap_rule = dict(rule)
            overlap_rule["_source_names"] = source_names
            overlap_rule["_dest_names"] = dest_names
            for existing in parsed_config.rules:
                if existing.disabled or existing.name == rule["name"]:
                    continue
                if _rule_overlap(overlap_rule, existing, src_resolved, dst_resolved, parsed_config):
                    _issue(
                        issues,
                        "warning",
                        "overlap",
                        f"request may overlap existing rule {existing.name!r} "
                        f"(zones {existing.from_zones}->{existing.to_zones}, action {existing.action})",
                        "rule",
                    )

    ok = not any(i.severity == "error" for i in issues)
    return ValidationResult(ok=ok, issues=issues, request=request)
