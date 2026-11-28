# SPDX-License-Identifier: Apache-2.0
"""Push a validated plan to the firewall candidate config. Default is dry-run."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from panlab import PANORAMA_NOT_IMPLEMENTED
from panlab.backup import backup_running_config
from panlab.plan import Plan, PlannedObject, PlannedRule, build_plan, render_plan
from panlab.settings import Settings, connect, load_settings


@dataclass
class PushResult:
    dry_run: bool
    applied: bool
    committed: bool
    backup_path: Path | None
    created_objects: list[str]
    reused_objects: list[str]
    rule_name: str | None
    message: str

    def to_text(self) -> str:
        lines = [self.message]
        if self.backup_path:
            lines.append(f"Backup written to {self.backup_path}")
        if self.created_objects:
            lines.append("Created objects: " + ", ".join(self.created_objects))
        if self.reused_objects:
            lines.append("Reused objects: " + ", ".join(self.reused_objects))
        if self.rule_name:
            state = "committed" if self.committed else ("written to candidate" if self.applied else "planned")
            lines.append(f"Rule {self.rule_name} ({state})")
        return "\n".join(lines) + "\n"


def _require_firewall_plan(plan: Plan) -> None:
    if plan.target.get("type") == "panorama" or not plan.supported:
        raise RuntimeError(plan.message or PANORAMA_NOT_IMPLEMENTED)
    if not plan.ok:
        errors = [i.message for i in plan.issues if i.severity == "error"]
        raise RuntimeError("refusing to push: " + ("; ".join(errors) or "validation failed"))
    if plan.rule is None:
        raise RuntimeError("plan does not include a security rule")
    if plan.rule.action == "exists":
        raise RuntimeError(f"security rule {plan.rule.name!r} already exists; refusing to overwrite")
    conflicts = [o for o in plan.objects if o.action == "conflict"]
    if conflicts:
        names = ", ".join(o.name for o in conflicts)
        raise RuntimeError(f"address object conflict: {names}")


def _create_address_object(fw, obj: PlannedObject, vsys: str) -> None:
    from panos.objects import AddressObject

    address = AddressObject(
        name=obj.name,
        value=obj.value,
        type=obj.addr_type,
        description=obj.description or None,
    )
    fw.add(address)
    address.create()


def _create_security_rule(fw, rule: PlannedRule, vsys: str) -> None:
    from panos.policies import Rulebase, SecurityRule

    rulebase = Rulebase()
    fw.add(rulebase)
    security = SecurityRule(
        name=rule.name,
        fromzone=rule.from_zones,
        tozone=rule.to_zones,
        source=rule.source,
        destination=rule.destination,
        application=rule.applications,
        service=rule.services,
        action=rule.rule_action,
        log_start=rule.log_start,
        log_end=rule.log_end,
        description=rule.description or None,
        disabled=rule.disabled,
        group=rule.profile_group or None,
    )
    rulebase.add(security)
    security.create()


def push_request(
    request: dict[str, Any] | Path | str,
    *,
    config: Path | str | None = None,
    apply: bool = False,
    commit: bool = False,
    settings: Settings | None = None,
    backup_dir: Path | str | None = None,
) -> PushResult:
    """Dry-run by default. ``commit=True`` implies apply and backs up first."""
    plan = build_plan(request, config=config)
    _require_firewall_plan(plan)

    if commit:
        apply = True

    if not apply:
        text = render_plan(plan)
        host = (settings or load_settings()).host or "(PANOS_HOST not set)"
        message = (
            f"Dry-run only. No changes were written to {host}.\n"
            "Re-run with --apply to write the candidate config, and add --commit "
            "only after a review if you want this tool to commit.\n\n"
            f"{text}"
        )
        return PushResult(
            dry_run=True,
            applied=False,
            committed=False,
            backup_path=None,
            created_objects=[o.name for o in plan.objects if o.action == "create"],
            reused_objects=[o.name for o in plan.objects if o.action == "reuse"],
            rule_name=plan.rule.name if plan.rule else None,
            message=message,
        )

    settings = settings or load_settings()
    backup_path = None
    if commit:
        backup_path = backup_running_config(dest_dir=backup_dir, settings=settings)

    fw = connect(settings)
    created = []
    reused = []
    vsys = plan.target.get("vsys") or settings.vsys
    for obj in plan.objects:
        if obj.action == "reuse":
            reused.append(obj.name)
            continue
        if obj.action == "create":
            _create_address_object(fw, obj, vsys)
            created.append(obj.name)
        elif obj.action == "skip":
            continue
        else:
            raise RuntimeError(f"cannot push address object {obj.name}: {obj.action}")

    assert plan.rule is not None
    _create_security_rule(fw, plan.rule, vsys)

    committed = False
    if commit:
        fw.commit(sync=True)
        committed = True
        message = (
            f"Wrote candidate config on {settings.host} and committed "
            f"(backup first). Review config logs / Config Audit on the device."
        )
    else:
        message = (
            f"Wrote objects and rule to the candidate config on {settings.host}. "
            "Nothing was committed. Review the candidate on the firewall and commit there, "
            "or re-run with --commit if you intend this tool to commit."
        )
    return PushResult(
        dry_run=False,
        applied=True,
        committed=committed,
        backup_path=backup_path,
        created_objects=created,
        reused_objects=reused,
        rule_name=plan.rule.name,
        message=message,
    )
