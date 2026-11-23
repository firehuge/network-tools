# SPDX-License-Identifier: Apache-2.0
"""CLI for the OS upgrade wizard (same code as the GUI).

  python -m panlab.upgrade discover <customer> [--no-refresh] [--no-managed]
  python -m panlab.upgrade plan <customer> <discovery-id> <device-id>=<version> ...
  python -m panlab.upgrade arm <customer> <plan-id> --cr CHG123 --approved [--ack-yellow]
  python -m panlab.upgrade step <customer> <plan-id> --confirm <device-name> [--wait]
  python -m panlab.upgrade poll <customer> <plan-id>
  python -m panlab.upgrade show <customer> <plan-id>
  python -m panlab.upgrade changeplan <customer> <plan-id>

discover is read-only. arm/step need PANLAB_UPGRADE_EXECUTE=1.
"""

from __future__ import annotations

import argparse
import json
import sys

from panlab.customers import load_profile
from panlab.upgrade import planner, runner
from panlab.upgrade.crplan import render_cr


def _summary(snap: dict) -> dict:
    out = {"id": snap["id"], "devices": []}
    for did in snap["order"]:
        f = snap["devices"][did]
        av = f.get("available") or []
        out["devices"].append({
            "id": did, "name": f.get("name"), "kind": f.get("kind"), "reachable": f.get("reachable"), "model": f.get("model"),
            "sw_version": f.get("sw_version"), "app_version": f.get("app_version"), "threat_version": f.get("threat_version"),
            "ha": (f.get("ha") or {}).get("enabled"), "pending_changes": f.get("pending_changes"),
            "repo_free_mb": (f.get("disk") or {}).get("repo_free_mb"), "panorama_status": f.get("panorama_status"),
            "managed_by": f.get("managed_by"), "managed": [(m.get("hostname"), m.get("sw_version"), m.get("connected")) for m in f.get("managed") or []],
            "software_source": f.get("software_source"), "versions_offered": len(av),
            "downloaded": [a["version"] for a in av if a.get("downloaded")],
            "recommended": f.get("recommended"), "errors": f.get("errors"), "warnings": f.get("warnings")})
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m panlab.upgrade")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("discover"); d.add_argument("customer"); d.add_argument("--no-refresh", action="store_true")
    d.add_argument("--no-managed", action="store_true"); d.add_argument("--full", action="store_true")
    p = sub.add_parser("plan"); p.add_argument("customer"); p.add_argument("snapshot"); p.add_argument("select", nargs="+")
    a = sub.add_parser("arm"); a.add_argument("customer"); a.add_argument("plan"); a.add_argument("--cr", required=True)
    a.add_argument("--approved", action="store_true"); a.add_argument("--ack-yellow", action="store_true")
    s = sub.add_parser("step"); s.add_argument("customer"); s.add_argument("plan"); s.add_argument("--confirm", required=True)
    s.add_argument("--wait", action="store_true"); s.add_argument("--interval", type=int, default=15)
    for n in ("poll", "show", "changeplan"):
        x = sub.add_parser(n); x.add_argument("customer"); x.add_argument("plan")
    ap.add_argument("--actor", default="cli")
    args = ap.parse_args(argv)
    prof = load_profile(args.customer)
    try:
        if args.cmd == "discover":
            snap = planner.discover_customer(prof, actor=args.actor, refresh=not args.no_refresh, include_managed=not args.no_managed)
            print(json.dumps(snap if args.full else _summary(snap), indent=1, default=str))
        elif args.cmd == "plan":
            sel = dict(x.split("=", 1) for x in args.select)
            plan = planner.build_plan(prof, planner.load_snapshot(prof, args.snapshot), sel, actor=args.actor)
            print(json.dumps({k: plan[k] for k in ("id", "status_light", "blocked")}, indent=1))
            for dv in plan["devices"]:
                print(f"- {dv['name']} {dv['current']} -> {dv['target']} [{dv['status']}]")
                for c in dv["checks"]:
                    print(f"    {c['level']:6} {c['title']}: {c['detail']}")
            for st in plan["steps"]:
                print(f"  {st['n']:2}. {st['title']}")
        elif args.cmd == "arm":
            plan = runner.arm(prof, planner.load_plan(prof, args.plan), actor=args.actor, cr=args.cr, approved=args.approved,
                              ack_yellow=args.ack_yellow)
            print("armed", plan["id"])
        elif args.cmd == "step":
            plan = runner.start_step(prof, planner.load_plan(prof, args.plan), actor=args.actor, confirm=args.confirm)
            if args.wait:
                plan = runner.run_until_idle(prof, args.plan, interval=args.interval)
            _print_state(plan)
        elif args.cmd == "poll":
            _print_state(runner.poll(prof, planner.load_plan(prof, args.plan)))
        elif args.cmd == "show":
            _print_state(planner.load_plan(prof, args.plan))
        elif args.cmd == "changeplan":
            print(render_cr(planner.load_plan(prof, args.plan)))
    except runner.UpgradeRefused as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2
    return 0


def _print_state(plan: dict) -> None:
    print(f"plan {plan['id']} mode={plan['mode']} status={plan['status']}")
    for s in plan["steps"]:
        extra = s.get("error") or s.get("waiting") or ""
        print(f"  {s['n']:2}. [{s['status']:7}] {s['title']} {s.get('started', '')}->{s.get('finished', '')} {extra[:300]}")
        if s.get("hint"):
            print(f"      hint: {s['hint']}")


if __name__ == "__main__":
    sys.exit(main())
