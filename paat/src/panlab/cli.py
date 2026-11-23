# SPDX-License-Identifier: Apache-2.0
"""Command-line interface (paat, also installed as panlab): import | decom | validate | plan | push | backup | check | customers."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from panlab import __version__, brand
from panlab.backup import backup_running_config
from panlab.check import check_connection
from panlab.paths import backups_dir
from panlab.plan import build_plan, render_plan
from panlab.push import push_request
from panlab.settings import load_settings
from panlab.validate import validate_request


def _add_customer(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--customer",
        default=os.environ.get("PANLAB_CUSTOMER", "example"),
        help="Customer profile under customers/<name>/ (default: $PAAT_CUSTOMER or 'example')",
    )
    parser.add_argument("--target", default=None, help="Target name inside the customer profile (default: first)")


def _profile(args: argparse.Namespace):
    from panlab.customers import load_profile

    return load_profile(args.customer)


def _target_settings(args: argparse.Namespace):
    """Settings for the chosen customer target; falls back to PANOS_* settings."""
    from panlab.sources import settings_for

    try:
        prof = _profile(args)
    except FileNotFoundError:
        return load_settings()
    tgt = next((t for t in prof.targets if t.name == args.target), None) if args.target else prof.targets[0]
    if tgt is None:
        raise RuntimeError(f"customer {prof.name} has no target {args.target!r}")
    s = settings_for(prof, tgt)
    return s if s.configured else load_settings()


def _add_request_args(parser: argparse.ArgumentParser, optional: bool = False) -> None:
    _add_customer(parser)
    if optional:
        parser.add_argument("request", type=Path, nargs="?", help="Rule-request YAML (or use --changeset)")
        parser.add_argument("--changeset", type=Path, default=None, help="Change-set JSON written by 'panlab import'")
    else:
        parser.add_argument("request", type=Path, help="Path to a rule-request YAML file")
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Offline PAN-OS config XML used for duplicate, overlap, and reuse checks",
    )
    parser.add_argument("--json", action="store_true", help="Print machine-readable output")


def _cmd_validate(args: argparse.Namespace) -> int:
    result = validate_request(args.request, config=args.config)
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        if not result.issues:
            print("Valid. No errors or warnings.")
        else:
            for issue in result.issues:
                location = f" @ {issue.path}" if issue.path else ""
                print(f"[{issue.severity}] {issue.code}{location}: {issue.message}")
            if result.ok:
                print("Valid, with warnings or notes.")
            else:
                print("Invalid.")
    return 0 if result.ok else 1


def _load_changeset(args: argparse.Namespace) -> dict:
    cs = json.loads(Path(args.changeset).read_text(encoding="utf-8"))
    if cs.get("schema") != "panlab.changeset/v1":
        raise RuntimeError(f"{args.changeset} is not a panlab change set")
    if cs.get("customer") != args.customer:
        raise RuntimeError(
            f"change set belongs to customer {cs.get('customer')!r}, not {args.customer!r}; refusing to mix customers"
        )
    return cs


def _cmd_plan(args: argparse.Namespace) -> int:
    if args.changeset:
        from panlab.report import to_markdown

        try:
            cs = _load_changeset(args)
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(cs, indent=2) if args.json else to_markdown(cs))
        return 1 if cs["summary"]["needs_human"] else 0
    if args.request is None:
        print("error: give a request YAML or --changeset", file=sys.stderr)
        return 2
    plan = build_plan(args.request, config=args.config)
    if args.json:
        print(json.dumps(plan.to_dict(), indent=2))
    else:
        sys.stdout.write(render_plan(plan))
    if not plan.supported:
        return 2
    return 0 if plan.ok else 1


def _cmd_push(args: argparse.Namespace) -> int:
    if args.changeset:
        from panlab.report import set_commands

        try:
            cs = _load_changeset(args)
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        if args.apply or args.commit:
            return _push_changeset(args, cs)
        print(f"# Dry run for customer {cs['customer']}. Nothing was written to any device.")
        print("\n".join(set_commands(cs)))
        return 0
    if args.request is None:
        print("error: give a request YAML or --changeset", file=sys.stderr)
        return 2
    try:
        result = push_request(
            args.request,
            config=args.config,
            apply=args.apply,
            commit=args.commit,
            backup_dir=args.backup_dir,
        )
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    sys.stdout.write(result.to_text())
    return 0


def _push_changeset(args: argparse.Namespace, cs: dict) -> int:
    """Live push of a change set: same backup / re-validate / diff / commit / verify flow as the GUI."""
    import getpass

    from panlab import pusher
    from panlab.customers import load_profile

    if not (args.apply and args.commit):
        print("error: change sets are pushed with --apply --commit together (no half-written candidates)", file=sys.stderr)
        return 2
    if not args.cr:
        print("error: --cr <approved CR number> is required to push", file=sys.stderr)
        return 2
    prof = load_profile(args.customer)
    actor = f"cli:{getpass.getuser()}"
    try:
        from panlab.uploads import refuse_push
        refuse_push(cs)
        pusher.check_cr(prof, args.cr)
        dev = pusher.connect_target(prof, args.target)
        selected = None
        if getattr(args, "only_rule", None):
            wanted = set(args.only_rule)
            selected = [it["token"] for it in pusher.selectable_items(cs)
                        if it["kind"] == "rule" and it.get("name") in wanted]
            if len(selected) != len(wanted):
                missing = wanted - {it.get("name") for it in pusher.selectable_items(cs) if it["kind"] == "rule"}
                raise pusher.PushError("unknown --only-rule name(s): " + ", ".join(sorted(missing)))
        s = pusher.prepare(prof, cs, Path(args.changeset).stem, actor=actor, cr=args.cr, dev=dev, target_name=args.target,
                           changeset_path=str(Path(args.changeset).resolve()), selected=selected)
        print(f"session {s['id']}  backup {s['backup']}")
        print("\n".join(s["diff"]))
        for w in s["warnings"]:
            print(f"warning: {w}")
        if s["errors"]:
            for x in s["errors"]:
                print(f"error: {x}", file=sys.stderr)
            print("refused: re-validation failed; nothing was written", file=sys.stderr)
            return 1
        if s.get("target_type") == "panorama" and s.get("status") == "dry-run":
            print("# Panorama commit-and-push plan (NOT executed):")
            for pstep in s["push_plan"]:
                print(f"- {pstep['step']}: {pstep['api']} {pstep['cmd']}")
            print(f"dry-run: {pusher.PANORAMA_DRY_RUN}")
            print(f"report: {s['report']['md']}")
            return 0
        s = pusher.apply(prof, cs, s["id"], actor=actor, confirm_target=s["target"], dev=dev)
    except pusher.PushError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    for j in s["jobs"]:
        print(f"job {j.get('jobid')} {j['step']} success={j.get('success')}")
    for v in s.get("verify", []):
        print(f"{'OK  ' if v['ok'] else 'FAIL'} {v['check']} {v.get('detail', '')}")
    print(f"{s['status']}: {s.get('result', '')}")
    if s["status"].startswith("committed"):
        print(f"rollback: paat rollback --customer {args.customer} --session {s['id']} --confirm-target {s['target']}")
    return 0 if s["status"] == "committed" else 1


def _cmd_rollback(args: argparse.Namespace) -> int:
    import getpass

    from panlab import pusher
    from panlab.customers import load_profile

    prof = load_profile(args.customer)
    try:
        s = pusher.load_session(prof, args.session)
        cs = pusher.session_changeset(prof, s)
        s = pusher.rollback(prof, cs, args.session, actor=f"cli:{getpass.getuser()}", confirm_target=args.confirm_target,
                            dev=pusher.connect_target(prof, s["target"]))
    except pusher.PushError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    for j in s["jobs"]:
        print(f"job {j.get('jobid')} {j['step']} success={j.get('success')}")
    for v in s.get("rollback_verify", []):
        print(f"{'OK  ' if v['ok'] else 'FAIL'} {v['check']}")
    for k in s["rollback_result"]["kept"]:
        print(f"kept {k}")
    print(s["status"])
    return 0 if s["status"] == "rolled-back" else 1


def _cmd_denylog(args: argparse.Namespace) -> int:
    """Read-only traffic-log deny lookup for a change set or an ad-hoc flow."""
    from panlab import denylog, pusher
    from panlab.customers import load_profile

    prof = load_profile(args.customer)
    try:
        api = denylog.connect_logs(prof, args.target)
        if args.changeset:
            cs = _load_changeset(args)
            ev = denylog.changeset_evidence(prof, cs, api, target_name=args.target, days=args.days, max_logs=args.max)
            print(f"saved {denylog.save_evidence(prof, Path(args.changeset).stem, ev)}")
            results = ev["results"]
        else:
            if not (args.src and args.dst and args.port):
                print("error: give --changeset or --src --dst --port", file=sys.stderr)
                return 2
            q = denylog.adhoc_query(args.src, args.dst, args.proto, args.port, args.from_zone or "", args.to_zone or "")
            results = [denylog.lookup(api, name="(proposed rule)", q=q, apps=[], days=args.days, max_logs=args.max,
                                      rulebase=api.running_rule_names())]
    except (pusher.PushError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    for r in results:
        print(f"{r['rule']}: hits={r['summary']['hits']} policy-match-now={r['policy_match_now']}")
        print(f"  {r['explanation']}")
    return 0


def _cmd_appadvisor(args: argparse.Namespace) -> int:
    """Read-only Port-to-App-ID advisor: suggest App-ID rules for port-based rules from the traffic logs."""
    from panlab import appadvisor, pusher
    from panlab.customers import load_profile

    prof = load_profile(args.customer)
    try:
        adv = appadvisor.run(prof, rules=args.rule or None, days=max(1, min(90, args.days)), max_logs=max(100, min(5000, args.max)),
                             actor="cli", log_targets=[args.target] if getattr(args, "target", None) else None)
    except (pusher.PushError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    pusher.audit(prof, actor="cli", action="app_advisor", result="ok", advisor=adv["id"],
                 rules=[r["rule"]["name"] for r in adv["results"]], days=adv["window_days"])
    md = appadvisor.render_cr(adv)
    out = args.out or (appadvisor.advisor_dir(prof) / f"{adv['id']}-changeplan.md")
    Path(out).write_text(md, encoding="utf-8")
    print(f"{adv['id']}: {len(adv['results'])} rule(s), window {adv['window_days']} d; change plan {out}")
    for r in adv["results"]:
        print(f"{r['rule']['name']}: {r['sessions']} sessions, confidence {r['overall_confidence']}")
        for n in r["new_rules"]:
            print(f"  + {n['name']}: {', '.join(n['application'])} / {', '.join(n['service'])} ({n['confidence']})")
        o = r["original"]
        print(f"  {o['action']} {r['rule']['name']}" + (f" -> {', '.join(o['service'])}" if o["action"] == "narrow" else ""))
        if r["review_ports"]:
            print(f"  needs review: {', '.join(r['review_ports'])}")
        if r["remove_ports"]:
            print(f"  unused (remove): {', '.join(r['remove_ports'])}")
    return 0


def _cmd_users(args: argparse.Namespace) -> int:
    """Add a GUI user. The password is random and written only to --password-file (mode 600); never printed."""
    import os
    import secrets

    from panlab.web import auth

    uf = Path(args.users_file) if args.users_file else auth.users_file()
    if args.action == "list":
        for n, u in sorted(auth.load_users(uf).items()):
            print(n, auth.Principal(n, u)[1], " ".join(sorted(auth.effective_perms(u))), " ".join(auth.Principal(n, u).customers))
        return 0
    if args.action == "migrate":  # role records -> explicit permission checkboxes (same access); backs up first
        import shutil
        import time
        if not uf.is_file():
            print(f"no users file at {uf}")
            return 1
        bak = uf.with_name(f"{uf.name}.bak-{time.strftime('%Y%m%d-%H%M%S')}")
        shutil.copy2(uf, bak)
        os.chmod(bak, 0o600)
        before = {n: auth.effective_perms(u) for n, u in auth.load_users(uf).items()}
        done = auth.migrate_roles(uf)
        after = {n: auth.effective_perms(u) for n, u in auth.load_users(uf).items()}
        if before != after:  # should never happen; put the file back
            shutil.copy2(bak, uf)
            print("error: access changed during migration; restored the backup", file=sys.stderr)
            return 1
        for n, role, perms in done:
            auth.write_user_audit(actor="panlab users migrate", action="permissions_migrate", target=n, result="ok",
                                  from_role=role, after={"permissions": perms, "customers": ["*"], "devices": {}})
            print(f"{n}: role {role} -> {' '.join(perms)} (all customers)")
        print(f"backup: {bak}; {len(done)} user(s) migrated, access unchanged for all {len(after)}")
        return 0
    if args.action == "grant-edl-admins":
        # Existing platform/legacy admins whose checkbox list predates EDL. Backs up first. Never touches passwords.
        import shutil
        import time
        import yaml
        if not uf.is_file():
            print(f"no users file at {uf}")
            return 1
        bak = uf.with_name(f"{uf.name}.bak-{time.strftime('%Y%m%d-%H%M%S')}")
        shutil.copy2(uf, bak)
        os.chmod(bak, 0o600)
        before = yaml.safe_load(uf.read_text(encoding="utf-8")) or {}
        hashes = {n: (u or {}).get("hash") for n, u in (before.get("users") or {}).items()}
        done = auth.grant_edl_to_admins(uf)
        after = yaml.safe_load(uf.read_text(encoding="utf-8")) or {}
        after_hashes = {n: (u or {}).get("hash") for n, u in (after.get("users") or {}).items()}
        if hashes != after_hashes:
            shutil.copy2(bak, uf)
            print("error: a password hash changed; restored the backup", file=sys.stderr)
            return 1
        for n in done:
            rec = (after.get("users") or {})[n]
            auth.write_user_audit(actor="panlab users grant-edl-admins", action="permissions_grant_edl", target=n, result="ok",
                                  after={"permissions": sorted(auth.effective_perms(rec))})
            print(f"{n}: granted edl_view edl_edit edl_approve edl_admin")
        print(f"backup: {bak}; {len(done)} admin(s) updated, passwords unchanged")
        return 0
    if args.action == "remove":
        ok = auth.remove_user(args.name or "", uf)
        print(f"user {args.name} {'removed' if ok else 'not found'}")
        return 0 if ok else 1
    if args.name and getattr(args, "password_stdin", False):
        # Installer path: the password arrives on stdin (never argv/env), is never echoed, printed or logged.
        pw = sys.stdin.readline().rstrip("\r\n")
        if len(pw) < auth.MIN_PASSWORD_LENGTH:
            print(f"error: password must be at least {auth.MIN_PASSWORD_LENGTH} characters", file=sys.stderr)
            return 2
        custs = list(args.customer) if getattr(args, "customer", None) else None
        auth.add_user(args.name, args.role, pw, uf, customers=custs)
        auth.write_user_audit(actor="paat users add (stdin)", action="user_add", target=args.name, result="ok")
        print(f"user {args.name} ({args.role}) saved to {uf}")
        return 0
    if not args.name or not args.password_file:
        print("error: users add NAME --password-file PATH  (or --password-stdin)", file=sys.stderr)
        return 2
    pf = Path(args.password_file).expanduser()
    if pf.exists():
        print(f"error: {pf} exists; refusing to overwrite", file=sys.stderr)
        return 1
    pw = secrets.token_urlsafe(18)
    fd = os.open(pf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(f"user: {args.name}\npassword: {pw}\n")
    custs = list(args.customer) if getattr(args, "customer", None) else None
    auth.add_user(args.name, args.role, pw, uf, customers=custs)
    scope = ", ".join(custs) if custs else "all customers"
    print(f"user {args.name} ({args.role}; {scope}) added to {uf}; password written to {pf} (mode 600)")
    return 0


def _cmd_backup(args: argparse.Namespace) -> int:
    settings = _target_settings(args)
    try:
        path = backup_running_config(dest_dir=args.out, settings=settings)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"Wrote running-config backup to {path}")
    return 0



def _cmd_check(args: argparse.Namespace) -> int:
    try:
        result = check_connection(_target_settings(args), show_serial=args.show_serial)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    sys.stdout.write(result.to_text(show_serial=args.show_serial))
    return 0


def _cmd_import(args: argparse.Namespace) -> int:
    from panlab.changeset import build_changeset
    from panlab.fcr import Tickets, read_fcr
    from panlab.report import to_markdown, write_outputs
    from panlab import uploads
    from panlab.sources import load_customer_envs

    try:
        prof = _profile(args)
        if getattr(args, "backup", None) and args.live:
            print("error: use only one of --backup and --live", file=sys.stderr)
            return 2
        src = f"backup:{args.backup}" if getattr(args, "backup", None) else ("live" if args.live else "cached")
        envs, src_meta = uploads.resolve_envs(prof, src, configs=args.config)
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    override = Tickets(ritm=args.ritm or [], sctask=args.sctask or [], cr=args.cr or [])
    requests, files = [], []
    for f in args.files:
        try:
            reqs, meta = read_fcr(f, ticket_patterns=prof.tickets, override=override, requester=args.requester or "")
        except (ValueError, KeyError, OSError) as exc:
            print(f"error: {f}: {exc}", file=sys.stderr)
            return 1
        requests += reqs
        files.append(meta)
    overrides = dict(x.split("=", 1) for x in (args.name or []))
    cs = build_changeset(prof, envs, requests, files=files, name_overrides=overrides, name_template=args.name_template,
                         combine=not args.no_combine, use_engine_path=True)
    uploads.attach_source(cs, src_meta)
    out_dir = args.out or prof.data_dir("changesets")
    stem = args.stem or ("changeset-" + cs["created"].replace(":", "").replace("-", "")[:15])
    paths = write_outputs(cs, Path(out_dir), stem)
    if not args.quiet:
        sys.stdout.write(to_markdown(cs))
    print(f"\nWrote {paths['json']} (+ .md, .html)", file=sys.stderr)
    return 0


def _cmd_changeplan(args: argparse.Namespace) -> int:
    from panlab.changeplan import load_configs, render_changeplan

    try:
        cs = _load_changeset(args)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    text = render_changeplan(cs, load_configs(args.config or []))
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"Wrote {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


def _cmd_customers(args: argparse.Namespace) -> int:
    from panlab.customers import list_customers, load_profile

    for name in list_customers():
        p = load_profile(name)
        kinds = ", ".join(f"{t.name} ({t.type})" for t in p.targets)
        print(f"{name}: {p.display_name} - targets: {kinds}")
    return 0



def _cmd_decom(args: argparse.Namespace) -> int:
    from panlab.decom import build_decom_changeset, parse_item_text, parse_item_xlsx
    from panlab.report import to_markdown, write_outputs
    from panlab import uploads
    from panlab.sources import load_customer_envs

    try:
        prof = _profile(args)
        if getattr(args, "backup", None) and args.live:
            print("error: use only one of --backup and --live", file=sys.stderr)
            return 2
        src = f"backup:{args.backup}" if getattr(args, "backup", None) else ("live" if args.live else "cached")
        envs, src_meta = uploads.resolve_envs(prof, src, configs=args.config)
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.target:
        envs = [e for e in envs if e.target == args.target]
        if not envs:
            print(f"error: no config for target {args.target!r}", file=sys.stderr)
            return 1
    items: list[str] = []
    for s in args.items or []:
        items += parse_item_text(s)
    for f in args.file or []:
        try:
            if f.suffix.lower() == ".xlsx":
                items += parse_item_xlsx(f)
            else:
                items += parse_item_text(f.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            print(f"error: {f}: {exc}", file=sys.stderr)
            return 1
    # unique, keep order
    seen: set[str] = set()
    uniq = []
    for i in items:
        if i not in seen:
            seen.add(i)
            uniq.append(i)
    if not uniq:
        print("error: give --items or --file with at least one IP, object, group, or rule name", file=sys.stderr)
        return 2
    tickets = {"ritm": args.ritm or [], "sctask": args.sctask or [], "cr": args.cr or []}
    files = [{"file": "cli-items", "project": "decommission", "tickets": tickets, "rows": len(uniq)}]
    if args.file:
        files = [{"file": f.name, "project": "decommission", "tickets": tickets, "rows": len(uniq)} for f in args.file]
    mode = "block" if args.mode in ("block", "stop") else "remove"
    flows_text = "\n".join(args.flow or [])
    if mode == "block" and not flows_text.strip():
        print("error: --mode stop needs at least one --flow 'SRC DST tcp/443'", file=sys.stderr)
        return 2
    cs = build_decom_changeset(prof, envs, uniq, tickets=tickets, files=files, created_by="cli",
                               mode=mode, flows_text=flows_text, select=None)
    if args.select or args.likely:
        from panlab.decom import current_selection, rebuild_with_selection
        pick = current_selection(cs) + list(args.select or [])
        if args.likely:
            pick += [c["id"] for c in cs["decom"]["candidates"] if c["tier"] == "likely" and c.get("selectable")]
        cs = rebuild_with_selection(prof, envs, cs, pick)
    uploads.attach_source(cs, src_meta)
    out_dir = args.out or prof.data_dir("changesets")
    stem = args.stem or ("decom-" + cs["created"].replace(":", "").replace("-", "")[:15])
    paths = write_outputs(cs, Path(out_dir), stem)
    if args.json:
        print(json.dumps(cs, indent=2))
    elif not args.quiet:
        sys.stdout.write(to_markdown(cs))
    print(f"\nWrote {paths['json']} (+ .md, .html)", file=sys.stderr)
    return 1 if cs["summary"]["needs_human"] else 0


def _cmd_uploads(args: argparse.Namespace) -> int:
    from panlab import uploads
    from panlab.customers import load_profile

    action = args.action
    try:
        if action == "add" and args.create_customer:
            if not args.path_or_id:
                print("error: give the backup file to add", file=sys.stderr)
                return 2
            path = Path(args.path_or_id)
            data = path.read_bytes()
            prof, rec = uploads.create_offline_customer(
                args.create_customer, data, path.name, uploaded_by="cli", display_name=args.display_name)
            print(f"{prof.name}\t{rec['id']}\t{rec['kind']}\t{rec['original_name']}\t{rec['sha256'][:8]}")
            return 0
        if not args.customer:
            print("error: --customer is required", file=sys.stderr)
            return 2
        prof = load_profile(args.customer)
        if action == "list":
            rows = uploads.list_uploads(prof)
            if not rows:
                print(f"no uploaded backups for {prof.name}")
                return 0
            for rec in rows:
                print(f"{rec['id']}\t{rec['kind']}\t{rec['original_name']}\t{rec['sha256'][:8]}\t"
                      f"{uploads.format_uploaded(rec['uploaded'])}\t{rec.get('uploaded_by')}")
            return 0
        if action == "add":
            if not args.path_or_id:
                print("error: give the backup file to add", file=sys.stderr)
                return 2
            path = Path(args.path_or_id)
            rec = uploads.store(prof, path.read_bytes(), path.name, uploaded_by="cli")
            print(f"{rec['id']}\t{rec['kind']}\t{rec['original_name']}\t{rec['sha256'][:8]}")
            return 0
        if action == "delete":
            if not args.path_or_id:
                print("error: give the backup id to delete", file=sys.stderr)
                return 2
            rec = uploads.delete(prof, args.path_or_id, actor="cli")
            print(f"deleted {rec['id']}")
            return 0
    except (uploads.UploadError, FileNotFoundError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print("error: unknown action", file=sys.stderr)
    return 2


def _cmd_flowtrace(args: argparse.Namespace) -> int:
    """Trace FCR text or a file against one or more config XMLs (plan only, no push)."""
    from panlab import flowmapper as fm
    from panlab import uploads
    from panlab.changeset import build_changeset
    from panlab.report import write_outputs

    prof = _profile(args)
    files: list[fm.ConfigFile] = []
    for pth in args.config or []:
        path = Path(pth)
        if not path.is_file():
            print(f"error: config not found: {path}", file=sys.stderr)
            return 2
        files.append(fm.ConfigFile(path=path, name=path.name))
    for ident in args.backup or []:
        rec = uploads.get(prof, ident)
        files.append(fm.ConfigFile(path=uploads.stored_path(prof, rec), name=rec.get("original_name") or ident))
    if args.live:
        from panlab import liveconfig
        try:
            snap = liveconfig.ensure_snapshot(prof, refresh=args.refresh_live)
        except liveconfig.LiveError as exc:
            print(f"error: live snapshot: {exc}", file=sys.stderr)
            return 1
        for path in snap.config_files():
            files.append(fm.ConfigFile(path=path, name=path.name))
    if not files:
        print("error: give --live, --config PATH, and/or --backup ID", file=sys.stderr)
        return 2
    if args.fcr:
        text, _, _ = fm.fcr_from_upload(Path(args.fcr), ticket_patterns=prof.tickets)
    else:
        text = sys.stdin.read()
    from panlab import siteroles
    try:
        roles = siteroles.load_file(args.roles) if args.roles else siteroles.load(prof)
        scope = siteroles.parse_scope(args.scope) if args.scope is not None else None
    except siteroles.RolesError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    try:
        tables = [fm.parse_route_spec(x) for x in (args.routes or [])]
        links = [fm.parse_link_spec(x) for x in (args.link or [])]
        result = fm.run_trace(files, text, ignore_intrazone=args.ignore_intrazone,
                              route_tables=tables, links=links, roles=roles, scope=scope)
        if args.pick:
            pins = fm.pins_from_picks(result, args.pick)
            result = fm.run_trace(files, text, ignore_intrazone=args.ignore_intrazone,
                                  route_tables=tables, links=links, pins=pins, roles=roles, scope=scope)
    except fm.FlowMapperError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if getattr(args, "live_check", False):
        from panlab import livecheck, liveconfig as lc
        result = dict(result)
        result["live_check"] = livecheck.check_trace(prof, result, lc.load_cached_snapshot(prof))
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        s = result.get("summary") or {}
        print(f"engine { (result.get('engine') or {}).get('version') }  files={s.get('files')}  "
              f"devices={s.get('devices')}  routes={s.get('staticRoutes')}  rows={len(result.get('rows') or [])}")
        for t in result.get("routeTables") or []:
            print(f"route table {t.get('label')} for {t.get('device')}: {t.get('format')}, {t.get('routes')} route(s) used"
                  + (f"; {'; '.join(t.get('warnings') or [])}" if t.get("warnings") else ""))
        sc = result.get("scope") or {}
        if sc:
            print(sc.get("chip"))
            if sc.get("hidden"):
                print(f"  hidden: {sc.get('text')}  (use --scope all to include them, or --roles FILE to change roles)")
        ov = result.get("overlap") or {}
        if ov.get("total"):
            print(f"overlapping address space: {ov.get('text')}")
            for c in ov.get("cloned") or []:
                print(f"  look-alike firewalls {c['a'].get('label')} and {c['b'].get('label')}: not HA ({c.get('notHa')})")
        for i, row in enumerate(result.get("rows") or [], 1):
            q = row.get("query") or {}
            ps = row.get("pathStatus") or {}
            print(f"\n[{i}] {q.get('src')} -> {q.get('dst')} {q.get('proto')}/{q.get('port')}  status={row.get('status')}"
                  f"  path={ps.get('label') or ps.get('status')}")
            if ps.get("text"):
                print(f"  {ps['text']}")
            for a in ps.get("assumptions") or []:
                print(f"  {'pinned' if a.get('kind') == 'pinned' else 'assumed'}: {a.get('what')}"
                      + (f"  (confirm: {a['confirm']})" if a.get("confirm") and a.get("kind") != "pinned" else ""))
            for j, c in enumerate(ps.get("choices") or [], 1):
                chosen = next((x.get("hostname") or x.get("device") for x in c.get("candidates") or [] if x.get("device") == c.get("chosen")), c.get("chosen"))
                state = f"pinned to {chosen} ({c.get('pinBy')})" if c.get("pinned") else "NEEDS YOUR CHOICE"
                print(f"  choice {i}.{j} {c.get('kind')}: {c.get('what')} at {c.get('at')}  [{state}]")
                for x in c.get("candidates") or []:
                    print(f"      - {x.get('hostname') or x.get('device')} · serial {x.get('serial') or '?'} · stack {x.get('stack') or '?'}"
                          f" · site {x.get('site') or '?'}: {x.get('reason') or ''}")
                if not c.get("pinned"):
                    print(f"      pick one: --pick {i}.{j}=<hostname or serial>"
                          + (f"  or save a link: --link {c['link']['device']}:{c['link']['iface']}:{c['link'].get('nexthop') or ''}=<device>" if c.get("link") else ""))
            via = (row.get("scope") or {}).get("viaHidden")
            if via:
                print(f"  SCOPE: {via.get('text')}")
            conf = row.get("conflict")
            if conf:
                if conf.get("scopeCause") in ("hidden-routed-hop", "hidden-owner"):
                    print(f"  SCOPE CONFLICT: {conf.get('scopeText')}")
                else:
                    print(f"  Routing and rules disagree: routing={conf.get('routing')}; rules={conf.get('rules')}"
                          + (f"  ({conf.get('scopeText')})" if conf.get("scopeText") else ""))
            why = (row.get("why") or {}).get("text")
            if why:
                print(why)
            for h in row.get("hops") or []:
                print(f"  hop {h.get('n')}: {h.get('hostname') or h.get('device')} {h.get('vsys')}  "
                      f"{h.get('fromZone')} -> {h.get('toZone')}  {h.get('verdict')}"
                      f"{' by ' + h['rule'] if h.get('rule') else ''}"
                      f"{' hairpin' if h.get('hairpin') else ''}")
            plan = row.get("plan") or {}
            print(f"  required changes: {plan.get('required') or 0}  uncertain: {plan.get('uncertain') or 0}")
            mir = row.get("drMirror")
            if mir:
                print(f"  DR copy advice: {mir.get('text')}")
                for it in mir.get("items") or []:
                    for c in it.get("candidates") or []:
                        print(f"      {it.get('device')} -> {c.get('device')}: {c.get('level')} ({'; '.join(c.get('reasons') or [])})"
                              + (f" {c['addrNote']}" if c.get("addrNote") else ""))
        chk = result.get("live_check") or {}
        if chk:
            print(f"\nlive check: {chk.get('hops')} hop(s), {chk.get('disagreements')} disagreement(s), {chk.get('errors')} error(s)")
            for row in chk.get("rows") or []:
                for h in row.get("hops") or []:
                    for d in h.get("disagreements") or []:
                        print(f"  DISAGREES hop {h.get('n')}: {d}")
                    for err in h.get("errors") or []:
                        print(f"  error hop {h.get('n')}: {err}")
    if args.changeset:
        target = prof.targets[0].name if prof.targets else "offline"
        reqs, placed = fm.requests_and_placements(result, target=target, project="flowtrace")
        from panlab.netmodel import load_environment
        envs = []
        for f in files:
            try:
                envs.append(load_environment(f.path, target=target, site_codes=prof.site_codes))
            except Exception:
                continue
        if not reqs or not envs:
            print("error: could not build a change set from this trace", file=sys.stderr)
            return 1
        cs = build_changeset(prof, envs, reqs, path_placements=placed, require_profile_targets=False, combine=False)
        cs["plan_only"] = True
        out = Path(args.changeset)
        stem = out.stem if out.suffix else out.name
        dest = out.parent if out.suffix else out
        dest.mkdir(parents=True, exist_ok=True)
        write_outputs(cs, dest, stem)
        print(f"wrote change set {dest / (stem + '.json')} (plan only)")
    return 0


def _prog() -> str:
    """Show the name the user typed (paat or panlab) in usage lines."""
    name = os.path.basename(sys.argv[0] or "")
    return name if name in ("paat", "panlab") else "paat"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=_prog(),
        description=(
            f"{brand.FULL_NAME}, {brand.FOR}. "
            "Validate, plan, and (optionally) push firewall rule requests. "
            "Default push is a dry-run. Commits are never implicit."
        ),
        epilog="'paat' and 'panlab' are the same command; both names are installed.",
    )
    parser.add_argument("--version", action="version", version=f"{brand.NAME} ({brand.LONG_NAME}) {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    validate_p = sub.add_parser("validate", help="Validate a request YAML against the schema and an optional offline config")
    _add_request_args(validate_p)
    validate_p.set_defaults(func=_cmd_validate)

    plan_p = sub.add_parser("plan", help="Show objects and rules that would be created (offline), or render a change set")
    _add_request_args(plan_p, optional=True)
    plan_p.set_defaults(func=_cmd_plan)

    push_p = sub.add_parser(
        "push",
        help="Dry-run a plan (default), write the candidate config (--apply), or commit (--commit)",
    )
    _add_request_args(push_p, optional=True)
    push_p.add_argument(
        "--apply",
        action="store_true",
        help="Write address objects and the security rule to the candidate config (no commit)",
    )
    push_p.add_argument(
        "--commit",
        action="store_true",
        help="Back up the running config, apply the change, and commit. Implies --apply. Off by default.",
    )
    push_p.add_argument(
        "--backup-dir",
        type=Path,
        default=None,
        help="Directory for the pre-commit running-config export (default: backups/)",
    )
    push_p.add_argument("--cr", default=None, help="Approved CR number (required with --apply --commit for a change set)")
    push_p.add_argument("--only-rule", action="append", default=None, metavar="NAME",
                        help="Prepare/apply only this planned rule (repeatable). Default: every planned rule.")
    push_p.set_defaults(func=_cmd_push)

    rb_p = sub.add_parser("rollback", help="Roll back a committed change-set push (rules, then objects it created and nothing else uses)")
    rb_p.add_argument("--customer", required=True)
    rb_p.add_argument("--session", required=True, help="Push session id (push-YYYYmmdd-HHMMSS-xxxxxx)")
    rb_p.add_argument("--confirm-target", required=True, help="Type the target name to confirm")
    rb_p.set_defaults(func=_cmd_rollback)

    dl = sub.add_parser("denylog", help="Read-only: find denied traffic in the firewall's logs and explain whether the rule fixes it")
    _add_customer(dl)
    dl.add_argument("--changeset", type=Path, default=None)
    dl.add_argument("--src")
    dl.add_argument("--dst")
    dl.add_argument("--port")
    dl.add_argument("--proto", default="tcp", choices=["tcp", "udp"])
    dl.add_argument("--from-zone")
    dl.add_argument("--to-zone")
    dl.add_argument("--days", type=int, default=7)
    dl.add_argument("--max", type=int, default=200, help="Cap on log entries per lookup")
    dl.set_defaults(func=_cmd_denylog)

    aa = sub.add_parser("appadvisor", help="Read-only: suggest App-ID rules for port-based rules from the traffic logs")
    _add_customer(aa)
    aa.add_argument("--rule", action="append", help="Rule name (repeat); default every port-based allow rule")
    aa.add_argument("--days", type=int, default=7)
    aa.add_argument("--max", type=int, default=5000, help="Cap on log entries per rule")
    aa.add_argument("--out", type=Path, default=None, help="Write the CR change plan here")
    aa.set_defaults(func=_cmd_appadvisor)

    us = sub.add_parser("users", help="Manage GUI users (users file outside the repo)")
    us.add_argument("action", choices=["add", "list", "remove", "migrate", "grant-edl-admins"], help="add also resets an existing user's password and role")
    us.add_argument("name", nargs="?")
    us.add_argument("--role", default="viewer", choices=["viewer", "prep", "engineer", "admin"])
    us.add_argument("--customer", action="append", default=None, metavar="NAME",
                    help="limit the new user to this customer (repeat for several); default is all customers")
    us.add_argument("--password-file", help="Where to write the random password (mode 600). Required for add.")
    us.add_argument("--password-stdin", action="store_true",
                    help="add: read the password from standard input instead (never echoed or printed; min 12 chars)")
    us.add_argument("--users-file", default=None, help="Default: $PAAT_USERS_FILE / $PANLAB_USERS_FILE, else <config dir>/users.yaml")
    us.set_defaults(func=_cmd_users)

    backup_p = sub.add_parser("backup", help="Export the running configuration to backups/")
    backup_p.add_argument(
        "--out",
        type=Path,
        default=None,
        help=f"Destination directory (default: {backups_dir()})",
    )
    _add_customer(backup_p)
    backup_p.set_defaults(func=_cmd_backup)

    check_p = sub.add_parser(
        "check",
        help="Read-only connectivity test (show system info). Does not change config.",
    )
    check_p.add_argument(
        "--show-serial",
        action="store_true",
        help="Print the device serial locally. Do not commit it or paste it into the repo.",
    )
    _add_customer(check_p)
    check_p.set_defaults(func=_cmd_check)

    imp = sub.add_parser("import", help="Import one or more FCR spreadsheets into a placed, grouped change set (read-only)")
    _add_customer(imp)
    imp.add_argument("files", nargs="+", type=Path, help="FCR .xlsx or .csv files (customer form layout, or a close equivalent)")
    imp.add_argument("--ritm", action="append", help="RITM number (overrides what the files say)")
    imp.add_argument("--sctask", action="append", help="SCTASK number")
    imp.add_argument("--cr", action="append", help="CR / CHG number")
    imp.add_argument("--requester", default="", help="Requester name for rule descriptions")
    imp.add_argument("--config", action="append", help="Config XML ([target=]path); repeat per target")
    imp.add_argument("--live", action="store_true", help="Export each target's running config read-only first")
    imp.add_argument("--backup", default=None, help="Use an uploaded backup id (plan only; cannot be pushed)")
    imp.add_argument("--name", action="append", help="Rule name override R001=My-Rule-Name (repeatable)")
    imp.add_argument("--name-template", default=None, help="Rule name template, e.g. '{ritm}-{project}-{dst}-{port}'")
    imp.add_argument("--out", type=Path, default=None, help="Output dir (default: customer data dir/changesets)")
    imp.add_argument("--stem", default=None, help="Output file name stem")
    imp.add_argument("--quiet", action="store_true", help="Do not print the report")
    imp.add_argument("--no-combine", action="store_true",
                     help="Do not merge similar requests into one rule (default: combine where possible)")
    imp.set_defaults(func=_cmd_import)

    decom = sub.add_parser("decom", help="Build a decommission (removal) change plan from IPs, objects, groups, or rule names")
    _add_customer(decom)
    decom.add_argument("--items", action="append", default=[], help="IPs/CIDRs, FQDNs, object, group, or rule names (repeatable; also comma/newline separated)")
    decom.add_argument("--file", action="append", type=Path, default=[], help="Text or .xlsx (one item per row, first column)")
    decom.add_argument("--ritm", action="append", help="RITM number")
    decom.add_argument("--sctask", action="append", help="SCTASK number")
    decom.add_argument("--cr", action="append", help="CR / CHG number")
    decom.add_argument("--config", action="append", help="Config XML ([target=]path); repeat per target")
    decom.add_argument("--live", action="store_true", help="Export each target's running config read-only first")
    decom.add_argument("--backup", default=None, help="Use an uploaded backup id (plan only; cannot be pushed)")
    decom.add_argument("--out", type=Path, default=None, help="Output dir (default: customer data dir/changesets)")
    decom.add_argument("--stem", default=None, help="Output file name stem")
    decom.add_argument("--quiet", action="store_true", help="Do not print the report")
    decom.add_argument("--json", action="store_true", help="Print machine-readable output")
    decom.add_argument("--mode", choices=["remove", "stop", "block"], default="remove",
                       help="remove: clean out references (default). stop: also find every rule that would still allow --flow and add a narrow deny above it")
    decom.add_argument("--flow", action="append", help="Flow to stop, 'SRC DST tcp/443' (repeatable; --mode stop)")
    decom.add_argument("--select", action="append", help="Also include this Highly likely item id (see the JSON 'decom.candidates'); repeatable")
    decom.add_argument("--likely", action="store_true", help="Include every Highly likely item (Possible items are never included)")
    decom.set_defaults(func=_cmd_decom)

    cp = sub.add_parser("changeplan", help="Change plan for a change set: GUI steps, set CLI, rollback, verification (Markdown)")
    _add_customer(cp)
    cp.add_argument("--changeset", type=Path, required=True)
    cp.add_argument("--out", type=Path, default=None, help="Write to a file instead of stdout")
    cp.add_argument("--config", type=Path, action="append", default=None,
                    help="Current running config XML; rollback then keeps created objects that something else references (repeatable)")
    cp.set_defaults(func=_cmd_changeplan)

    cust = sub.add_parser("customers", help="List customer profiles")
    cust.set_defaults(func=_cmd_customers)

    ups = sub.add_parser("uploads", help="List, add, or delete uploaded firewall/Panorama backup files (plan only)")
    ups.add_argument("action", choices=["list", "add", "delete"], help="list | add FILE | delete ID")
    ups.add_argument("path_or_id", nargs="?", help="File to add, or backup id to delete")
    ups.add_argument("--customer", default=None, help="Existing customer (required for list/delete; optional with --create-customer)")
    ups.add_argument("--create-customer", default=None, dest="create_customer",
                     help="Create an ad-hoc offline customer from this backup (name: lowercase, digits, - _)")
    ups.add_argument("--display-name", default="", help="Display name for --create-customer")
    ups.set_defaults(func=_cmd_uploads)

    ft = sub.add_parser("flowtrace", help="Trace an FCR across Panorama and local backups (FlowMapper engine; plan only)")
    _add_customer(ft)
    ft.add_argument("--config", action="append", default=[], help="Config XML path (repeat for a Panorama export plus local backups)")
    ft.add_argument("--backup", action="append", default=[], help="Uploaded backup id (repeat)")
    ft.add_argument("--fcr", help="FCR file (.xlsx, .csv, or text). If omitted, read paste/CSV from stdin")
    ft.add_argument("--ignore-intrazone", action="store_true", help="Ignore the implicit intrazone-default allow")
    ft.add_argument("--routes", action="append", default=[], metavar="FILE@DEVICE",
                    help="Actual route table for one firewall (show routing route, show advanced-routing route, XML API or CSV). Repeat per firewall; wins over BGP inference")
    ft.add_argument("--pick", action="append", default=[], metavar="ROW.N=DEVICE",
                    help="Answer a 'needs your choice' decision for this trace (hostname, serial or device id), e.g. --pick 1.1=core-dc2-fw")
    ft.add_argument("--link", action="append", default=[], metavar="FROMDEV:IFACE[:NEXTHOP]=TODEV[:IFACE]",
                    help="Custom next-hop link applied to every flow (for example a next hop that several firewalls share)")
    ft.add_argument("--scope", default=None, metavar="production|all|sites=a,b",
                    help="Which firewalls take part: production (default; leaves DR, Lab and Test sites out), all, or sites=name1,name2")
    ft.add_argument("--roles", metavar="FILE", help="Site-role file (the JSON FlowMapper exports): roles per site or firewall, extra words, custom roles. Default: the customer's saved roles")
    ft.add_argument("--changeset", help="Write a plan-only change set (directory or .json path)")
    ft.add_argument("--json", action="store_true", help="Print the full trace result as JSON")
    ft.add_argument("--live", action="store_true", help="Include the cached read-only live snapshot (Panorama running/candidate and managed firewalls)")
    ft.add_argument("--refresh-live", action="store_true", help="Refresh the live snapshot first (rate-limited)")
    ft.add_argument("--live-check", action="store_true", help="Confirm each hop against live policy-match, FIB, and traffic logs")
    ft.set_defaults(func=_cmd_flowtrace)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
