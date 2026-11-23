# SPDX-License-Identifier: Apache-2.0
"""Is anything mid-flight that a PAAT restart would cut off? Shared check for every deploy.

Looks at the files the long-running features keep under the data root (all customers):

* OS upgrade plans (``<customer>/upgrade/upg-*.json``): plan status ``running`` or any step ``running``
  (a device job the run page is polling). A CLI run outside the web service shows here too.
* URL filter requests (``<customer>/urlfilter/*.json``): ``pushing`` or ``rolling-back``.
* Rule push sessions (``<customer>/push/push-*.json``): written in the last ``recent`` seconds
  (apply/rollback run inside one web request; a fresh write means one may be in progress).

Fails closed: an unreadable file counts as busy. Usage before a restart::

    sudo -u paat env PAAT_DATA_DIR=/var/lib/paat/data python -m panlab.activity || echo "busy, do not restart"

Exit 0 = idle, 1 = busy (one line per item), 2 = could not check.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from panlab.customers import data_root

RECENT_PUSH_S = 180


def busy_items(root: Path | None = None, *, recent: int = RECENT_PUSH_S, now: float | None = None) -> list[str]:
    root = Path(root or data_root())
    now = now or time.time()
    out: list[str] = []
    if not root.is_dir():
        return out
    for cdir in sorted(p for p in root.iterdir() if p.is_dir()):
        cust = cdir.name
        for p in sorted((cdir / "upgrade").glob("upg-*.json")):
            try:
                plan = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                out.append(f"{cust}: upgrade plan {p.stem} unreadable (treated as busy)")
                continue
            run = [s for s in plan.get("steps") or [] if s.get("status") == "running"]
            if plan.get("status") == "running" or run:
                s = run[0] if run else {}
                out.append(f"{cust}: OS upgrade {plan.get('id', p.stem)} step {s.get('n', '?')} {s.get('action', '')} running")
        for p in sorted((cdir / "urlfilter").glob("*.json")):
            try:
                req = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                out.append(f"{cust}: URL filter request {p.stem} unreadable (treated as busy)")
                continue
            if isinstance(req, dict) and req.get("status") in ("pushing", "rolling-back"):
                out.append(f"{cust}: URL filter request {req.get('id', p.stem)} {req['status']}")
        for p in sorted((cdir / "push").glob("push-*.json")):
            try:
                age = now - p.stat().st_mtime
            except OSError:
                continue
            if age < recent:
                out.append(f"{cust}: rule push session {p.stem} written {int(age)} s ago (may be applying)")
    return out


def main(argv: list[str] | None = None) -> int:
    try:
        items = busy_items()
    except Exception as exc:  # noqa: BLE001 - cannot tell: do not restart
        print(f"could not check activity: {type(exc).__name__}: {exc}")
        return 2
    for i in items:
        print(i)
    if not items:
        print("idle: no OS upgrade step, URL filter push or rule push in progress")
    return 1 if items else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
