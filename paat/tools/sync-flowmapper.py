#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Copy FlowMapper build/core.js, build/render.js and build/decom.js into vendor/flowmapper and record their hashes.

PAAT and `paat flowtrace` run this vendored file with Node. Do not
edit the copy by hand: change ../flowmapper/build, then re-run this script.

Usage:
  python3 tools/sync-flowmapper.py --from ../flowmapper
  python3 tools/sync-flowmapper.py --from ../flowmapper/build/core.js
  python3 tools/sync-flowmapper.py --check          # verify hash only
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

PAAT_ROOT = Path(__file__).resolve().parents[1]
VENDOR = PAAT_ROOT / "vendor" / "flowmapper"
CORE = VENDOR / "core.js"
RENDER = VENDOR / "render.js"
DECOM = VENDOR / "decom.js"
MANIFEST = VENDOR / "manifest.json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _engine_version(text: str) -> str:
    matches = re.findall(r'version:\s*"([0-9][^"]*)"', text)
    return matches[-1] if matches else "unknown"


def _git_commit(repo: Path) -> str | None:
    try:
        out = subprocess.check_output(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            text=True, stderr=subprocess.DEVNULL)
        return out.strip() or None
    except (OSError, subprocess.CalledProcessError):
        return None


def resolve_source(src: Path) -> tuple[Path, Path | None]:
    src = src.expanduser().resolve()
    if src.is_file() and src.name == "core.js":
        repo = src.parents[1] if src.parent.name == "build" else None
        return src, repo if repo and (repo / ".git").exists() else None
    if src.is_dir():
        candidate = src / "build" / "core.js"
        if candidate.is_file():
            return candidate, src if (src / ".git").exists() else None
    raise SystemExit(f"no build/core.js at {src}")


def load_manifest() -> dict:
    if not MANIFEST.is_file() or not CORE.is_file():
        raise SystemExit(f"missing vendored engine at {CORE} or {MANIFEST}")
    return json.loads(MANIFEST.read_text())


def check() -> dict:
    man = load_manifest()
    sha = _sha256(CORE)
    ver = _engine_version(CORE.read_text(encoding="utf-8", errors="replace"))
    if sha != man.get("sha256"):
        raise SystemExit(
            f"vendored core.js sha256 {sha} does not match manifest {man.get('sha256')}. "
            "Re-run tools/sync-flowmapper.py.")
    if man.get("engine_version") and ver != man["engine_version"]:
        raise SystemExit(
            f"vendored core.js version {ver} does not match manifest {man.get('engine_version')}.")
    rend = (man.get("render") or {})
    if rend:
        if not RENDER.is_file():
            raise SystemExit(f"vendored render.js is missing at {RENDER}. Re-run tools/sync-flowmapper.py.")
        rsha = _sha256(RENDER)
        if rsha != rend.get("sha256"):
            raise SystemExit(
                f"vendored render.js sha256 {rsha} does not match manifest {rend.get('sha256')}. "
                "Re-run tools/sync-flowmapper.py.")
    dec = (man.get("decom") or {})
    if dec:
        if not DECOM.is_file():
            raise SystemExit(f"vendored decom.js is missing at {DECOM}. Re-run tools/sync-flowmapper.py.")
        dsha = _sha256(DECOM)
        if dsha != dec.get("sha256"):
            raise SystemExit(
                f"vendored decom.js sha256 {dsha} does not match manifest {dec.get('sha256')}. "
                "Re-run tools/sync-flowmapper.py.")
    return {"ok": True, "sha256": sha, "engine_version": ver, "source_commit": man.get("source_commit"),
            "render_sha256": rend.get("sha256"), "decom_sha256": dec.get("sha256")}


def sync(src: Path, commit: str | None) -> dict:
    core_src, repo = resolve_source(src)
    text = core_src.read_text(encoding="utf-8", errors="replace")
    if "mergeLocalBackups" not in text or "annotateFcr" not in text or "vsysMap" not in text:
        raise SystemExit(f"{core_src} does not look like FlowMapper core.js (missing expected exports)")
    ver = _engine_version(text)
    VENDOR.mkdir(parents=True, exist_ok=True)
    shutil.copy2(core_src, CORE)
    sha = _sha256(CORE)
    render_src = core_src.parent / "render.js"
    render_info = None
    if render_src.is_file():
        shutil.copy2(render_src, RENDER)
        render_info = {"file": "render.js", "sha256": _sha256(RENDER), "bytes": RENDER.stat().st_size}
    elif RENDER.exists():
        RENDER.unlink()
    decom_src = core_src.parent / "decom.js"
    decom_info = None
    if decom_src.is_file():
        shutil.copy2(decom_src, DECOM)
        dtext = DECOM.read_text(encoding="utf-8", errors="replace")
        m = re.search(r'const VERSION = "([^"]+)"', dtext)
        decom_info = {"file": "decom.js", "sha256": _sha256(DECOM), "bytes": DECOM.stat().st_size,
                      "version": m.group(1) if m else "unknown"}
    elif DECOM.exists():
        DECOM.unlink()
    if commit is None and repo is not None:
        commit = _git_commit(repo)
    now = datetime.now().astimezone().isoformat(timespec="seconds")
    man = {
        "source_repo": "flowmapper/ (this repository)",
        "source_commit": commit,
        "engine_version": ver,
        "file": "core.js",
        "sha256": sha,
        "bytes": CORE.stat().st_size,
        "render": render_info,
        "decom": decom_info,
        "synced": now,
        "note": "Vendored single source for path tracing, diagrams and decommission plans. Do not edit these copies; run tools/sync-flowmapper.py.",
    }
    if not render_info:
        man.pop("render")
    if not decom_info:
        man.pop("decom")
    MANIFEST.write_text(json.dumps(man, indent=2) + "\n")
    check()
    return man


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--from", dest="source", type=Path, help="FlowMapper folder (default ../flowmapper) or path to core.js")
    p.add_argument("--commit", help="Source commit SHA to record (default: git HEAD of --from)")
    p.add_argument("--check", action="store_true", help="Verify the vendored hash and exit")
    args = p.parse_args()
    if args.check:
        info = check()
        print(f"ok FlowMapper engine {info['engine_version']} sha256={info['sha256'][:12]}… commit={info.get('source_commit') or '-'}")
        return 0
    if not args.source:
        args.source = PAAT_ROOT.parent / "flowmapper"
    man = sync(args.source, args.commit)
    print(f"synced FlowMapper engine {man['engine_version']} ({man['bytes']} bytes, sha256={man['sha256'][:12]}…)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
