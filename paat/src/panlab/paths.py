# SPDX-License-Identifier: Apache-2.0
"""Resolve repo-relative paths without assuming a fixed install layout."""

from __future__ import annotations

import os
from pathlib import Path


def etc_dir() -> Path:
    """Server config directory: $PANLAB_ETC_DIR (or $PAAT_ETC_DIR), default /etc/panlab.

    install.sh and the container set PAAT_ETC_DIR=/etc/paat.
    """
    return Path(os.environ.get("PANLAB_ETC_DIR") or "/etc/panlab")


def repo_root(start: Path | None = None) -> Path:
    """Find the repo root by walking up from *start* (or this file) looking for the schema."""
    here = start.resolve() if start is not None else Path(__file__).resolve()
    candidates = [here] if here.is_dir() else [here.parent]
    candidates.extend(here.parents if here.is_file() else here.parents)
    for path in candidates:
        if (path / "schema" / "rule_request.schema.json").is_file():
            return path
    return Path.cwd()


def schema_path(root: Path | None = None) -> Path:
    return (root or repo_root()) / "schema" / "rule_request.schema.json"


def backups_dir(root: Path | None = None) -> Path:
    """CLI config exports: $PANLAB_BACKUPS_DIR (or $PAAT_BACKUPS_DIR), else <repo>/backups.

    Created when possible; a read-only install tree is not an error here (the export reports it).
    """
    env = os.environ.get("PANLAB_BACKUPS_DIR") if root is None else None
    path = Path(env) if env else (root or repo_root()) / "backups"
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    return path
