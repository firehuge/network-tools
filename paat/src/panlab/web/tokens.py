"""API Bearer tokens with the same permission and customer scope as the user.

The plaintext token is shown once. Only a hash is stored, in a file
outside the repo (PANLAB_API_TOKENS_FILE, default /etc/panlab/api-tokens.yaml).
Revoking a token does not disable the person.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

import yaml

from panlab.web import auth
from panlab.paths import etc_dir


def tokens_file() -> Path:
    return Path(os.environ.get("PANLAB_API_TOKENS_FILE") or etc_dir() / "api-tokens.yaml")


def _load(path: Path | None = None) -> dict:
    p = path or tokens_file()
    if not p.is_file():
        return {"tokens": []}
    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        return {"tokens": []}
    raw.setdefault("tokens", [])
    return raw


def _write(raw: dict, path: Path | None = None) -> None:
    p = path or tokens_file()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        yaml.safe_dump(raw, f, sort_keys=True)
    os.replace(tmp, p)
    os.chmod(p, 0o600)


def create_token(username: str, *, label: str = "", path: Path | None = None) -> str:
    """Return the plaintext token once. Store only a hash."""
    if not auth.load_users().get(username):
        raise KeyError(username)
    raw = _load(path)
    token = "plb_" + secrets.token_urlsafe(32)
    rec = {"id": secrets.token_hex(8), "user": username, "hash": auth.hash_password(token), "label": label or ""}
    raw.setdefault("tokens", []).append(rec)
    _write(raw, path)
    auth.write_user_audit(actor=username, action="api_token_create", target=username, result="ok",
                          token_id=rec["id"], label=label or "")
    return token


def revoke_token(token_id: str, *, actor: str = "", path: Path | None = None) -> bool:
    raw = _load(path)
    before = len(raw.get("tokens") or [])
    raw["tokens"] = [t for t in (raw.get("tokens") or []) if str(t.get("id")) != token_id]
    if len(raw["tokens"]) == before:
        return False
    _write(raw, path)
    auth.write_user_audit(actor=actor or "system", action="api_token_revoke", target=token_id, result="ok")
    return True


def read_token(plaintext: str, path: Path | None = None) -> auth.Principal | None:
    if not plaintext:
        return None
    for rec in _load(path).get("tokens") or []:
        if auth.verify_password(plaintext, rec.get("hash") or ""):
            users = auth.load_users()
            u = users.get(rec.get("user") or "")
            if u and not u.get("disabled"):
                return auth.Principal(rec["user"], u)
            return None
    auth.verify_password(plaintext, auth.hash_password("x", 1000))
    return None
