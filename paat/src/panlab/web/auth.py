"""Local users and signed session cookies for the panlab GUI.

Users live in a YAML file outside the repo (``PANLAB_USERS_FILE``, default
``/etc/panlab/users.yaml``, mode 600, owned by the service user)::

    users:
      admin: {role: admin, hash: "pbkdf2_sha256$600000$<salt>$<hex>"}

Access is a set of **permissions** (checkboxes, see ``PERMS``) plus a
**scope**: which customers (``customers: ["*"]`` = all) and, per customer,
optionally which devices (target names, hostnames, serials, or ``dg:<device
group>``). Older records with only ``role:`` (viewer, prep, engineer, admin)
get exactly the permissions that role had (``ROLE_PERMS``) and all customers,
so nobody gains or loses access when this was introduced. The session cookie is
HMAC-signed with a key from ``PANLAB_SESSION_KEY_FILE`` (default
``/etc/panlab/session.key``); without that file a per-process key is used,
so sessions end on restart. The user's role is re-read from the users file
on every request, so removing a user takes effect at once.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path

import yaml
from panlab.paths import etc_dir

ROLES = ["viewer", "prep", "engineer", "admin"]
PERMS: dict[str, str] = {
    "view": "View change sets, change plans and reports",
    "fcr": "FCR and decommission plans, backup-file uploads, deny lookups",
    "request": "Submit FCRs: upload a filled request spreadsheet to build a plan (no decommission, backups, approval or push)",
    "push": "Push changes to firewalls (red push area)",
    "upgrade_plan": "OS upgrades: discover devices and build plans",
    "upgrade_exec": "OS upgrades: arm plans and run steps (red area)",
    "upgrade_panorama": "OS upgrades: may plan/run Panorama itself (not just firewalls)",
    "backup_admin": "Manage backup destinations",
    "user_admin": "Manage users, passwords and permissions",
    "urlfilter_request": "URL filter: request changes (see the customer's URL Filtering profile and submit change requests)",
    "urlfilter_approve": "URL filter: approve & push (review, approve or reject requests and push approved ones)",
    "approve": "Approve FCR and push change plans (second-person gate when the customer requires it)",
    "edl_view": "EDLs: see the customer's external dynamic lists, entries, history and which firewalls use them",
    "edl_edit": "EDLs: add, remove and import entries (risky entries, and lists that need approval, wait for a second person)",
    "edl_approve": "EDLs: approve or reject staged EDL changes and EDL firewall-object requests (never your own)",
    "edl_admin": "EDLs: create and delete lists, publish targets (PAAT-hosted, S3), safety settings, firewall objects, refresh now",
}
EDL_PERMS = frozenset({"edl_view", "edl_edit", "edl_approve", "edl_admin"})
# Permissions added after existing admin checkbox lists were saved (`request`,
# two-person `approve`, then EDL). When adding a new permission, include it here
# too so those accounts still count as platform admins and receive EDL access.
ADMIN_ADDED_PERMS = frozenset({"request", "approve"}) | EDL_PERMS
ROLE_PERMS: dict[str, frozenset[str]] = {
    "viewer": frozenset({"view"}),
    "prep": frozenset({"view", "fcr", "upgrade_plan", "upgrade_panorama"}),
    "engineer": frozenset({"view", "fcr", "upgrade_plan", "upgrade_panorama", "push", "upgrade_exec"}),
    "admin": frozenset(PERMS),
}
# Legacy role checks map to the permission that role needed.
ROLE_TO_PERM = {"viewer": "view", "prep": "fcr", "engineer": "push", "admin": "user_admin"}


class Principal(tuple):
    """(name, label) for older call sites, plus permissions and scope."""

    def __new__(cls, name: str, rec: dict):
        perms = effective_perms(rec)
        label = next((r for r in reversed(ROLES) if ROLE_PERMS[r] == perms), "custom")
        obj = tuple.__new__(cls, (name, label))
        obj.name, obj.perms = name, perms
        obj.must_change = bool(rec.get("must_change_password"))
        obj.disabled = bool(rec.get("disabled"))
        cs = rec.get("customers")  # [] = none; missing = all only for an old role-only record
        if isinstance(cs, list):
            obj.customers = [str(c) for c in cs]
        else:  # fail closed: a record with explicit permissions but no customer list sees no customer
            obj.customers = [] if isinstance(rec.get("permissions"), list) else ["*"]
        obj.devices = {str(k): [str(x) for x in (v or [])] for k, v in (rec.get("devices") or {}).items()}
        return obj

    def can(self, perm: str) -> bool:
        return perm in self.perms

    def all_customers(self) -> bool:
        return "*" in self.customers

    def sees_customer(self, customer: str) -> bool:
        return self.all_customers() or customer in self.customers

    def device_scope(self, customer: str) -> list[str] | None:
        """None = every device of this customer; else the allowed patterns."""
        pats = self.devices.get(customer)
        return pats if pats else None


def is_legacy_platform_admin(perms: frozenset[str]) -> bool:
    """True for a full admin whose saved list just predates later permissions (request, approve, EDL)."""
    return "user_admin" in perms and perms | ADMIN_ADDED_PERMS == frozenset(PERMS)


def effective_perms(rec: dict) -> frozenset[str]:
    if isinstance(rec.get("permissions"), list):
        held = frozenset(p for p in rec["permissions"] if p in PERMS)
        # Existing platform / legacy admins get EDL admin without a manual re-tick.
        if is_legacy_platform_admin(held):
            return held | EDL_PERMS
        return held
    return ROLE_PERMS.get(rec.get("role", ""), frozenset())


def device_in_scope(patterns: list[str] | None, *, target: str = "", hostname: str = "", serial: str = "",
                    device_groups: list[str] | tuple = ()) -> bool:
    """A device matches a user's device scope by profile target name, hostname, serial or ``dg:<device group>``."""
    if patterns is None:
        return True
    keys = {x.lower() for x in (target, hostname, serial) if x}
    dgs = {d.lower() for d in device_groups or ()}
    for p in patterns:
        p = p.strip().lower()
        if p.startswith("dg:") and p[3:] in dgs:
            return True
        if p in keys:
            return True
    return False
COOKIE = "panlab_session"
SESSION_SECONDS = 8 * 3600
ITERATIONS = 600_000
MIN_PASSWORD_LENGTH = 12
_EPHEMERAL = secrets.token_bytes(32)
_AUDIT_FORBIDDEN = {"password", "new_password", "confirm", "current", "hash", "pw", "ssh_password", "gui_password"}


def users_file() -> Path:
    return Path(os.environ.get("PANLAB_USERS_FILE") or etc_dir() / "users.yaml")


def hash_password(pw: str, iterations: int = ITERATIONS) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), iterations)
    return f"pbkdf2_sha256${iterations}${salt}${dk.hex()}"


def verify_password(pw: str, stored: str) -> bool:
    try:
        algo, it, salt, hexd = stored.split("$")
    except ValueError:
        return False
    if algo != "pbkdf2_sha256":
        return False
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), int(it))
    return hmac.compare_digest(dk.hex(), hexd)


def load_users(path: Path | None = None) -> dict[str, dict]:
    p = path or users_file()
    if not p.is_file():
        return {}
    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return {k: v for k, v in (raw.get("users") or {}).items()
            if isinstance(v, dict) and (v.get("role") in ROLES or isinstance(v.get("permissions"), list))}


def _write_raw(p: Path, raw: dict) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        yaml.safe_dump(raw, f, sort_keys=True)
    os.replace(tmp, p)
    os.chmod(p, 0o600)


def set_access(name: str, permissions: list[str], customers: list[str], devices: dict[str, list[str]],
               path: Path | None = None) -> dict:
    """Replace a user's permissions and scope. Returns the stored record (without the hash)."""
    p = path or users_file()
    raw = (yaml.safe_load(p.read_text(encoding="utf-8")) or {}) if p.is_file() else {}
    rec = (raw.get("users") or {}).get(name)
    if not isinstance(rec, dict):
        raise KeyError(name)
    bad = [x for x in permissions if x not in PERMS]
    if bad:
        raise ValueError(f"unknown permissions: {', '.join(bad)}")
    rec["permissions"] = sorted(set(permissions))
    rec["customers"] = sorted(set(customers)) or []
    rec["devices"] = {k: sorted(set(v)) for k, v in devices.items() if v}
    rec.pop("role", None)  # permissions are now the source of truth
    _write_raw(p, raw)
    return {k: v for k, v in rec.items() if k != "hash"}


def migrate_roles(path: Path | None = None) -> list[tuple[str, str, list[str]]]:
    """Write explicit permissions for every role-only user (same access). Returns (user, role, perms) changed."""
    p = path or users_file()
    raw = (yaml.safe_load(p.read_text(encoding="utf-8")) or {}) if p.is_file() else {}
    done = []
    for n, rec in (raw.get("users") or {}).items():
        if isinstance(rec, dict) and "permissions" not in rec and rec.get("role") in ROLES:
            perms = sorted(ROLE_PERMS[rec["role"]])
            rec.update({"permissions": perms, "customers": ["*"], "devices": {}, "migrated_from_role": rec["role"]})
            rec.pop("role")
            done.append((n, rec["migrated_from_role"], perms))
    if done:
        _write_raw(p, raw)
    return done


def grant_edl_to_admins(path: Path | None = None) -> list[str]:
    """Persist EDL admin permissions onto existing platform/legacy admins.

    Only the permissions list is updated. Passwords, hashes and every other
    field are left untouched. Idempotent; returns the usernames that changed.
    """
    p = path or users_file()
    raw = (yaml.safe_load(p.read_text(encoding="utf-8")) or {}) if p.is_file() else {}
    done: list[str] = []
    for n, rec in (raw.get("users") or {}).items():
        if not isinstance(rec, dict) or not isinstance(rec.get("permissions"), list):
            continue
        held = frozenset(x for x in rec["permissions"] if x in PERMS)
        if is_legacy_platform_admin(held) and not EDL_PERMS <= held:
            rec["permissions"] = sorted(held | EDL_PERMS)
            done.append(n)
    if done:
        _write_raw(p, raw)
    return done


def add_user(name: str, role: str, password: str, path: Path | None = None, *, permissions: list[str] | None = None,
             customers: list[str] | None = None, devices: dict[str, list[str]] | None = None,
             must_change: bool = False) -> None:
    """Add (or reset) a user. ``role`` is a shortcut for that role's permission set (all customers)."""
    if role not in ROLES:
        raise ValueError(f"role must be one of {', '.join(ROLES)}")
    if not name or not name.replace("-", "").replace("_", "").replace(".", "").isalnum():
        raise ValueError("user names: letters, digits, . _ -")
    p = path or users_file()
    raw = (yaml.safe_load(p.read_text(encoding="utf-8")) or {}) if p.is_file() else {}
    if permissions is None and customers is None and devices is None and not must_change:
        # Plain role record: that role's permissions, all customers (what ``users add --role`` has always made)
        raw.setdefault("users", {})[name] = {"role": role, "hash": hash_password(password)}
    else:
        # Any scope, device limit or forced change must be stored: expand the role to explicit permissions so
        # the customer/device scope is honored whether access came from a role or from checkboxes.
        if permissions is None:
            permissions = sorted(ROLE_PERMS[role])
        bad = [x for x in permissions if x not in PERMS]
        if bad:
            raise ValueError(f"unknown permissions: {', '.join(bad)}")
        raw.setdefault("users", {})[name] = {
            "permissions": sorted(permissions), "customers": sorted(customers if customers is not None else ["*"]),
            "devices": devices or {}, "hash": hash_password(password)}
        if must_change:
            raw["users"][name]["must_change_password"] = True
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        yaml.safe_dump(raw, f, sort_keys=True)
    os.replace(tmp, p)
    os.chmod(p, 0o600)


def remove_user(name: str, path: Path | None = None) -> bool:
    p = path or users_file()
    raw = (yaml.safe_load(p.read_text(encoding="utf-8")) or {}) if p.is_file() else {}
    if name not in (raw.get("users") or {}):
        return False
    del raw["users"][name]
    tmp = p.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        yaml.safe_dump(raw, f, sort_keys=True)
    os.replace(tmp, p)
    return True


def set_flag(name: str, key: str, value: bool, path: Path | None = None) -> bool:
    """Set (True) or clear (False) a boolean flag such as ``disabled`` on a user."""
    p = path or users_file()
    raw = (yaml.safe_load(p.read_text(encoding="utf-8")) or {}) if p.is_file() else {}
    rec = (raw.get("users") or {}).get(name)
    if not isinstance(rec, dict):
        return False
    if value:
        rec[key] = True
    else:
        rec.pop(key, None)
    _write_raw(p, raw)
    return True


def authenticate(name: str, pw: str) -> str | None:
    u = load_users().get(name)
    if u and not u.get("disabled") and verify_password(pw, u.get("hash", "")):
        return Principal(name, u)[1]
    verify_password(pw, hash_password("x", 1000))  # similar work for unknown users
    return None


def _key() -> bytes:
    p = Path(os.environ.get("PANLAB_SESSION_KEY_FILE") or etc_dir() / "session.key")
    try:
        k = p.read_bytes().strip()
        if len(k) >= 32:
            return k
    except OSError:
        pass
    return _EPHEMERAL


def make_cookie(user: str) -> str:
    body = base64.urlsafe_b64encode(json.dumps({"u": user, "exp": int(time.time()) + SESSION_SECONDS}).encode()).decode()
    sig = hmac.new(_key(), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"


def read_cookie(value: str | None) -> Principal | None:
    """The signed-in user (permissions and scope re-read from the users file), or None."""
    if not value or "." not in value:
        return None
    body, sig = value.rsplit(".", 1)
    if not hmac.compare_digest(hmac.new(_key(), body.encode(), hashlib.sha256).hexdigest(), sig):
        return None
    try:
        d = json.loads(base64.urlsafe_b64decode(body.encode()))
    except Exception:  # noqa: BLE001
        return None
    if d.get("exp", 0) < time.time():
        return None
    u = load_users().get(d.get("u", ""))
    return Principal(d["u"], u) if u and not u.get("disabled") else None


def has_role(user, need: str) -> bool:
    """Legacy check: does ``user`` (a Principal) hold the permission that role ``need`` required?"""
    if isinstance(user, Principal):
        return user.can(ROLE_TO_PERM[need])
    return ROLES.index(user) >= ROLES.index(need)  # a bare role name


def generate_password() -> str:
    """Random password of at least MIN_PASSWORD_LENGTH (same generator as ``panlab users add``)."""
    pw = secrets.token_urlsafe(18)
    while len(pw) < MIN_PASSWORD_LENGTH:
        pw = secrets.token_urlsafe(18)
    return pw


def validate_new_password(pw: str, confirm: str | None = None) -> str | None:
    """Return an error message, or None if the new password is acceptable."""
    if not pw or len(pw) < MIN_PASSWORD_LENGTH:
        return f"New password must be at least {MIN_PASSWORD_LENGTH} characters."
    if confirm is not None and pw != confirm:
        return "New password and confirmation do not match."
    return None


def set_password(name: str, password: str, path: Path | None = None, *, must_change: bool = False) -> bool:
    """Update an existing user's password hash; keep their access. False if no such user.

    ``must_change=True`` (admin-set or generated passwords) makes the user choose a new one at next login.
    """
    err = validate_new_password(password)
    if err:
        raise ValueError(err)
    p = path or users_file()
    raw = (yaml.safe_load(p.read_text(encoding="utf-8")) or {}) if p.is_file() else {}
    rec = (raw.get("users") or {}).get(name)
    if not isinstance(rec, dict):
        return False
    rec["hash"] = hash_password(password)
    if must_change:
        rec["must_change_password"] = True
    else:
        rec.pop("must_change_password", None)
    tmp = p.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        yaml.safe_dump(raw, f, sort_keys=True)
    os.replace(tmp, p)
    os.chmod(p, 0o600)
    return True


def audit_file() -> Path:
    return Path(os.environ.get("PANLAB_USER_AUDIT_FILE") or etc_dir() / "user-audit.jsonl")


def write_user_audit(**rec: object) -> None:
    """Append one JSONL audit record. Password-like keys are dropped, never written."""
    from datetime import datetime
    from zoneinfo import ZoneInfo

    clean = {k: v for k, v in rec.items() if k.lower() not in _AUDIT_FORBIDDEN and "password" not in k.lower() and "hash" not in k.lower()}
    clean.setdefault("ts", datetime.now(ZoneInfo("America/Chicago")).isoformat(timespec="seconds"))
    p = audit_file()
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(p, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        f.write(json.dumps(clean, sort_keys=True) + "\n")
    os.chmod(p, 0o600)


def read_user_audit(limit: int = 200) -> list[dict]:
    p = audit_file()
    if not p.is_file():
        return []
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()][-limit:]
