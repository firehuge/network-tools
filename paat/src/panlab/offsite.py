"""Off-box copies of tool backups (upgrade backups, pre-push running configs).

Opt-in per customer, configured by an admin. With no configuration the tool
keeps local copies only, exactly as before. The local copy is always written
first and always kept; an off-box copy is extra.

Where things live (never in git):

* ``/etc/panlab/backup-destinations/<customer>.json``: the destinations
  (type, host, bucket, path...). No secrets. Mode 600.
* ``/etc/panlab/backup-destinations/<customer>.env``: passwords, tokens and
  keys, ``PANLAB_DEST_<ID>_<FIELD>=value``. Mode 600. Never shown in the UI,
  logs or errors.

Destination types: ``git`` (a separate private repo per customer; the tool's
own repo is refused), ``sftp``, ``ftps`` (FTP over TLS) and ``s3`` (AWS S3 or
any S3-compatible store such as MinIO). Plain FTP is not offered: it sends the
password and the configs in clear text.

Layout, the same on every destination (under the destination's base path)::

    <hostname>_<serial>/<YYYY-MM-DD>/<HHMMSS>_<run-id>_<type>.<ext>
    <hostname>_<serial>/<YYYY-MM-DD>/<HHMMSS>_<run-id>_manifest.json

Every file is verified after upload (size and SHA-256, or the pushed git
commit), and every upload writes one audit line. :func:`ship` never raises: a
destination failure is returned (and shown yellow); it never fails or blocks
the upgrade or push that made the backup.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import secrets as pysecrets
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable
from zoneinfo import ZoneInfo
from panlab.paths import etc_dir as _server_etc_dir

TZ = ZoneInfo("America/Chicago")
TYPES = ("git", "sftp", "ftps", "s3")
FIELDS: dict[str, tuple[str, ...]] = {  # non-secret settings per type
    "git": ("url", "branch", "base_dir", "host_key"),
    "sftp": ("host", "port", "username", "base_dir", "host_key"),
    "ftps": ("host", "port", "username", "base_dir", "verify_tls"),
    "s3": ("endpoint_url", "region", "bucket", "prefix", "path_style"),
}
SECRETS: dict[str, tuple[str, ...]] = {
    "git": ("token", "ssh_key"),
    "sftp": ("password", "ssh_key"),
    "ftps": ("password",),
    "s3": ("access_key", "secret_key"),
}
# Exact last path component of the tool's GitHub repo, including the former name.
OWN_REPOS = frozenset({"paat", "network-tools"})
OWN_REPO = "PAAT"  # display name in error messages
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,30}$")
TIMEOUT = 60


class OffsiteError(RuntimeError):
    pass


def _now() -> datetime:
    return datetime.now(TZ)


# ---------------------------------------------------------------- config storage

def etc_dir(create: bool = False) -> Path:
    d = _server_etc_dir() / "backup-destinations"
    if not create:
        return d
    d.mkdir(parents=True, exist_ok=True)
    try:
        d.chmod(0o700)
    except OSError:
        pass
    return d


def _cfg_path(customer: str) -> Path:
    if not re.match(r"^[A-Za-z0-9._-]+$", customer):
        raise OffsiteError("bad customer name")
    return etc_dir() / f"{customer}.json"


def _env_path(customer: str) -> Path:
    return _cfg_path(customer).with_suffix(".env")


def _write_600(p: Path, text: str) -> None:
    etc_dir(create=True)
    tmp = p.with_name(f".{p.name}.{pysecrets.token_hex(4)}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, p)
    p.chmod(0o600)


def load_config(customer: str) -> list[dict]:
    p = _cfg_path(customer)
    if not p.is_file():
        return []
    return list((json.loads(p.read_text(encoding="utf-8")) or {}).get("destinations") or [])


def _load_env(customer: str) -> dict[str, str]:
    p = _env_path(customer)
    out: dict[str, str] = {}
    if p.is_file():
        for line in p.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip()
    return out


def _skey(did: str, field: str) -> str:
    return f"PANLAB_DEST_{did.upper().replace('-', '_')}_{field.upper()}"


def secret(customer: str, did: str, field: str) -> str:
    v = _load_env(customer).get(_skey(did, field), "")
    if field == "ssh_key" and v:
        try:
            return base64.b64decode(v).decode()
        except ValueError:
            return ""
    return v


def secrets_set(customer: str, d: dict) -> dict[str, bool]:
    env = _load_env(customer)
    return {f: bool(env.get(_skey(d["id"], f))) for f in SECRETS.get(d["type"], ())}


def refuse_own_repo(url: str) -> None:
    norm = re.sub(r"\.git/?$", "", (url or "").strip().lower().rstrip("/"))
    name = norm.rsplit("/", 1)[-1].rsplit(":", 1)[-1]
    if name in OWN_REPOS:
        raise OffsiteError(f"Backups never go into the tool's own repo ({OWN_REPO}). Use a separate private repo for this customer.")


def validate(d: dict) -> dict:
    t = d.get("type")
    if t not in TYPES:
        raise OffsiteError(f"type must be one of {', '.join(TYPES)} (plain FTP is not offered: it sends passwords in clear text)")
    if not ID_RE.match(d.get("id") or ""):
        raise OffsiteError("id: lowercase letters, digits and dashes")
    out = {"id": d["id"], "type": t, "name": (d.get("name") or d["id"]).strip()[:60], "enabled": bool(d.get("enabled"))}
    for f in FIELDS[t]:
        out[f] = str(d.get(f) or "").strip()
    if t == "git":
        if not out["url"]:
            raise OffsiteError("git: repository URL is required")
        refuse_own_repo(out["url"])
        if out["url"].startswith("http://"):
            raise OffsiteError("git: use https:// or ssh (git@host:owner/repo.git), not http://")
        out["branch"] = out["branch"] or "main"
    if t in ("sftp", "ftps") and not (out["host"] and out["username"]):
        raise OffsiteError(f"{t}: host and username are required")
    if t == "sftp":
        out["port"] = out["port"] or "22"
    if t == "ftps":
        out["port"] = out["port"] or "21"
        out["verify_tls"] = "no" if str(d.get("verify_tls")).lower() in ("no", "off", "false", "0") else "yes"
    if t == "s3":
        if not out["bucket"]:
            raise OffsiteError("s3: bucket is required")
        out["path_style"] = "yes" if str(d.get("path_style")).lower() in ("yes", "on", "true", "1") else "no"
    for k in ("base_dir", "prefix"):
        if k in out:
            out[k] = out[k].strip("/")
            if ".." in out[k].split("/"):
                raise OffsiteError(f"{k}: '..' is not allowed")
    return out


def save_destination(customer: str, d: dict, new_secrets: dict[str, str]) -> dict:
    """Add or replace one destination. Blank secrets keep the stored value."""
    d = validate(d)
    dests = [x for x in load_config(customer) if x["id"] != d["id"]] + [d]
    _write_600(_cfg_path(customer), json.dumps({"destinations": dests}, indent=2) + "\n")
    env = _load_env(customer)
    for f in SECRETS[d["type"]]:
        v = (new_secrets.get(f) or "").strip()
        if v:
            if f == "ssh_key":
                v = base64.b64encode((new_secrets[f].strip() + "\n").encode()).decode()
            env[_skey(d["id"], f)] = v
    _write_600(_env_path(customer), "".join(f"{k}={v}\n" for k, v in sorted(env.items())))
    return d


def delete_destination(customer: str, did: str) -> None:
    dests = [x for x in load_config(customer) if x["id"] != did]
    _write_600(_cfg_path(customer), json.dumps({"destinations": dests}, indent=2) + "\n")
    prefix = _skey(did, "")
    env = {k: v for k, v in _load_env(customer).items() if not k.startswith(prefix)}
    _write_600(_env_path(customer), "".join(f"{k}={v}\n" for k, v in sorted(env.items())))


def set_field(customer: str, did: str, field: str, value: str) -> None:
    dests = load_config(customer)
    for x in dests:
        if x["id"] == did:
            x[field] = value
    _write_600(_cfg_path(customer), json.dumps({"destinations": dests}, indent=2) + "\n")


# ---------------------------------------------------------------- layout

def _safe(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", s or "") or "unknown"


def device_dir(ident: dict | None) -> str:
    ident = ident or {}
    return f"{_safe(ident.get('hostname') or 'hostname-unknown')}_{_safe(ident.get('serial') or 'serial-unknown')}"


def file_name(when: datetime, run_id: str, ftype: str, ext: str) -> str:
    return f"{when:%H%M%S}_{_safe(run_id)}_{_safe(ftype)}{ext}"


def date_dirs(when: datetime) -> str:
    """Year, month and day folders: ``YYYY/MM/DD``."""
    return f"{when:%Y}/{when:%m}/{when:%d}"


def device_path(customer: str, ident: dict | None) -> str:
    """``<customer>/<hostname>_<serial>``: one master folder per device, under its customer."""
    return f"{_safe(customer)}/{device_dir(ident)}"


def remote_name(ident: dict | None, when: datetime, run_id: str, ftype: str, ext: str, customer: str = "") -> str:
    """``<customer>/<hostname>_<serial>/<YYYY>/<MM>/<DD>/<HHMMSS>_<run-id>_<type><ext>`` (inside the destination's base folder)."""
    head = device_path(customer, ident) if customer else device_dir(ident)
    return f"{head}/{date_dirs(when)}/{file_name(when, run_id, ftype, ext)}"


@dataclass
class Item:
    path: Path
    type: str  # running-config, device-state, pre-change-running-config ...


def _ext(p: Path) -> str:
    n = p.name
    return ".tgz" if n.endswith(".tgz") else ".tar.gz" if n.endswith(".tar.gz") else (p.suffix or ".bin")


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# ---------------------------------------------------------------- backends

class _Redactor:
    def __init__(self, values: list[str]):
        self.values = [v for v in values if v and len(v) >= 4]

    def __call__(self, msg: str) -> str:
        msg = str(msg)
        for v in self.values:
            msg = msg.replace(v, "***")
            for line in v.splitlines():
                if len(line) > 8:
                    msg = msg.replace(line, "***")
        return re.sub(r"(Authorization: *Basic +)\S+", r"\1***", msg, flags=re.I)


class Backend:
    def __init__(self, customer: str, d: dict, data_dir: Path | None = None):
        self.customer, self.d = customer, d
        self.sec = {f: secret(customer, d["id"], f) for f in SECRETS[d["type"]]}
        self.redact = _Redactor(list(self.sec.values()))
        self.data_dir = data_dir

    def base(self, rel: str) -> str:
        b = self.d.get("base_dir") or self.d.get("prefix") or ""
        return f"{b}/{rel}" if b else rel

    def describe(self) -> str:
        raise NotImplementedError

    def put(self, files: list[tuple[str, bytes]], message: str) -> list[dict]:
        """Upload, then verify. Returns one dict per file: remote, size, sha256, verified, detail."""
        raise NotImplementedError

    def test(self) -> str:
        raise NotImplementedError


# ---- S3 / MinIO

def s3_client(*, endpoint_url: str = "", region: str = "", path_style: bool = False, access_key: str = "", secret_key: str = ""):
    """boto3 S3 client for AWS or an S3-compatible store (MinIO). Shared by backups and the EDL manager.
    Blank keys fall back to boto3's default chain (environment, instance role)."""
    import boto3
    from botocore.config import Config

    cfg = Config(connect_timeout=15, read_timeout=TIMEOUT, retries={"max_attempts": 2},
                 s3={"addressing_style": "path" if path_style else "auto"})
    return boto3.client("s3", endpoint_url=endpoint_url or None, region_name=region or None,
                        aws_access_key_id=access_key or None, aws_secret_access_key=secret_key or None, config=cfg)


class S3Backend(Backend):
    def _client(self):
        return s3_client(endpoint_url=self.d.get("endpoint_url") or "", region=self.d.get("region") or "",
                         path_style=self.d.get("path_style") == "yes", access_key=self.sec.get("access_key") or "",
                         secret_key=self.sec.get("secret_key") or "")

    def describe(self) -> str:
        return f"s3://{self.d['bucket']}/{self.d.get('prefix') or ''} ({self.d.get('endpoint_url') or 'AWS'})"

    def put(self, files, message):
        c = self._client()
        out = []
        for rel, data in files:
            key = self.base(rel)
            h = sha256(data)
            c.put_object(Bucket=self.d["bucket"], Key=key, Body=data, Metadata={"sha256": h})
            head = c.head_object(Bucket=self.d["bucket"], Key=key)
            ok = head["ContentLength"] == len(data) and (head.get("Metadata") or {}).get("sha256") == h
            out.append({"remote": f"s3://{self.d['bucket']}/{key}", "size": len(data), "sha256": h, "verified": ok,
                        "detail": f"HEAD size {head['ContentLength']}, sha256 metadata {'matches' if ok else 'DIFFERS'}"})
        return out

    def test(self):
        c = self._client()
        key = self.base(f".panlab-test-{pysecrets.token_hex(4)}")
        c.put_object(Bucket=self.d["bucket"], Key=key, Body=b"panlab test\n")
        c.head_object(Bucket=self.d["bucket"], Key=key)
        c.delete_object(Bucket=self.d["bucket"], Key=key)
        return f"Wrote, read back and deleted a test object in {self.describe()}."


# ---- SFTP

def _load_pkey(text: str):
    import paramiko

    last = None
    for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return cls.from_private_key(io.StringIO(text))
        except (paramiko.SSHException, ValueError) as exc:
            last = exc
    raise OffsiteError(f"the stored private key could not be read ({type(last).__name__})")


class SftpBackend(Backend):
    def describe(self) -> str:
        return f"sftp://{self.d['username']}@{self.d['host']}:{self.d.get('port') or 22}/{self.d.get('base_dir') or ''}"

    def scan_host_key(self) -> str:
        import paramiko

        t = paramiko.Transport((self.d["host"], int(self.d.get("port") or 22)))
        try:
            t.start_client(timeout=15)
            k = t.get_remote_server_key()
            return f"{k.get_name()} {k.get_base64()}"
        finally:
            t.close()

    def _connect(self):
        import paramiko

        if not self.d.get("host_key"):
            raise OffsiteError("the server's host key is not pinned yet: run Test connection and pin the key it shows")
        kt, kb = self.d["host_key"].split()[:2]
        cli = paramiko.SSHClient()
        cli.get_host_keys().add(f"[{self.d['host']}]:{self.d.get('port') or 22}" if str(self.d.get("port") or "22") != "22"
                                else self.d["host"], kt, paramiko.PKey.from_type_string(kt, base64.b64decode(kb)))
        cli.set_missing_host_key_policy(paramiko.RejectPolicy())
        pkey = None
        if self.sec.get("ssh_key"):
            pkey = _load_pkey(self.sec["ssh_key"])
        cli.connect(self.d["host"], port=int(self.d.get("port") or 22), username=self.d["username"],
                    password=self.sec.get("password") or None, pkey=pkey, timeout=15, banner_timeout=15,
                    auth_timeout=15, look_for_keys=False, allow_agent=False)
        return cli

    @staticmethod
    def _mkdirs(sftp, path: str) -> None:
        cur = ""
        for part in [p for p in path.split("/") if p]:
            cur = f"{cur}/{part}" if cur or path.startswith("/") else part
            try:
                sftp.stat(cur)
            except OSError:
                sftp.mkdir(cur)

    def put(self, files, message):
        cli = self._connect()
        out = []
        try:
            sftp = cli.open_sftp()
            sftp.get_channel().settimeout(TIMEOUT)
            for rel, data in files:
                path = self.base(rel)
                self._mkdirs(sftp, path.rsplit("/", 1)[0])
                sftp.putfo(io.BytesIO(data), path, confirm=True)
                st = sftp.stat(path)
                back = io.BytesIO()
                sftp.getfo(path, back)
                ok = st.st_size == len(data) and sha256(back.getvalue()) == sha256(data)
                out.append({"remote": f"{self.describe().rstrip('/')}/{rel}", "size": len(data), "sha256": sha256(data),
                            "verified": ok, "detail": f"size {st.st_size}, read back sha256 {'matches' if ok else 'DIFFERS'}"})
        finally:
            cli.close()
        return out

    def test(self):
        if not self.d.get("host_key"):
            raise OffsiteError(f"Host key not pinned. The server presented: {self.scan_host_key()}. Check it, then pin it.")
        name = f".panlab-test-{pysecrets.token_hex(4)}"
        cli = self._connect()
        try:
            sftp = cli.open_sftp()
            base = self.d.get("base_dir") or "."
            self._mkdirs(sftp, base) if base != "." else None
            p = f"{base}/{name}"
            sftp.putfo(io.BytesIO(b"panlab test\n"), p)
            sftp.remove(p)
        finally:
            cli.close()
        return f"Logged in, wrote and deleted a test file in {self.describe()}."


# ---- FTPS (explicit TLS). Plain FTP is deliberately not offered.

class FtpsBackend(Backend):
    ftp_class: Callable | None = None  # tests replace this

    def describe(self) -> str:
        return f"ftps://{self.d['username']}@{self.d['host']}:{self.d.get('port') or 21}/{self.d.get('base_dir') or ''}"

    def _connect(self):
        import ftplib
        import ssl

        ctx = ssl.create_default_context()
        if self.d.get("verify_tls") == "no":
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        cls = self.ftp_class or ftplib.FTP_TLS
        f = cls(context=ctx, timeout=TIMEOUT)
        f.connect(self.d["host"], int(self.d.get("port") or 21))
        f.login(self.d["username"], self.sec.get("password") or "")
        f.prot_p()
        return f

    @staticmethod
    def _mkdirs(f, path: str) -> None:
        for i, _ in enumerate(parts := [p for p in path.split("/") if p]):
            try:
                f.mkd("/".join(parts[: i + 1]))
            except Exception:  # noqa: BLE001 - exists
                pass

    def put(self, files, message):
        f = self._connect()
        out = []
        try:
            for rel, data in files:
                path = self.base(rel)
                self._mkdirs(f, path.rsplit("/", 1)[0])
                f.storbinary(f"STOR {path}", io.BytesIO(data))
                f.voidcmd("TYPE I")
                size = f.size(path)
                back = io.BytesIO()
                f.retrbinary(f"RETR {path}", back.write)
                ok = size == len(data) and sha256(back.getvalue()) == sha256(data)
                out.append({"remote": f"{self.describe().rstrip('/')}/{rel}", "size": len(data), "sha256": sha256(data),
                            "verified": ok, "detail": f"SIZE {size}, read back sha256 {'matches' if ok else 'DIFFERS'}"})
        finally:
            try:
                f.quit()
            except Exception:  # noqa: BLE001
                f.close()
        return out

    def test(self):
        f = self._connect()
        try:
            name = self.base(f".panlab-test-{pysecrets.token_hex(4)}")
            if "/" in name:
                self._mkdirs(f, name.rsplit("/", 1)[0])
            f.storbinary(f"STOR {name}", io.BytesIO(b"panlab test\n"))
            f.delete(name)
        finally:
            f.close()
        return f"Logged in over TLS, wrote and deleted a test file in {self.describe()}."


# ---- git (a separate private repo per customer)

def ssh_host_port(url: str) -> tuple[str, int]:
    """Host and port of an SSH git URL: ``git@host:owner/repo.git`` or ``ssh://git@host:443/owner/repo.git``."""
    if url.startswith("ssh://"):
        hp = url[6:].split("/", 1)[0].split("@", 1)[-1]
        host, _, port = hp.partition(":")
        return host, int(port or 22)
    return url.split("@", 1)[-1].split(":", 1)[0].split("/", 1)[0], 22


def known_hosts_name(host: str, port: int) -> str:
    return host if port == 22 else f"[{host}]:{port}"


class GitBackend(Backend):
    def describe(self) -> str:
        return f"git {self.d['url']} ({self.d.get('branch') or 'main'})"

    def _env(self, tmp: Path) -> dict[str, str]:
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_AUTHOR_NAME": "panlab", "GIT_AUTHOR_EMAIL": "panlab@localhost",
                    "GIT_COMMITTER_NAME": "panlab", "GIT_COMMITTER_EMAIL": "panlab@localhost", "HOME": str(tmp)})
        url = self.d["url"]
        if self.sec.get("token") and url.startswith("https://"):
            cred = base64.b64encode(f"x-access-token:{self.sec['token']}".encode()).decode()
            env.update({"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.extraHeader",
                        "GIT_CONFIG_VALUE_0": f"Authorization: Basic {cred}"})  # env, not argv: never in `ps`
        if self.sec.get("ssh_key") and not url.startswith(("https://", "file://", "/")):
            key = tmp / "id"
            key.write_text(self.sec["ssh_key"])
            key.chmod(0o600)
            kh = tmp / "known_hosts"
            kh.write_text(f"{known_hosts_name(*ssh_host_port(url))} {self.d.get('host_key')}\n" if self.d.get("host_key") else "")
            env["GIT_SSH_COMMAND"] = (f"ssh -i {key} -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=15 "
                                      f"-o StrictHostKeyChecking=yes -o UserKnownHostsFile={kh}")
        return env

    def _git(self, env, *args, cwd: Path | None = None, check: bool = True) -> str:
        r = subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, text=True, timeout=TIMEOUT * 2)
        if check and r.returncode != 0:
            raise OffsiteError(self.redact(f"git {args[0]} failed: {(r.stderr or r.stdout).strip()[-600:]}"))
        return r.stdout

    def _need_host_key(self) -> None:
        url = self.d["url"]
        if self.sec.get("ssh_key") and not url.startswith(("https://", "file://", "/")) and not self.d.get("host_key"):
            raise OffsiteError("the git server's SSH host key is not pinned: run Test connection and pin the key it shows")

    def scan_host_key(self) -> str:
        host, port = ssh_host_port(self.d["url"])
        r = subprocess.run(["ssh-keyscan", "-T", "10", "-p", str(port), "-t", "ed25519", host], capture_output=True, text=True, timeout=30)
        line = next((x for x in r.stdout.splitlines() if x and not x.startswith("#")), "")
        return " ".join(line.split()[1:3])

    def put(self, files, message):
        refuse_own_repo(self.d["url"])
        self._need_host_key()
        branch = self.d.get("branch") or "main"
        work = (self.data_dir or Path(tempfile.gettempdir())) / "offsite-git" / _safe(self.d["id"])
        with tempfile.TemporaryDirectory(prefix="panlab-git-") as t:
            tmp = Path(t)
            env = self._env(tmp)
            if not (work / ".git").is_dir():
                shutil.rmtree(work, ignore_errors=True)
                work.parent.mkdir(parents=True, exist_ok=True)
                self._git(env, "clone", "--quiet", "--no-tags", self.d["url"], str(work))
            self._git(env, "remote", "set-url", "origin", self.d["url"], cwd=work)
            last = None
            for _attempt in range(2):  # one retry if someone else pushed in between
                self._git(env, "fetch", "--quiet", "origin", cwd=work, check=False)
                has = self._git(env, "ls-remote", "--heads", "origin", branch, cwd=work).strip()
                if has:
                    self._git(env, "checkout", "--quiet", "-B", branch, f"origin/{branch}", cwd=work)
                    self._git(env, "reset", "--quiet", "--hard", f"origin/{branch}", cwd=work)
                else:
                    self._git(env, "checkout", "--quiet", "--orphan", branch, cwd=work, check=False)
                for rel, data in files:
                    p = work / self.base(rel)
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_bytes(data)
                    self._git(env, "add", "--", self.base(rel), cwd=work)
                self._git(env, "commit", "--quiet", "-m", message, cwd=work)
                r = subprocess.run(["git", "push", "--quiet", "origin", f"HEAD:refs/heads/{branch}"], cwd=work, env=env,
                                   capture_output=True, text=True, timeout=TIMEOUT * 2)
                if r.returncode == 0:
                    break
                last = self.redact((r.stderr or r.stdout).strip()[-600:])
            else:
                raise OffsiteError(f"git push failed: {last}")
            head = self._git(env, "rev-parse", "HEAD", cwd=work).strip()
            remote = self._git(env, "ls-remote", "origin", f"refs/heads/{branch}", cwd=work).split()[:1]
            out = []
            for rel, data in files:
                blob = self._git(env, "rev-parse", f"HEAD:{self.base(rel)}", cwd=work).strip()
                want = hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()
                ok = remote == [head] and blob == want
                out.append({"remote": f"{self.d['url']}#{branch}:{self.base(rel)}", "size": len(data), "sha256": sha256(data),
                            "verified": ok, "commit": head,
                            "detail": f"commit {head[:12]} {'is' if remote == [head] else 'is NOT'} the remote branch head; "
                                      f"blob {'matches' if blob == want else 'DIFFERS'}"})
            return out

    def test(self):
        refuse_own_repo(self.d["url"])
        if self.sec.get("ssh_key") and not self.d["url"].startswith(("https://", "file://", "/")) and not self.d.get("host_key"):
            raise OffsiteError(f"SSH host key not pinned. The server presented: {self.scan_host_key()}. Check it, then pin it.")
        branch = self.d.get("branch") or "main"
        with tempfile.TemporaryDirectory(prefix="panlab-git-") as t:
            tmp = Path(t)
            env = self._env(tmp)
            self._git(env, "ls-remote", self.d["url"])
            repo = tmp / "r"
            self._git(env, "init", "--quiet", str(repo))
            self._git(env, "commit", "--quiet", "--allow-empty", "-m", "panlab write test (not pushed)", cwd=repo)
            # A dry-run push still authenticates for receive-pack, so a read-only key or token fails here.
            self._git(env, "push", "--dry-run", "--quiet", self.d["url"], f"HEAD:refs/heads/panlab-write-test-{pysecrets.token_hex(3)}",
                      cwd=repo)
        return f"Read access and write permission confirmed for {self.describe()} (dry-run push; nothing was written)."


BACKENDS: dict[str, type[Backend]] = {"s3": S3Backend, "sftp": SftpBackend, "ftps": FtpsBackend, "git": GitBackend}


def backend(customer: str, d: dict, data_dir: Path | None = None) -> Backend:
    return BACKENDS[d["type"]](customer, d, data_dir)


def test_destination(customer: str, did: str, data_dir: Path | None = None) -> tuple[bool, str]:
    d = next((x for x in load_config(customer) if x["id"] == did), None)
    if d is None:
        return False, "no such destination"
    b = backend(customer, d, data_dir)
    try:
        return True, b.test()
    except Exception as exc:  # noqa: BLE001 - shown to the admin, redacted
        return False, b.redact(f"{type(exc).__name__}: {exc}")


def scan_host_key(customer: str, did: str) -> str:
    d = next(x for x in load_config(customer) if x["id"] == did)
    return backend(customer, d).scan_host_key()


# ---------------------------------------------------------------- ship

def ship(profile, items: list[Item], *, run_id: str, kind: str, ident: dict | None, actor: str = "", cr: str = "",
         extra: dict | None = None, when: datetime | None = None, audit: Callable | None = None) -> list[dict]:
    """Copy local backup files to every enabled destination of this customer. Never raises.

    Returns one result per destination: {dest, name, type, ok, files:[...], error}. ``ok`` is True only when every
    file (and the manifest) was uploaded and verified.
    """
    try:
        dests = [d for d in load_config(profile.name) if d.get("enabled")]
    except Exception as exc:  # noqa: BLE001
        return [{"dest": "?", "name": "configuration", "type": "?", "ok": False, "files": [],
                 "error": f"could not read the backup destinations: {exc}"}]
    if not dests or not items:
        return []
    if audit is None:
        from panlab.pusher import audit as audit  # noqa: PLW0127
    when = when or _now()
    payload = []
    for it in items:
        data = Path(it.path).read_bytes()
        payload.append((remote_name(ident, when, run_id, it.type, _ext(Path(it.path)), customer=profile.name), data, it))
    manifest = {"schema": "panlab.backup-manifest/v1", "customer": profile.name, "kind": kind, "run_id": run_id,
                "created": when.isoformat(timespec="seconds"), "timezone": "America/Chicago", "user": actor, "cr": cr,
                "device": {k: (ident or {}).get(k, "") for k in ("hostname", "serial", "model")}, **(extra or {}),
                "files": [{"name": rel.rsplit("/", 1)[-1], "type": it.type, "local_name": Path(it.path).name,
                           "size": len(data), "sha256": sha256(data)} for rel, data, it in payload]}
    mrel = remote_name(ident, when, run_id, "manifest", ".json", customer=profile.name)
    files = [(rel, data) for rel, data, _ in payload] + [(mrel, (json.dumps(manifest, indent=2) + "\n").encode())]
    msg = f"{kind} backup {run_id}: {device_path(profile.name, ident)} ({cr or 'no CR'}, by {actor or '?'})"
    results = []
    for d in dests:
        res = {"dest": d["id"], "name": d.get("name") or d["id"], "type": d["type"], "ok": False, "files": [], "error": ""}
        b = None
        try:
            b = backend(profile.name, d, profile.data_dir())
            res["where"] = b.describe()
            res["files"] = b.put(files, msg)
            bad = [f for f in res["files"] if not f["verified"]]
            res["ok"] = not bad and len(res["files"]) == len(files)
            if bad:
                res["error"] = "verification failed: " + "; ".join(f"{f['remote']}: {f['detail']}" for f in bad)
        except Exception as exc:  # noqa: BLE001 - never fails the run; shown yellow
            red = b.redact if b else (lambda m: m)
            res["error"] = red(f"{type(exc).__name__}: {exc}")[:600]
        for f in res["files"] or [{"remote": "", "size": None, "sha256": "", "verified": False, "detail": ""}]:
            try:
                audit(profile, actor=actor, action="backup-offsite", area=kind, run=run_id, cr=cr,
                      destination=f"{res['name']} ({d['type']})", remote=f.get("remote"), size=f.get("size"),
                      sha256=f.get("sha256"), verified=bool(f.get("verified")),
                      hostname=(ident or {}).get("hostname") or "hostname unknown",
                      serial=(ident or {}).get("serial") or "serial unknown",
                      result="ok" if res["ok"] else "failed", error=res["error"][:300] if not res["ok"] else "")
            except Exception:  # noqa: BLE001
                pass
        results.append(res)
    return results


def summary_lines(results: list[dict]) -> list[str]:
    out = []
    for r in results or []:
        if r["ok"]:
            out.append(f"Off-box copy OK: {r['name']} ({r['type']}), {len(r['files'])} file(s) uploaded and verified to {r.get('where', '')}")
        else:
            out.append(f"CHECK: off-box copy to {r['name']} ({r['type']}) failed: {r['error']} (the local backup is kept)")
    return out
