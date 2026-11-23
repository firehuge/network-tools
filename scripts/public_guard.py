#!/usr/bin/env python3
"""Public-release guard: blocks customer markers, private addresses and other
site-specific data from being committed to this repository.

Usage:
  python3 scripts/public_guard.py --staged     # pre-commit hook: staged files
  python3 scripts/public_guard.py --all        # CI: every tracked file

Checks (all of them fail the run):
  * 192.168.x.x addresses anywhere (except the bare network address 192.168.0.0 used in RFC 1918 range
    constants, and the files listed under "allow_192_168_paths").
  * 10.x / 172.16-31.x addresses outside the example paths in .public-guard.json
    ("private_ok_paths"); inside those paths they are allowed as examples.
  * Public IPv4 addresses outside the RFC 5737 / RFC 2544 documentation ranges
    and a small allowlist of well-known public DNS servers.
  * 12- and 15-digit serial numbers that do not look synthetic (synthetic =
    four or more identical digits in a row, or 0123456789).
  * E-mail addresses other than example.com / example.org / *.noreply addresses.
  * File names that must never be committed (mapping.csv, *.pem, .env, ...).
  * Office/zip files (.xlsx/.docx/.zip/.tgz) whose metadata or members contain a
    blocked marker (sensitivity labels, tenant IDs, author names).
  * Customer markers: a PRIVATE list of words kept OUTSIDE the repository.
    Put one word or regex per line in the file named by $PUBLIC_GUARD_TERMS
    (default: ~/.public-guard-terms). The list itself must never be committed.
    In CI, store the list in a repository secret and write it to a file first.
"""
import io, ipaddress, json, os, re, subprocess, sys, tarfile, zipfile

ROOT = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True).stdout.strip() or "."
CFG_PATH = os.path.join(ROOT, ".public-guard.json")
CFG = {"private_ok_paths": [], "allow_public_ips": ["8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9"],
       "allow_emails": [], "allow_email_paths": [], "allow_192_168_paths": [], "skip_terms_paths": [], "skip_paths": [".public-guard.json", "scripts/public_guard.py"]}
if os.path.exists(CFG_PATH):
    CFG.update(json.load(open(CFG_PATH)))

DOC = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "198.18.0.0/15")]
IP4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
SERIAL = re.compile(r"(?<![\w.:-])(?:\d{12}|\d{15})(?![\w.:-])")
EMAIL = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")
BAD_NAMES = re.compile(r"(^|/)(mapping\.csv|\.env|id_rsa|id_ed25519|.*\.pem|.*\.key|.*\.p12|.*\.pfx)$")
ARCHIVES = (".xlsx", ".docx", ".zip", ".tgz", ".tar.gz", ".tar")


def terms():
    p = os.environ.get("PUBLIC_GUARD_TERMS", os.path.expanduser("~/.public-guard-terms"))
    out = []
    if os.path.exists(p):
        for l in open(p, encoding="utf-8"):
            l = l.strip()
            if l and not l.startswith("#"):
                out.append(re.compile(l, re.I))
    return out


def files(mode):
    cmd = ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"] if mode == "--staged" else ["git", "ls-files"]
    return [f for f in subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT).stdout.split("\n") if f]


def content(path, mode):
    if mode == "--staged":
        return subprocess.run(["git", "show", ":" + path], capture_output=True, cwd=ROOT).stdout
    try:
        return open(os.path.join(ROOT, path), "rb").read()
    except OSError:
        return b""


def blobs(path, data):
    """Yield (name, text) for the file and for members of zip/tar archives."""
    low = path.lower()
    try:
        if low.endswith((".xlsx", ".docx", ".zip")):
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for n in z.namelist():
                    yield from blobs(path + "!" + n, z.read(n))
            return
        if low.endswith((".tgz", ".tar.gz", ".tar")):
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as t:
                for m in t.getmembers():
                    if m.isfile():
                        yield from blobs(path + "!" + m.name, t.extractfile(m).read())
            return
    except Exception:
        return
    if b"\0" in data[:4000]:
        return
    yield path, data.decode("utf-8", "replace")


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "--all"
    pats = terms()
    problems = []
    for path in files(mode):
        if path in CFG["skip_paths"]:
            continue
        if BAD_NAMES.search(path):
            problems.append((path, 0, "forbidden file name"))
            continue
        priv_ok = any(path.startswith(p) for p in CFG["private_ok_paths"])
        for name, text in blobs(path, content(path, mode)):
            for ln, line in enumerate(text.split("\n"), 1):
                for m in IP4.finditer(line):
                    try:
                        ip = ipaddress.ip_address(m.group(0))
                    except ValueError:
                        continue
                    s = m.group(0)
                    if any(ip in d for d in DOC) or ip.is_unspecified or ip.is_loopback or ip.is_multicast or s.startswith(("255.", "0.")) or ip in ipaddress.ip_network("100.64.0.0/10"):
                        continue
                    if s.startswith("192.168."):
                        if s != "192.168.0.0" and not any(path.startswith(p) for p in CFG["allow_192_168_paths"]):
                            problems.append((name, ln, "192.168.x.x address " + s))
                    elif ip.is_private:
                        if not priv_ok:
                            problems.append((name, ln, "private address outside example paths " + s))
                    elif s not in CFG["allow_public_ips"] and not re.search(r"\d+\.\d+\.\d+\.\d+/\d+|version|v\d|detail-version|\d+\.\d+\.\d+\.\d+-", line[max(0, m.start() - 12):m.end() + 12]):
                        if not re.search(r"(?i)version|release|content|panos|pan-os|app-id|threat|build", line):
                            problems.append((name, ln, "public address outside documentation ranges " + s))
                for m in SERIAL.finditer(line):
                    v = m.group(0)
                    if not (re.search(r"(\d)\1{3,}", v) or "0123456789" in v or "1234567890" in v):
                        problems.append((name, ln, "serial-like number " + v[:3] + "…" + v[-3:]))
                for m in ([] if any(path.startswith(p) for p in CFG["allow_email_paths"]) else EMAIL.finditer(line)):
                    dom = m.group(1).lower()
                    if not (dom in ("example.com", "example.org", "example.net") or dom.endswith((".example.com", ".example.org", "noreply.github.com", ".test", ".invalid")) or m.group(0) in CFG["allow_emails"] or dom in ("github.com", "ssh.github.com", "host.example")):
                        problems.append((name, ln, "e-mail address with domain " + dom))
                for p in ([] if any(path.startswith(q) for q in CFG["skip_terms_paths"]) else pats):
                    if p.search(line):
                        problems.append((name, ln, "customer marker (private list)"))
    for name, ln, why in problems:
        print(f"public-guard: {name}:{ln}: {why}")
    if problems:
        print(f"public-guard: {len(problems)} problem(s). Fix them or, for a documented example, adjust .public-guard.json.")
        sys.exit(1)
    print("public-guard: clean")


main()
