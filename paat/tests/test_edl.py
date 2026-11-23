# SPDX-License-Identifier: Apache-2.0
"""EDL manager: validation, safety, approval, revert, expiry, hosted feed, S3 publishing, firewall objects, roles.
Synthetic data only (documentation ranges, example.* domains); fake devices and moto / fake S3."""
from __future__ import annotations

import base64
import copy
import re
import xml.etree.ElementTree as ET
from datetime import timedelta

import pytest

from panlab import edl
from panlab.customers import load_profile
from panlab.web import auth, layers

SEG = re.compile(r"^([\w-]+)(?:\[@name='([^']*)'\])?$")


@pytest.fixture
def env(tmp_path, monkeypatch):
    d = tmp_path / "customers"
    for cust, extra in (("acme", "allow_live_panorama_push: true\n"), ("globex", "")):
        (d / cust).mkdir(parents=True)
        (d / cust / "profile.yaml").write_text(
            f"name: {cust}\ntargets:\n  - {{name: pano, type: panorama, host_env: X_H, api_key_env: X_K}}\n"
            "  - {name: fw1, type: firewall, host_env: Y_H, api_key_env: Y_K}\n" + extra
            + "edl:\n  target: pano\n  device_group: DG-EDGE\n")
    monkeypatch.setenv("PANLAB_CUSTOMERS_DIR", str(d))
    monkeypatch.setenv("PANLAB_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PANLAB_CUSTOMER_OVERRIDE_DIR", str(tmp_path / "none"))
    monkeypatch.setenv("PANLAB_ETC_DIR", str(tmp_path / "etc"))
    for k in [k for k in __import__("os").environ if k.startswith("PANLAB_EDL_S3_")]:
        monkeypatch.delenv(k)
    monkeypatch.setattr(edl, "s3_client_factory", None)
    monkeypatch.setattr(edl, "op_device_factory", None)
    return tmp_path


def _prof(name="acme"):
    return load_profile(name)


def _list(prof, lid="blk-ip", kind="ip", **kw):
    return edl.create_list(prof, lid=lid, name=f"Test {lid}", kind=kind, description="synthetic", actor="admin1", **kw)


def _add(prof, lid, lines, actor="soc1", reason="test", **kw):
    p = edl.plan_changes(prof, edl.load_meta(prof, lid), edl.load_entries(prof, lid), add_lines=lines, actor=actor, **kw)
    return p, edl.submit(prof, lid, p, actor=actor, reason=reason, publisher=lambda *a, **k: {})


# ---------------------------------------------------------------- validation, normalization, safety

@pytest.mark.parametrize("kind,raw,value", [
    ("ip", "203.0.113.7", "203.0.113.7"),
    ("ip", "203.0.113.0/24", "203.0.113.0/24"),
    ("ip", "203.0.113.9/24", "203.0.113.0/24"),           # host bits cleared
    ("ip", "203.0.113.5/32", "203.0.113.5"),
    ("ip", "203.0.113.10-203.0.113.20", "203.0.113.10-203.0.113.20"),
    ("ip", "2001:DB8::1", "2001:db8::1"),
    ("domain", "Bad.Example.COM.", "bad.example.com"),
    ("domain", "*.bad.example", "*.bad.example"),
    ("domain", "^exact.example", "^exact.example"),
    ("domain", "https://bad.example.com", "bad.example.com"),
    ("url", "https://bad.example.com/login?x=1", "bad.example.com/login?x=1"),
    ("url", "*.bad.example/*", "*.bad.example/*"),
])
def test_normalize_valid(kind, raw, value):
    c = edl.check(kind, raw)
    assert c.error is None and c.value == value


@pytest.mark.parametrize("kind,raw", [
    ("ip", "203.0.113.300"), ("ip", "example.com"), ("ip", "203.0.113.20-203.0.113.10"),
    ("domain", "https://bad.example.com/path"), ("domain", "bad_ex!ample.com"), ("domain", "bad.*.example"), ("domain", "x" * 250 + ".example"), ("domain", "203.0.113.7"),
    ("url", "bad.example.com/^/x"), ("url", "ba*d.example.com/"),
])
def test_normalize_invalid(kind, raw):
    assert edl.check(kind, raw).error


def test_comment_after_value_is_kept():
    # PAN-OS treats text after a space as a comment, so "bad example.com" is the bare name "bad": refused, not silently accepted
    assert edl.check("domain", "bad example.com").level == "blocked"
    c = edl.check("ip", "203.0.113.7 phishing C2 TKT-1")
    assert c.value == "203.0.113.7" and c.comment == "phishing C2 TKT-1"


@pytest.mark.parametrize("kind,value,level", [
    ("ip", "0.0.0.0/0", "blocked"), ("ip", "::/0", "blocked"), ("ip", "8.0.0.0/7", "blocked"), ("ip", "127.0.0.1", "blocked"),
    ("ip", "198.0.0.0/12", "approval"), ("ip", "10.20.30.40", "approval"), ("ip", "100.64.1.1", "approval"),
    ("ip", "203.0.113.7", "ok"), ("ip", "198.51.100.0/24", "ok"),
    ("domain", "com", "blocked"), ("domain", "*.com", "blocked"), ("domain", "*.co.uk", "blocked"), ("domain", "*.click", "approval"),
    ("domain", "bad.example", "ok"), ("domain", "*.bad.example", "ok"), ("url", "*", "blocked"),
])
def test_safety_levels(kind, value, level):
    c = edl.check(kind, value)
    assert c.level == level, c.why


def test_safety_settings_never_block_and_protected(env):
    prof = _prof()
    edl.save_settings(prof, {"never_block": "198.51.100.53  # DNS\ndns.example.net", "protected_domains": "corp.example",
                             "protected_ranges": "192.0.2.0/24 # our DMZ", "protected_rfc1918": True,
                             "hard_min_prefix_v4": "8", "approval_prefix_v4": "16", "hard_min_prefix_v6": "16",
                             "approval_prefix_v6": "32", "model": "small", "public_base_url": ""}, actor="admin1")
    st = edl.load_settings(prof)
    assert edl.check("ip", "198.51.100.0/24", st).level == "blocked"          # covers the DNS server
    assert "DNS" in " ".join(edl.check("ip", "198.51.100.53", st).why)
    assert edl.check("domain", "*.example.net", st).level == "blocked"        # covers dns.example.net
    assert edl.check("domain", "dns.example.net", st).level == "blocked"
    assert edl.check("domain", "corp.example", st).level == "approval"
    assert edl.check("domain", "vpn.corp.example", st).level == "approval"    # inside the protected zone
    assert edl.check("ip", "192.0.2.10", st).level == "approval"
    assert edl.check("domain", "other.example", st).level == "ok"


def test_plan_dedupes_and_reports_covered(env):
    prof = _prof()
    _list(prof)
    _add(prof, "blk-ip", ["203.0.113.0/24"])
    p = edl.plan_changes(prof, edl.load_meta(prof, "blk-ip"), edl.load_entries(prof, "blk-ip"),
                         add_lines=["203.0.113.0/24", "198.51.100.7", "198.51.100.7", "# comment", "", "nope", "203.0.113.9"], actor="soc1")
    assert p.unchanged == 1 and p.duplicates == ["198.51.100.7"] and [c.raw for c in p.invalid] == ["nope"]
    assert [a["value"] for a in p.adds] == ["198.51.100.7", "203.0.113.9"]
    assert ("203.0.113.9", "203.0.113.0/24") in p.covered


def test_capacity_warnings(env, monkeypatch):
    prof = _prof()
    _list(prof)
    _add(prof, "blk-ip", [f"203.0.113.{i}" for i in range(1, 11)])
    monkeypatch.setitem(edl.MODEL_LIMITS, "small", ("tiny test model", 12, 50, 50))
    cap = edl.capacity(prof)
    assert cap["totals"]["ip"] == 10 and any("80%" in w for w in cap["warnings"])


# ---------------------------------------------------------------- versions, approval, revert, expiry, audit

def test_add_remove_versions_and_revert(env):
    prof = _prof()
    meta = _list(prof)
    assert meta["version"] == 1 and edl.render_text(meta, []) == "192.0.2.1\n"  # placeholder when empty
    _, r = _add(prof, "blk-ip", ["203.0.113.7", "198.51.100.0/24"])
    assert r["status"] == "applied" and r["version"] == 2
    assert edl.render_text(edl.load_meta(prof, "blk-ip"), edl.load_entries(prof, "blk-ip")) == "198.51.100.0/24\n203.0.113.7\n"
    p = edl.plan_changes(prof, edl.load_meta(prof, "blk-ip"), edl.load_entries(prof, "blk-ip"), remove_values=["203.0.113.7"], actor="soc1")
    with pytest.raises(edl.EdlError, match="say why"):
        edl.submit(prof, "blk-ip", p, actor="soc1", reason=" ", publisher=lambda *a, **k: {})
    edl.submit(prof, "blk-ip", p, actor="soc1", reason="false positive", publisher=lambda *a, **k: {})
    assert [x["value"] for x in edl.load_entries(prof, "blk-ip")] == ["198.51.100.0/24"]
    vs = edl.versions(prof, "blk-ip")
    assert [v["version"] for v in vs] == [3, 2, 1] and vs[0]["removed"] == ["203.0.113.7"] and vs[0]["reason"] == "false positive"
    rp = edl.revert_plan(prof, "blk-ip", 2, actor="soc2")
    assert [a["value"] for a in rp.adds] == ["203.0.113.7"] and rp.removes == []
    edl.submit(prof, "blk-ip", rp, actor="soc2", reason="revert to v2", publisher=lambda *a, **k: {})
    assert {x["value"] for x in edl.load_entries(prof, "blk-ip")} == {"198.51.100.0/24", "203.0.113.7"}
    acts = [a["action"] for a in edl.read_audit(prof, "blk-ip")]
    assert acts.count("apply") == 3 and "create" in acts


def test_blocked_entries_are_refused(env):
    prof = _prof()
    _list(prof)
    p = edl.plan_changes(prof, edl.load_meta(prof, "blk-ip"), [], add_lines=["0.0.0.0/0", "203.0.113.7"], actor="soc1")
    assert [c.value for c in p.blocked] == ["0.0.0.0/0"]
    with pytest.raises(edl.EdlError, match="refused"):
        edl.submit(prof, "blk-ip", p, actor="soc1", reason="x")


def test_two_person_approval_no_self_approval(env):
    prof = _prof()
    _list(prof, require_approval=True)
    _, r = _add(prof, "blk-ip", ["203.0.113.7"], actor="cust1")
    assert r["status"] == "pending" and edl.load_entries(prof, "blk-ip") == []
    cid = r["change"]["id"]
    assert edl.pending_count(prof) == 1
    with pytest.raises(edl.EdlError, match="own change"):
        edl.approve_change(prof, "blk-isp" if False else "blk-ip", cid, actor="cust1")
    ch = edl.approve_change(prof, "blk-ip", cid, actor="isso1", publisher=lambda *a, **k: {"hosted": {"state": "live"}})
    assert ch["status"] == "approved" and ch["version"] == 2
    assert [x["value"] for x in edl.load_entries(prof, "blk-ip")] == ["203.0.113.7"]
    v = edl.load_version(prof, "blk-ip", 2)
    assert v["actor"] == "cust1" and v["approved_by"] == "isso1"
    with pytest.raises(edl.EdlError, match="approved"):
        edl.approve_change(prof, "blk-ip", cid, actor="isso2")


def test_risky_entry_needs_approval_even_without_list_flag(env):
    prof = _prof()
    _list(prof)
    _, r = _add(prof, "blk-ip", ["10.180.2.10"], actor="soc1")
    assert r["status"] == "pending" and "RFC 1918" in " ".join(r["change"]["approval_reasons"])
    cid = r["change"]["id"]
    with pytest.raises(edl.EdlError, match="say why"):
        edl.reject_change(prof, "blk-ip", cid, actor="isso1", comment="")
    assert edl.reject_change(prof, "blk-ip", cid, actor="soc1", comment="mistake")["status"] == "withdrawn"
    _, r2 = _add(prof, "blk-ip", ["10.180.2.10"], actor="soc1")
    assert edl.reject_change(prof, "blk-ip", r2["change"]["id"], actor="isso1", comment="internal host")["status"] == "rejected"


def test_approval_rechecks_safety_settings(env):
    prof = _prof()
    _list(prof)
    _, r = _add(prof, "blk-ip", ["10.180.2.10"], actor="soc1")
    st = {**edl.load_settings(prof), "never_block": "10.180.2.10"}
    edl.save_settings(prof, {k: ("\n".join(v) if isinstance(v, list) else v) for k, v in st.items()}, actor="admin1")
    with pytest.raises(edl.EdlError, match="now refused"):
        edl.approve_change(prof, "blk-ip", r["change"]["id"], actor="isso1")


def test_expiry_hides_then_sweeps(env, monkeypatch):
    prof = _prof()
    _list(prof)
    _add(prof, "blk-ip", ["203.0.113.7"], expires_at=edl.parse_expiry("2h"))
    _add(prof, "blk-ip", ["198.51.100.9"])
    meta = edl.load_meta(prof, "blk-ip")
    later = edl.now() + timedelta(hours=3)
    assert edl.render_text(meta, edl.load_entries(prof, "blk-ip"), at=later) == "198.51.100.9\n"
    with pytest.raises(edl.EdlError, match="past"):
        edl.parse_expiry("2001-01-01")
    assert edl.sweep_expired(prof, "blk-ip") is None  # nothing expired yet
    monkeypatch.setattr(edl, "now", lambda: later)
    v = edl.sweep_expired(prof, "blk-ip")
    assert v and [x["value"] for x in edl.load_entries(prof, "blk-ip")] == ["198.51.100.9"]
    assert edl.load_version(prof, "blk-ip", v)["source"] == "expiry"


def test_import_txt_csv_preview_and_replace(env):
    prof = _prof()
    _list(prof, lid="blk-dom", kind="domain")
    _add(prof, "blk-dom", ["old.example"])
    lines, rows = edl.parse_import("value,comment,expires_at,ticket\nbad.example,phish,,TKT-9\n*.worse.example,,,\n", "x.csv")
    assert lines == [] and rows[0] == {"value": "bad.example", "comment": "phish", "expires_at": "", "ticket": "TKT-9"}
    p = edl.plan_changes(prof, edl.load_meta(prof, "blk-dom"), edl.load_entries(prof, "blk-dom"), rows=rows, replace=True, actor="soc1")
    assert [a["value"] for a in p.adds] == ["bad.example", "*.worse.example"] and p.removes == ["old.example"]
    assert p.adds[0]["ticket"] == "TKT-9" and p.adds[0]["comment"] == "phish"
    did = edl.save_draft(prof, "blk-dom", p, source="import (replace)")
    p2 = edl.plan_from_dict(edl.load_draft(prof, "blk-dom", did)["plan"])
    assert p2.adds == p.adds and p2.removes == p.removes
    edl.submit(prof, "blk-dom", p2, actor="soc1", reason="bulk", publisher=lambda *a, **k: {})
    assert edl.render_text(edl.load_meta(prof, "blk-dom"), edl.load_entries(prof, "blk-dom")) == "bad.example\n*.worse.example\n"
    assert "bad.example,phish" in edl.export_csv(edl.load_entries(prof, "blk-dom"))
    assert edl.parse_import("a.example\nb.example\n") == (["a.example", "b.example"], None)


def test_list_ids_reserved_and_duplicates(env):
    prof = _prof()
    with pytest.raises(edl.EdlError, match="reserved"):
        _list(prof, lid="settings")
    _list(prof)
    with pytest.raises(edl.EdlError, match="exists"):
        _list(prof)
    with pytest.raises(edl.EdlError):
        _list(prof, lid="x", kind="mac")


def test_tenant_isolation_on_disk(env):
    a, g = _prof("acme"), _prof("globex")
    _list(a)
    assert edl.list_ids(a) == ["blk-ip"] and edl.list_ids(g) == []
    with pytest.raises(edl.EdlError):
        edl.load_meta(g, "blk-ip")


# ---------------------------------------------------------------- S3 publishing (moto)

@pytest.fixture
def s3(env, monkeypatch):
    moto = pytest.importorskip("moto")
    pytest.importorskip("boto3")
    import boto3

    for k, v in (("AWS_ACCESS_KEY_ID", "testing"), ("AWS_SECRET_ACCESS_KEY", "testing"), ("AWS_DEFAULT_REGION", "us-east-1")):
        monkeypatch.setenv(k, v)
    with moto.mock_aws():
        c = boto3.client("s3", region_name="us-east-1")
        c.create_bucket(Bucket="paat-edl-test")
        monkeypatch.setattr(edl, "s3_client_factory", lambda prof, meta: c)
        prof = _prof()
        _list(prof)
        edl.update_meta(prof, "blk-ip", actor="admin1", s3=edl.validate_s3(
            {"enabled": True, "bucket": "paat-edl-test", "key": "edl/blocked-ips.txt", "region": "us-east-1", "verify": True}))
        yield prof, c


def _body(c, key="edl/blocked-ips.txt"):
    return c.get_object(Bucket="paat-edl-test", Key=key)["Body"].read().decode()


def test_s3_publish_atomic_verified_and_status(s3):
    prof, c = s3
    assert edl.s3_status(prof, "blk-ip")["state"] == "missing"
    p = edl.plan_changes(prof, edl.load_meta(prof, "blk-ip"), [], add_lines=["203.0.113.7"], actor="soc1")
    res = edl.submit(prof, "blk-ip", p, actor="soc1", reason="block C2")  # real publisher
    s = res["publish"]["s3"]
    assert s["ok"] and s["state"] == "published" and "matches" in s["detail"] and s["version"] == 2
    assert _body(c) == "203.0.113.7\n"
    head = c.head_object(Bucket="paat-edl-test", Key="edl/blocked-ips.txt")
    assert head["ContentType"].startswith("text/plain") and head["Metadata"]["sha256"] == s["sha256"]
    keys = [o["Key"] for o in c.list_objects_v2(Bucket="paat-edl-test")["Contents"]]
    assert keys == ["edl/blocked-ips.txt"]  # temp key removed
    assert edl.s3_status(prof, "blk-ip")["state"] == "in-sync"
    assert edl.load_meta(prof, "blk-ip")["publish"]["s3"]["state"] == "published"
    assert edl.publish(prof, "blk-ip", actor="soc1")["s3"]["detail"].startswith("already up to date")


def test_s3_out_of_band_edit_is_detected_not_overwritten(s3):
    prof, c = s3
    _add_real = edl.plan_changes(prof, edl.load_meta(prof, "blk-ip"), [], add_lines=["203.0.113.7"], actor="soc1")
    edl.submit(prof, "blk-ip", _add_real, actor="soc1", reason="x")
    c.put_object(Bucket="paat-edl-test", Key="edl/blocked-ips.txt", Body=b"203.0.113.7\n198.51.100.66 added by hand\n")
    st = edl.s3_status(prof, "blk-ip")
    assert st["state"] == "changed-outside" and "198.51.100.66" in st["body"]
    p = edl.plan_changes(prof, edl.load_meta(prof, "blk-ip"), edl.load_entries(prof, "blk-ip"), add_lines=["192.0.2.200"], actor="soc1")
    res = edl.submit(prof, "blk-ip", p, actor="soc1", reason="y")
    assert res["publish"]["s3"]["state"] == "conflict" and "198.51.100.66" in _body(c)  # not overwritten
    ip, n = edl.s3_import_plan(prof, "blk-ip", actor="soc1", mode="merge")
    assert n == 2 and [a["value"] for a in ip.adds] == ["198.51.100.66"] and ip.removes == []
    rp, _ = edl.s3_import_plan(prof, "blk-ip", actor="soc1", mode="replace")
    assert rp.removes == ["192.0.2.200"]
    res = edl.submit(prof, "blk-ip", ip, actor="soc1", reason="merge S3")
    assert res["publish"]["s3"]["state"] == "published"
    assert _body(c) == "192.0.2.200\n198.51.100.66\n203.0.113.7\n"
    c.put_object(Bucket="paat-edl-test", Key="edl/blocked-ips.txt", Body=b"198.18.0.1\n")
    forced = edl.publish(prof, "blk-ip", actor="admin1", force=True)["s3"]
    assert forced["state"] == "published" and "198.18.0.1" not in _body(c)


def test_s3_errors_are_redacted_and_creds_status(env, monkeypatch):
    prof = _prof()
    _list(prof)
    edl.update_meta(prof, "blk-ip", actor="a", s3=edl.validate_s3({"enabled": True, "bucket": "paat-edl-test", "key": "k.txt"}))
    (env / "etc" / "edl").mkdir(parents=True)
    (env / "etc" / "edl" / "acme.env").write_text("PANLAB_EDL_S3_BLK_IP_ACCESS_KEY=AKIASYNTHETIC0001\nPANLAB_EDL_S3_SECRET_KEY=s3cr3t-synthetic\n")
    assert edl.s3_secret(prof, "blk-ip", "access_key") == "AKIASYNTHETIC0001"
    assert edl.s3_secret(prof, "blk-ip", "secret_key") == "s3cr3t-synthetic"  # customer-wide fallback
    assert edl.s3_creds_status(prof, "blk-ip") == "set on the server"

    class Boom:
        def get_object(self, **kw):
            raise RuntimeError("denied for AKIASYNTHETIC0001 / s3cr3t-synthetic")
    monkeypatch.setattr(edl, "s3_client_factory", lambda p, m: Boom())
    r = edl.publish_s3(prof, "blk-ip", actor="a")
    assert r["state"] == "error" and "AKIASYNTHETIC0001" not in r["detail"] and "s3cr3t" not in r["detail"]
    assert "s3cr3t" not in (env / "data").joinpath("acme", "edl", "blk-ip", "audit.jsonl").read_text()
    for bad in ({"bucket": "UPPER"}, {"bucket": "ok-bucket", "key": ""}, {"bucket": "ok-bucket", "key": "k", "endpoint_url": "ftp://x"}):
        with pytest.raises(edl.EdlError):
            edl.validate_s3({"enabled": True, **bad})


# ---------------------------------------------------------------- firewall objects, references, refresh info

def test_object_xml_and_set_commands():
    x = edl.object_element(kind="ip", name="EDL-TEST-IP", url="https://paat.example.net/edl/tok.txt", description="d",
                           cert_profile="CP-PAAT", username="fw")
    el = ET.fromstring(x)
    assert el.get("name") == "EDL-TEST-IP" and el.find("./type/ip/recurring/five-minute") is not None
    assert el.findtext("./type/ip/url") == "https://paat.example.net/edl/tok.txt" and el.findtext("./type/ip/certificate-profile") == "CP-PAAT"
    assert el.find("./type/ip/auth/password") is None  # never generated
    d = ET.fromstring(edl.object_element(kind="domain", name="EDL-D", url="http://x.example/edl/t.txt", recurring="daily"))
    assert d.findtext("./type/domain/expand-domain") == "no" and d.findtext("./type/domain/recurring/daily/at") == "03"
    cmds = edl.object_set_commands(kind="url", name="EDL-U", url="https://x.example/u.txt", where="device-group DG-EDGE")
    assert cmds[0] == 'set device-group DG-EDGE external-list "EDL-U" type url url "https://x.example/u.txt"'
    with pytest.raises(edl.EdlError):
        edl.object_element(kind="ip", name="bad'name", url="https://x")
    with pytest.raises(edl.EdlError, match="certificate"):
        edl.object_element(kind="ip", name="N", url="http://x.example/a", cert_profile="CP")
    with pytest.raises(edl.EdlError, match="certificate profile"):
        edl.object_element(kind="ip", name="N", url="https://x.example/a", username="fw")
    assert "<refresh><type><ip><name>EDL-TEST-IP</name>" in edl.op_refresh("ip", "EDL-TEST-IP")


def test_find_references_in_panorama_config(env):
    prof = _prof()
    m1 = _list(prof)
    m2 = _list(prof, lid="blk-dom", kind="domain")
    edl.update_meta(prof, "blk-dom", actor="a", s3={"enabled": True, "bucket": "paat-edl-test", "key": "edl/dom.txt"})
    tok = m1["hosted"]["token"]
    cfg = ET.fromstring(
        "<config><shared><external-list><entry name='EDL-DOM'><type><domain><recurring><hourly/></recurring>"
        "<url>https://paat-edl-test.s3.us-east-1.amazonaws.com/edl/dom.txt</url></domain></type></entry></external-list>"
        "<profiles><spyware><entry name='AS-1'><botnet-domains><lists><entry name='EDL-DOM'/></lists></botnet-domains></entry></spyware></profiles>"
        "</shared><devices><entry name='localhost.localdomain'><device-group><entry name='DG-EDGE'>"
        "<devices><entry name='0070000000001'/></devices><external-list><entry name='EDL-IP'><type><ip><recurring><five-minute/></recurring>"
        f"<url>http://paat.example.net/edl/{tok}.txt</url></ip></type></entry><entry name='OTHER'><type><ip><url>http://elsewhere.example/x.txt</url>"
        "</ip></type></entry></external-list><pre-rulebase><security><rules><entry name='Block EDL'><destination><member>EDL-IP</member>"
        "</destination><action>deny</action></entry></rules></security></pre-rulebase></entry></device-group></entry></devices></config>")
    refs = edl.find_references(cfg, [edl.load_meta(prof, "blk-ip"), edl.load_meta(prof, "blk-dom")])
    (ip,) = refs["blk-ip"]
    assert ip["object"] == "EDL-IP" and ip["where"] == "device group DG-EDGE" and ip["devices"] == ["0070000000001"]
    assert ip["recurring"] == "five-minute" and ip["used_by"][0]["name"] == "Block EDL" and ip["used_by"][0]["field"] == "destination"
    (dom,) = refs["blk-dom"]
    assert dom["where"] == "shared" and dom["used_by"][0]["kind"] == "anti-spyware DNS policy"
    assert m2["id"] == "blk-dom"


def test_refresh_info_and_status_fallback(env, monkeypatch):
    out = ET.fromstring("<response status='success'><result>vsys1/EDL-IP:\n  Next update at : Sun Nov 22 10:05:00 2026\n"
                        "  Source : http://paat.example.net/edl/x.txt\n  Total valid entries : 3\n  Total invalid entries : 0\n"
                        "  Last updated : Sun Nov 22 10:00:00 2026\n</result></response>")
    info = edl.parse_refresh_info(out)
    assert info["valid"] == "3" and info["invalid"] == "0" and info["last_update"].startswith("Sun Nov 22 10:00")
    real = edl.parse_refresh_info(ET.fromstring(
        "<response status='success'><result total-count='1'><external-list><vsys>(null)</vsys><name>EDL-X</name><total-valid>2</total-valid>"
        "<total-ignored>0</total-ignored><total-invalid>1</total-invalid><valid-members><member>203.0.113.7</member>"
        "<member>10.180.2.10</member></valid-members></external-list></result></response>"))
    assert (real["valid"], real["invalid"], real["ignored"], real["members"]) == ("2", "1", "0", ["203.0.113.7", "10.180.2.10"])
    calls = []

    class Dev:
        def __init__(self, admin):
            self.admin = admin

        def op(self, cmd):
            calls.append((self.admin, cmd))
            if not self.admin:
                raise RuntimeError("403 not authorized")
            return out
    monkeypatch.setattr(edl, "op_device_factory", lambda prof, t, serial, admin: Dev(admin))
    prof = _prof()
    _list(prof)
    st = edl.firewall_status(prof, "ip", "EDL-IP", target="pano", serial="0070000000001")
    assert st["ok"] and st["key"] == "admin" and [a for a, _ in calls] == [False, True]
    r = edl.firewall_refresh(prof, "blk-ip", "ip", "EDL-IP", target="pano", serial="0070000000001", actor="admin1")
    assert r["ok"] and edl.read_audit(prof, "blk-ip")[-1]["action"] == "firewall-refresh"


class FakeDev:
    """Candidate + running XML trees (like tests/test_urlfilter.FakeUrlDevice) plus a backup export."""

    def __init__(self):
        self.cand = ET.fromstring("<config/>")
        self.run = copy.deepcopy(self.cand)
        self.pending, self.commits, self.commit_alls, self.backups = False, [], [], 0

    def _walk(self, root, xpath, create=False):
        node, parent = root, None
        for s in [s for s in xpath.split("/") if s][1:]:
            tag, name = SEG.match(s).groups()
            nxt = next((c for c in node if c.tag == tag and (name is None or c.get("name") == name)), None)
            if nxt is None:
                if not create:
                    return None, None
                nxt = ET.SubElement(node, tag, {"name": name} if name else {})
            parent, node = node, nxt
        return parent, node

    def export_running(self):
        self.backups += 1
        return ET.tostring(self.run, encoding="unicode")

    def show(self, xpath):
        return copy.deepcopy(self._walk(self.run, xpath)[1])

    def edit(self, xpath, element):
        parent, node = self._walk(self.cand, xpath, create=True)
        idx = list(parent).index(node)
        parent.remove(node)
        parent.insert(idx, ET.fromstring(element))

    def delete(self, xpath):
        parent, node = self._walk(self.cand, xpath)
        if node is not None:
            parent.remove(node)

    def pending_changes(self):
        return self.pending

    def revert(self):
        self.cand = copy.deepcopy(self.run)

    def commit(self, description):
        self.commits.append(description)
        self.run = copy.deepcopy(self.cand)
        return {"jobid": len(self.commits), "success": True}

    def commit_all(self, cmd):
        self.commit_alls.append(cmd)
        return {"jobid": 100 + len(self.commit_alls), "success": True}


def test_object_request_approve_push_rollback(env):
    prof = _prof()
    meta = _list(prof)
    url = edl.hosted_url(prof, meta, "http://paat.example.net")
    r = edl.create_object_request(prof, "blk-ip", actor="admin1", name="EDL-TEST-IP", where="", url=url)
    assert r["where"] == "DG-EDGE" and r["xpath"].endswith("device-group/entry[@name='DG-EDGE']/external-list/entry[@name='EDL-TEST-IP']")
    dev = FakeDev()
    with pytest.raises(edl.EdlError, match="own request"):
        edl.approve_object(prof, r["id"], dev, actor="admin1", cr="CHG0001")
    with pytest.raises(Exception, match="CR"):
        edl.approve_object(prof, r["id"], dev, actor="isso1", cr="nope")
    with pytest.raises(edl.EdlError, match="approved first"):
        edl.push_object(prof, r["id"], dev, actor="op1", confirm_target="pano")
    a = edl.approve_object(prof, r["id"], dev, actor="isso1", cr="CHG0001")
    assert a["status"] == "approved" and a["mode"] == "live" and a["before"] == ""
    with pytest.raises(edl.EdlError, match="typed target"):
        edl.push_object(prof, r["id"], dev, actor="op1", confirm_target="fw1")
    dev.pending = True
    with pytest.raises(edl.EdlError, match="uncommitted"):
        edl.push_object(prof, r["id"], dev, actor="op1", confirm_target="pano")
    dev.pending = False
    p = edl.push_object(prof, r["id"], dev, actor="op1", confirm_target="pano")
    assert p["status"] == "pushed" and "read back matches" in p["result"] and dev.backups == 1 and p["backups"]
    assert "DG-EDGE" in dev.commit_alls[0]
    assert (env / "data" / "acme" / "backups" / p["backups"][0]).is_file()
    assert edl.load_meta(prof, "blk-ip")["firewall"]["object_name"] == "EDL-TEST-IP"
    rb = edl.rollback_object(prof, r["id"], dev, actor="op1", confirm_target="pano")
    assert rb["status"] == "rolled-back" and dev.show(r["xpath"]) is None and dev.backups == 2


def test_object_push_refused_when_live_push_off(env):
    prof = _prof("globex")
    meta = _list(prof)
    r = edl.create_object_request(prof, "blk-ip", actor="admin1", name="EDL-X", where="", url=edl.hosted_url(prof, meta, "http://p.example"))
    dev = FakeDev()
    assert edl.approve_object(prof, r["id"], dev, actor="isso1", cr="CHG0002")["mode"] == "dry-run"
    with pytest.raises(edl.EdlError, match="live Panorama push is off"):
        edl.push_object(prof, r["id"], dev, actor="op1", confirm_target="pano")
    assert dev.backups == 0 and not dev.commits


def test_push_refused_without_backup(env):
    prof = _prof()
    meta = _list(prof)
    r = edl.create_object_request(prof, "blk-ip", actor="admin1", name="EDL-Y", where="", url=edl.hosted_url(prof, meta, "http://p.example"))
    dev = FakeDev()
    edl.approve_object(prof, r["id"], dev, actor="isso1", cr="CHG0003")

    def boom():
        raise RuntimeError("timeout")
    dev.export_running = boom
    with pytest.raises(edl.EdlError, match="backup"):
        edl.push_object(prof, r["id"], dev, actor="op1", confirm_target="pano")
    assert not dev.commits and edl.load_object_request(prof, r["id"])["status"] == "approved"


# ---------------------------------------------------------------- web: roles, scope, hosted feed

PW = "pw-synthetic-123456"


@pytest.fixture
def web(env, monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from panlab.web import edl_routes as er
    from panlab.web.app import app

    uf = env / "users.yaml"
    monkeypatch.setenv("PANLAB_USERS_FILE", str(uf))
    monkeypatch.setenv("PANLAB_USER_AUDIT_FILE", str(env / "ua.jsonl"))
    lay = {x["id"]: sorted(x["perms"]) for x in layers.LAYERS}
    auth.add_user("boss", "admin", PW, uf)
    auth.add_user("cust-acme", "viewer", PW, uf, permissions=lay["edl_customer"], customers=["acme"])
    auth.add_user("cust-globex", "viewer", PW, uf, permissions=lay["edl_customer"], customers=["globex"])
    auth.add_user("soc1", "viewer", PW, uf, permissions=lay["soc"], customers=["*"])
    auth.add_user("isso1", "viewer", PW, uf, permissions=lay["isso"], customers=["*"])
    auth.add_user("edladm", "viewer", PW, uf, permissions=lay["edl_admin"], customers=["acme"])
    auth.add_user("op1", "viewer", PW, uf, permissions=["view", "push", "edl_view"], customers=["acme"])
    auth.add_user("plain", "viewer", PW, uf, permissions=["view"], customers=["*"])
    dev = FakeDev()
    monkeypatch.setattr(er, "device_factory", lambda prof, t: dev)

    def client(user):
        c = TestClient(app)
        assert c.post("/login", data={"username": user, "password": PW}, follow_redirects=False).status_code == 303
        return c
    return client, dev, TestClient(app)


def test_layers_presets_exist_and_match():
    lay = {x["id"]: x["perms"] for x in layers.LAYERS}
    assert lay["edl_customer"] == {"edl_view", "edl_edit"}
    assert "edl_approve" in lay["isso"] and "edl_edit" not in lay["isso"]
    assert {"edl_edit", "edl_view"} <= lay["soc"] and "edl_approve" not in lay["soc"]
    assert {"edl_view", "edl_edit", "edl_approve", "edl_admin"} <= lay["edl_admin"]
    assert set(auth.EDL_PERMS) <= set(auth.PERMS)


def test_web_role_matrix_and_tenant_scope(web):
    client, _, anon = web
    adm = client("edladm")
    r = adm.post("/edls/acme/new", data={"name": "Blocked IPs", "lid": "blk-ip", "kind": "ip", "hosted": "yes"}, follow_redirects=False)
    assert r.status_code == 303 and "/edls/acme/blk-ip" in r.headers["location"]
    assert client("cust-acme").post("/edls/acme/new", data={"name": "x", "lid": "x", "kind": "ip"}).status_code == 403  # admin only
    assert adm.post("/edls/globex/new", data={"name": "x", "lid": "x", "kind": "ip"}).status_code == 403             # other tenant
    cu = client("cust-acme")
    assert "Blocked IPs" in cu.get("/edls?customer=acme").text
    assert cu.get("/edls/globex/blk-ip").status_code in (403, 404) and client("cust-globex").get("/edls/acme/blk-ip").status_code == 403
    assert "Blocked IPs" not in client("cust-globex").get("/edls").text
    assert client("plain").get("/edls").status_code == 403
    assert anon.get("/edls/acme/blk-ip", follow_redirects=False).status_code == 303  # login
    # customer adds an entry: applied straight away (public test address)
    cu.post("/edls/acme/blk-ip/add", data={"entries": "203.0.113.7", "reason": "phishing"})
    assert "203.0.113.7" in cu.get("/edls/acme/blk-ip").text
    # an RFC 1918 entry needs a second person: staged, the ISSO approves, the requester cannot
    page = cu.post("/edls/acme/blk-ip/add", data={"entries": "10.180.2.10", "reason": "test"}).text
    m = re.search(r"/edls/acme/blk-ip/changes/(chg-[\w-]+)", page) or re.search(r"name='draft' value='(drf-[0-9a-f]+)'", page)
    assert m, page[:2000]
    if m.group(1).startswith("drf-"):
        r = cu.post("/edls/acme/blk-ip/confirm", data={"draft": m.group(1), "reason": "test"}, follow_redirects=False)
    prof = _prof()
    (ch,) = [c for c in edl.list_changes(prof, "blk-ip") if c["status"] == "pending"]
    assert cu.post(f"/edls/acme/blk-ip/changes/{ch['id']}/approve", data={"action": "approve"}).status_code == 403
    assert client("soc1").post(f"/edls/acme/blk-ip/changes/{ch['id']}/approve", data={"action": "approve"}).status_code == 403
    isso = client("isso1")
    assert isso.post("/edls/acme/blk-ip/add", data={"entries": "203.0.113.8", "reason": "x"}).status_code == 403  # ISSO reviews only
    isso.post(f"/edls/acme/blk-ip/changes/{ch['id']}/approve", data={"action": "approve", "comment": "ok"})
    assert edl.load_change(prof, "blk-ip", ch["id"])["status"] == "approved"
    # settings and S3 are admin-only; force publish is admin-only
    assert cu.get("/edls/acme/blk-ip/settings").status_code == 403
    assert cu.post("/edls/acme/blk-ip/publish", data={"force": "yes"}).status_code == 403
    assert client("soc1").post("/edls/acme/settings", data={"model": "small"}).status_code == 403
    # firewall refresh is admin-only
    assert cu.post("/edls/acme/blk-ip/firewall/refresh", data={"object": "EDL-IP"}).status_code == 403
    # history, audit, export for viewers in scope
    assert "phishing" in cu.get("/edls/acme/blk-ip/history").text
    assert cu.get("/edls/acme/blk-ip/export.txt").text == "10.180.2.10\n203.0.113.7\n"
    assert "added_by" in cu.get("/edls/acme/blk-ip/export.csv").text


def test_web_hosted_feed_auth_allowlist_and_isolation(web):
    client, _, anon = web
    prof = _prof()
    meta = _list(prof)
    _add(prof, "blk-ip", ["203.0.113.7"])
    tok = meta["hosted"]["token"]
    r = anon.get(f"/edl/{tok}.txt")
    assert r.status_code == 200 and r.text == "203.0.113.7\n" and r.headers["content-type"].startswith("text/plain")
    assert anon.get(f"/edl/{tok}.txt", headers={"If-None-Match": r.headers["etag"]}).status_code == 304
    assert anon.get("/edl/" + "A" * 32 + ".txt").status_code == 404 and anon.get("/edl/short.txt").status_code == 404
    assert edl.fetches(prof, "blk-ip")[0]["status"] == 200
    adm = client("edladm")
    base = {"name": "Test blk-ip", "hosted": "yes", "placeholder": "yes"}
    adm.post("/edls/acme/blk-ip/settings", data={**base, "basic_user": "fw-fetch", "basic_password": "synthetic-pass-123"})
    stored = edl.load_meta(prof, "blk-ip")["hosted"]
    assert stored["basic_auth_hash"] and "synthetic-pass-123" not in str(stored)
    assert "synthetic-pass-123" not in adm.get("/edls/acme/blk-ip/settings").text
    assert anon.get(f"/edl/{tok}.txt").status_code == 401
    bad = "Basic " + base64.b64encode(b"fw-fetch:wrong").decode()
    good = "Basic " + base64.b64encode(b"fw-fetch:synthetic-pass-123").decode()
    assert anon.get(f"/edl/{tok}.txt", headers={"Authorization": bad}).status_code == 401
    assert anon.get(f"/edl/{tok}.txt", headers={"Authorization": good}).text == "203.0.113.7\n"
    adm.post("/edls/acme/blk-ip/settings", data={**base, "basic_user": "fw-fetch", "allow_ips": "192.0.2.0/24"})
    assert anon.get(f"/edl/{tok}.txt", headers={"Authorization": good}).status_code == 403  # testclient is not in 192.0.2.0/24
    adm.post("/edls/acme/blk-ip/settings", data={**base, "allow_ips": "testclient-bad"})
    assert edl.load_meta(prof, "blk-ip")["hosted"]["allow_ips"] == ["192.0.2.0/24"]  # invalid input not saved
    adm.post("/edls/acme/blk-ip/settings", data={**base, "new_token": "yes"})
    tok2 = edl.load_meta(prof, "blk-ip")["hosted"]["token"]
    assert tok2 != tok and anon.get(f"/edl/{tok}.txt").status_code == 404
    adm.post("/edls/acme/blk-ip/settings", data={"name": "Test blk-ip"})  # hosting off
    assert anon.get(f"/edl/{tok2}.txt").status_code == 404
    assert edl.ip_allowed("192.0.2.9", ["192.0.2.0/24"]) and edl.ip_allowed("192.0.2.9", ["192.0.2.1-192.0.2.10"])
    assert not edl.ip_allowed("198.51.100.1", ["192.0.2.0/24"]) and edl.ip_allowed("anything", [])


def test_web_object_flow_roles(web):
    client, dev, _ = web
    prof = _prof()
    meta = _list(prof)
    adm = client("edladm")
    url = edl.hosted_url(prof, meta, "http://paat.example.net")
    pv = adm.post("/edls/acme/blk-ip/object", data={"action": "preview", "name": "EDL-TEST-IP", "url": url}).text
    assert "set device-group DG-EDGE external-list" in pv and "&lt;entry name=" in pv
    assert client("soc1").post("/edls/acme/blk-ip/object", data={"action": "request", "name": "EDL-TEST-IP", "url": url}).status_code == 403
    r = adm.post("/edls/acme/blk-ip/object", data={"action": "request", "name": "EDL-TEST-IP", "url": url}, follow_redirects=False)
    rid = r.headers["location"].split("/objects/")[1].split("?")[0]
    assert "own request" in adm.post(f"/edls/acme/objects/{rid}/review", data={"action": "approve", "cr": "CHG0001"}).text \
        or edl.load_object_request(prof, rid)["status"] == "pending"
    assert client("isso1").post(f"/edls/acme/objects/{rid}/push", data={"confirm": "pano"}).status_code == 403  # no push perm
    client("isso1").post(f"/edls/acme/objects/{rid}/review", data={"action": "approve", "cr": "CHG0001"})
    assert edl.load_object_request(prof, rid)["status"] == "approved"
    client("op1").post(f"/edls/acme/objects/{rid}/push", data={"confirm": "pano"})
    assert edl.load_object_request(prof, rid)["status"] == "pushed" and dev.commit_alls
    assert "pushed" in client("op1").get(f"/edls/acme/objects/{rid}").text


def test_no_secrets_or_real_hosts_in_module_source():
    import inspect

    from panlab.web import edl_routes
    src = inspect.getsource(edl) + inspect.getsource(edl_routes)
    assert not re.search(r"192\.168\.50\.|10\.80\.|AKIA[0-9A-Z]{16}", src)
