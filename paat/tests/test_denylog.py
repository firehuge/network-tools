"""Traffic-log deny lookup: query, summary, explanation, evidence in plan and GUI (fake API, read-only)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from test_push import _client, _login, fwtest  # noqa: E402,F401

from panlab import denylog  # noqa: E402
from panlab.changeplan import render_changeplan  # noqa: E402
from panlab.pusher import PushError  # noqa: E402


class FakeLogs:
    def __init__(self, entries, match=None, rules=("LAN-to-internet",)):
        self.entries, self.match, self.queries, self.writes = entries, match, [], 0
        self.rules = rules if isinstance(rules, dict) else list(rules)

    def traffic_logs(self, query, nlogs):
        self.queries.append((query, nlogs))
        return self.entries[:nlogs]

    def policy_match(self, q):
        return self.match

    def running_rule_names(self):
        return self.rules


def ent(rule="interzone-default", n="1", t="2026/11/16 10:00:00", app="postgres"):
    return {"rule": rule, "repeatcnt": n, "receive_time": t, "from": "Tunnel", "to": "LAN", "app": app, "action": "deny"}


def test_query_has_filters_and_window():
    from datetime import datetime
    q = denylog.build_query("10.1.1.1", "10.2.2.2", "443", datetime(2026, 11, 10, 0, 0, 0))
    for s in ("(addr.src in 10.1.1.1)", "(addr.dst in 10.2.2.2)", "(port.dst eq 443)", "(action neq allow)", "(receive_time geq '2026/11/10 00:00:00')"):
        assert s in q


def test_summary_and_default_rule_explanation(fwtest):
    prof, cs, _ = fwtest
    api = FakeLogs([ent(n="3", t="2026/11/15 09:00:00"), ent(t="2026/11/16 11:00:00")], match="interzone-default")
    ev = denylog.changeset_evidence(prof, cs, api)
    r = ev["results"][0]
    s = r["summary"]
    assert s["hits"] == 4 and s["first_seen"].startswith("2026/11/15") and s["last_seen"].startswith("2026/11/16")
    assert s["rules"][0] == ["interzone-default", 4] or s["rules"][0] == ("interzone-default", 4)
    assert "blocked 4 time(s)" in r["explanation"] and "WOULD allow" in r["explanation"]
    assert api.queries[0][1] == 200 and "(port.dst eq 5432)" in api.queries[0][0]


def test_shadowed_by_explicit_rule_and_app_mismatch(fwtest):
    prof, cs, _ = fwtest
    cs["groups"][0]["rules"][0]["application"] = ["mysql"]
    api = FakeLogs([ent(rule="block-db", app="postgres")], match="block-db", rules=["block-db", "LAN-to-internet"])
    r = denylog.changeset_evidence(prof, cs, api)["results"][0]
    assert "SHADOWED" in r["explanation"] and "Move" in r["explanation"]
    assert "logs show app(s) postgres" in r["explanation"] and "mysql" in r["explanation"]


def test_no_hits_and_cap(fwtest):
    prof, cs, _ = fwtest
    r = denylog.changeset_evidence(prof, cs, FakeLogs([]), max_logs=10)["results"][0]
    assert r["summary"]["hits"] == 0 and "No denied traffic" in r["explanation"] and not r["capped"]
    r = denylog.changeset_evidence(prof, cs, FakeLogs([ent()] * 20), max_logs=10)["results"][0]
    assert r["capped"] and r["summary"]["entries"] == 10


def test_adhoc_validation():
    with pytest.raises(PushError):
        denylog.adhoc_query("10.1.1.1) or (1", "10.2.2.2", "tcp", "443")
    with pytest.raises(PushError):
        denylog.adhoc_query("10.1.1.1", "10.2.2.2", "tcp", "99999")
    with pytest.raises(PushError):
        denylog.adhoc_query("10.1.1.1", "10.2.2.2", "tcp", "443", "Z'; x")


def test_evidence_in_changeplan_and_gui(tmp_path, monkeypatch, fwtest):
    prof, cs, _ = fwtest
    import panlab.web.app as web

    api = FakeLogs([ent(n="5")], match="interzone-default")
    c = _client(tmp_path, monkeypatch)
    from panlab.web import auth
    auth.add_user("prep1", "prep", "pw-prep", tmp_path / "users.yaml")
    monkeypatch.setattr(web, "log_factory", lambda p, t: api)
    _login(c, "prep1", "pw-prep")
    assert "Check traffic logs for denies" in c.get("/changesets/fwtest/cs-test").text
    r = c.post("/denylog/fwtest/cs-test", data={"days": "7", "max_logs": "200"})
    assert r.status_code == 200 and "5 denied hit(s)" in r.text
    plan = c.get("/changesets/fwtest/cs-test/changeplan.md").text
    assert "Evidence from traffic logs" in plan and "5 denied hit(s)" in plan and "WOULD allow" in plan
    r = c.post("/denylog/fwtest", data={"src": "10.200.1.5", "dst": "10.1.20.60", "proto": "tcp", "port": "5432", "days": "3"})
    assert r.status_code == 200 and "Policy test today: interzone-default" in r.text
    assert c.post("/denylog/fwtest", data={"src": "x", "dst": "10.1.20.60", "proto": "tcp", "port": "5432"}).status_code == 400
    assert render_changeplan(cs).count("Not checked") == 1  # without evidence the plan says so


def test_allow_rule_match_is_not_called_shadowed(fwtest):
    prof, cs, _ = fwtest
    api = FakeLogs([], match="Tunnel test", rules={"Tunnel test": "allow", "x": "deny"})
    r = denylog.changeset_evidence(prof, cs, api)["results"][0]
    assert "already matches ALLOW rule 'Tunnel test'" in r["explanation"] and "SHADOWED" not in r["explanation"]
    assert "interzone-default does NOT log by default" in r["explanation"]
