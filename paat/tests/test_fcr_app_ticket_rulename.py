"""FCR follow-ups: non-App-ID values, PRJ-style tickets, requested rule names (synthetic data only)."""
from __future__ import annotations

import sys
from pathlib import Path

import openpyxl

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from test_push import FWXML  # noqa: E402

from panlab.apps import split_app_ids  # noqa: E402
from panlab.changeset import build_changeset, requests_from_changeset  # noqa: E402
from panlab.customers import load_profile  # noqa: E402
from panlab.fcr import find_tickets, read_fcr  # noqa: E402
from panlab.sources import load_customer_envs  # noqa: E402

HEADERS = ["Rule Name", "Usage - (Temporary/Permanent)", "Source_VLAN_VNET_Name", "Source DNS Name", "Source IP", "Ports",
           "Protocol(TCP/UDP)", "Destination_VLAN_VNET_Name", "Destination DNS Name", "Destination_IP", "Justification", "App"]


def _book(path: Path, rows: list[list]) -> Path:
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Firewall Rules"
    for c, h in enumerate(HEADERS, 1):
        ws.cell(1, c, h)
    for r, row in enumerate(rows, 2):
        for c, v in enumerate(row, 1):
            ws.cell(r, c, v)
    wb.save(path)
    return path


def _row(name, app, usage="Temporary", port=8443):
    return [name, usage, "NET_ONE", None, "10.1.20.5", port, "TCP", "NET_TWO", None, "8.8.8.8", "because", app]


def _cs(tmp_path, rows, fname="Change_PRJ0012345_v1.xlsx", prof=None):
    prof = prof or load_profile("fwtest")
    reqs, meta = read_fcr(_book(tmp_path / fname, rows), ticket_patterns=prof.tickets)
    cs = build_changeset(prof, load_customer_envs(prof, configs=[str(FWXML)]), reqs, files=[meta])
    return reqs, meta, cs


def _rules(cs):
    return [r for g in cs["groups"] for r in g["rules"]]


def test_project_number_in_the_file_name_is_the_ticket(tmp_path):
    reqs, meta, cs = _cs(tmp_path, [_row("Allow_One_TCP", "ssl")])
    assert meta["tickets"]["project"] == ["PRJ0012345"]
    assert "no-ticket" not in {f.code for f in reqs[0].flags}
    assert any("PRJ0012345" in r["description"] for r in _rules(cs))


def test_project_pattern_is_generic_and_configurable():
    t = find_tickets(["WEB00123 and app00456 are hosts", "see PROJ-123456"], {"ritm": r"RITM\d+", "sctask": r"SCTASK\d+", "cr": r"CHG\d+"})
    assert t.project == ["PROJ-123456"]  # host names such as WEB00123 are not tickets
    t2 = find_tickets(["WO9999999"], {"ritm": r"RITM\d+", "sctask": r"SCTASK\d+", "cr": r"CHG\d+", "project": r"WO\d{7}"})
    assert t2.project == ["WO9999999"]


def test_non_app_id_values_become_any_and_the_name_goes_in_the_description(tmp_path):
    reqs, meta, cs = _cs(tmp_path, [_row("Allow_One_TCP", "Billing"), _row("Allow_Two_TCP", "ssl")])
    rules = {r["name"]: r for r in _rules(cs)}
    one, two = rules["Allow_One_TCP"], rules["Allow_Two_TCP"]
    assert one["application"] == ["any"]
    assert "FCR app: Billing" in one["description"]
    flags = {f["code"]: f for f in one["flags"]}
    assert flags["app-not-appid"]["level"] == "yellow"  # warning stays, nothing blocks the push
    assert two["application"] == ["ssl"]
    assert "app-not-appid" not in {f["code"] for f in two["flags"]}


def test_known_apps_in_the_profile_are_kept(tmp_path):
    prof = load_profile("fwtest")
    prof.known_apps = ["Billing"]
    _, _, cs = _cs(tmp_path, [_row("Allow_One_TCP", "Billing")], prof=prof)
    assert _rules(cs)[0]["application"] == ["billing"]


def test_split_app_ids():
    assert split_app_ids(["SSL", "Jenkins", "web-browsing", "Tableau"]) == (["ssl", "web-browsing"], ["Jenkins", "Tableau"])


def test_rule_name_column_is_used_sanitized_and_made_unique(tmp_path):
    reqs, meta, cs = _cs(tmp_path, [
        _row("Allow/From:Net*One To Net-Two (TCP)", None),
        _row("Same_Name", None, port=8444),
        _row("Same_Name", None, port=8445),
        _row("x" * 80, None, port=8446),
        _row("-", None, port=8447),
    ])
    assert meta["mapping"]["rule_name"] == "Rule Name"
    names = [r["name"] for r in _rules(cs)]
    assert "Allow-From-Net-One To Net-Two -TCP" in names
    assert "Same_Name" in names
    assert all(len(n) <= 63 for n in names)
    assert len(names) == len(set(names)) == 4  # the two Same_Name rows share a name and combine into one rule
    assert not any(n in ("-", "rule") for n in names)  # a junk name falls back to the template name


def test_usage_and_network_names_ride_in_the_description(tmp_path):
    _, _, cs = _cs(tmp_path, [_row("Allow_One_TCP", None, usage="Temporary")])
    d = _rules(cs)[0]["description"]
    assert "usage: Temporary" in d and "src net: NET_ONE" in d and "dst net: NET_TWO" in d


def test_saved_change_set_round_trips_the_new_fields(tmp_path):
    reqs, meta, cs = _cs(tmp_path, [_row("Allow_One_TCP", "Billing")])
    back = requests_from_changeset(cs)[0]
    assert back.rule_name == "Allow_One_TCP" and back.usage == "Temporary"
    assert back.app_labels == ["Billing"] and back.tickets.project == ["PRJ0012345"]


def test_requested_names_keep_rules_apart_and_equal_names_still_combine(tmp_path):
    rows = [_row("Allow_A", None, port=8443), _row("Allow_B", None, port=8443)]
    rows[1][9] = "8.8.4.4"
    rows.append(_row("Allow_A", None, port=8443))
    rows[2][9] = "1.1.1.1"
    _, _, cs = _cs(tmp_path, rows)
    rules = _rules(cs)
    names = sorted(r["name"] for r in rules)
    assert names == ["Allow_A", "Allow_B"]  # A's two destinations combined, B stayed separate
    a = next(r for r in rules if r["name"] == "Allow_A")
    assert len(a["destination"]) == 2
