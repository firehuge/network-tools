"""FCR workbooks with snake_case headers, an instructions sheet that repeats the form
headers, and vertically merged request cells (synthetic data only)."""
from __future__ import annotations

import sys
from pathlib import Path

import openpyxl

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from panlab.customers import load_profile  # noqa: E402
from panlab.fcr import _canon, read_fcr  # noqa: E402

TICKETS = load_profile("fwtest").tickets

INSTRUCTION_HEADERS = [
    "Firewall\n(Optional, if known)", "Source DNS Name\n(Optional)", "Source IP Address",
    "Destination DNS Name\n(Optional)", "Destination Address", "Destination Protocol",
    "Destination Port", "Application\n(If Known)", "Notes",
]
RULE_HEADERS = [
    "Rule Name", "Usage - (Temporary/Permanent)", "Source_VLAN_VNET_Name", "Source DNS Name",
    "Source IP", "Ports", "Protocol(TCP/UDP)", "Destination_VLAN_VNET_Name",
    "Destination DNS Name", "Destination_IP", "Justification", "App",
]


def _book(path: Path, rows: list[list], merges: list[str] | None = None) -> Path:
    wb = openpyxl.Workbook()
    ins = wb.active
    ins.title = "Instructions"
    ins["A1"] = "Please fill out the Firewall Rules worksheet as follows:"
    for c, h in enumerate(INSTRUCTION_HEADERS, 1):
        ins.cell(3, c, h)
    ins.cell(4, 3, "This field is mandatory. If you know the name but not the IP, use nslookup.")
    ins.cell(4, 5, "This field is mandatory.")
    ins.cell(4, 7, "This field is mandatory.\nPort Number")
    ws = wb.create_sheet("Firewall Rules")
    for c, h in enumerate(RULE_HEADERS, 1):
        ws.cell(1, c, h)
    for r, row in enumerate(rows, 2):
        for c, v in enumerate(row, 1):
            ws.cell(r, c, v)
    for m in merges or []:
        ws.merge_cells(m)
    wb.create_sheet("Site to Site VPN Modification")
    wb.save(path)
    return path


def _row(name, src, ports, dst, proto="TCP", app="Web"):
    return [name, "Permanent", "NET_A", "host-a", src, ports, proto, None, None, dst, "why", app]


def test_underscore_is_a_word_separator():
    assert _canon("Destination_IP") == "destination ip"
    assert _canon("Source_VLAN_VNET_Name") == "source vlan vnet name"


def test_rule_sheet_beats_instructions_sheet_and_snake_case_headers_map(tmp_path):
    f = _book(tmp_path / "a.xlsx", [
        _row("r1", "192.0.2.10", "8443, 9000", "198.51.100.5"),
        _row("r2", "192.0.2.0/24", 25, "198.51.100.6, 198.51.100.7"),
        _row("r3", "192.0.2.11", "55001-55009", "198.51.100.8", app=None),
    ])
    reqs, meta = read_fcr(f, ticket_patterns=TICKETS)
    assert meta["sheet"] == "Firewall Rules"
    assert meta["mapping"]["source"] == "Source IP"
    assert meta["mapping"]["destination"] == "Destination_IP"
    assert len(reqs) == 3
    assert [r.row for r in reqs] == [2, 3, 4]
    assert [e.value for e in reqs[1].destinations] == ["198.51.100.6", "198.51.100.7"]
    assert [s.text for s in reqs[0].services] == ["tcp/8443", "tcp/9000"]
    assert [s.text for s in reqs[2].services] == ["tcp/55001-55009"]
    assert not [fl for r in reqs for fl in r.flags if fl.level == "red"]


def test_vertically_merged_request_cells_apply_to_every_destination_row(tmp_path):
    rows = [
        _row("r1", "192.0.2.20", "445, 5985", "198.51.100.10"),
        [None] * 9 + ["198.51.100.11"],
        [None] * 9 + ["198.51.100.12/30"],
        _row("r2", "192.0.2.21", 9446, "198.51.100.20"),
    ]
    merges = [f"{c}2:{c}4" for c in "ABCDEFGHIKL"]
    f = _book(tmp_path / "m.xlsx", rows, merges)
    reqs, _ = read_fcr(f, ticket_patterns=TICKETS)
    assert len(reqs) == 4
    for r in reqs[:3]:
        assert [e.value for e in r.sources] == ["192.0.2.20"]
        assert [s.text for s in r.services] == ["tcp/445", "tcp/5985"]
    assert [e.value for e in reqs[2].destinations] == ["198.51.100.12/30"]
    assert not [fl for r in reqs for fl in r.flags if fl.level == "red"]


def test_horizontal_title_merge_is_not_copied(tmp_path):
    f = _book(tmp_path / "t.xlsx", [_row("r1", "192.0.2.10", 80, "198.51.100.5")])
    wb = openpyxl.load_workbook(f)
    ws = wb["Site to Site VPN Modification"]
    ws["A1"] = "Existing tunnel changes"
    ws.merge_cells("A1:H1")
    wb.save(f)
    reqs, meta = read_fcr(f, ticket_patterns=TICKETS)
    assert meta["sheet"] == "Firewall Rules" and len(reqs) == 1
