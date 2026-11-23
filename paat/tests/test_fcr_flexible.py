# SPDX-License-Identifier: Apache-2.0
"""Forgiving FCR importer: synonyms, CSV, mapping, and non-template layouts (synthetic only)."""
from __future__ import annotations

import sys
from pathlib import Path

import openpyxl
import pytest

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from fcr_factory import make_fcr  # noqa: E402

from panlab.customers import load_profile  # noqa: E402
from panlab.fcr import parse_ports, read_fcr  # noqa: E402
from panlab.report import to_html, to_markdown  # noqa: E402

TICKETS = load_profile("fwtest").tickets


def _write_xlsx(path: Path, *, sheet: str, headers: list[str], rows: list[list],
                header_row: int = 1, project: str | None = None,
                extra_sheets: dict[str, list[list]] | None = None) -> Path:
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = sheet
    if project is not None:
        ws.cell(1, 1, "Project")
        ws.cell(1, 2, project)
        if header_row < 2:
            header_row = 2
    for c, h in enumerate(headers, 1):
        ws.cell(header_row, c, h)
    for i, row in enumerate(rows, header_row + 1):
        for c, v in enumerate(row, 1):
            ws.cell(i, c, v)
    for name, data in (extra_sheets or {}).items():
        other = wb.create_sheet(name)
        for r, row in enumerate(data, 1):
            for c, v in enumerate(row, 1):
                other.cell(r, c, v)
    wb.save(path)
    return path


def _cs(files: list[dict]) -> dict:
    return {
        "customer": "fwtest",
        "created": "2026-11-17 14:00:00",
        "summary": {
            "requests_in": 1, "requests_unique": 1, "placed": 0, "unplaced": 0,
            "rules": 0, "skipped_intrazone": 0, "new_objects": 0, "reused_objects": 0,
            "red_flags": 0, "needs_human": 0,
            "confidence": {"high": 0, "medium": 0, "low": 0},
        },
        "files": files,
        "groups": [],
        "unplaced": [],
        "requests": [],
    }


def test_standard_template_still_identical(tmp_path):
    f = make_fcr(tmp_path / "RITM0003001.xlsx", [
        ("10.10.0.5", None, "10.20.1.10", None, None, "443", None, "SCTASK0000002", None),
    ], project="Web")
    reqs, meta = read_fcr(f, ticket_patterns=TICKETS)
    assert meta["standard_template"] is True
    assert meta["sheet"] == "Firewall Rules"
    assert meta["header_row"] == 3
    assert reqs[0].row == 4 and meta["project"] == "Web"
    assert reqs[0].sources[0].value == "10.10.0.5"
    assert reqs[0].destinations[0].value == "10.20.1.10"
    assert [s.text for s in reqs[0].services] == ["tcp/443"]
    assert "source" in meta["mapping"] and "Source Address" in meta["mapping"]["source"]
    assert "destination" in meta["mapping"] and "Destination address" in meta["mapping"]["destination"]
    assert "ports" in meta["mapping"] and "port" in meta["mapping"]["ports"].lower()
    md = to_markdown(_cs([meta]))
    html = to_html(_cs([meta]))
    assert "Firewall Rules" in md and "Header row" in md
    assert "non-standard format" not in md and "non-standard format" not in html
    assert "source ←" in md and "source ←" in html


def test_real_template_is_standard():
    tpl = Path(__file__).parents[1] / "templates" / "customer-rule-request-form.xlsx"
    _, meta = read_fcr(tpl, ticket_patterns=TICKETS)
    assert meta["standard_template"] is True
    assert meta["sheet"] == "Firewall Rules"
    assert meta["header_row"] == 3


def test_alt_sheet_and_header_synonyms(tmp_path):
    f = _write_xlsx(
        tmp_path / "synonyms.xlsx",
        sheet="ACL",
        headers=["Src", "Dst", "Service"],
        rows=[["10.1.1.1", "10.2.2.2", "443"]],
        project="Syn",
    )
    reqs, meta = read_fcr(f, ticket_patterns=TICKETS)
    assert meta["standard_template"] is False
    assert meta["sheet"] == "ACL"
    assert meta["header_row"] == 2
    assert meta["mapping"]["source"] == "Src"
    assert meta["mapping"]["destination"] == "Dst"
    assert meta["mapping"]["ports"] == "Service"
    assert reqs[0].sources[0].value == "10.1.1.1"
    assert reqs[0].destinations[0].value == "10.2.2.2"
    assert [s.text for s in reqs[0].services] == ["tcp/443"]
    html = to_html(_cs([meta]))
    md = to_markdown(_cs([meta]))
    assert "non-standard format, check the mapping" in html
    assert "non-standard format, check the mapping" in md
    assert "source ← Src" in html and "source ← Src" in md
    assert "ACL" in html and "ACL" in md


@pytest.mark.parametrize("headers,expect", [
    (["source ip", "dest address", "destination port", "proto"],
     {"source": "source ip", "destination": "dest address", "ports": "destination port", "protocol": "proto"}),
    (["From", "To", "Ports", "Transport"],
     {"source": "From", "destination": "To", "ports": "Ports", "protocol": "Transport"}),
    (["Origin", "Target", "tcp/udp port"],
     {"source": "Origin", "destination": "Target", "ports": "tcp/udp port"}),
    (["source host", "destination", "services"],
     {"source": "source host", "destination": "destination", "ports": "services"}),
])
def test_header_synonym_table(tmp_path, headers, expect):
    f = _write_xlsx(tmp_path / "h.xlsx", sheet="Rules", headers=headers,
                    rows=[["10.1.1.1", "10.2.2.2", "443"] + (["tcp"] if len(headers) > 3 else [])])
    _, meta = read_fcr(f, ticket_patterns=TICKETS)
    for k, v in expect.items():
        assert meta["mapping"][k] == v, meta["mapping"]
    assert meta["standard_template"] is False


def test_header_row_below_title_rows(tmp_path):
    f = _write_xlsx(
        tmp_path / "deep.xlsx",
        sheet="Export",
        headers=["Src", "Dest", "Port"],
        rows=[["10.8.8.8", "10.9.9.9", "53"]],
        header_row=8,
    )
    _, meta = read_fcr(f, ticket_patterns=TICKETS)
    assert meta["header_row"] == 8
    assert meta["sheet"] == "Export"


def test_picks_best_sheet_among_several(tmp_path):
    f = _write_xlsx(
        tmp_path / "multi.xlsx",
        sheet="Cover",
        headers=["Title", "Value"],
        rows=[["ignore", "me"]],
        extra_sheets={
            "Data": [["Src", "Dst", "Port"], ["10.1.1.1", "10.2.2.2", "22"]],
        },
    )
    reqs, meta = read_fcr(f, ticket_patterns=TICKETS)
    assert meta["sheet"] == "Data"
    assert meta["mapping"]["source"] == "Src"
    assert reqs[0].services[0].text == "tcp/22"


def test_csv_import(tmp_path):
    f = tmp_path / "rules.csv"
    f.write_text("Src,Dst,Service\n10.3.3.3,10.4.4.4,443\n", encoding="utf-8")
    reqs, meta = read_fcr(f, ticket_patterns=TICKETS)
    assert meta["standard_template"] is False
    assert meta["sheet"] == "Sheet1"
    assert meta["header_row"] == 1
    assert meta["mapping"] == {"source": "Src", "destination": "Dst", "ports": "Service"}
    assert reqs[0].sources[0].value == "10.3.3.3"
    assert [s.text for s in reqs[0].services] == ["tcp/443"]


def test_source_dns_and_source_port_are_not_source_address(tmp_path):
    f = _write_xlsx(
        tmp_path / "careful.xlsx",
        sheet="Rules",
        headers=["Source DNS", "Source", "Destination", "Destination Port", "Source Port"],
        rows=[["host.example.test", "10.1.1.1", "10.2.2.2", "80", "443"]],
    )
    reqs, meta = read_fcr(f, ticket_patterns=TICKETS)
    assert meta["mapping"]["source"] == "Source"
    assert meta["mapping"]["destination"] == "Destination"
    assert meta["mapping"]["ports"] == "Destination Port"
    assert meta["mapping"]["source_dns"] == "Source DNS"
    assert "source port" not in meta["mapping"]["ports"].lower()
    assert reqs[0].sources[0].value == "10.1.1.1"
    assert [s.text for s in reqs[0].services] == ["tcp/80"]
    assert any("Source Port" in n and "443" in n for n in meta["mapping_notes"])


def test_source_port_ephemeral_has_no_note(tmp_path):
    f = _write_xlsx(
        tmp_path / "eph.xlsx",
        sheet="Rules",
        headers=["Source", "Destination", "Destination Port", "Source Port"],
        rows=[["10.1.1.1", "10.2.2.2", "443", "49152"]],
    )
    _, meta = read_fcr(f, ticket_patterns=TICKETS)
    assert meta["mapping"]["ports"] == "Destination Port"
    assert meta["mapping_notes"] == []


def test_source_port_alone_is_not_the_ports_column(tmp_path):
    f = _write_xlsx(
        tmp_path / "only-src-port.xlsx",
        sheet="Rules",
        headers=["Source", "Destination", "Source Port"],
        rows=[["10.1.1.1", "10.2.2.2", "443"]],
    )
    with pytest.raises(ValueError) as ei:
        read_fcr(f, ticket_patterns=TICKETS)
    msg = str(ei.value)
    assert "could not find source, destination, and port columns" in msg
    assert "Source Port" in msg
    assert "Headers seen:" in msg
    assert "Looking for:" in msg
    assert "destination port" in msg


def test_missing_columns_lists_headers_seen(tmp_path):
    f = tmp_path / "also.csv"
    f.write_text("a,b\n1,2\n", encoding="utf-8")
    with pytest.raises(ValueError) as ei:
        read_fcr(f, ticket_patterns=TICKETS)
    msg = str(ei.value)
    assert "also.csv" in msg
    assert "Headers seen: a, b" in msg
    assert "Looking for:" in msg
    assert "source" in msg and "destination" in msg and "ports" in msg


def test_xls_asks_to_save_as_xlsx_or_csv(tmp_path):
    f = tmp_path / "old.xls"
    f.write_bytes(b"not a real xls")
    with pytest.raises(ValueError) as ei:
        read_fcr(f, ticket_patterns=TICKETS)
    assert "save as .xlsx or .csv" in str(ei.value)
    assert ".xls is not supported" in str(ei.value)


@pytest.mark.parametrize("cell,proto,want,default", [
    ("tcp/443", None, ["tcp/443"], False),
    ("443/tcp", None, ["tcp/443"], False),
    ("TCP 443", None, ["tcp/443"], False),
    ("udp 53", None, ["udp/53"], False),
    ("443-445/tcp", None, ["tcp/443-445"], False),
    ("tcp/1000-2000", "udp", ["udp/1000-2000"], False),  # protocol column wins
    ("80, 443/tcp", None, ["tcp/80", "tcp/443"], True),  # 80 needed default
    ("443", None, ["tcp/443"], True),
])
def test_inline_port_protocol(cell, proto, want, default):
    specs, flags = parse_ports(cell, proto)
    assert [s.text for s in specs] == want
    has = any(f.code == "protocol-default" for f in flags)
    assert has is default
