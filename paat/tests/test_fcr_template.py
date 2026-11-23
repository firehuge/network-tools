"""The FCR request template (templates/customer-rule-request-form.xlsx), built by tools/make_fcr_template.py.

Covers: the importer still reads it as the standard form, validation exists on every column, the
Instructions tab answers the usual questions, and (when LibreOffice is installed) the Row check
and validation formulas give the right answers for good and bad entries.
"""

from __future__ import annotations

import csv
import shutil
import subprocess
import sys
from pathlib import Path

import openpyxl
import pytest

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import make_fcr_template as mft  # noqa: E402
from panlab.fcr import read_fcr  # noqa: E402

TICKETS = {"ritm": r"RITM\d+", "sctask": r"SCTASK\d+", "cr": r"(?:CHG|CR)\d+"}
TEMPLATE = ROOT / "templates" / "customer-rule-request-form.xlsx"
HAS_LO = shutil.which("soffice") is not None


def _dvs(path: Path, sheet: str = "Firewall Rules") -> dict[str, object]:
    wb = openpyxl.load_workbook(path)
    out = {}
    for dv in wb[sheet].data_validations.dataValidation:
        for rng in str(dv.sqref).split():
            out[rng] = dv
    return out


def test_template_is_the_standard_layout_and_blank_parses():
    reqs, meta = read_fcr(TEMPLATE, ticket_patterns=TICKETS)
    assert reqs == []
    assert meta["standard_template"] is True
    assert meta["sheet"] == "Firewall Rules" and meta["header_row"] == 3
    assert set(meta["mapping"]) == {"source", "source_dns", "destination", "destination_dns", "protocol", "ports",
                                    "firewall", "notes", "application"}


def test_formulas_fit_excel_limits():
    ws = openpyxl.load_workbook(TEMPLATE)["Firewall Rules"]
    longest = 0
    for r in (mft.FIRST, mft.LAST):
        for c in range(10, 18):
            v = ws.cell(r, c).value
            text = v.text if hasattr(v, "text") else v
            assert isinstance(text, str) and text.startswith("="), (r, c)
            longest = max(longest, len(text))
    assert longest < 8192  # Excel's formula length limit
    assert TEMPLATE.stat().st_size < 1_000_000


def test_column_order_is_unchanged():
    ws = openpyxl.load_workbook(TEMPLATE)["Firewall Rules"]
    words = ["source address", "source dns", "destination address", "destination dns", "protocol", "port", "firewall", "notes", "application"]
    for i, w in enumerate(words, 1):
        h = str(ws.cell(3, i).value).lower()
        assert all(part in h for part in w.split()), (i, h)


def test_filled_template_imports(tmp_path):
    rows = [
        ("10.60.0.0/24", "clients.example.com", "10.70.0.7", "web01.example.com", "TCP", "80,443", "fw-fwtest", "CHG0012345 staff web", "ssl"),
        ("10.60.0.25", None, "10.70.0.10", None, "TCP and UDP", "53", None, None, None),
        ("10.60.0.5", None, "10.70.0.50", None, "ICMP", None, None, None, None),
        ("10.60.0.5", None, "10.70.0.51", None, "TCP", 3389, None, None, "ms-rdp"),
        ("EXAMPLE\\Payroll Admins", None, "10.70.0.30", None, "UDP", "5000-5010", None, None, None),
    ]
    f = mft.build(tmp_path / "RITM0099999-fwtest-template.xlsx", rows=rows, project="Lab refresh SCTASK0012345")
    reqs, meta = read_fcr(f, ticket_patterns=TICKETS)
    assert meta["standard_template"] is True and meta["rows"] == 5
    assert [r.row for r in reqs] == [4, 5, 6, 7, 8]
    assert [e.value for e in reqs[0].sources] == ["10.60.0.0/24"]
    assert [s.text for s in reqs[0].services] == ["tcp/80", "tcp/443"]
    assert reqs[0].applications == ["ssl"]
    assert [s.text for s in reqs[1].services] == ["tcp/53", "udp/53"]
    assert [s.text for s in reqs[2].services] == ["icmp"]
    assert [s.text for s in reqs[3].services] == ["tcp/3389"] and reqs[3].applications == ["ms-rdp"]
    assert [s.text for s in reqs[4].services] == ["udp/5000-5010"]
    assert reqs[4].sources[0].kind == "user"
    t = reqs[0].tickets
    assert t.ritm == ["RITM0099999"] and t.sctask == ["SCTASK0012345"] and t.cr == ["CHG0012345"]
    assert all(not [x for x in r.flags if x.level == "red"] for r in reqs)


def test_example_tab_is_not_imported(tmp_path):
    f = mft.build(tmp_path / "x.xlsx")  # Example tab holds sample rows; Firewall Rules is empty
    assert openpyxl.load_workbook(f)["Example"]["A4"].value
    reqs, _ = read_fcr(f, ticket_patterns=TICKETS)
    assert reqs == []


def test_every_entry_column_has_validation_and_hover_help():
    dvs = _dvs(TEMPLATE)
    rng = lambda c: f"{c}{mft.FIRST}:{c}{mft.LAST}"  # noqa: E731
    kinds = {c: dvs[rng(c)].type for c in "ABCDEF"}
    assert kinds == {"A": "custom", "B": "custom", "C": "custom", "D": "custom", "E": "list", "F": "custom"}
    for c in "ABCDEFGHI":
        dv = dvs[rng(c)]
        assert dv.showInputMessage and dv.prompt and dv.promptTitle
        assert len(dv.prompt) <= 255 and len(dv.promptTitle) <= 32
        assert len(dv.formula1) <= 255, (c, len(dv.formula1))  # Excel's limit
        assert not dv.formula1.startswith("=")
    for c in "ABCDEF":
        dv = dvs[rng(c)]
        assert dv.showErrorMessage and dv.errorStyle == "stop" and dv.error
    assert dvs[rng("E")].formula1 == '"TCP,UDP,ICMP,TCP and UDP"'
    for c in "ABCDEFGHI":  # help also on the header cells
        assert f"{c}3" in dvs and dvs[f"{c}3"].prompt


def test_sheet_is_locked_except_entry_cells_and_headers_frozen():
    ws = openpyxl.load_workbook(TEMPLATE)["Firewall Rules"]
    assert ws.protection.sheet and ws.freeze_panes == "A4"
    assert ws["A3"].protection.locked and ws["J4"].protection.locked
    assert not ws["A4"].protection.locked and not ws[f"I{mft.LAST}"].protection.locked
    assert ws.column_dimensions["K"].hidden and not ws.column_dimensions["J"].hidden


def test_instructions_answer_the_usual_questions():
    wb = openpyxl.load_workbook(TEMPLATE)
    assert wb.sheetnames[0] == "Instructions" and "Firewall Rules" in wb.sheetnames and "Example" in wb.sheetnames
    ws = wb["Instructions"]
    text = "\n".join(str(c.value) for row in ws.iter_rows() for c in row if c.value)
    for needle in ("What does '/24' mean", "/32", "/30", "/29", "/28", "/27", "/26", "/25", "/24", "/23", "/22", "/16",
                   "What if I do not know the application", "nslookup", "ICMP", "one row", "Row check", "RITM0012345"):
        assert needle in text, needle
    links = [c.hyperlink.target for row in ws.iter_rows() for c in row if c.hyperlink]
    assert mft.APPLIPEDIA in links
    assert wb["Firewall Rules"]["G1"].hyperlink.target == mft.APPLIPEDIA
    for col in "ABCDEFGHI":  # one row per column in the guide
        assert f"{col}. " in text


def test_committed_template_matches_the_builder(tmp_path):
    fresh = mft.build(tmp_path / "fresh.xlsx")
    a, b = openpyxl.load_workbook(TEMPLATE), openpyxl.load_workbook(fresh)
    assert a.sheetnames == b.sheetnames
    for name in a.sheetnames:
        for row_a, row_b in zip(a[name].iter_rows(), b[name].iter_rows()):
            for ca, cb in zip(row_a, row_b):
                va = ca.value.text if hasattr(ca.value, "text") else ca.value
                vb = cb.value.text if hasattr(cb.value, "text") else cb.value
                assert va == vb, (name, ca.coordinate)
    assert {(str(d.sqref), d.formula1) for d in _dvs(TEMPLATE).values()} == {(str(d.sqref), d.formula1) for d in _dvs(fresh).values()}


def test_nat_and_vpn_tabs_kept_with_validation():
    wb = openpyxl.load_workbook(TEMPLATE)
    assert "Source or Static NATs" in wb.sheetnames and "Site to Site VPN Modification" in wb.sheetnames
    nat = _dvs(TEMPLATE, "Source or Static NATs")
    assert nat["C4:C100"].formula1 == '"Source NAT,Static NAT"' and nat["F4:F100"].type == "list"
    assert nat["A4:A100"].type == "custom" and nat["G4:G100"].type == "custom"
    vpn = _dvs(TEMPLATE, "Site to Site VPN Modification")
    assert vpn["C3:C100"].type == "custom" and vpn["G3:G100"].type == "list"


# ---------------------------------------------------------------- formulas, evaluated by LibreOffice
def _lo_csv(xlsx: Path, outdir: Path, sheet_no: int) -> list[list[str]]:
    prof = outdir / "lo-profile"
    cmd = ["soffice", f"-env:UserInstallation=file://{prof}", "--headless", "--convert-to",
           f"csv:Text - txt - csv (StarCalc):44,34,76,1,,0,false,true,false,false,false,{sheet_no}", "--outdir", str(outdir), str(xlsx)]
    subprocess.run(cmd, capture_output=True, timeout=300, check=True)
    csv_file = next(outdir.glob(f"{xlsx.stem}-*.csv"))
    return list(csv.reader(csv_file.open(encoding="utf-8")))


A_S, C_S, E_S, F_S = "Source", "Destination", "Protocol", "Ports"
ROW_CASES = [  # (A, B, C, D, E, F), expected: "OK" or a fragment of the Fix message
    (("10.60.0.25", None, "10.70.0.7", None, "TCP", "443"), "OK"),
    (("10.60.0.0/24", None, "10.70.0.0/24", None, "TCP and UDP", "80,443, 8000-8010"), "OK"),
    (("10.1.2.4/32", None, "172.16.0.0/16", None, "UDP", "53;123"), "OK"),
    (("EXAMPLE\\Payroll Admins", None, "10.1.2.3", None, "TCP", "3389"), "OK"),
    ((" 10.1.2.3 ", None, " 10.1.2.4 ", None, "TCP", 443), "OK"),
    (("10.1.2.3", "app01.example.com", "10.1.2.4", "web01.example.com", "TCP", "22"), "OK"),
    (("10.1.2.3", None, "10.1.2.4", None, "ICMP", None), "OK"),
    (("10.1.2.3", None, "10.1.2.4", None, "ICMP", "80"), "ICMP has no ports"),
    (("10.1.2.256", None, "10.1.2.4", None, "TCP", "443"), "Source '10.1.2.256'"),
    (("10.1.2.3", None, "10.1.2.4/33", None, "TCP", "443"), "Destination '10.1.2.4/33'"),
    (("10.1.2.3", None, "10.1.2.4/0", None, "TCP", "443"), "Destination '10.1.2.4/0'"),
    (("10.1.2", None, "10.1.2.4", None, "TCP", "443"), "Source '10.1.2'"),
    (("010.1.2.3", None, "10.1.2.4", None, "TCP", "443"), "Source '010.1.2.3'"),
    (("10.1.2.3/24.1", None, "10.1.2.4", None, "TCP", "443"), "Source '10.1.2.3/24.1'"),
    (("any", None, "10.1.2.4", None, "TCP", "443"), "Source can't be 'any'"),
    (("10.1.2.3", None, "ANY", None, "TCP", "443"), "Destination can't be 'any'"),
    (("10.1.2.3, 10.1.2.4", None, "10.1.2.4", None, "TCP", "443"), "One source per cell"),
    (("10.1.2.3", None, "10.1.2.4;10.1.2.5", None, "TCP", "443"), "One destination per cell"),
    (("web01.example.com", None, "10.1.2.4", None, "TCP", "443"), "looks like a DNS name"),
    (("10.1.2.3", None, "web02.example.com", None, "TCP", "443"), "Destination 'web02.example.com'"),
    ((None, None, "10.1.2.4", None, "TCP", "443"), "Source address is required"),
    (("10.1.2.3", None, None, None, "TCP", "443"), "Destination address is required"),
    (("10.1.2.3", None, "10.1.2.4", None, None, "443"), "Pick a protocol"),
    (("10.1.2.3", None, "10.1.2.4", None, "FTP", "443"), "Protocol must be"),
    (("10.1.2.3", None, "10.1.2.4", None, "TCP", None), "Port number(s) are required"),
    (("10.1.2.3", None, "10.1.2.4", None, "TCP", "0"), "Ports must be numbers"),
    (("10.1.2.3", None, "10.1.2.4", None, "TCP", "65536"), "Ports must be numbers"),
    (("10.1.2.3", None, "10.1.2.4", None, "TCP", "8010-8000"), "Ports must be numbers"),
    (("10.1.2.3", None, "10.1.2.4", None, "TCP", "https"), "Ports must be numbers"),
    (("10.1.2.3", None, "10.1.2.4", None, "TCP", "80 443"), "Ports must be numbers"),
    (("10.1.2.3", None, "10.1.2.4", None, "TCP", "0443"), "Ports must be numbers"),
    (("10.1.2.3", None, "10.1.2.4", None, "TCP", "443,,80"), "Stray comma or dash"),
    (("10.1.2.3", None, "10.1.2.4", None, "TCP", "80-"), "Stray comma or dash"),
    (("10.1.2.3", None, "10.1.2.4", None, "TCP", "1-2-3"), "Ports must be numbers"),
    (("10.1.2.3", None, "10.1.2.4", None, "TCP", "80,100-200,300"), "OK"),
    (("10.1.2.3", None, "10.1.2.4", None, "TCP", "70000-70001"), "Ports must be numbers"),
    (("10.1.2.3", None, "10.1.2.4", None, "TCP", "8000-8000"), "OK"),
    (("10.1.2.3", None, "10.1.2.4", None, "TCP", "1,2,3,4,5,6,7,8,9,10,11,12"), "OK"),
    (("10.1.2.3", None, "10.1.2.4", None, "TCP", "1,2,3,4,5,6,7,8,9,10,11,12,13"), "Too many ports"),
    (("10.1.2.3", "https://app01.example.com/x", "10.1.2.4", None, "TCP", "22"), "Source DNS name"),
    (("10.1.2.3", None, "10.1.2.4", "web 01", "TCP", "22"), "Destination DNS name"),
]


@pytest.mark.skipif(not HAS_LO, reason="LibreOffice not installed")
def test_row_check_formulas(tmp_path):
    f = mft.build(tmp_path / "rowcheck.xlsx", rows=[c for c, _ in ROW_CASES], hide_helpers=False)
    rows = _lo_csv(f, tmp_path, 2)  # sheet 2 = Firewall Rules
    for i, (case, expect) in enumerate(ROW_CASES):
        got = rows[mft.FIRST - 1 + i][9]
        if expect == "OK":
            assert got == "OK", (case, got)
        else:
            assert got.startswith("Fix: ") and expect in got, (case, got)
    assert rows[mft.FIRST - 1 + len(ROW_CASES)][9] == ""  # an untouched row says nothing


DV_CASES = {  # which formula, input, expected
    "A": [("10.60.0.25", True), ("10.60.0.0/24", True), ("EXAMPLE\\Payroll Admins", True), ("any", False), ("ANY", False),
          ("*", False), ("10.1.2.3,10.1.2.4", False), ("10.1.2", False), ("10.1.2.3.4", False), ("10.1.2.3/24/1", False),
          ("10.1.2.3/", False),
          ("10.1.2.256", True)],  # known limit: octet range is not a hard stop, the Row check flags it
    "C": [("10.70.0.7", True), ("10.70.0.0/24", True), ("web01.example.com", False), ("EXAMPLE\\x", False),
          ("10.1.2.3,10.1.2.4", False), ("10.1.2", False), ("10.1.2.3/", False), ("10.1.2.3..4", False), ("10.1.2.3/24/1", False),
          (".10.1.2.3", False), ("1e1.1.1.1", False), ("10.1.2.3/33", True), ("10.1.2.256", True)],
    "B": [("app01.example.com", True), ("a.b", True), ("app01", False), ("https://app01.example.com", False), ("app01.example.com/x", False),
          ("app 01.example.com", False), ("a.com,b.com", False)],
    "F": [(443, True), (1, True), (65535, True), (0, False), (65536, False), (-1, False), (1.5, False), ("80,443", True),
          ("8000-8010", True), ("80;443", True), ("80, 443", True), ("any", False), ("https", False), ("80,,443", False),
          (",80", False), ("80,", False), ("80-", False), ("1e3", False)],
}


@pytest.mark.skipif(not HAS_LO, reason="LibreOffice not installed")
def test_validation_formulas_accept_and_reject(tmp_path):
    forms = {"A": mft.dv_ip("A", allow_ad=True), "C": mft.dv_ip("C"), "B": mft.dv_dns("B"), "F": mft.dv_ports("F")}
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "T"
    expected: list[tuple[str, object, bool]] = []
    r = 1
    for col, cases in DV_CASES.items():
        for value, ok in cases:
            ws.cell(r, 1, value)
            ws.cell(r, 2, forms[col].replace(f"{col}4", "A%d" % r))
            expected.append((col, value, ok))
            r += 1
    p = tmp_path / "dv.xlsx"
    wb.save(p)
    rows = _lo_csv(p, tmp_path, 1)
    for i, (col, value, ok) in enumerate(expected):
        assert rows[i][1].upper() == ("TRUE" if ok else "FALSE"), (col, value, rows[i][1])
