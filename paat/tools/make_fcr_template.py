"""Build templates/customer-rule-request-form.xlsx (the FCR request form customers fill in).

Run from the repo root:  python tools/make_fcr_template.py [output.xlsx]

What the workbook contains
- Instructions: how to fill in every column, a /CIDR cheat sheet, an FAQ, the Applipedia link.
- Firewall Rules: the sheet `panlab import` reads (header row 3, same column order and header
  keywords as the original form). Data validation per column, hover help on every header and
  cell, an automatic "Row check" column (J) and red highlighting of the cells that need fixing.
- Example: a filled-in sample (fake example data). Not imported (the importer reads "Firewall Rules").
- Source or Static NATs / Site to Site VPN Modification: kept from the original form, now with
  validation. `panlab import` does not read these sheets.

Limits worth knowing: Excel data validation formulas are capped at 255 characters and Excel does
not re-run validation on pasted values, so the hard stops (DV) catch typing mistakes and the
Row check column (formulas in hidden helper columns K:Q) catches the rest, including pasted data.
Only synthetic values are used here (RFC 1918 example addresses, *.example.com names).
"""

from __future__ import annotations

import sys
from pathlib import Path

from openpyxl import Workbook
from openpyxl.comments import Comment  # noqa: F401  (kept for callers that want cell notes)
from openpyxl.formatting.rule import FormulaRule
from openpyxl.styles import Alignment, Border, Font, PatternFill, Protection, Side
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.datavalidation import DataValidation
from openpyxl.worksheet.formula import ArrayFormula

APPLIPEDIA = "https://applipedia.paloaltonetworks.com/"
FIRST, LAST = 4, 503  # data rows on "Firewall Rules" (500 rows)
HEADER_ROW = 3
LAB_NOTE = "Synthetic example values only."

NAVY, PALE, WHITE = "1F3B57", "DCE6F1", "FFFFFF"
GREY, YELLOW, RED_BG, RED_FG, GREEN_BG, GREEN_FG = "F2F2F2", "FFF2CC", "FFC7CE", "9C0006", "C6EFCE", "006100"
THIN = Side(style="thin", color="A6A6A6")
BOX = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)

# (column, header text, required?, width, prompt title, prompt text)
FIELDS = [
    ("A", "*Source Address\n(One IP like 10.1.2.3, or one network like 10.1.2.0/24)\nor AD Group Name", True, 30,
     "Source address (required)",
     "Who is the traffic coming FROM? One IP (10.1.2.3) or one network (10.1.2.0/24) per cell. "
     "An AD group name (DOMAIN\\GroupName) is also fine. Several sources? Use one row each. Not sure what /24 means? See the Instructions tab."),
    ("B", "Source DNS Name\n(Optional)\nlike app01.example.com", False, 24,
     "Source DNS name (optional)",
     "Optional: the server name of the source, like app01.example.com. Name only: no https://, no path, no spaces. "
     "You still need the IP address in the column to the left."),
    ("C", "*Destination address\n(One IP like 10.1.2.3, or one network like 10.1.2.0/24)", True, 30,
     "Destination address (required)",
     "Where is the traffic going TO? One IP (10.1.2.3) or one network (10.1.2.0/24) per cell. "
     "Only know the name? Look the IP up with nslookup (steps on the Instructions tab). Several destinations? One row each."),
    ("D", "Destination DNS Name\n(Optional)\nlike web01.example.com", False, 24,
     "Destination DNS name (optional)",
     "Optional: the server name of the destination, like web01.example.com. Name only: no https://, no path, no spaces."),
    ("E", "*Destination Protocol\n(pick from the list)", True, 16,
     "Protocol (required)",
     "Pick TCP, UDP, ICMP or TCP and UDP from the list. Web, SSH, RDP, databases are TCP. DNS and NTP are UDP. Ping is ICMP. Not sure? Ask the application owner."),
    ("F", "*Destination port number(s)\n(like 443, or 80,443, or 8000-8010)", True, 24,
     "Destination port(s) (required)",
     "The port the destination listens on: 443, or a list 80,443, or a range 8000-8010 (numbers 1-65535). "
     "Leave EMPTY when the protocol is ICMP. 'any' is not accepted: list the ports you need."),
    ("G", "Firewall\n(Optional, if known)", False, 22,
     "Firewall (optional)",
     "Optional. If you know which firewall must change, type its name. Leave blank if you do not know; the engineer will work it out."),
    ("H", "Notes\n(Optional: what is this for? Ticket numbers like RITM0012345 or CHG0012345)", False, 34,
     "Notes (optional)",
     "Optional. Why is this needed, who owns it, when must it work? Ticket numbers (RITM..., SCTASK..., CHG... or CR...) written here are picked up automatically."),
    ("I", "Application\n(Optional, if known)\nApp-ID name like ssl or ms-rdp", False, 26,
     "Application (optional)",
     "Optional. If you do not know the application, leave it blank, that is fine. To look it up, search https://applipedia.paloaltonetworks.com/ "
     "and copy the app's name. Several apps: separate with commas."),
]


# ---------------------------------------------------------------- formula builders
def _dots(e: str) -> str:
    return f'(LEN({e})-LEN(SUBSTITUTE({e},".","")))'


def _slashes(e: str) -> str:
    return f'(LEN({e})-LEN(SUBSTITUTE({e},"/","")))'


def _piece(e: str, j: int) -> str:
    """j-th number of 'a.b.c.d/n' (j=5 is the prefix), as text."""
    return f'TRIM(MID(SUBSTITUTE(SUBSTITUTE({e},"/","."),".",REPT(" ",20)),{(j - 1) * 20 + 1},20))'


def _num_ok(t: str, lo: int, hi: int) -> str:
    return f'IFERROR(AND(LEN({t})>0,TEXT(--{t},"0")={t},--{t}>={lo},--{t}<={hi}),FALSE)'


def ip_ok(e: str) -> str:
    """TRUE for exactly one IPv4 address or IPv4/prefix (each number 0-255, no leading zeros, prefix 1-32)."""
    octets = ",".join(_num_ok(_piece(e, j), 0, 255) for j in range(1, 5))
    before_slash = f'LEFT({e},FIND("/",{e}))'
    return (f'IFERROR(AND(LEN({e})<=18,{_dots(e)}=3,{_slashes(e)}<=1,{octets},'
            f'IF({_slashes(e)}=0,TRUE,AND({_dots(before_slash)}=3,{_num_ok(_piece(e, 5), 1, 32)}))),FALSE)')


def _multi(c: str, r: int) -> str:
    return f'OR(ISNUMBER(FIND(",",{c}{r})),ISNUMBER(FIND(";",{c}{r})),ISNUMBER(FIND(CHAR(10),{c}{r})))'


def _is_any(c: str, r: int) -> str:
    t = f"TRIM({c}{r})"
    return f'OR(LOWER({t})="any",LOWER({t})="all",{t}="*")'


def _guard(r: int) -> str:
    return f"COUNTA($A{r}:$I{r})=0"


def f_source(r: int) -> str:
    t = f"TRIM(A{r})"
    return (f'=IF({_guard(r)},"",IF({t}="","Source address is required. ",'
            f'IF({_is_any("A", r)},"Source can\'t be \'any\': list the real address or network. ",'
            f'IF({_multi("A", r)},"One source per cell: put each on its own row. ",'
            f'IF(ISNUMBER(--SUBSTITUTE(SUBSTITUTE({t},".",""),"/","")),'
            f'IF({ip_ok(t)},"","Source \'"&{t}&"\' is not a valid IP address or network (like 10.1.2.3 or 10.1.2.0/24). "),'
            f'IF(AND(ISNUMBER(FIND(".",{t})),ISERROR(FIND("\\",{t})),ISERROR(FIND(" ",{t}))),'
            f'"Source looks like a DNS name: put its IP here and the name in the Source DNS column. ",""))))))')


def f_dest(r: int) -> str:
    t = f"TRIM(C{r})"
    return (f'=IF({_guard(r)},"",IF({t}="","Destination address is required (if you only know a name, look up its IP with nslookup, see Instructions). ",'
            f'IF({_is_any("C", r)},"Destination can\'t be \'any\': list the real address or network. ",'
            f'IF({_multi("C", r)},"One destination per cell: put each on its own row. ",'
            f'IF({ip_ok(t)},"","Destination \'"&{t}&"\' is not a valid IP address or network (like 10.1.2.3 or 10.1.2.0/24). '
            f'If it is a name, put the IP here and the name in the Destination DNS column. ")))))')


def f_proto(r: int) -> str:
    t = f"TRIM(E{r})"
    return (f'=IF({_guard(r)},"",IF({t}="","Pick a protocol (TCP, UDP, ICMP or TCP and UDP). ",'
            f'IF(ISNUMBER(MATCH({t},{{"TCP","UDP","ICMP","TCP and UDP"}},0)),"","Protocol must be TCP, UDP, ICMP or TCP and UDP. ")))')


MAX_PORT_ITEMS = 12


def f_ports_norm(r: int) -> str:
    """Helper column Q: the ports cell with ; and line breaks turned into commas."""
    return f'=SUBSTITUTE(SUBSTITUTE(SUBSTITUTE(TRIM(F{r}),";",","),CHAR(10),","),CHAR(13),"")'


def f_ports(r: int) -> str:
    """Array formula (needs array evaluation for the per-item checks). Reads helper column Q.

    Entries are split on commas. Every number (ranges are split on the dash) must be 1-65535 with no
    leading zero, empty entries are flagged, a range may have only one dash and must go low to high.
    """
    q = f"$Q{r}"
    q3 = f'SUBSTITUTE({q},"-",",")'
    ks = "{" + ",".join(str(k) for k in range(1, 2 * MAX_PORT_ITEMS + 1)) + "}"
    u = f'TRIM(MID(SUBSTITUTE({q3},",",REPT(" ",150)),({ks}-1)*150+1,150))'
    numok = f'IFERROR((TEXT(--{u},"0")={u})*(--{u}>=1)*(--{u}<=65535),0)'
    t = f'TRIM(MID(SUBSTITUTE({q},",",REPT(" ",150)),({{{",".join(str(k) for k in range(1, MAX_PORT_ITEMS + 1))}}}-1)*150+1,150))'
    nf = f'(LEN({q})-LEN(SUBSTITUTE({q},",",""))+1)'
    uf = f'(LEN({q3})-LEN(SUBSTITUTE({q3},",",""))+1)'
    bad_num = f'SUM(({u}<>"")*(1-{numok}))'
    empty = f'SUM(({u}="")*({ks}<={uf}))'
    two_dash = f'SUM(--(LEN({t})-LEN(SUBSTITUTE({t},"-",""))>1))'
    reversed_ = f'SUM(IFERROR(--(--LEFT({t},FIND("-",{t})-1)>--MID({t},FIND("-",{t})+1,9)),0))'
    return (f'=IF({_guard(r)},"",IF(UPPER(TRIM(E{r}))="ICMP",IF(TRIM(F{r})="","","ICMP has no ports: leave the port cell empty. "),'
            f'IF(TRIM(F{r})="","Port number(s) are required. ",'
            f'IF(OR({nf}>{MAX_PORT_ITEMS},LEN({q})>150),"Too many ports in one cell (max {MAX_PORT_ITEMS}): use another row. ",'
            f'IF({empty}>0,"Stray comma or dash in the ports. ",'
            f'IF({bad_num}+{two_dash}+{reversed_}>0,"Ports must be numbers 1-65535, like 443 or 80,443 or 8000-8010 (a range goes low to high). ",""))))))')


def f_dns(c: str, r: int, label: str) -> str:
    t = f"TRIM({c}{r})"
    return (f'=IF({_guard(r)},"",IF({t}="","",IF(AND(ISNUMBER(FIND(".",{t})),ISERROR(FIND("/",{t})),ISERROR(FIND(":",{t})),'
            f'ISERROR(FIND(" ",{t})),ISERROR(FIND(",",{t})),ISERROR(FIND(";",{t})),ISERROR(FIND(CHAR(10),{t})),LEN({t})<=253),"",'
            f'"{label} DNS name should look like host.example.com (no https://, no path, no spaces, one name per cell). ")))')


def f_row(r: int) -> str:
    j = f"K{r}&L{r}&M{r}&N{r}&O{r}&P{r}"
    return f'=IF({_guard(r)},"",IF({j}="","OK","Fix: "&TRIM({j})))'


# Data-validation (hard stop while typing) formulas. Excel caps these at 255 characters.
def dv_ip(c: str, allow_ad: bool = False) -> str:
    x = f"{c}4"
    stripped = f'SUBSTITUTE(SUBSTITUTE({x},".",""),"/","")'
    shape = (f'AND(LEN({x})-LEN(SUBSTITUTE({x},".",""))=3,LEN({x})-LEN(SUBSTITUTE({x},"/",""))<2,LEN({x})<19,'
             f'ISERROR(FIND("..",{x})),ISERROR(SEARCH("e",{x})),RIGHT({x})<>".",RIGHT({x})<>"/",LEFT({x})<>".")')
    if not allow_ad:
        return f'=AND(ISNUMBER(--{stripped}),{shape})'
    return (f'=AND(NOT(OR({x}="any",{x}="all",{x}="*")),ISERROR(FIND(",",{x})),'
            f'OR(NOT(ISNUMBER(--{stripped})),AND(LEN({x})<19,LEN({x})-LEN(SUBSTITUTE({x},".",""))=3,'
            f'LEN({x})-LEN(SUBSTITUTE({x},"/",""))<2,ISERROR(SEARCH("e",{x})),RIGHT({x})<>"/")))')


def dv_dns(c: str) -> str:
    x = f"{c}4"
    return (f'=AND(ISNUMBER(FIND(".",{x})),ISERROR(FIND("/",{x})),ISERROR(FIND(":",{x})),ISERROR(FIND(" ",{x})),'
            f'ISERROR(FIND(",",{x})),ISERROR(FIND(";",{x})),LEN({x})<=253)')


def dv_ports(c: str) -> str:
    x = f"{c}4"
    stripped = f'SUBSTITUTE(SUBSTITUTE(SUBSTITUTE(SUBSTITUTE({x},",",""),";",""),"-","")," ","")'
    return (f'=IF(ISNUMBER({x}),AND({x}>=1,{x}<=65535,{x}=INT({x})),AND(ISNUMBER(--{stripped}),ISERROR(SEARCH("e",{x})),'
            f'ISERROR(FIND(",,",{x})),LEFT({x})<>",",RIGHT({x})<>",",LEFT({x})<>"-",RIGHT({x})<>"-"))')


# ---------------------------------------------------------------- helpers
def _font(bold=False, color="000000", size=11, italic=False):
    return Font(name="Calibri", bold=bold, color=color, size=size, italic=italic)


def _fill(color: str) -> PatternFill:
    return PatternFill("solid", start_color=color, end_color=color)


def _add_dv(ws, rng: str, *, kind: str, formula: str, title: str, prompt: str, err_title: str, err: str,
            style: str = "stop") -> DataValidation:
    assert len(title) <= 32 and len(prompt) <= 255, (title, len(prompt))
    assert len(err_title) <= 32 and len(err) <= 255, (err_title, len(err))
    formula = formula[1:] if formula.startswith("=") else formula  # the file format stores it without "="
    assert len(formula) <= 255, (rng, len(formula))
    dv = DataValidation(type=kind, formula1=formula, allow_blank=True, showErrorMessage=True, showInputMessage=True,
                        errorStyle=style, promptTitle=title, prompt=prompt, errorTitle=err_title, error=err)
    ws.add_data_validation(dv)
    dv.add(rng)
    return dv


def _prompt_only(ws, rng: str, title: str, prompt: str) -> None:
    """A validation that always passes: it only shows the hover help."""
    assert len(title) <= 32 and len(prompt) <= 255, (title, len(prompt))
    dv = DataValidation(type="custom", formula1="TRUE", allow_blank=True, showErrorMessage=False,
                        showInputMessage=True, promptTitle=title, prompt=prompt)
    ws.add_data_validation(dv)
    dv.add(rng)


ERR = {
    "A": ("Check the source", "Enter ONE IP (10.1.2.3), ONE network (10.1.2.0/24) or an AD group name. "
          "Not 'any', and no commas: use one row per source. Each number must be 0-255 and the /number 1-32."),
    "C": ("Check the destination", "Enter ONE IP address (10.1.2.3) or ONE network (10.1.2.0/24): four numbers 0-255 separated by dots, "
          "optionally /1 to /32. Only know the name? Use nslookup to get the IP. One destination per row."),
    "B": ("Check the DNS name", "Use a name like app01.example.com: it needs a dot, and no https://, no /path, no spaces, commas or colons."),
    "E": ("Pick from the list", "Choose TCP, UDP, ICMP or TCP and UDP from the drop-down list."),
    "F": ("Check the port(s)", "Use numbers 1-65535: 443, or a list 80,443, or a range 8000-8010. No words (not 'any', not 'https'). "
          "Leave this EMPTY for ICMP."),
}


# ---------------------------------------------------------------- sheets
def _header_row(ws, row: int, fields, widths=True) -> None:
    for col, text, required, width, *_ in fields:
        c = ws[f"{col}{row}"]
        c.value = text
        c.font = _font(True, WHITE if required else "000000", 10)
        c.fill = _fill(NAVY if required else PALE)
        c.alignment = Alignment(wrap_text=True, vertical="center", horizontal="center")
        c.border = BOX
        if widths:
            ws.column_dimensions[col].width = width
    ws.row_dimensions[row].height = 78


def _fit_width(ws) -> None:
    ws.page_setup.orientation = "landscape"
    ws.page_setup.fitToWidth = 1
    ws.page_setup.fitToHeight = 0
    ws.sheet_properties.pageSetUpPr.fitToPage = True


def _protect(ws) -> None:
    ws.protection.sheet = True  # no password: Review > Unprotect Sheet
    ws.protection.formatCells = False
    ws.protection.formatColumns = False
    ws.protection.formatRows = False
    ws.protection.sort = False
    ws.protection.autoFilter = False


def build_rules_sheet(ws, rows: list[tuple] | None = None, project: str = "", hide_helpers: bool = True) -> None:
    ws.title = "Firewall Rules"
    ws.sheet_properties.tabColor = NAVY
    ws["A1"] = "Firewall rules request"
    ws["A1"].font = _font(True, NAVY, 16)
    ws["B1"] = "*  = required. Fill one rule per row from row 4 down. Read the Instructions tab first."
    ws["B1"].font = _font(False, "444444", 10, True)
    ws.merge_cells("B1:F1")
    ws["B1"].alignment = Alignment(vertical="center")
    ws["G1"] = "Don't know the application? Look it up on Applipedia"
    ws["G1"].hyperlink = APPLIPEDIA
    ws["G1"].font = Font(name="Calibri", size=10, underline="single", color="0563C1", bold=True)
    ws.merge_cells("G1:I1")
    ws["G1"].alignment = Alignment(horizontal="right", vertical="center", wrap_text=True)
    ws.row_dimensions[1].height = 30
    ws["A2"] = "Project"
    ws["A2"].font = _font(True)
    ws["B2"] = project or None
    ws.merge_cells("B2:E2")
    for col in "BCDE":
        ws[f"{col}2"].border = BOX
        ws[f"{col}2"].fill = _fill(YELLOW)
    ws.row_dimensions[2].height = 20
    _prompt_only(ws, "B2", "Project (and ticket number)",
                 "Name of the project or request. If you have a ticket number (RITM0012345, SCTASK0012345, CHG0012345 or CR12345), add it here: it is picked up automatically.")
    _header_row(ws, HEADER_ROW, FIELDS)
    ws["J3"] = "Row check\n(automatic: must say OK)"
    ws["J3"].font = _font(True, "000000", 10)
    ws["J3"].fill = _fill("D9D9D9")
    ws["J3"].alignment = Alignment(wrap_text=True, vertical="center", horizontal="center")
    ws["J3"].border = BOX
    ws.column_dimensions["J"].width = 75
    # hover help on the header cells too
    for col, _text, _req, _w, title, prompt in FIELDS:
        _prompt_only(ws, f"{col}{HEADER_ROW}", title, prompt)
    _prompt_only(ws, f"J{HEADER_ROW}", "Row check",
                 "Filled in automatically. OK means the row is in the right format. 'Fix: ...' says what to change; the cell to fix is also shaded red.")

    for r in range(FIRST, LAST + 1):
        for ci in range(1, 10):
            c = ws.cell(r, ci)
            c.border = BOX
            c.alignment = Alignment(wrap_text=True, vertical="top")
            c.font = _font(size=11)
            c.protection = Protection(locked=False)
        ws.cell(r, 10, f_row(r))
        ws.cell(r, 11, f_source(r))
        ws.cell(r, 12, f_dest(r))
        ws.cell(r, 13, f_proto(r))
        ref = f"N{r}"
        ws[ref] = ArrayFormula(ref, f_ports(r))
        ws.cell(r, 15, f_dns("B", r, "Source"))
        ws.cell(r, 16, f_dns("D", r, "Destination"))
        ws.cell(r, 17, f_ports_norm(r))
        ws.row_dimensions[r].height = 30
        j = ws.cell(r, 10)
        j.font = _font(False, "444444", 9)
        j.alignment = Alignment(wrap_text=True, vertical="top")
        j.border = BOX
        j.fill = _fill(GREY)
    if rows:
        for r, row in enumerate(rows, FIRST):
            for ci, v in enumerate(row, 1):
                if v is not None:
                    ws.cell(r, ci, v)
    ws.column_dimensions["J"].hidden = False
    for col in "KLMNOPQ":
        ws.column_dimensions[col].width = 14
        ws.column_dimensions[col].hidden = hide_helpers

    rng = lambda c: f"{c}{FIRST}:{c}{LAST}"  # noqa: E731
    _add_dv(ws, rng("A"), kind="custom", formula=dv_ip("A", allow_ad=True), title=FIELDS[0][4], prompt=FIELDS[0][5],
            err_title=ERR["A"][0], err=ERR["A"][1])
    _add_dv(ws, rng("B"), kind="custom", formula=dv_dns("B"), title=FIELDS[1][4], prompt=FIELDS[1][5],
            err_title=ERR["B"][0], err=ERR["B"][1])
    _add_dv(ws, rng("C"), kind="custom", formula=dv_ip("C"), title=FIELDS[2][4], prompt=FIELDS[2][5],
            err_title=ERR["C"][0], err=ERR["C"][1])
    _add_dv(ws, rng("D"), kind="custom", formula=dv_dns("D"), title=FIELDS[3][4], prompt=FIELDS[3][5],
            err_title=ERR["B"][0], err=ERR["B"][1])
    _add_dv(ws, rng("E"), kind="list", formula='"TCP,UDP,ICMP,TCP and UDP"', title=FIELDS[4][4], prompt=FIELDS[4][5],
            err_title=ERR["E"][0], err=ERR["E"][1])
    _add_dv(ws, rng("F"), kind="custom", formula=dv_ports("F"), title=FIELDS[5][4], prompt=FIELDS[5][5],
            err_title=ERR["F"][0], err=ERR["F"][1])
    for i in (6, 7, 8):
        _prompt_only(ws, rng(FIELDS[i][0]), FIELDS[i][4], FIELDS[i][5])

    red = dict(fill=PatternFill("solid", start_color=RED_BG, end_color=RED_BG, bgColor=RED_BG), font=Font(color=RED_FG))
    for col, helper in (("A", "K"), ("C", "L"), ("E", "M"), ("F", "N"), ("B", "O"), ("D", "P")):
        ws.conditional_formatting.add(rng(col), FormulaRule(formula=[f'${helper}{FIRST}<>""'], **red))
    ws.conditional_formatting.add(rng("J"), FormulaRule(formula=[f'LEFT($J{FIRST},3)="Fix"'], **red))
    ws.conditional_formatting.add(rng("J"), FormulaRule(
        formula=[f'$J{FIRST}="OK"'], fill=PatternFill("solid", start_color=GREEN_BG, end_color=GREEN_BG, bgColor=GREEN_BG),
        font=Font(color=GREEN_FG, bold=True)))

    ws.freeze_panes = f"A{FIRST}"
    ws.sheet_view.zoomScale = 100
    _fit_width(ws)
    ws.print_area = f"A1:J{LAST}"
    ws.print_title_rows = f"{HEADER_ROW}:{HEADER_ROW}"
    _protect(ws)


EXAMPLE_ROWS = [
    ("10.60.0.0/24", "clients.example.com", "10.70.0.7", "web01.example.com", "TCP", "443", "", "Staff web portal", "ssl"),
    ("10.60.0.25", "", "10.70.0.10", "db01.example.com", "TCP", "5432", "", "App server to database", "postgres"),
    ("10.60.0.0/24", "", "10.70.0.20", "files01.example.com", "TCP", "80,443,8080", "", "Several ports in one cell", ""),
    ("EXAMPLE\\Payroll Admins", "", "10.70.0.30", "", "TCP", "3389", "", "An AD group as the source", "ms-rdp"),
    ("10.60.0.5", "", "10.70.0.40", "", "UDP", "5000-5010", "", "A range of ports. Application left blank on purpose", ""),
    ("10.60.0.5", "", "10.70.0.50", "", "ICMP", "", "", "Ping: ICMP has no port, so Ports stays empty", ""),
]


def build_example_sheet(ws) -> None:
    ws.title = "Example"
    ws.sheet_properties.tabColor = "BF9000"
    ws["A1"] = "EXAMPLE ONLY: how a finished sheet looks. Do not fill in this tab and do not send it (the tool reads only the 'Firewall Rules' tab)."
    ws["A1"].font = _font(True, "7F6000", 12)
    ws.merge_cells("A1:I1")
    ws["A2"] = "Example"
    ws["A2"].font = _font(True)
    ws["B2"] = "Sample (all addresses and names are made up)"
    ws.merge_cells("B2:E2")
    _header_row(ws, HEADER_ROW, FIELDS)
    for r, row in enumerate(EXAMPLE_ROWS, FIRST):
        for ci, v in enumerate(row, 1):
            c = ws.cell(r, ci, v or None)
            c.fill = _fill(YELLOW)
            c.border = BOX
            c.alignment = Alignment(wrap_text=True, vertical="top")
            c.font = _font()
    ws.freeze_panes = f"A{FIRST}"
    _fit_width(ws)
    _protect(ws)


NAT_FIELDS = [
    ("A", "*Private address\nFormat X.X.X.X or X.X.X.X/CIDR", True, 28, "Private address (required)",
     "The real (inside) address: ONE IP like 10.1.2.3 or ONE network like 10.1.2.0/24 per cell."),
    ("B", "Private DNS name\n[FQDN/URL]\n(Optional)", False, 24, "Private DNS name (optional)", "Optional: name only, like app01.example.com."),
    ("C", "Source NAT\nor\nStatic NAT", True, 16, "NAT type (required)", "Pick Source NAT or Static NAT from the list."),
    ("D", "*Public address\nFormat X.X.X.X or X.X.X.X/CIDR", True, 28, "Public address (required)",
     "The translated (outside) address: ONE IP like 203.0.113.10 or ONE network per cell."),
    ("E", "Public DNS name\n[FQDN/URL]\n(Optional)", False, 24, "Public DNS name (optional)", "Optional: name only, like www.example.com."),
    ("F", "*Destination protocol\n(pick from the list)", True, 16, "Protocol (required)", "Pick TCP, UDP, ICMP or TCP and UDP from the list."),
    ("G", "*Destination port number(s)", True, 22, "Port(s) (required)", "Numbers 1-65535: 443, or 80,443, or a range 8000-8010. Empty for ICMP."),
    ("H", "Firewall\n(Optional, if known)", False, 22, "Firewall (optional)", "Optional. Leave blank if you do not know."),
    ("I", "Notes", False, 34, "Notes (optional)", "Optional: why this is needed, who owns it."),
]
VPN_FIELDS = [
    ("A", "Agency", False, 22, "Agency", "Your agency or team name."),
    ("B", "Firewall\n(Optional, if known)", False, 22, "Firewall (optional)", "Optional. Leave blank if you do not know."),
    ("C", " Vendor public address\n(Peer)\nFormat X.X.X.X or X.X.X.X/CIDR", False, 28, "Vendor public address",
     "The vendor's tunnel peer address: ONE IP like 203.0.113.10 per cell."),
    ("D", " Vendor private address\n(Traffic)\nFormat X.X.X.X or X.X.X.X/CIDR", False, 28, "Vendor private address",
     "The vendor-side network behind the tunnel: ONE IP or ONE network like 10.1.2.0/24."),
    ("E", "Destination Public Address\n(Peer) \"If known\"\nFormat X.X.X.X or X.X.X.X/CIDR", False, 28, "Destination public address",
     "Our tunnel peer address, if known: ONE IP per cell."),
    ("F", "Destination Private Address\n(Traffic) \"If known\"\nFormat X.X.X.X or X.X.X.X/CIDR", False, 28, "Destination private address",
     "Our network behind the tunnel, if known: ONE IP or ONE network like 10.1.2.0/24."),
    ("G", "Destination protocol\n(pick from the list)", False, 16, "Protocol", "Pick TCP, UDP, ICMP or TCP and UDP from the list."),
    ("H", "Destination port", False, 18, "Port(s)", "Numbers 1-65535: 443, or 80,443, or a range 8000-8010."),
    ("I", "Vendor", False, 22, "Vendor", "Vendor company name."),
    ("J", "Vendor contact name", False, 22, "Vendor contact name", "A person we can contact at the vendor."),
    ("K", "Vendor contact phone number", False, 22, "Vendor contact phone", "Phone number of that contact."),
    ("L", "Vendor contact email", False, 28, "Vendor contact email", "Email of that contact."),
]


def _simple_validated_sheet(ws, title: str, heading: str, fields, header_row: int, ip_cols: str, dns_cols: str,
                            proto_col: str, port_col: str, nat_col: str | None, last: int = 100, project_row: bool = True) -> None:
    ws.title = title
    ws["A1"] = heading
    ws["A1"].font = _font(True, NAVY, 14)
    ws["A1"].alignment = Alignment(vertical="center")
    ws.row_dimensions[1].height = 24
    if project_row:
        ws["A2"] = "Project"
        ws["A2"].font = _font(True)
        ws.merge_cells("B2:E2")
        for col in "BCDE":
            ws[f"{col}2"].border = BOX
            ws[f"{col}2"].fill = _fill(YELLOW)
    _header_row(ws, header_row, fields)
    first = header_row + 1
    for r in range(first, last + 1):
        for ci in range(1, len(fields) + 1):
            c = ws.cell(r, ci)
            c.border = BOX
            c.alignment = Alignment(wrap_text=True, vertical="top")
            c.protection = Protection(locked=False)
    by_col = {f[0]: f for f in fields}
    for col, f in by_col.items():
        _prompt_only(ws, f"{col}{header_row}", f[4], f[5])
    for col in ip_cols:
        f = by_col[col]
        probe = dv_ip("A").replace("A4", f"{col}{first}")
        _add_dv(ws, f"{col}{first}:{col}{last}", kind="custom", formula=probe, title=f[4], prompt=f[5],
                err_title=ERR["C"][0], err=ERR["C"][1], style="stop")
    for col in dns_cols:
        f = by_col[col]
        _add_dv(ws, f"{col}{first}:{col}{last}", kind="custom", formula=dv_dns("B").replace("B4", f"{col}{first}"),
                title=f[4], prompt=f[5], err_title=ERR["B"][0], err=ERR["B"][1])
    f = by_col[proto_col]
    _add_dv(ws, f"{proto_col}{first}:{proto_col}{last}", kind="list", formula='"TCP,UDP,ICMP,TCP and UDP"', title=f[4],
            prompt=f[5], err_title=ERR["E"][0], err=ERR["E"][1])
    f = by_col[port_col]
    _add_dv(ws, f"{port_col}{first}:{port_col}{last}", kind="custom", formula=dv_ports("F").replace("F4", f"{port_col}{first}"),
            title=f[4], prompt=f[5], err_title=ERR["F"][0], err=ERR["F"][1])
    if nat_col:
        f = by_col[nat_col]
        _add_dv(ws, f"{nat_col}{first}:{nat_col}{last}", kind="list", formula='"Source NAT,Static NAT"', title=f[4], prompt=f[5],
                err_title="Pick from the list", err="Choose Source NAT or Static NAT from the drop-down list.")
    plain = set(by_col) - set(ip_cols) - set(dns_cols) - {proto_col, port_col} - ({nat_col} if nat_col else set())
    for col in sorted(plain):
        f = by_col[col]
        _prompt_only(ws, f"{col}{first}:{col}{last}", f[4], f[5])
    ws.freeze_panes = f"A{first}"
    _fit_width(ws)
    _protect(ws)


def build_nat_sheet(ws) -> None:
    _simple_validated_sheet(ws, "Source or Static NATs", "Firewall rule network address translation (NAT) request", NAT_FIELDS, 3,
                            ip_cols="AD", dns_cols="BE", proto_col="F", port_col="G", nat_col="C")


def build_vpn_sheet(ws) -> None:
    _simple_validated_sheet(ws, "Site to Site VPN Modification",
                            "Existing site-to-site virtual private network (VPN) tunnel endpoint changes", VPN_FIELDS, 2,
                            ip_cols="CDEF", dns_cols="", proto_col="G", port_col="H", nat_col=None, project_row=False)


# ---------------------------------------------------------------- instructions
def _para(ws, row: int, text: str, *, bold=False, size=11, color="000000", fill=None, height=None, cols="A:F", italic=False) -> int:
    a, b = cols.split(":")
    ws.merge_cells(f"{a}{row}:{b}{row}")
    c = ws[f"{a}{row}"]
    c.value = text
    c.font = _font(bold, color, size, italic)
    c.alignment = Alignment(wrap_text=True, vertical="top")
    if fill:
        for ci in range(ord(a) - 64, ord(b) - 63):
            ws.cell(row, ci).fill = _fill(fill)
    width_chars = 150
    lines = sum(max(1, -(-len(p) // width_chars)) for p in text.split("\n"))
    ws.row_dimensions[row].height = height or max(16, 15.5 * lines * (size / 11))
    return row + 1


def _table(ws, row: int, header: list[str], rows: list[list[str]], heights: int | None = None) -> int:
    for ci, h in enumerate(header, 1):
        c = ws.cell(row, ci, h)
        c.font = _font(True, WHITE, 10)
        c.fill = _fill(NAVY)
        c.alignment = Alignment(wrap_text=True, vertical="center")
        c.border = BOX
    ws.row_dimensions[row].height = 20
    row += 1
    widths = [ws.column_dimensions[get_column_letter(i)].width or 12 for i in range(1, len(header) + 1)]
    for vals in rows:
        longest = 1
        for ci, v in enumerate(vals, 1):
            c = ws.cell(row, ci, v)
            c.font = _font(ci == 1, size=10)
            c.alignment = Alignment(wrap_text=True, vertical="top")
            c.border = BOX
            longest = max(longest, sum(max(1, -(-len(p) // max(8, int(widths[ci - 1] * 1.05)))) for p in str(v).split("\n")))
        ws.row_dimensions[row].height = heights or max(16, 14 * longest)
        row += 1
    return row + 1


def build_instructions(ws) -> None:
    ws.title = "Instructions"
    ws.sheet_properties.tabColor = "548235"
    for col, w in zip("ABCDEF", (30, 30, 36, 28, 40, 6)):
        ws.column_dimensions[col].width = w
    ws.sheet_view.showGridLines = False
    r = 1
    r = _para(ws, r, "Firewall change request (FCR) form: how to fill it in", bold=True, size=18, color=NAVY, height=32)
    r = _para(ws, r, "This form asks for the same few facts every time, in the same format, so the request can be processed quickly and without "
                     "back-and-forth. Every cell has hover help (click a cell and read the yellow note). Cells that need fixing turn red.",
              italic=True, color="444444")
    r += 1
    r = _para(ws, r, "Quick start", bold=True, size=13, color="FFFFFF", fill=NAVY)
    steps = [
        "1. Open the 'Firewall Rules' tab. Type your project name (and ticket number, if you have one) in the yellow Project box.",
        "2. Fill in ONE rule per row, starting at row 4. Each row = one source, one destination, one protocol, and the port(s).",
        "3. Source and destination must be an IP address (10.1.2.3) or a network (10.1.2.0/24). Need several? Use one row each, copying the other columns down.",
        "4. Pick the protocol from the drop-down. Type the port number(s).",
        "5. If you know the application, put its name in the Application column. If you don't, leave it blank. That is fine (see 'Application' below).",
        "6. Look at the 'Row check' column on the far right. Every filled row must say OK. If it says 'Fix: ...', do what it says (the cell is also shaded red).",
        "7. Save the file (keep it as .xlsx) and send it with your ticket. Put the ticket number in the file name too if you can, like RITM0012345-my-project.xlsx.",
    ]
    for s in steps:
        r = _para(ws, r, s)
    r += 1
    r = _para(ws, r, "What each column wants", bold=True, size=13, color="FFFFFF", fill=NAVY)
    colrows = [
        ["Project (yellow box, top)", "Optional", "Free text. Add a ticket number if you have one.",
         "Web refresh RITM0012345", "Ticket numbers look like RITM0012345, SCTASK0012345, CHG0012345 or CR12345. They are read automatically from here, from Notes, and from the file name."],
        ["A. Source Address", "REQUIRED", "ONE IP address, or ONE network with /number, or an AD group name.",
         "10.60.0.25\n10.60.0.0/24\nEXAMPLE\\Payroll Admins", "Not 'any'. No commas or lists (one row per source). Four numbers, each 0-255. The /number must be 1-32."],
        ["B. Source DNS Name", "Optional", "The server name of the source, name only.", "app01.example.com",
         "No https://, no /path, no spaces. This does NOT replace the IP in column A."],
        ["C. Destination address", "REQUIRED", "ONE IP address or ONE network with /number.", "10.70.0.7\n10.70.0.0/24",
         "Only know the name? Look the IP up (see 'How do I find an IP from a name?'). Not 'any'. One per row."],
        ["D. Destination DNS Name", "Optional", "The server name of the destination, name only.", "web01.example.com",
         "Same rules as column B."],
        ["E. Destination Protocol", "REQUIRED", "Pick from the drop-down: TCP, UDP, ICMP, or TCP and UDP.", "TCP",
         "Web, SSH, RDP and databases are TCP. DNS and NTP are UDP. Ping is ICMP. If unsure, ask the application owner."],
        ["F. Destination port number(s)", "REQUIRED (empty for ICMP)", "Port numbers 1-65535. A list uses commas. A range uses a dash.",
         "443\n80,443\n8000-8010", "Numbers only: not 'https', not 'any'. Range goes low to high. Up to 12 entries per cell. Leave EMPTY for ICMP."],
        ["G. Firewall", "Optional", "Name of the firewall that must change, if you know it.", "(blank if unsure)", "The engineer finds the right firewall from the addresses."],
        ["H. Notes", "Optional", "Why it is needed, who owns it, when it must work.", "Staff portal for new office RITM0012345",
         "Ticket numbers typed here are picked up automatically."],
        ["I. Application", "Optional", "The application's name (its App-ID), if you know it. Several: separate with commas.", "ssl\nms-rdp\npostgres",
         "Blank is fine. See 'What if I do not know the application?' below."],
        ["J. Row check", "Automatic", "Do not type here. It says OK or tells you what to fix.", "OK", "The sheet is locked except for the entry cells, so formulas and headers can't be broken by accident."],
    ]
    r = _table(ws, r, ["Column", "Required?", "What to enter", "Examples", "Tips and common mistakes"], colrows)

    r = _para(ws, r, "Questions people ask", bold=True, size=13, color="FFFFFF", fill=NAVY)
    qa = [
        ("What does '/24' mean? What is a network?",
         "A single computer has one IP address: 10.60.0.25. A network is a whole block of addresses. The number after the slash says how big the block is: "
         "the bigger the number, the smaller the block. 10.60.0.0/24 means every address from 10.60.0.0 to 10.60.0.255 (256 addresses). "
         "Use a plain IP for one server. Use a /number only when you really need a whole block. A network should start at the beginning of its block "
         "(10.1.2.0/24 is right; 10.1.2.5/24 is not: the tool will round it down to 10.1.2.0/24 and warn). The cheat sheet is just below."),
        ("Do I need /32 for one server?",
         "No. 10.1.2.3 and 10.1.2.3/32 mean the same thing. Just type the IP."),
        ("Can I list several IPs or ports in one cell?",
         "Ports: yes, with commas (80,443) or a dash for a range (8000-8010), up to 12 per cell. Addresses: no. Put each source or destination on its own row and "
         "copy the other columns down. The tool merges similar rows into one rule for you."),
        ("Can I ask for a range of addresses like 10.1.2.5-10.1.2.20?",
         "Use a network (/number) when it fits. Otherwise one row per address. If you must send a range, ask the engineer first."),
        ("I only know the server's name, not its IP.",
         "Look up the IP (steps below), type the IP in the address column and the name in the DNS column. The IP is required so the right firewall can be found."),
        ("What if I do not know the application?",
         "That is OK. Leave Application blank. The port and protocol are enough to start; the engineer can suggest the safer application-based version. "
         "If you want to name it yourself: open https://applipedia.paloaltonetworks.com/ , search for the application by name or keyword (for example 'remote desktop'), "
         "open the matching entry, and copy the application name shown on its page (names look like ssl, ms-rdp, postgres) into column I. "
         "It also shows the standard ports, which helps you fill in column F. Not sure which entry is right? Leave it blank."),
        ("What is the difference between a port and an application?",
         "A port is the 'door number' on the server (443). An application is the program using it (for example ssl or ms-rdp). Allowing by application is safer because "
         "only that program gets through, not anything that happens to use the port. You always give the port. The application is a bonus."),
        ("What goes in Protocol for ping?",
         "ICMP. ICMP has no port numbers, so leave the port cell empty."),
        ("The sheet will not let me type my entry.",
         "A pop-up tells you the rule. Fix the cell and try again. If you pasted data in, the paste is not checked as you go: look at the Row check column and the red cells."),
        ("The Row check says 'Fix:'. What now?",
         "Read the message; it names the problem and the cell is red. Correct it and the row turns green with OK."),
        ("I need more than 500 rows.", "Send a second file. Keep the same format."),
        ("Can I add or rename columns?",
         "Please don't. The tool finds the columns by their headings. The sheet is protected without a password (Review > Unprotect Sheet) only for the rare case an administrator needs to."),
        ("Where do the NAT and VPN tabs go?",
         "Fill those only for NAT or site-to-site VPN requests. They have the same hover help and format checks. They are handled by an engineer; the automatic import reads only the 'Firewall Rules' tab."),
    ]
    for q, a in qa:
        r = _para(ws, r, q, bold=True, color=NAVY)
        r = _para(ws, r, a)
        r += 0
    r += 1
    r = _para(ws, r, "Cheat sheet: how big is a /number network?", bold=True, size=13, color="FFFFFF", fill=NAVY)
    cidr = [
        ["/32", "255.255.255.255", "1", "One server. Same as typing just the IP (10.60.0.25)."],
        ["/30", "255.255.255.252", "4 (2 usable)", "A tiny link between two devices (10.60.0.0/30)."],
        ["/29", "255.255.255.248", "8 (6 usable)", "A handful of servers (10.60.0.0/29)."],
        ["/28", "255.255.255.240", "16 (14 usable)", "10.60.0.0/28 is .0 to .15"],
        ["/27", "255.255.255.224", "32 (30 usable)", "10.60.0.0/27 is .0 to .31"],
        ["/26", "255.255.255.192", "64 (62 usable)", "10.60.0.0/26 is .0 to .63"],
        ["/25", "255.255.255.128", "128 (126 usable)", "10.60.0.0/25 is .0 to .127"],
        ["/24", "255.255.255.0", "256 (254 usable)", "A typical VLAN. 10.60.0.0/24 is 10.60.0.0 to 10.60.0.255"],
        ["/23", "255.255.254.0", "512", "Two /24s together (10.60.0.0 to 10.60.1.255)"],
        ["/22", "255.255.252.0", "1,024", "Four /24s together (10.60.0.0 to 10.60.3.255)"],
        ["/16", "255.255.0.0", "65,536", "A very large block (10.60.0.0 to 10.60.255.255). Expect extra review."],
    ]
    r = _table(ws, r, ["Network size", "Netmask", "Addresses", "Example"], cidr)
    r = _para(ws, r, "'any' is not accepted on this form, and very large networks (/16 and bigger) get extra review. Talk to the security team first.", italic=True, color="444444")
    r += 1
    r = _para(ws, r, "Where to look up an application", bold=True, size=13, color="FFFFFF", fill=NAVY)
    ws.merge_cells(start_row=r, start_column=1, end_row=r, end_column=5)
    c = ws.cell(r, 1, "Applipedia (Palo Alto Networks): click to open  " + APPLIPEDIA)
    c.hyperlink = APPLIPEDIA
    c.font = Font(name="Calibri", size=12, underline="single", color="0563C1", bold=True)
    ws.row_dimensions[r].height = 22
    r += 1
    r = _para(ws, r, "Search by name or keyword, open the matching application, and copy the application name from its page into column I. Skip it if you are not sure.")
    r += 1
    r = _para(ws, r, "Critical firewall rule guidelines", bold=True, size=13, color="FFFFFF", fill=NAVY)
    rules = [
        "1. Remote desktop protocol (RDP), secure shell (SSH) and virtual network computing (VNC) (3389, 22, varied) traffic requires two-factor authentication. Any requests for these ports and applications from a user to a server must come from agency VPN landing zone IP addresses.",
        "2. If you know the name of a server or website but do not know its IP address, use nslookup to get it (steps below).",
        "3. All tickets require information security officer (ISO) approval. Follow your agency's process for getting it; it varies from agency to agency.",
        "4. Pick a protocol (TCP, UDP or ICMP) for every row. (If a protocol is ever left blank, TCP is assumed.)",
        "5. If troubleshooting is needed after a rule is implemented, tell us what time you tested. We will need your help to troubleshoot traffic issues.",
        "6. When troubleshooting needs a third party, be available to coordinate with your vendor, yourself and the managed security staff (MSS) or provider firewall staff.",
        "7. Source (IP or AD group), destination IP and destination port are REQUIRED before an ISO can approve a firewall ticket.",
    ]
    for s in rules:
        r = _para(ws, r, s)
    r += 1
    r = _para(ws, r, "How do I find an IP from a name? (nslookup)", bold=True, size=13, color="FFFFFF", fill=NAVY)
    for s in ("1. On Windows, click Start and type: cmd   then press Enter.",
              "2. At the prompt type: nslookup server-name.example.com   then press Enter. (Use your own server name.)",
              "3. Look for the line 'Address:' under the server name: that is the IP. (The first Address line is your DNS server, ignore it.)",
              "4. Type that IP in the address column and the name in the DNS name column."):
        r = _para(ws, r, s)
    r += 1
    r = _para(ws, r, "All IP addresses and names in this workbook are made-up examples. Last updated for form version 2.", italic=True, color="7F7F7F", size=9)
    _fit_width(ws)
    _protect(ws)


def build(path: str | Path, rows: list[tuple] | None = None, project: str = "", hide_helpers: bool = True) -> Path:
    wb = Workbook()
    build_instructions(wb.active)
    build_rules_sheet(wb.create_sheet(), rows=rows, project=project, hide_helpers=hide_helpers)
    build_example_sheet(wb.create_sheet())
    build_nat_sheet(wb.create_sheet())
    build_vpn_sheet(wb.create_sheet())
    wb.properties.creator = "panlab"
    wb.properties.title = "Firewall change request form"
    wb.calculation.fullCalcOnLoad = True
    wb.active = 0
    wb.save(path)
    return Path(path)


if __name__ == "__main__":
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1] / "templates" / "customer-rule-request-form.xlsx"
    print(build(out))
