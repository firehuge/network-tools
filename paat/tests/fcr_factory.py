# SPDX-License-Identifier: Apache-2.0
"""Build synthetic FCR workbooks with the same layout and headers as the customer form."""

from __future__ import annotations

from pathlib import Path

HEADERS = [
    "*Source Address\n(Format X.X.X.X or X.X.X.X /CIDR) or AD Group Name",
    "Source DNS Name\n[FQDN/URL]\n(Optional)",
    "*Destination address\nformat X.X.X.X or X.X.X.X /CIDR",
    "Destination DNS\nName[FQDN/URL]\n(Optional)",
    "*Destination Protocol\n(Ex, ICMP, TCP or UDP)",
    "*Destination port number(s)",
    "Firewall\n(Optional, if known)",
    "Notes",
    "Application\n(If known)",
]


def make_fcr(path: Path, rows: list[tuple], project: str = "Synthetic Project") -> Path:
    import openpyxl

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Firewall Rules"
    ws["A1"] = "Firewall rules request"
    ws["B1"] = "*- Indicates required field"
    ws["A2"] = "Project"
    ws["B2"] = project
    for i, h in enumerate(HEADERS, 1):
        ws.cell(3, i, h)
    for r, row in enumerate(rows, 4):
        for c, v in enumerate(row, 1):
            ws.cell(r, c, v)
    wb.create_sheet("Instructions")
    wb.save(path)
    return path
