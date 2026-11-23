# The FCR request form (Excel template)

This is the blank spreadsheet a requester fills in to ask for a firewall change.
It is built so the data arrives in the format the tool needs: the sheet checks
each cell as the person types, explains every column, and shows a green **OK** or
a red **Fix:** note on every row. PAAT reads the filled-in file directly (see
[FCR upload and change plans](fcr-upload-and-change-plans.md)).

## Where to get it

- **In the GUI:** open **Upload FCRs** and click **Download the FCR request form (.xlsx)**
  (direct link: `/fcr-template.xlsx`). You need the FCR or view permission.
- **In the repo:** `templates/customer-rule-request-form.xlsx`.
- It is rebuilt by `python tools/make_fcr_template.py` (run from the repo root), so
  every change to the form is reviewed in git. Do not edit the `.xlsx` by hand.

## What is in the workbook

| Tab | What it is |
|---|---|
| **Instructions** | Quick start, a guide to every column, an FAQ (what is `/24`, one row per address, what if I do not know the application, ping, ports vs applications, nslookup), a `/32` to `/16` cheat sheet, and the Applipedia link. |
| **Firewall Rules** | The tab to fill in. One rule per row, from row 4, up to 500 rows. This is the only tab `paat import` reads. |
| **Example** | A finished sample (made-up addresses) so people can see what good looks like. It is not imported. |
| **Source or Static NATs**, **Site to Site VPN Modification** | Kept from the original form, now with the same format checks. An engineer handles these by hand; the import does not read them. |

## What each column checks

The first row of data is row 4. Required columns have a dark header.

| Column | Required | What the cell accepts | While typing | Row check column says |
|---|---|---|---|---|
| **A Source Address** | Yes | One IPv4 address (`10.60.0.25`), one network (`10.60.0.0/24`), or an AD group name (`DOMAIN\Group`) | Blocks `any`/`all`/`*`, commas (one source per row), a wrong number of dots, a stray `e`, or a trailing `/` | Also checks each number is 0-255 with no leading zero, the `/prefix` is 1-32, and flags "looks like a DNS name" |
| **B Source DNS Name** | No | A name like `app01.example.com` | Blocks names with no dot, `https://`, `/path`, `:`, spaces, commas | Same rules |
| **C Destination address** | Yes | One IPv4 address or one network | Same as column A but no AD group, so names are blocked | Same checks as column A, plus "required" |
| **D Destination DNS Name** | No | A name like `web01.example.com` | Same as column B | Same rules |
| **E Destination Protocol** | Yes | Drop-down: `TCP`, `UDP`, `ICMP`, `TCP and UDP` | Only the list values are allowed | "Pick a protocol" if empty |
| **F Destination port number(s)** | Yes (empty for ICMP) | `443`, a list `80,443`, a range `8000-8010` (1-65535) | Blocks 0, over 65535, words (`any`, `https`), stray commas | Checks every number and range (low to high), up to 12 entries, and "ICMP has no ports" |
| **G Firewall** | No | Free text | Hover help only | |
| **H Notes** | No | Free text. Ticket numbers typed here are picked up. | Hover help only | |
| **I Application** | No | Free text (an App-ID name such as `ssl`, `ms-rdp`) | Hover help only | |
| **J Row check** | Automatic | Formula. Do not type. | Locked | `OK` or `Fix: ...` |

Every column header and every entry cell has hover help (click the cell and read the
yellow note). A cell that needs fixing turns red. Columns K to Q are hidden helper
formulas that feed the Row check.

The **Project** box (yellow, top) is free text. Ticket numbers typed there, in Notes,
or in the file name (`RITM0012345`, `SCTASK0012345`, `CHG0012345`, `CR12345`) are read
automatically by the importer.

## Application is optional

Leaving **Application** blank is fine. The Instructions tab explains the difference
between a port and an application, and links to
[Applipedia](https://applipedia.paloaltonetworks.com/) (a clickable link on the
Instructions tab and at the top right of **Firewall Rules**). A requester who wants to
name the application can search Applipedia by name or keyword, open the entry, and
copy the application name into column I. If they do not know it, the engineer can use
the [Port to App-ID advisor](app-id-advisor.md) later.

## What you should see when you use it

1. Open the file in Excel. The **Instructions** tab is first.
2. On **Firewall Rules**, type `10.60.0.0/24` in A4, pick `TCP` in E4, type `443` in F4,
   and `10.70.0.7` in C4. The Row check in J4 turns green with `OK`.
3. Type `10.60.0.256` in A5 and Excel accepts it (the typing check only
   looks at the shape) but J5 says `Fix: Source '10.60.0.256' is not a valid IP address...`
   and A5 turns red.
4. Try `any` in A6 or `https` in F6: Excel refuses with a pop-up that explains the format.

## Limits (read these)

- **Excel does not re-check pasted values.** Pasting over a cell skips the typing
  checks. The Row check column and red cells still catch the problem, and so does the
  importer, so always look at column J before sending.
- **Typing checks are capped by Excel at 255 characters per formula.** They catch the
  common mistakes (wrong shape, wrong characters, wrong protocol, port out of range).
  Deeper checks, like each number being 0-255, live in the Row check column.
- **One address per cell.** This is deliberate: it is the easiest format to check
  and the tool merges similar rows into one rule anyway. Ports may be a list or range.
- The sheet is protected **without a password** so headers and formulas cannot be broken
  by accident (Review > Unprotect Sheet if an administrator needs to). Only the entry cells
  are unlocked. Do not rename or reorder the headers: the importer finds the columns by
  their wording.
- Needs Excel 2010 or newer, or LibreOffice. Google Sheets keeps the drop-down and the
  Row check but may ignore some typing checks.
- Rows beyond 500 are not covered. Send a second file.

## For the engineer

The importer reads this form as the standard layout (header on row 3, same column order
and header keywords as the original customer form), so older filled-in files and
older request files keep working. The tests in `tests/test_fcr_template.py`
fill the template with made-up data and import it, and (when LibreOffice is installed)
evaluate every Row check and typing-check formula against good and bad entries.
