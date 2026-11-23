# PAN Tech-Support Triage Viewer (tsf-reader)

> **Read [../LEGAL.md](../LEGAL.md) first (draft).** Provided AS IS, no warranty; use only legally licensed Palo Alto Networks products and do not use it to violate any vendor terms; organizations must have their security team approve it before use. Not affiliated with Palo Alto Networks.

A single HTML page that reads a Palo Alto Networks **tech support file** (TSF) from a firewall or Panorama and highlights problems in plain English.

## Quick start
1. Open `pan-tsf-triage.html` in Chrome, Edge, Firefox or Safari (double-click it; no server needed).
2. Drop a `techsupport_*.tgz` onto the page.
3. Read the dashboard and the **Findings** tab.

To try it, load `samples/techsupport_fw-issues.tgz` (synthetic data).

Nothing is uploaded; the page works offline. See [INSTALL.md](INSTALL.md) and [USAGE.md](USAGE.md).

## Development
```
python3 scripts/generate_samples.py   # rebuild synthetic samples
npm install                            # test dependency (playwright-core)
npm test                               # headless tests, needs Chrome (set CHROME_PATH if not on PATH)
python3 build/assemble.py              # rebuild pan-tsf-triage.html from build/*
```
