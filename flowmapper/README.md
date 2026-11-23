# PAN-OS FlowMapper

> **Read [../LEGAL.md](../LEGAL.md) first.** Provided AS IS, no warranty; use only legally licensed Palo Alto Networks products and do not use it to violate any vendor terms; organizations must have their security team approve it before use. Not affiliated with Palo Alto Networks.

A single offline HTML page that reads a Palo Alto Networks **firewall config XML** or a **Panorama export** and answers: *"If 10.1.1.10 talks to 10.2.2.20 on tcp/1433, which firewalls, vsys, zones and rules does it cross, and what must change so it works?"*

It is built for messy multi-vsys environments. It follows the routing, tells you **every place a rule (or route, or zone) is needed**, and produces the CLI for the change. Nothing is uploaded: the page runs entirely in your browser and works offline.

## Quick start
1. Open `pan-flowmapper.html` in Chrome, Edge or Firefox (double-click it). There is nothing to install.
2. Click **Load demo** (or drop in your own firewall backup or Panorama export).
3. Enter source, destination, protocol and port, then press **Trace**.

## Documentation
- [Install](INSTALL.md): download the HTML file, or build it from source.
- [Usage guide](USAGE.md): tracing, multi-firewall paths, Panorama, decommission, change requests, limitations.

## Your data
Config files contain sensitive information. They stay in your browser and are never uploaded. Do not commit real configs: the repository `.gitignore` blocks `*.xml`.

## Development
```
npm install            # test dependency (playwright-core)
npm run build          # generate synthetic samples, rebuild pan-flowmapper.html
npm test               # core tests and headless-browser tests (needs Chrome; set CHROME_PATH if needed)
```
The engine files `build/core.js`, `build/render.js` and `build/decom.js` are shared with [PAAT](../paat/README.md) (`paat/tools/sync-flowmapper.py` copies them).
