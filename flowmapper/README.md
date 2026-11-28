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

## Safe defaults on generated rules (1.9.4)

Every allow rule FlowMapper generates now ends with `log-end yes`, so the new traffic shows up in the traffic log.
You can also type the name of a **security profile group** in the *Profile group for new rules* box next to Trace. It is
added to every generated allow rule as `profile-setting group <name>`, in the on-screen CLI, the ticket HTML and the
ticket CSV (new columns *Log at session end* and *Profile group*). The box is saved in your browser and left blank by
default: FlowMapper never invents a group name, because a group that does not exist on the firewall or Panorama fails the
commit. The group must already exist where the rule is created (the device group, or shared, for Panorama).
The same setting exists in PAAT (`change_plan.rule_profile_group` in the customer profile).

## FCR import (1.9.3)

Paste text, load a `.csv`, or load an `.xlsx` in the FCR box. Everything is read in the browser; nothing is uploaded.

- Header names are matched by words, so `Destination_IP`, `destination ip`, `Source IP`, `Ports`, `Protocol(TCP/UDP)` and `App` all work. A column that only names a VLAN or network (`Source_VLAN_VNET_Name`) is kept as a label, never used as the address. If both `Source` and `Source IP` exist, the IP/address column wins.
- Prose above the header row is skipped. In an `.xlsx`, the sheet named like the rule list is read and instruction or example sheets are skipped. Cells merged down over several rows are filled down; a row with a blank source under a request continues that request.
- A cell with several destinations or ports (`a, b` or `55001-55009`) becomes one flow each (a range is traced at its first port). One request expands to at most 500 flows.
- The ticket comes from a ticket or project column, or a PRJ-style number (`PRJ0012345`, `PROJ-123456`) in the file name, the lines above the header or the notes. The pattern can be changed in the box next to **Load CSV or .xlsx**.
- Application values that are not PAN-OS App-IDs (a system or team name) become application `any` in the proposed rule, with the name in the rule description. A `Rule Name` column becomes the proposed rule name (cleaned to PAN-OS limits). Usage and VLAN names go in the description.
