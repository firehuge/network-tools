# PAN Physical Upgrade Planner (pan-physical-upgrade)

> **Read [../LEGAL.md](../LEGAL.md) first.** Provided AS IS, no warranty; use only legally licensed Palo Alto Networks products and do not use it to violate any vendor terms; organizations must have their security team approve it before use. Not affiliated with Palo Alto Networks.

A single HTML page for Palo Alto Networks firewall refreshes. Drop in the **tech-support file (TSF)** from the old firewall and it
sizes a replacement, lists the hardware and licenses to quote, converts the config to the new model, and writes a report and a
cutover runbook. It runs only in your browser and works offline. A strict Content-Security-Policy blocks all network access unless you click **Check for newer catalog**. No prices, by design.

## What it does

1. **Shows the current device**: model, PAN-OS, serial (can be hidden), HA, vsys, Panorama, end-of-sale / end-of-life dates,
   licenses and a usage matrix (sessions, throughput, new sessions per second, packets per second, average interface use).
   Numbers that are not in the file are marked **not in file**, never guessed.
2. **Suggests the right-sized replacement**: the smallest currently sold model that meets peak load plus headroom (default
   30%), ports and vsys, a next-step alternative and a VM-Series size. It explains why each smaller model was ruled out.
   You can change the requirements, pick any model, or include end-of-sale models.
3. **Calls out hardware and cabling**: power supplies and cords, optics (type and count), copper cables and HA cables,
   flagging speed, copper/fiber and SFP to SFP+ changes. Quantities are editable and doubled for HA.
4. **Reviews licenses**: every current license with a Keep/Drop choice and a hint from the config, a neutral "add or change"
   list of what is sold today, and doubling for an HA pair.
5. **Converts the config** to the new model or a VM: old interfaces are mapped to new ports (auto-suggested) and every
   reference follows (routes, routing protocols, zones, NAT, PBF, VPN, GlobalProtect, DHCP, DNS proxy, QoS, LLDP, HA, service
   routes, management profiles, VLAN, vwire, aggregates, subinterfaces and any other XML leaf that names an interface).
   Choose **100% conversion** (interface map only) or **customized** (management IP, DNS, hostname, standalone, a break-glass
   local admin). Download the new XML and a change-log CSV. Anything it cannot place is listed.
6. **Runs readiness checks**: PAN-OS version and upgrade path, what will not move with the config (certificates, keys, secrets,
   master key, User-ID, licenses), Panorama steps, target feature flags, capacity against published limits (unknown is shown
   as unknown), and rack/power facts, each with its source.
7. **Builds a report for finance / sales** (always light mode, no prices) as HTML or PDF, a **cutover runbook** (Markdown) and
   a **plan file** (JSON, no passwords or hashes) you can reload later.

HA pairs default to HA on the target, with a switch to turn it off. Light/dark mode follows your OS.

Also reads VM-Series and Panorama-managed firewalls (from the merged config in the file), and a plain `running-config.xml`
(conversion only, no sizing data).

## Quick start
1. Collect a tech-support file from the old firewall (Device > Support > Generate Tech Support File; from the **active** unit
   for an HA pair). For a config you can load on the new firewall, also export the running config as a **superuser**
   (see below).
2. Open `pan-physical-upgrade.html` in Chrome, Edge or Firefox (double-click it; no server needed).
3. Drop the `techsupport_*.tgz` on the page and walk the seven tabs.

To try it, load `samples/techsupport_pa3220-ha.tgz` (synthetic data). The other samples cover a standalone PA-440 with
masked secrets, a PA-820, a multi-vsys PA-5220 and a Panorama-managed VM-Series.

### Important: sanitized configs
A tech-support file masks every secret in its config (`********`), and PAN-OS refuses to load such a config
(`validate full`: "This config has been sanitized of password data ... Please use a non-sanitized config."). The tool tells you
when the file is masked. Export the running config as a superuser (Device > Setup > Operations > Export named configuration
snapshot) and load it under **Real exported config** on the Convert tab to get a config the new firewall will accept. Details in
[USAGE.md](USAGE.md).

## Documentation
- [INSTALL.md](INSTALL.md): get the file, build from source
- [USAGE.md](USAGE.md): what to collect, each tab, HA, license review, convert options, loading on the new firewall
- [docs/COLLECT_TSF.md](docs/COLLECT_TSF.md): how to get a tech-support file, and what the planner reads from it
- [docs/DATA_SOURCES.md](docs/DATA_SOURCES.md): where model, end-of-life and capacity data come from, and how to refresh it
- [docs/VALIDATION.md](docs/VALIDATION.md): how converted configs were checked on real PAN-OS
- [docs/github-actions-ci.yml](docs/github-actions-ci.yml): the CI job to add to `.github/workflows/ci.yaml`
- [docs/KNOWN_GAPS.md](docs/KNOWN_GAPS.md): what it does not do yet
- [docs/EXPEDITION_NOTES.md](docs/EXPEDITION_NOTES.md): notes on Palo Alto Expedition

## Development
```
npm ci                                  # test dependencies (@xmldom/xmldom, playwright-core)
npm run build                           # catalog/models.json + pan-physical-upgrade.html
npm test                                # unit tests (Node) + UI tests (headless Chrome; set CHROME_PATH if needed)
python3 tools/gen_synthetic_tsf.py      # rebuild the synthetic samples in samples/
```

- `build/core.js`: parsing, sizing, licenses, conversion (no DOM; runs in Node and the browser)
- `build/app.js`, `build/style.css`, `build/template.html`: the page
- `build/unpack-worker.js`: tgz/zip reader (same approach as the TSF Reader)
- `tools/build_catalog.py`: model catalog with sources

Tests and samples use synthetic data only. Never commit a real tech-support file or config.
