# Usage: PAN Tech-Support Triage Viewer

## What it does

Drop a `techsupport_*.tgz` onto the page (or click to browse). The tool, running only in your browser:

1. Unpacks the bundle (including a nested `.tgz`).
2. Reads device identity, HA, resources, sessions, counters, licenses, jobs, routing, interfaces, and the running config.
3. Browses the logs (`var/log/pan/mp-log`, `dp-log`, and similar).
4. Lists **findings** with a severity, a plain-English explanation, a recommended action, and clickable evidence (file + line).
5. Offers **performance suggestions** (logging at session start, overly broad decryption, missing zone protection, unused rules, and so on). Suggestions are labeled as suggestions, not certainties.
6. Exports a findings report as HTML or CSV. Identity fields (hostname, serial, management IP) are hidden by default. Leave **Show sensitive values** off before you share a report or take a screenshot. Authcodes, passwords, and keys stay redacted even when that box is on.

Nothing is uploaded. The page works offline. You can copy `pan-tsf-triage.html` to a USB stick or a shared folder and double-click it.

## Privacy

- Files never leave this computer.
- Core dumps under `var/cores` are listed, not opened.
- Hostname, serial, and management IP are hidden on the dashboard and in exports until you turn on **Show sensitive values**. The dashboard says **Hidden — turn on Show sensitive values** when a value is present but hidden, and **Not found in this bundle** when it really is not in the file. Each identity field also shows its source (for example `show system info` or `running-config.xml`).
- Authcodes, passwords, and private keys are always redacted.
- Identity is resolved in this order: `show system info`, then `running-config.xml` (`deviceconfig/system` hostname and management IP), then other bundle files (`show interface management`, license serials, the tech-support filename, and conservative log fallbacks). Serial is often only in CLI or license output, not in the config.

A tech support file is sensitive. It usually contains hostnames, serial numbers, IP addresses, usernames, and the running configuration. Do not post it, or an unredacted screenshot, in a public place.

## How to get a tech support file

### Firewall or Panorama — GUI

1. Sign in to the device web interface.
2. Go to **Device → Support** (on Panorama: **Panorama → Support**).
3. Click **Generate Tech Support File**. Wait until it finishes. This can take several minutes.
4. Click **Download Tech Support File**. The file is usually named `techsupport_<hostname>_<timestamp>.tgz`.

### Firewall or Panorama — CLI

From a workstation that can reach the management interface (replace the path and user):

```
scp export tech-support to user@host.example.com:/tmp/techsupport.tgz
```

Or generate it on the device and copy it off later:

```
tftp export tech-support to <host>
```

You do not need to unpack the `.tgz` first. Drop the file onto the tool as it is.

## How to use the tool

1. Open `pan-tsf-triage.html` in a current Chrome, Edge, Firefox, or Safari.
2. Drop the `.tgz` on the dashed box. For a large file you will see progress (bytes read, files indexed, current file) and a **Cancel** button.
3. Read the **dashboard**: device type, model, PAN-OS version, HA, licenses, a health score, and the top findings.
4. Open **Findings** for the full list. Click a card, or an evidence line, to jump to the matching log lines.
5. Use **Logs** to search (plain text or regex), filter by file, severity, or time, and walk issue lines with Previous / Next.
6. **System / Resources**, **Counters**, and **Config overview** show the parsed tables. **Raw files** lists everything in the bundle.
7. Export HTML or CSV. Leave **Show sensitive values** off if you will attach the report to a ticket or send it out.

Red cards are likely to matter now. Yellow cards are worth a look. Blue cards marked “suggestion” are hygiene or performance ideas.

## What the checks cover

**Problems (when the bundle contains the evidence):**

- High management or dataplane CPU, or high memory (warning at 60% CPU / 80% memory, critical at 80% / 90%)
- Session table near capacity (warning 80%, critical 90%)
- Packet buffer or descriptor pool depletion (warning 80%, critical 90%)
- Packet / session allocation failures and incrementing drop counters (`show counter global`)
- HA split brain, link- or path-monitor failure, config out of sync, preempt flaps
- Licenses expired or expiring (critical if expired, warning within 30 days)
- Disk usage high (warning 80%, critical 90%), especially `/opt/panlogs`
- Commit, Commit-All, or content/software download job failures
- User-ID agent or server-monitor disconnects
- Authentication failure bursts in `authd`
- BGP neighbors down or flapping
- Interface errors or drops
- SSL decryption errors and expired certificates
- Firewall not connected to Panorama; log forwarding failures
- On Panorama: disconnected managed devices, disconnected log collectors, failed commit-all
- Crash dumps under `var/cores`
- Process restarts / unexpected exits
- NTP configured but not synchronized
- Security content not installed (version 0) **when the matching subscription is licensed**; unlicensed packages (for example WildFire on a firewall that never had a WildFire license) are an informational “Not licensed” note, not a warning. If the license is expired, the expired-license finding is used instead of “content missing.” If `request license info` is absent from the TSF, a version-0 package is informational (“license status unknown”). Stale threat / AV / URL / WildFire content dates are reported only for licensed (or license-unknown) packages.

**Suggestions (labeled, with a rationale, never as certainties):**

- Logging at session start on security rules
- A decryption rule that matches any source / any destination
- Zone protection missing on untrust-like zones
- Rules that allow unknown-tcp / unknown-udp, or high unknown App-ID counters
- A long TCP session timeout *while* the session table is already high
- Jumbo frames / raised MTU (verify the path)
- Security rules with zero hits, if a hit-count command is in the bundle

Every finding cites the CLI command or log file it came from. If a command is missing, the tool says **Not found in this bundle** and does not invent a value.

## Limitations

- **Developed against synthetic PAN-OS 10.x / 11.x bundles.** Real files still vary by platform and software version. A command the tool does not recognize is reported as not found, not as a crash.
- Thresholds are conservative starting points (see above), not Palo Alto TAC official limits for every platform.
- The log view shows up to 8,000 matching lines at a time. Filters, search, and evidence links still consider the full parsed set.
- Large tech-support files (including multi-GB Panorama bundles) are unpacked in a background worker: the page stays responsive, a progress line shows bytes read, files indexed, and the current file, and you can cancel. The decompressed archive is never held in memory, and file contents are sent to the page in small batches (not one giant message). A memory budget (about 256 MB of kept text, by default) caps what is retained; if it is reached, leftover large files are listed by name and size and a notice is shown — the rest of the triage still runs. Panorama log-collector, logdb, Elasticsearch, and pan_logs trees are indexed only. Big logs are scanned in the worker; the page keeps the start, the end, and matching issue lines. Use **Load more of this file** on the Raw files tab to re-read a larger slice from the original file. Core dumps, packet captures, and other binaries are listed by name and size only.
- `.7z` and password-protected zips are not supported. Re-save as a normal `.zip` or use the original `.tgz`.
- Times are taken from the file as written. They may not include a time zone.

