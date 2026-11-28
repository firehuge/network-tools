# Getting a tech-support file

## Web UI (firewall)

1. Device > Support > **Generate Tech Support File**.
2. Wait for it to finish (a few minutes), then **Download Tech Support File**.
3. The file is named like `techsupport_<serial>_<date>.tgz`.

For an HA pair, take it from the **active** unit (it has the live session and throughput data).

## CLI

```
scp export tech-support to user@host:/path/
```

or `tftp export tech-support to <host>`.

## Panorama-managed firewalls

Generate the file on the firewall itself: its own web UI (or Panorama's **Context** switch to
that firewall) or its CLI. A Panorama tech-support file is not the same thing.

## What the planner reads

| Data | Where in the TSF |
|---|---|
| Model, PAN-OS, serial, uptime, multi-vsys | `show system info` in `tmp/cli/techsupport_*.txt` |
| Licenses and expiry | `request license info` (auth codes are ignored) |
| Sessions, throughput, CPS now | `show session info` |
| Peak sessions, throughput, CPS, PPS | `var/log/pan/dp-monitor.log*` |
| Interfaces, media, speed, counters | `show interface all`, `show interface ethernetX`, `show counter interface all` |
| HA | `show high-availability all` + config |
| Panorama | `show panorama-status`, config, `panorama_pushed/mergesp.xml` |
| Config | `opt/pancfg/mgmt/saved-configs/running-config.xml` |

Older or trimmed TSFs may be missing some of these. The planner shows **not in file** instead of guessing.

## Keep it private

A TSF holds the full config, addresses and hostnames. The planner reads it in your browser and
uploads nothing. Don't email it around or put it in a git repo.
