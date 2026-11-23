# Backup files (plan-only config source)

You can upload a Palo Alto firewall or Panorama configuration snapshot
and get rule suggestions and a change plan from it. Those change sets
are **plan only** — they cannot be pushed to a device.

The PAAT server is isolated. Real customer backups may be stored in the
server's data directory (the operator's call). They must **never** be
copied into git, test fixtures, or log files. This tool is written so
another install (or a later container) can point at its own data
directory with environment variables; nothing is hard-coded to this
the server's paths.

## How to export a backup from PAN-OS

### Standalone firewall

1. Log in to the firewall Web UI.
2. **Device > Setup > Operations**.
3. **Export named configuration snapshot** (or **Export configuration
   version** / a saved named snapshot). This is an `.xml` file.
4. Optional: **Export device state** produces a `.tgz` that also works
   here if it contains `running-config.xml`.

### Panorama

1. Log in to Panorama.
2. **Panorama > Setup > Operations**.
3. **Export named Panorama configuration snapshot** for an `.xml` file,
   or **Export Panorama and devices config bundle** for a `.tgz`.
4. A device-state `.tgz` from a managed firewall is also accepted if it
   contains a PAN-OS `<config>` XML (for example `running-config.xml`).

Use a named snapshot or a running-config export, not a tech-support
dump.

## What the GUI does

Open **Backup files** (prep role and above).

- Pick a customer and upload a `.xml` file (`.tgz` / `.tar.gz` / `.tar`
  are also accepted). The tool detects **standalone firewall** vs
  **Panorama** and shows a summary: hostname if present, vsys / device
  group / template stack counts, address and security-rule counts, and
  the PAN-OS version if the file has one.
- Files are stored under `$PAAT_DATA_DIR/<customer>/configs/` (mode
  600, owned by the service user). They are never stored under the git
  repository. Default size limit is 200 MB (`PAAT_MAX_BACKUP_BYTES`,
  and nginx `client_max_body_size 200m`).
- The list shows upload time (America/Chicago), uploader, and sha256.
  Delete is audited; only the uploader or an admin can delete a file.
- Optional auto-expiry: set `config_retention_days` in the customer
  profile (default `0` = off, keep until deleted).
- **Create an offline customer from a backup** generates a placeholder
  profile (built-in naming templates, no device credentials) so you can
  drop in any file without editing YAML. Those profiles live under
  `$PAAT_OFFLINE_CUSTOMERS_DIR` (default
  `$PAAT_DATA_DIR/offline-customers`), not in the repo.

On **Upload FCRs** and **Decommission**, the **Config source** picker
offers:

- Cached / profile config
- Live device (read-only export of the running config), when credentials
  are configured
- Each uploaded backup, by file name and sha8

A change set built from a backup is marked:

`Offline - from backup <file> (<sha8>) uploaded <time>`

The change plan uses the same CR format as a live/cached plan. The push
area refuses it with **plan only - built from a backup file**. Traffic-log
lookup is also unavailable for those change sets.

XML is parsed with defusedxml (no external entities). Filenames are
sanitized. Form posts use the same Origin/Host check as the rest of the
GUI. Audit records store the file name, sha256, size, kind, and
uploader — never the configuration XML.

## CLI

```text
paat uploads add --customer <name> FILE.xml
paat uploads list --customer <name>
paat uploads delete --customer <name> cfg-YYYYMMDD-HHMMSS-xxxxxxxx
paat uploads add FILE.xml --create-customer <new-name> [--display-name "..."]

paat import --customer <name> FCR.xlsx --backup cfg-...
paat decom --customer <name> --items '...' --backup cfg-...
```

`--backup` is plan only. Do not combine it with `--live`.
`paat push --changeset ... --apply --commit` is refused for these
change sets. A dry-run print of `set` commands is still allowed.

## Environment variables (container-ready)

| Variable | Default | Purpose |
|---|---|---|
| `PAAT_DATA_DIR` | `/var/lib/paat/data` | Changesets, caches, audit logs, **uploaded backups** (`<customer>/configs/`) |
| `PAAT_CUSTOMERS_DIR` | `<repo>/customers` | Committed customer profiles |
| `PAAT_OFFLINE_CUSTOMERS_DIR` | `$PAAT_DATA_DIR/offline-customers` | Generated ad-hoc profiles |
| `PAAT_CUSTOMER_OVERRIDE_DIR` | `/etc/paat/customers` | Local `change_plan` overlays |
| `PAAT_USERS_FILE` | `/etc/paat/users.yaml` | GUI users |
| `PAAT_SESSION_KEY_FILE` | `/etc/paat/session.key` | Signed session cookie key |
| `PAAT_MAX_BACKUP_BYTES` | `209715200` (200 MB) | Upload / extract size cap |

Point these at paths **outside** the git checkout. The tool refuses to
store an upload if `PAAT_DATA_DIR` is inside the repository.

A later container image would mount a volume at `PAAT_DATA_DIR`,
bind-mount or copy profiles to `PAAT_CUSTOMERS_DIR`, and keep users
and the session key in `/etc/paat` or another secret path.
