# Backup-file plans

Plan an FCR or a decommission against a saved Panorama or firewall XML
snapshot when you cannot (or must not) reach the live device. The plan
is the same CR format as a live export. The push area will **refuse**
to apply it.

## When to use this

- The engineer sent a `running-config.xml` or a Panorama export and you
  are planning off-box.
- The live device is down, upgrading, or out of reach.
- You want a second opinion against a known-good backup, not today's
  running config.

This is **plan only**. It will not make the backup the running config,
and it will not push.

## How to export a snapshot (on the device)

**Standalone firewall:** Device > Setup > Operations > Export named
configuration snapshot (or Export configuration bundle). A
`running-config.xml` from the device works.

**Panorama:** Panorama > Setup > Operations > Export Panorama and
devices config bundle, or export the named Panorama configuration
snapshot. The file must be the Panorama config (device groups,
templates, and shared), not a single firewall's local file, if you
want device-group placement.

There are no secrets in this manual; keep the XML on the PAAT server or
your own workstation, not in git.

## Step by step (GUI)

1. Open **Backup files** (needs the **fcr** permission).
2. Upload the XML. The page shows a short summary: type (firewall or
   Panorama), hostname, vsys or device groups / template stacks,
   address and rule counts, PAN-OS version.
3. You can also create an ad-hoc offline customer from a file, with no
   YAML to edit, if the file is not for an existing customer.
4. On **Upload FCRs** or **Decommission**, set **Config source** to
   that backup (`cfg-YYYYMMDD-HHMMSS-...`).
5. Generate the change set and open the **Change plan** as usual.

## What you should see

- The change set header notes that it was built from a backup file.
- The plan looks like any other CR plan (objects, rules, CLI,
  rollback).
- In the push area, apply is refused with a message such as
  **plan only - built from a backup file**.

Rows that the snapshot's policy already permits show green (no rule). Rows
it permits for only some ports show yellow, and only the missing ports are
proposed. See [Already permitted](fcr-upload-and-change-plans.md#already-permitted-green-and-partly-permitted-yellow).

## Safety checks already in the tool

- `--backup` cannot be combined with `--live`.
- The push path will not apply a backup-built change set, even for
  `example` where live Panorama push is otherwise opted in.
- Uploaded files stay under the customer's data directory on the PAAT server, not in git.See the backup-files notes in docs/backup-files.md for
  storage limits and environment variables.

## CLI equivalent

```text
paat uploads add --customer example FILE.xml
paat uploads list --customer example
paat import --customer example FCR.xlsx --backup cfg-YYYYMMDD-HHMMSS-xxxxxxxx
```

## Troubleshooting

| What you see | What to try |
| --- | --- |
| File not recognized as Panorama or a firewall | You may have a partial export, a tech-support file, or a pre-11.x format the loader rejects. Export a named configuration snapshot and try again. |
| Empty Panorama looks like a firewall | Current PAAT versions treat a management-only Panorama export (no device groups yet) as Panorama. Upgrade if your server is older than that fix. |
| Push button missing or refused | That is expected for backup-built plans. Recreate the plan from a live or cached export if you truly intend to push. |
| Summary shows the wrong hostname | You uploaded a different device's file. Check the summary before you plan. |
