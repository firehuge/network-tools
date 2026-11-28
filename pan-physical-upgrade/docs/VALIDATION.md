# Validation on real PAN-OS

Converted configs were checked on a PA-VM (PAN-OS 11.1.13, managed by Panorama) without
committing anything. This is the method, so you can repeat it on your own device:

1. Save the current candidate config as a snapshot (it already had pending changes).
2. Import the converted XML as a named config, then `load config from <file>` into the candidate.
3. `validate full`.
4. `revert config`, load the saved snapshot back, and delete both files.
5. Check that the candidate and running configs hash the same as before, and that no files remain.

Device state matched before and after every run.

## Results

| Source | Target | Result |
|---|---|---|
| PA-440 (real TSF, PAN-OS 11.1.6) | VM-100, ports moved to ethernet1/4-1/7 | Interfaces, routing, zones, VPN and policy all valid. Only failures: encrypted secrets (certificate private keys, RADIUS/TACACS/LDAP secrets) because the VM has a different master key, and one admin-role setting (`master-key` with a masked value) that the newer release rejects. |
| Synthetic PA-3220 HA sample | VM-300, 6 ports kept, 4 dropped, HA removed | First run found schema gaps in the synthetic sample itself (fixed). Second run: everything valid except the synthetic certificate private key (expected: fake key). |

## Changes made from what we learned

- The converter now lists **every encrypted value** (`-AQ==` strings and private keys) in the result
  and the change log, with a master-key warning.
- `admin-role .../webui/device/master-key` with an invalid keyword is set to `disable` and logged.
- When HA is removed, dropped HA ports are no longer reported as unresolved.
- On this PA-VM with 3 vNICs, `validate full` accepted `ethernet1/4`-`ethernet1/9` but rejected `ethernet1/10`.
  Keep VM mappings within the vNICs you will attach.
- A Panorama-managed target validates the **merged** config: local interfaces that clash with ports the
  template stack already uses show as "already in use". Map around them, or update the template.

## Real-file round: PA-440 and PA-VM tech-support files

Inputs: tech-support files from a PA-440 (PAN-OS 11.1.6-h40) and from a Panorama-managed PA-VM (PAN-OS 11.1.13-h17, 16 vCPU / 24 GB tier). Nothing from them is in this repo;
the synthetic bundles `techsupport_pa440-masked-standalone.tgz` and `techsupport_vm-managed.tgz` reproduce each shape.

Real-file bugs found and fixed:

| Found | Fix |
|---|---|
| A standalone PA-440 was shown as "gets config from Panorama" (the 18 MB `mergesp.xml` was taken as proof). | Only `newsp.xml`/`lastsp.xml` larger than 200 bytes count. |
| SD-WAN reported "in use": `sdwan-*` admin-role permissions and `sdwan-link-settings enable no` matched. | SD-WAN counts only for real profiles, rules, interfaces or `enable yes`. |
| Secrets shown as `********` (admin `phash`, private keys, PSKs, RADIUS/TACACS/LDAP secrets) were not recognized: "0 encrypted values", converted config carried placeholders silently. | Masked values counted by field, warned on Current, Convert, Readiness, runbook and change log. |
| PAN-OS rejects those files itself: `validate full` returns "This config has been sanitized of password data because it was exported by a non-superuser or was part of a tech support export. Please use a non-sanitized config." | Warning text says so. Convert tab can load a real exported config (never saved in a plan) and converts that instead. |
| A banner-only `show transceiver-detail all` was reported as "optics not in file". | Present-but-empty section means "no optics installed". |
| PA-440 "power supply status not in file" although the model never reports adapters. | Not listed for models whose catalog entry says the CLI has no PSU status. |
| Current tab media "-" for ports the file did not detail; Hardware tab used the catalog. | Same catalog fallback ("per catalog") on the Current tab. |
| PA-VM: fields read from wrong keys (`vm-cores`, `vm-mem`), "model not in catalog", vNIC 10G speed forced 10G-port targets (PA-5xx suggested). | Reads `vm-cpu-count`, `vm-memory`, `vm-cap-tier`, `vm-license`; VM source described from its tier (24 GB = 2.5M sessions); vNIC speed ignored; virtual ports flagged as such through Hardware and runbook. |
| Panorama-managed VM: analysis used the near-empty local config. | Inventory and interfaces from `.merged-running-config.xml`; the local config is still what gets converted. |
| Certificate count included trusted CAs. | Count shows keyed certificates; CAs are described separately. |
| A very idle sample (2.9 days, 31 sessions) produced a confident "smallest model" with no caveat. | "Very low measured load" note on the Target tab. A measured 0 is shown as 0, not "not in file". |
| Custom mode changed the management IP but left a `management`-sourced service route on the old address; `validate full`: "address ... is not a valid reference". | The service-route address follows the new IP and is logged (`mgmt`). |

Validation on the PA-VM (no commit; snapshot, import, load, `validate full`, revert, restore, verify):

- Interfaces remapped to ethernet1/4-1/7 (the template stack owns 1/1-1/3).
- PA-440 config converted to VM-100 and PA-1410, exact and customized: all interface, zone, routing, NAT, VPN
  and policy references valid. What remained was only what a tech-support file cannot carry: private keys, TACACS+/RADIUS secrets, LDAP bind
  password (placeholder values are rejected as "bad encryption or wrong masterkey"; plain text is accepted for IKE PSKs only).
- Config exported from the PA-VM by a superuser, converted for PA-440 and VM-300 through the Convert tab override: `Configuration is valid`.
- Same file taken from a tech-support export: rejected by PAN-OS as sanitized.
- After every run the candidate and running configs hashed as before and no `ppu-*` files remained.

Method note: a snapshot saved over the API by a **non-superuser** account is sanitized too. Restoring it puts
placeholders into the candidate. On such a device with nothing pending, restore with `load config from running-config.xml`
instead. `type=export category=configuration` is masked the same way for a limited role (27 masked values on the PA-440 export
with a limited-role account, none on the VM export with a superuser key).

## Break-glass admin login test

The break-glass admin hash the page generates (`$5$` SHA-256 crypt, 16-character salt) was tested on a standalone PA-440
(PAN-OS 11.1.6-h40): a temporary local superuser with a generated hash was committed, then **API key generation** with the
right password worked, a wrong password was refused, and **SSH login** worked (PAN-OS asks for the password twice on SSH:
a consent banner and a second keyboard-interactive prompt). The user was then deleted and committed, and the running
config matched the original again. GUI login was not tested separately. Older releases that expect `$1$` were not tested.
