# Known gaps

- **Panorama-pushed config is not converted.** Only the firewall's local config changes. Update template
  interface names in Panorama to match your new port map.
- **Port numbering** for target models other than the PA-440 follows datasheet order. Check the hardware
  reference guide and edit the port list if needed.
- **Collapsing several ports into one trunk** (physical interface onto a subinterface of a new port) is not
  supported yet. Do it after loading, or use aggregates.
- **Peaks are sampled.** dp-monitor writes about every 10 minutes and keeps a few days, so short bursts and
  seasonal peaks can be missed. Add headroom or type your own numbers.
- **Per-interface peaks** are not in a TSF. Interface use is an average since boot.
- **VM-Series throughput** depends on the host. Figures shown are the legacy datasheet numbers.
- **Encrypted secrets** only work if the master key matches. The tool lists them; it cannot re-encrypt them.
- **Power supplies from a TSF.** A real PA-440 file only lists thermal sensors in `show system environmentals`,
  and the PA-400 CLI does not report adapter status, so the PSU count is then taken from the catalog and marked
  "from catalog". The PSU row parser is written for the documented `Power Supply #N` rows and `show chassis
  inventory` (PS lines) and has been tested on synthetic files only.
- **Optics in a TSF.** `show transceiver-detail all` is empty on the real PA-440 file tested, so the parser is a best
  guess at the layout (port line, then `Key: value` lines). Optics show as "not in file" when it finds nothing.
  Fiber type (multimode/single-mode), reach and the far-end switch are never in a TSF; the optic type starts as
  "to be chosen".
- **PSU catalog gaps.** Ruggedized models and a few series (PA-5500, PA-3500, PA-7500 counts) have no or partial
  PSU data. PA-1410/1420 sources disagree (one included + one optional vs. two); the datasheet value is used and the
  conflict is noted in the catalog. Dedicated HA port types for PA-3500, PA-5500, PA-5450 and PA-7000 are not
  published in the sources used, so those links say "type not in catalog".
- **Break-glass hash.** The `$5$` hash was tested with a real login (API and SSH) on a PAN-OS 11.1 PA-440, and a PAN-OS 11.1 PA-VM and Panorama store admin hashes in the same format. The converted config passed `validate full` with it. GUI login was not tested separately and older PAN-OS releases that expect `$1$` were not tested. Test the login on your new firewall before cutover.
- **License hints** are derived from the config only. Cloud-delivered services (IoT, SaaS, logging) cannot be seen.
- No prices, by design.

## Readiness checks (planning round 2)

- **Capacity limits.** Limits for PA-400, 800, 1400, 3400 and 5400 come from a reseller's copy of the Palo Alto datasheet tables. That copy is an older revision (some session counts differ from the catalog), so the tool says to verify in the Product Comparison tool. GlobalProtect tunnel and legacy rule counts come from Palo Alto KB articles. Limits for PA-455, 500-series, PA-3200, PA-5200, PA-7000 and the end-of-life models are not in the sources and show as unknown. Limits can change with the PAN-OS release.
- **Counts are from the saved config.** Pushed (Panorama) objects and rules are not counted unless the file has them in the local config. Dynamic routes, GlobalProtect users and live session counts are not in a config.
- **Rack and power facts** are series-level datasheet values. PA-500 series, PA-220/200, PA-3000/5000 and most ruggedized or 5G models have no rack data in the sources and show as "not in sources". Rail kits, cord lengths and AC/DC variants are not in the datasheets.
- **Feature flags are a short list.** Only features documented in the Palo Alto pages cited are flagged. Hardware offload and per-model feature limits are not published in those pages.
- **Upgrade path rules** follow the PAN-OS 10.2 to 12.1 documentation. Releases outside that range, hotfix-specific notes and end-of-life dates for PAN-OS releases are not included.
- **The runbook is generic.** It follows common practice (suspend the passive unit, cable one side at a time, clear ARP/MAC upstream, keep the old firewall for rollback) and your change process may differ.
- **Plan file** stores choices only. It cannot restore a converted config or the password; run the conversion again after loading it.

## Real-file round

- **Masked configs cannot be fully proven.** A tech-support config has no real secrets, and PAN-OS refuses it. The converter is validated for references and structure with stand-in values; secrets can only be checked from a real export.
- **PA-500 series** rack and limits are still not in the sources.
- **Panorama-managed firewalls**: interfaces shown come from the merged config, but the conversion changes only the local config. Template interface names must be updated in Panorama by hand.
- **A PA-440 target was not validated on hardware** with a loaded config; the validation runs used a PA-VM.
- **Tech-support files stay on the device.** PAN-OS has no documented command or API to delete the ones you generate. Plan for the disk space and remove them with support if needed.
