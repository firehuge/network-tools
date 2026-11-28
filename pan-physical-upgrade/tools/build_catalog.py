#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build catalog/models.json from the official figures transcribed below.

Every number here was copied from a Palo Alto Networks document listed in SOURCES.
If a figure is not published (or the source is ambiguous) it is None and the tool
shows it as "not published". Do not add figures from resellers or memory.

Refresh: re-read the sources, edit the tables below, run this script, commit.
"""
import json, datetime
from pathlib import Path

SOURCES = {
  "summary": {"title": "ML-Powered NGFW Specifications and Features Summary (PAN-OS 12.2, (c) 2026)",
              "url": "https://www.paloaltonetworks.com/apps/pan/public/downloadResource?pagePath=%2Fcontent%2Fpan%2Fen_US%2Fresources%2Fdatasheets%2Fproduct-summary-specsheet"},
  "eol": {"title": "Hardware End-of-Life Dates",
          "url": "https://www.paloaltonetworks.com/services/support/end-of-life-announcements/hardware-end-of-life-dates"},
  "compat": {"title": "Compatibility Matrix: Supported OS Releases by Model (NGFW)",
             "url": "https://docs.paloaltonetworks.com/compatibility-matrix/supported-os-releases-by-model/palo-alto-networks-next-gen-firewalls"},
  "ds400": {"title": "PA-400 Series datasheet", "url": "https://www.paloaltonetworks.com/apps/pan/public/downloadResource?pagePath=%2Fcontent%2Fpan%2Fen_US%2Fresources%2Fdatasheets%2Fpa-400-series"},
  "ds1400": {"title": "PA-1400 Series datasheet", "url": "https://www.paloaltonetworks.com/apps/pan/public/downloadResource?pagePath=%2Fcontent%2Fpan%2Fen_US%2Fresources%2Fdatasheets%2Fpa-1400-series"},
  "ds5400": {"title": "PA-5400 Series datasheet", "url": "https://www.paloaltonetworks.com/apps/pan/public/downloadResource?pagePath=%2Fcontent%2Fpan%2Fen_US%2Fresources%2Fdatasheets%2Fpa-5400-series"},
  "ds3200": {"title": "PA-3200 Series datasheet", "url": "https://www.paloaltonetworks.com/apps/pan/public/downloadResource?pagePath=%2Fcontent%2Fpan%2Fen_US%2Fresources%2Fdatasheets%2Fpa-3200-series"},
  "ds5200": {"title": "PA-5200 Series datasheet (PAN-OS 11.2)", "url": "https://www.paloaltonetworks.com/apps/pan/public/downloadResource?pagePath=%2Fcontent%2Fpan%2Fen_US%2Fresources%2Fdatasheets%2Fpa-5200-series-specsheet"},
  "ds800": {"title": "PA-800 Series datasheet", "url": "https://www.paloaltonetworks.com/apps/pan/public/downloadResource?pagePath=%2Fcontent%2Fpan%2Fen_US%2Fresources%2Fdatasheets%2Fpa-800-series-datasheet"},
  "ds220r": {"title": "PA-220R datasheet", "url": "https://www.paloaltonetworks.com/apps/pan/public/downloadResource?pagePath=%2Fcontent%2Fpan%2Fen_US%2Fresources%2Fdatasheets%2Fpa-220r"},
  "ds7000": {"title": "PA-7000 Series datasheet", "url": "https://www.paloaltonetworks.com/apps/pan/public/downloadResource?pagePath=%2Fcontent%2Fpan%2Fen_US%2Fresources%2Fdatasheets%2Fpa-7000-series"},
  "hw400": {"title": 'PA-400 Series hardware reference: back panel and connect power', "url": 'https://docs.paloaltonetworks.com/hardware/pa-400-hardware-reference/pa-400-firewall-overview/pa-400-back-panel'},
  "hw500": {"title": 'PA-500 Series electrical specifications', "url": 'https://docs.paloaltonetworks.com/hardware/pa-500-hardware-reference/pa-500-series-firewall-specifications/pa-500-series-firewall-electrical-specifications'},
  "ds500": {"title": 'PA-500 Series datasheet', "url": 'https://www.paloaltonetworks.com/apps/pan/public/downloadResource?pagePath=%2Fcontent%2Fpan%2Fen_US%2Fresources%2Fdatasheets%2Fpa-500-series'},
  "hw1400": {"title": 'PA-1400 Series hardware reference: back panel', "url": 'https://docs.paloaltonetworks.com/hardware/pa-1400-hardware-reference/pa-1400-series-overview/back-panel-1400-series'},
  "hw3400": {"title": 'PA-3400 Series electrical specifications', "url": 'https://docs.paloaltonetworks.com/hardware/pa-3400-hardware-reference/pa-3400-series-specifications/electrical-specs-pa-3400-series'},
  "ds3400": {"title": 'PA-3400 Series datasheet', "url": 'https://www.paloaltonetworks.com/apps/pan/public/downloadResource?pagePath=%2Fcontent%2Fpan%2Fen_US%2Fresources%2Fdatasheets%2Fpa-3400-series'},
  "hw3200": {"title": 'PA-3200 Series electrical specifications', "url": 'https://docs.paloaltonetworks.com/hardware/pa-3200-hardware-reference/pa-3200-series-specifications/electrical-specs-pa-3200-series'},
  "hw5200": {"title": 'PA-5200 Series hardware reference', "url": 'https://docs.paloaltonetworks.com/hardware/pa-5200-hardware-reference'},
  "hw5400": {"title": 'PA-5400 Series electrical specifications', "url": 'https://docs.paloaltonetworks.com/hardware/pa-5400-hardware-reference/pa-5400-series-firewall-specifications/pa-5400-series-firewall-electrical-specifications'},
  "hw800": {"title": 'PA-800 Series electrical specifications', "url": 'https://docs.paloaltonetworks.com/hardware/pa-800-hardware-reference/pa-800-series-firewall-specifications/pa-800-series-electrical-specifications'},
  "hw7000": {"title": 'PA-7000 Series power configuration options', "url": 'https://docs.paloaltonetworks.com/hardware/pa-7000-hardware-reference/PA-7000-series-firewall-installation/connect-power-to-a-pa-7000-series-firewall/pa-7000-series-power-configuration-options'},
  "lim_mirror": {"title": "Palo Alto Networks series datasheet capacity tables (copy on a reseller site, older revision; verify in the Product Comparison tool)", "url": "https://jmeastern.com/it-products/palo-alto/next-generation-firewall/hardware/pa-3400-series/"},
  "kb_gp": {"title": "KB: Maximum number of GlobalProtect VPN tunnels supported on firewall", "url": "https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000PPBCCA4&lang=en_US"},
  "kb_rules": {"title": "KB: Maximum number of rule objects supported", "url": "https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000ClVuCAK&lang=en_US"},
  "pc_tool": {"title": "Palo Alto Networks Product Comparison tool (all capacities, latest PAN-OS)", "url": "https://www.paloaltonetworks.com/products/product-comparison"},
  "upgrade_path": {"title": "Determine the Upgrade Path to PAN-OS 11.1 and later releases", "url": "https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-upgrade/upgrade-pan-os/upgrade-the-firewall-pan-os/determine-the-upgrade-path"},
  "upgrade_notes": {"title": "Upgrade/Downgrade Considerations (PAN-OS 11.1 and later)", "url": "https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-upgrade/upgrade-pan-os/upgradedowngrade-considerations"},
  "upgrade_panorama": {"title": "Upgrade Firewalls Using Panorama (PAN-OS 10.2)", "url": "https://origin-docs.paloaltonetworks.com/pan-os/10-2/pan-os-upgrade/upgrade-pan-os/upgrade-the-firewall-pan-os/upgrade-firewalls-using-panorama"},
  "vm_lacp": {"title": "VM-Series: Configure Link Aggregation Control Protocol (ESXi, KVM)", "url": "https://docs.paloaltonetworks.com/vm-series/deployment/private-cloud/set-up-a-vm-series-firewall-on-an-esxi-server/install-a-vm-series-firewall-on-vmware-vsphere-hypervisor-esxi/configure-link-aggregation-control-protocol"},
  "vm_jumbo": {"title": "Enable Jumbo Frames on the VM-Series Firewall", "url": "https://docs.paloaltonetworks.com/vm-series/getting-started/enable-jumbo-frames-on-the-vm-series-firewall"},
  "decrypt_mirror": {"title": "Decrypt Mirror Interface (PAN-OS 11.2)", "url": "https://docs.paloaltonetworks.com/ngfw/help/11-2/network/network-interfaces/decrypt-mirror-interface"},
  "haports": {"title": 'HA Port and Processor Support (compatibility matrix)', "url": 'https://docs.paloaltonetworks.com/compatibility-matrix/reference/supported-os-releases-by-model/ha-port-and-processor-support'},
  "vsys": {"title": "Platform Support and Licensing for Virtual Systems", "url": "https://docs.paloaltonetworks.com/ngfw/administration/virtual-systems/platform-support-and-licensing-for-virtual-systems"},
  "vm_models": {"title": "VM-Series Models (capacities)", "url": "https://docs.paloaltonetworks.com/vm-series/activation-and-onboarding/vm-series-models"},
  "vm_req": {"title": "VM-Series System Requirements", "url": "https://docs.paloaltonetworks.com/vm-series/activation-and-onboarding/vm-series-models/vm-series-system-requirements"},
  "vm_mem": {"title": "VM-Series Maximum Limits Based on Memory (11.2 and later)", "url": "https://docs.paloaltonetworks.com/vm-series/activation-and-onboarding/software-ngfw/maximum-limits-based-on-memory"},
  "vm_vsys": {"title": "Virtual Systems Support on VM-Series Firewall", "url": "https://docs.paloaltonetworks.com/vm-series/getting-started/virtual-systems-support-on-vm"},
  "vm_ds": {"title": "VM-Series datasheet (legacy fixed-model App-ID throughput)", "url": "https://www.paloaltonetworks.com/apps/pan/public/downloadResource?pagePath=%2Fcontent%2Fpan%2Fen_US%2Fresources%2Fdatasheets%2Fvm-series-specsheet"},
}

DATA_AS_OF = "2026-11-27"  # date the sources were last read; bump when you refresh
G, M, K = 1e9, 1e6, 1e3
# Port group shorthand: (count, media, max_mbps, extra)
# media: rj45, combo (1G SFP or RJ45), sfp (1G), sfp+ (1/10G), sfp28 (10/25G), qsfp+ (40G),
#        qsfp28 (40/100G), qsfp-dd (100/400G), mgig (copper multi-gig)
def P(n, media, mbps, **kw):
    d = {"n": n, "media": media, "mbps": mbps}
    d.update(kw)
    return d

HW = []
def hw(model, family, fw, tp, ipsec, cps, sess, vsys, ports, mgmt_ha, src, ports_text, **kw):
    d = {"model": model, "family": family, "form": "hardware",
         "fw_bps": fw, "tp_bps": tp, "ipsec_bps": ipsec, "cps": cps, "max_sessions": sess,
         "vsys_base": vsys[0] if vsys else None, "vsys_max": vsys[1] if vsys else None,
         "ports": ports, "ports_text": ports_text, "dedicated_ha": mgmt_ha, "sources": src}
    d.update(kw)
    HW.append(d)

S = ["summary"]
# ---- PA-400 Series (EoS announced Mar 22, 2027; EoL Mar 21, 2032) ----
eos400 = {"eos_date": "2027-03-22", "eol_date": "2032-03-21", "replacement": "PA-500 Series", "last_panos": "12.2"}
hw("PA-410", "PA-400", 1.4*G, 0.8*G, 0.5*G, 11*K, 64*K, (1, 1), [P(7, "rj45", 1000)], [], S+["ds400"], "10/100/1000 (7)", min_panos="10.1.2", last_panos="12.1", **{k: v for k, v in eos400.items() if k != "last_panos"})
hw("PA-415", "PA-400", 1.5*G, 0.8*G, 0.5*G, 11*K, 64*K, (1, 1), [P(1, "combo", 1000), P(4, "rj45", 1000), P(4, "rj45", 1000, poe=True)], [], S+["ds400"], "1G SFP/RJ45 combo (1), 1G RJ45 (4), 1G RJ45/PoE (4)", min_panos="11.0", last_panos="12.1", **{k: v for k, v in eos400.items() if k != "last_panos"})
hw("PA-415-5G", "PA-400", 1.5*G, 0.8*G, 0.5*G, 11.4*K, 64*K, (1, 1), [P(1, "combo", 1000), P(4, "rj45", 1000), P(4, "rj45", 1000, poe=True)], [], S+["ds400"], "Embedded 5G, 1G SFP/RJ45 combo (1), 1G RJ45 (4), 1G RJ45/PoE (4)", min_panos="11.1", last_panos="12.1", cellular=True, **{k: v for k, v in eos400.items() if k != "last_panos"})
hw("PA-440", "PA-400", 2.4*G, 1.2*G, 1.1*G, 34*K, 200*K, (1, 2), [P(8, "rj45", 1000)], [], S+["ds400"], "10/100/1000 (8)", min_panos="10.1", ports_verified=True, vsys_note="Adding virtual systems needs PAN-OS 11.0 or later", **eos400)
hw("PA-445", "PA-400", 2.7*G, 1.25*G, 1.1*G, 34*K, 200*K, (1, 2), [P(1, "combo", 1000), P(4, "rj45", 1000), P(4, "rj45", 1000, poe=True)], [], S+["ds400"], "1G SFP/RJ45 combo (1), 1G RJ45 (4), 1G RJ45/PoE (4)", min_panos="11.0", vsys_note="Adding virtual systems needs PAN-OS 11.0 or later", **eos400)
hw("PA-450", "PA-400", 3.3*G, 2.1*G, 1.7*G, 48*K, 300*K, (1, 5), [P(8, "rj45", 1000)], [], S+["ds400"], "10/100/1000 (8)", min_panos="10.1", vsys_note="Adding virtual systems needs PAN-OS 11.0 or later", **eos400)
hw("PA-455", "PA-400", 3.6*G, 2.3*G, 1.8*G, 56*K, 300*K, (1, 5), [P(2, "combo", 1000), P(2, "rj45", 1000), P(4, "rj45", 1000, poe=True)], [], S+["ds400"], "1G SFP/RJ45 combo (2), 1G RJ45 (2), 1G RJ45/PoE (4)", min_panos="11.1", **eos400)
hw("PA-455-5G", "PA-400", 3.2*G, 1.8*G, 1.6*G, 48*K, 300*K, (1, 5), [P(2, "combo", 1000), P(6, "rj45", 1000), P(4, "rj45", 1000, poe=True)], [], S+["ds400"], "Embedded 5G, 1G SFP/RJ45 combo (2), 1G RJ45 (6), 1G RJ45 PoE (4)", min_panos="11.2.3", cellular=True, **eos400)
hw("PA-460", "PA-400", 4.2*G, 3.0*G, 2.3*G, 67*K, 400*K, (1, 5), [P(8, "rj45", 1000)], [], S+["ds400"], "10/100/1000 (8)", min_panos="10.1", vsys_note="Adding virtual systems needs PAN-OS 11.0 or later", **eos400)
# ---- PA-400R ruggedized (not on the EoS list) ----
hw("PA-410R", "PA-400R", 1.4*G, 0.65*G, 0.65*G, 11.4*K, 64*K, (1, 2), [P(4, "rj45", 1000), P(2, "sfp", 1000)], [], S, "10/100/1000 (4), 1G SFP (2)", min_panos="11.1.3", rugged=True)
hw("PA-410R-5G", "PA-400R", 1.4*G, 0.65*G, 0.65*G, 11.4*K, 64*K, (1, 2), [P(4, "rj45", 1000), P(2, "sfp", 1000)], [], S, "Integrated 5G (DSSS), 10/100/1000 (4), 1G SFP (2)", min_panos="11.1.4", rugged=True, cellular=True)
hw("PA-450R", "PA-400R", 3.2*G, 1.7*G, 1.3*G, 48*K, 200*K, (1, 2), [P(6, "rj45", 1000), P(2, "combo", 1000)], [], S, "10/100/1000 (6), combo SFP or copper (2)", min_panos="11.1", rugged=True)
hw("PA-450R-5G", "PA-400R", 3.2*G, 1.7*G, 1.3*G, 48*K, 200*K, (1, 2), [P(6, "rj45", 1000), P(2, "combo", 1000)], [], S, "Integrated 5G DSSS, 10/100/1000 (6), 1G SFP/RJ-45 combo (2)", min_panos="11.1", rugged=True, cellular=True)
hw("PA-455R-5G", "PA-400R", 3.2*G, 1.8*G, 1.3*G, 48*K, 200*K, (1, 2), [P(6, "rj45", 1000), P(2, "combo", 1000), P(4, "rj45", 1000, poe=True)], [], S, "Integrated 5G (DSSS), 1G RJ-45 (6), 1G SFP/RJ-45 combo (2), 1G RJ45 PoE (4)", min_panos="12.1.2", rugged=True, cellular=True)
# ---- PA-500 Series (current) ----
hw("PA-501", "PA-500", 0.8*G, 0.5*G, 0.24*G, 5*K, 30*K, (1, 1), [P(7, "rj45", 1000)], [], S, "1G RJ-45 (7)", min_panos="12.1.4-h2")
hw("PA-505", "PA-500", 1.2*G, 0.8*G, 0.4*G, 9*K, 62*K, (1, 1), [P(7, "rj45", 1000)], [], S, "1G RJ-45 (7)", min_panos="12.1.3")
hw("PA-510", "PA-500", 1.8*G, 1.2*G, 0.8*G, 15*K, 98*K, (1, 1), [P(8, "rj45", 1000)], [], S, "1G RJ-45 (8)", min_panos="12.1.3")
hw("PA-520", "PA-500", 2.8*G, 1.8*G, 1.5*G, 25*K, 148*K, (1, 1), [P(8, "rj45", 1000)], [], S, "1G RJ-45 (8)", min_panos="12.1.2")
hw("PA-520-5G", "PA-500", 2.6*G, 1.6*G, 1.4*G, None, None, (1, 2), [P(8, "rj45", 1000), P(2, "sfp", 1000)], [], S, "Integrated 5G modem, 10/100/1000 RJ45 (8), 1G SFP (2)", min_panos="12.1.10", cellular=True,
   note="The summary sheet lists 148K new sessions/s and 25K max sessions for this model, which looks transposed, so both are left as not published here. Check the PA-500 datasheet.")
hw("PA-540", "PA-500", 3.8*G, 2.2*G, 2.0*G, 50*K, 248*K, (1, 2), [P(8, "rj45", 1000), P(2, "sfp", 1000)], [], S, "1G RJ-45 (8), 1G SFP (2)", min_panos="12.1.2")
hw("PA-545-POE", "PA-500", 5.0*G, 3.0*G, 3.0*G, 55*K, 298*K, (1, 2), [P(6, "rj45", 1000), P(2, "rj45", 1000, bypass=True), P(4, "mgig", 2500, poe=True), P(4, "sfp", 1000)], [], S, "1G RJ-45 (6), 1G RJ-45 bypass (2), 1G/2.5G PoE (4), 1G SFP (4)", min_panos="12.1.2")
hw("PA-550", "PA-500", 6.5*G, 4.5*G, 4.0*G, 70*K, 398*K, (1, 5), [P(10, "rj45", 1000), P(2, "rj45", 1000, bypass=True), P(2, "sfp", 1000), P(2, "sfp+", 10000)], [], S, "1G RJ-45 (10), 1G RJ-45 bypass (2), 1G SFP (2), 1G/10G SFP/SFP+ (2)", min_panos="12.1.2")
hw("PA-555-POE", "PA-500", 7.5*G, 5.0*G, 4.5*G, 75*K, 448*K, (1, 5), [P(2, "rj45", 1000), P(2, "rj45", 1000, bypass=True), P(4, "rj45", 1000, poe=True), P(4, "mgig", 2500, poe=True), P(2, "sfp", 1000), P(2, "sfp+", 10000)], [], S, "1G RJ-45 (2), 1G RJ-45 bypass (2), 1G RJ-45 PoE (4), 1G/2.5G PoE (4), 1G SFP (2), 1G/10G SFP/SFP+ (2)", min_panos="12.1.2")
hw("PA-560", "PA-500", 8.5*G, 6.0*G, 5.5*G, 100*K, 598*K, (1, 5), [P(16, "rj45", 1000), P(4, "sfp", 1000), P(4, "sfp+", 10000)], [], S, "1G RJ-45 (16), 1G SFP (4), 1G/10G SFP/SFP+ (4)", min_panos="12.1.2")
# ---- PA-5xR rugged (PAN-OS 12.2) ----
hw("PA-52R-5G", "PA-5xR", 2*G, 1*G, 0.8*G, 2.5*K, 64*K, (1, 2), [P(8, "rj45", 1000), P(2, "sfp", 1000)], [], S, "Integrated 5G (RedCap), 10/100/1000 (8), 1G SFP (2)", min_panos="12.2", rugged=True, cellular=True)
hw("PA-54R-POE", "PA-5xR", 2*G, 1.6*G, 1.2*G, 5*K, 200*K, (1, 5), [P(12, "rj45", 1000), P(2, "sfp", 1000)], [], S, "10/100/1000 (12), 1G SFP (2)", min_panos="12.2", rugged=True)
hw("PA-54R-POE-D-5G", "PA-5xR", 2*G, 1.6*G, 1.2*G, 5*K, 200*K, (1, 5), [P(12, "rj45", 1000), P(2, "sfp", 1000)], [], S, "Integrated dual 5G, 10/100/1000 (12), 1G SFP (2)", min_panos="12.2", rugged=True, cellular=True)
hw("PA-56R-POE-5G", "PA-5xR", 4*G, 2.4*G, 1.9*G, 5*K, 200*K, (1, 5), [P(16, "rj45", 1000), P(2, "sfp", 1000)], [], S, "Integrated 5G, 10/100/1000 (16), 1G SFP (2)", min_panos="12.2", rugged=True, cellular=True)
# ---- PA-1400 Series ----
hw("PA-1410", "PA-1400", 8.5*G, 4.5*G, 4.1*G, 100*K, 945*K, (1, 6), [P(8, "rj45", 1000), P(4, "mgig", 5000, poe=True), P(6, "sfp", 1000), P(4, "sfp+", 10000)], ["hsci"], S+["ds1400"], "10/100/1000 (8), 1/2.5/5G (4)/PoE, 1G SFP (6), 10G SFP+ (4)", min_panos="11.0")
hw("PA-1420", "PA-1400", 9.5*G, 6.2*G, 5.6*G, 140*K, 1.4*M, (1, 6), [P(4, "rj45", 1000), P(4, "mgig", 5000), P(4, "mgig", 5000, poe=True), P(2, "sfp", 1000), P(8, "sfp+", 10000)], ["hsci"], S+["ds1400"], "10/100/1000 (4), 1/2.5/5G (4), 1/2.5/5G (4)/PoE, 1G SFP (2), 10G SFP+ (8)", min_panos="11.0")
# ---- PA-1500 Series (PAN-OS 12.2) ----
hw("PA-1510", "PA-1500", 15*G, 9*G, 7*G, 120*K, 1.09*M, (1, 6), [P(12, "rj45", 1000), P(8, "mgig", 5000), P(4, "sfp", 1000), P(8, "sfp+", 10000)], [], S, "10/100/1000 Cu (12), 1G/2.5G/5G Cu (8), 1G SFP (4), 1G/10G SFP+ (8)", min_panos="12.2")
hw("PA-1520", "PA-1500", 25*G, 18*G, 14*G, 150*K, 1.49*M, (1, 11), [P(8, "rj45", 1000), P(8, "mgig", 5000), P(4, "mgig", 10000), P(8, "sfp+", 10000), P(4, "sfp28", 25000)], [], S, "10/100/1000 Cu (8), 1G/2.5G/5G Cu (8), 1G/2.5G/5/10G Cu (4), 1/10G SFP+ (8), 10G/25G SFP28 (4)", min_panos="12.2")
hw("PA-1530", "PA-1500", 35*G, 27*G, 18*G, 175*K, 1.75*M, (1, 11), [P(8, "rj45", 1000), P(4, "mgig", 5000), P(8, "mgig", 10000), P(8, "sfp+", 10000), P(4, "sfp28", 25000)], [], S, "10/100/1000 Cu (8), 1G/2.5G/5G Cu (4), 1G/2.5G/5/10G Cu (8), 1/10G SFP+ (8), 10G/25G SFP28 (4)", min_panos="12.2")
# ---- PA-3400 Series ----
p34a = [P(12, "mgig", 10000), P(10, "sfp+", 10000), P(4, "sfp28", 25000)]
hw("PA-3410", "PA-3400", 14*G, 7.5*G, 6.6*G, 145*K, 1.4*M, (1, 11), p34a, ["ha1-a", "ha1-b", "hsci"], S, "1G/2.5G/5G/10G (12), 1G/10G SFP/SFP+ (10), 25G SFP28 (4)", min_panos="10.2")
hw("PA-3420", "PA-3400", 19*G, 10*G, 9.9*G, 220*K, 2.2*M, (1, 11), p34a, ["ha1-a", "ha1-b", "hsci"], S, "1G/2.5G/5G/10G (12), 1G/10G SFP/SFP+ (10), 25G SFP28 (4)", min_panos="10.2")
hw("PA-3430", "PA-3400", 29*G, 15*G, 12*G, 240*K, 2.5*M, (1, 11), p34a+[P(2, "qsfp28", 100000)], ["ha1-a", "ha1-b", "hsci"], S, "1G/2.5G/5G/10G (12), 1G/10G SFP/SFP+ (10), 25G SFP28 (4), 40G/100G QSFP/QSFP28 (2)", min_panos="10.2")
hw("PA-3440", "PA-3400", 35*G, 20*G, 14.5*G, 268*K, 3*M, (1, 11), p34a+[P(2, "qsfp28", 100000)], ["ha1-a", "ha1-b", "hsci"], S, "1G/2.5G/5G/10G (12), 1G/10G SFP/SFP+ (10), 25G SFP28 (4), 40G/100G QSFP/QSFP28 (2)", min_panos="10.2")
# ---- PA-3500 Series (PAN-OS 12.2) ----
hw("PA-3510", "PA-3500", 30*G, 15*G, 13*G, 325*K, 2*M, (5, 15), [P(8, "mgig", 10000), P(8, "sfp+", 10000), P(6, "sfp28", 25000), P(2, "qsfp28", 100000)], ["hsci"], S, "10G mGig Cu (8), 1G/10G SFP+ (8), 10G/25G SFP28 (6), 40G/100G QSFP28 (2)", min_panos="12.2")
hw("PA-3520", "PA-3500", 35*G, 20*G, 15*G, 350*K, 4*M, (5, 15), [P(8, "mgig", 10000), P(8, "sfp+", 10000), P(6, "sfp28", 25000), P(2, "qsfp28", 100000)], ["hsci"], S, "10G mGig Cu (8), 1G/10G SFP+ (8), 10G/25G SFP28 (6), 40G/100G QSFP28 (2)", min_panos="12.2")
hw("PA-3530", "PA-3500", 45*G, 25*G, 22*G, 500*K, 5*M, (5, 20), [P(8, "mgig", 10000), P(12, "sfp+", 10000), P(6, "sfp28", 25000), P(4, "qsfp28", 100000)], ["hsci"], S, "10G mGig Cu (8), 1G/10G SFP+ (12), 10G/25G SFP28 (6), 40G/100G QSFP28 (4)", min_panos="12.2")
hw("PA-3540", "PA-3500", 55*G, 35*G, 35*G, 550*K, 6*M, (5, 20), [P(8, "mgig", 10000), P(12, "sfp+", 10000), P(6, "sfp28", 25000), P(4, "qsfp28", 100000)], ["hsci"], S, "10G mGig Cu (8), 1G/10G SFP+ (12), 10G/25G SFP28 (6), 40G/100G QSFP28 (4)", min_panos="12.2")
# ---- PA-5400 Series ----
p54 = [P(8, "mgig", 10000), P(12, "sfp+", 10000), P(4, "sfp28", 25000), P(4, "qsfp28", 100000)]
p54t = "1G/2.5G/5G/10G (8), 1G/10G SFP/SFP+ (12), 25G SFP28 (4), 40G/100G QSFP+/QSFP28 (4)"
ha54 = ["ha1-a", "ha1-b", "hsci"]
hw("PA-5410", "PA-5400", 52*G, 35*G, 20*G, 270*K, 5*M, (10, 20), p54, ha54, S+["ds5400"], p54t, min_panos="10.2")
hw("PA-5420", "PA-5400", 70*G, 50*G, 28*G, 370*K, 7*M, (15, 65), p54, ha54, S+["ds5400"], p54t, min_panos="10.2")
hw("PA-5430", "PA-5400", 80*G, 60*G, 42*G, 380*K, 9*M, (25, 125), p54, ha54, S+["ds5400"], p54t, min_panos="10.2")
hw("PA-5440", "PA-5400", 85*G, 70*G, 58*G, 390*K, 20*M, (25, 225), p54, ha54, S+["ds5400"], p54t, min_panos="11.0")
hw("PA-5445", "PA-5400", 90*G, 76*G, 64*G, 449*K, 48*M, (25, 225), p54, ha54, S+["ds5400"], p54t, min_panos="11.1")
hw("PA-5450", "PA-5400", 200*G, 189*G, 85*G, 3.6*M, 100*M, (25, 225), None, ["ha1-a", "ha1-b", "hsci"], S, "Card based: 100/1000/10G Cu (up to 8), 1G/10G SFP/SFP+ (up to 24), 40G/100G QSFP28 (up to 4)", min_panos="10.1",
   eos_date="2026-11-22", eol_date="2031-11-21", replacement="PA-5500 Series", chassis=True)
# ---- PA-5500 Series ----
p55a = [P(8, "sfp28", 25000), P(12, "qsfp28", 100000), P(8, "qsfp-dd", 400000)]
p55b = [P(16, "sfp28", 25000), P(16, "qsfp28", 100000), P(4, "qsfp-dd", 400000)]
p55c = [P(10, "mgig", 10000), P(12, "sfp+", 10000), P(8, "sfp28", 25000), P(6, "qsfp28", 100000)]
hw("PA-5510", "PA-5500", 65*G, 45*G, 34*G, 600*K, 7*M, (10, 20), p55c, ["hsci"], S, "10GE Cu mGig (10), 10GE SFP+ (12), 10G/25G SFP28 (8), 40G/100G QSFP28 (6)", min_panos="12.2")
hw("PA-5520", "PA-5500", 75*G, 55*G, 36*G, 971*K, 12*M, (15, 65), p55c, ["hsci"], S, "10GE Cu mGig (10), 10GE SFP+ (12), 10G/25G SFP28 (8), 40G/100G QSFP28 (6)", min_panos="12.2")
hw("PA-5530", "PA-5500", 100*G, 65*G, 38*G, 1.01*M, 14*M, (25, 125), p55c, ["hsci"], S, "10GE Cu mGig (10), 10GE SFP+ (12), 10G/25G SFP28 (8), 40G/100G QSFP28 (6)", min_panos="12.2")
hw("PA-5540", "PA-5500", 150*G, 90*G, 80*G, 1.33*M, 39*M, (25, 225), p55b, ["hsci"], S, "10G/25G SFP28 (16), 40G/100G QSFP28 (16), 100G/400G QSFP-DD (4)", min_panos="12.1.2")
hw("PA-5550", "PA-5500", 175*G, 120*G, 100*G, 1.67*M, 49*M, (25, 225), p55b, ["hsci"], S, "10G/25G SFP28 (16), 40G/100G QSFP28 (16), 100G/400G QSFP-DD (4)", min_panos="12.1.2")
hw("PA-5560", "PA-5500", 240*G, 180*G, 125*G, 2.5*M, 74*M, (25, 225), p55a, ["hsci"], S, "10G/25G SFP28 (8), 40G/100G QSFP28 (12), 100G/400G QSFP-DD (8)", min_panos="12.1.2")
hw("PA-5570", "PA-5500", 300*G, 240*G, 150*G, 3*M, 89*M, (25, 225), p55a, ["hsci"], S, "10G/25G SFP28 (8), 40G/100G QSFP28 (12), 100G/400G QSFP-DD (8)", min_panos="12.1.2")
hw("PA-5580", "PA-5500", 375*G, 300*G, 170*G, 3.3*M, 99*M, (25, 225), p55a, ["hsci"], S, "10G/25G SFP28 (8), 40G/100G QSFP28 (12), 100G/400G QSFP-DD (8)", min_panos="12.1.2")
# ---- PA-7500 ----
hw("PA-7500", "PA-7500", 1500*G, 1440*G, 407*G, 7.2*M, 440*M, (25, 225), None, ["hsci"], S, "Card based: SFP-DD (up to 84), QSFP-DD (up to 56)", min_panos="11.1", chassis=True,
   note="Figures measured with 6 PA-7500-DPC-A and 2 PA-7500-NPC-A cards.")

# ---- Legacy / end-of-sale models (for the 'current device' side) ----
def legacy(model, family, eos, eol, repl, last, **kw):
    d = {"model": model, "family": family, "form": "hardware", "eos_date": eos, "eol_date": eol,
         "replacement": repl, "last_panos": last, "fw_bps": None, "tp_bps": None, "ipsec_bps": None,
         "cps": None, "max_sessions": None, "vsys_base": None, "vsys_max": None, "ports": None,
         "ports_text": None, "dedicated_ha": [], "sources": ["eol"]}
    d.update(kw)
    HW.append(d)

legacy("PA-220", "PA-220", "2023-01-31", "2028-01-31", "PA-400 Series, PA-500 Series", "10.2", vsys_base=1, vsys_max=1, sources=["eol", "vsys"])
legacy("PA-220R", "PA-220R", "2025-01-31", "2030-01-31", "PA-400R Series", "10.2", fw_bps=535*M, tp_bps=320*M, ipsec_bps=550*M, cps=4.2*K, max_sessions=64*K,
       vsys_base=1, vsys_max=1, ports=[P(6, "rj45", 1000), P(2, "sfp", 1000)], ports_text="10/100/1000 (6), SFP (2)", sources=["eol", "ds220r", "vsys"])
for m, fw, tp, ip, sess, cps, ports, pt in [
    ("PA-820", 1.5*G, 840*M, 1.4*G, 128*K, 8.1*K, [P(4, "rj45", 1000), P(8, "sfp", 1000)], "10/100/1000 (4), Gigabit SFP (8)"),
    ("PA-850", 1.9*G, 1.0*G, 1.8*G, 192*K, 13.1*K, [P(4, "rj45", 1000), P(4, "sfp", 1000), P(4, "sfp+", 10000)], "10/100/1000 (4), Gigabit SFP (8) or Gigabit SFP (4) + 10G SFP+ (4)")]:
    legacy(m, "PA-800", "2024-08-31", "2029-08-31", "PA-1400 Series", "11.1", fw_bps=fw, tp_bps=tp, ipsec_bps=ip, max_sessions=sess, cps=cps,
           vsys_base=1, vsys_max=1, ports=ports, ports_text=pt, dedicated_ha=["ha1-a", "ha1-b"], sources=["eol", "ds800", "vsys"])
for m, fw, tp, ip, sess, cps, ports, pt in [
    ("PA-3220", 4*G, 2.2*G, 2.4*G, 1*M, 46*K, [P(12, "rj45", 1000), P(4, "sfp", 1000), P(4, "sfp+", 10000)], "10/100/1000 (12), 1G SFP (4), 1G/10G SFP/SFP+ (4)"),
    ("PA-3250", 5*G, 2.5*G, 2.6*G, 2*M, 58*K, [P(12, "rj45", 1000), P(8, "sfp+", 10000)], "10/100/1000 (12), 1G/10G SFP/SFP+ (8)"),
    ("PA-3260", 7.5*G, 4*G, 4.4*G, 2.2*M, 84*K, [P(12, "rj45", 1000), P(8, "sfp+", 10000), P(4, "qsfp+", 40000)], "10/100/1000 (12), 1G/10G SFP/SFP+ (8), 40G QSFP+ (4)")]:
    legacy(m, "PA-3200", "2023-08-31", "2028-08-31", "PA-3400 Series", "11.1", fw_bps=fw, tp_bps=tp, ipsec_bps=ip, max_sessions=sess, cps=cps,
           vsys_base=1, vsys_max=6, ports=ports, ports_text=pt, dedicated_ha=["ha1-a", "ha1-b", "hsci"], sources=["eol", "ds3200"])
for m, fw, tp, ip, sess, cps, vs, ports, pt in [
    ("PA-5220", 15*G, 8.8*G, 9.5*G, 4*M, 150*K, (10, 20), [P(4, "rj45", 10000), P(16, "sfp+", 10000), P(4, "qsfp+", 40000)], "100/1000/10G Cu (4), 1G/10G SFP/SFP+ (16), 40G QSFP+ (4)"),
    ("PA-5250", 35*G, 19*G, 18.4*G, 8*M, 368*K, (25, 125), [P(4, "rj45", 10000), P(16, "sfp+", 10000), P(4, "qsfp28", 100000)], "100/1000/10G Cu (4), 1G/10G SFP/SFP+ (16), 40G/100G QSFP28 (4)"),
    ("PA-5260", 55*G, 31*G, 25*G, 32*M, 500*K, (25, 225), [P(4, "rj45", 10000), P(16, "sfp+", 10000), P(4, "qsfp28", 100000)], "100/1000/10G Cu (4), 1G/10G SFP/SFP+ (16), 40G/100G QSFP28 (4)"),
    ("PA-5280", 55*G, 31*G, 25*G, 64*M, 500*K, (25, 225), [P(4, "rj45", 10000), P(16, "sfp+", 10000), P(4, "qsfp28", 100000)], "100/1000/10G Cu (4), 1G/10G SFP/SFP+ (16), 40G/100G QSFP28 (4)")]:
    legacy(m, "PA-5200", "2023-08-31", "2028-08-31", "PA-5400 Series, PA-5500 Series", "11.2", fw_bps=fw, tp_bps=tp, ipsec_bps=ip, max_sessions=sess, cps=cps,
           vsys_base=vs[0], vsys_max=vs[1], ports=ports, ports_text=pt, dedicated_ha=["ha1-a", "ha1-b", "hsci"], sources=["eol", "ds5200"])
for m in ("PA-7050", "PA-7080"):
    legacy(m, "PA-7000", "2025-12-31", "2030-12-31", "PA-7500, PA-5500", "11.2", chassis=True, dedicated_ha=["ha1-a", "ha1-b", "hsci"],
           note="Performance depends on the installed cards; see the PA-7000 datasheet.", sources=["eol", "ds7000"])
for m in ("PA-3020", "PA-3050", "PA-3060"):
    legacy(m, "PA-3000", "2019-10-31", "2024-10-31", "PA-3400 Series", "9.1")
for m in ("PA-5020", "PA-5050", "PA-5060"):
    legacy(m, "PA-5000", "2019-01-31", "2024-01-31", "PA-5400 Series, PA-5500 Series", "8.1")
legacy("PA-200", "PA-200", "2018-10-31", "2023-10-31", "PA-400 Series, PA-500 Series", "8.1")
legacy("PA-500", "PA-500 (2010)", "2018-10-31", "2023-10-31", "PA-400 Series, PA-500 Series", "8.1",
       note="This is the original PA-500 appliance, not the current PA-500 Series (PA-501 to PA-560).")
for m in ("PA-2020", "PA-2050"):
    legacy(m, "PA-2000", "2015-04-30", "2020-04-30", "PA-1400 Series", "7.1")
for m in ("PA-4020", "PA-4050", "PA-4060"):
    legacy(m, "PA-4000", "2014-04-30", "2019-04-30", "PA-1400 Series", "7.1")

# ---- VM-Series ----
VM = [
  {"model": "VM-50", "vcpu": [2], "mem_gb": 5.5, "max_sessions": 50000, "fw_bps": 200*M, "rules": 250, "zones": 15, "ipsec_tunnels": 250, "ssl_tunnels": 250, "vsys_max": 1},
  {"model": "VM-100", "vcpu": [2], "mem_gb": 6.5, "max_sessions": 250000, "fw_bps": 2*G, "rules": 1500, "zones": 40, "ipsec_tunnels": 1000, "ssl_tunnels": 500, "vsys_max": 1},
  {"model": "VM-300", "vcpu": [2, 4], "mem_gb": 9, "max_sessions": 400000, "fw_bps": 4*G, "rules": 10000, "zones": 40, "ipsec_tunnels": 2000, "ssl_tunnels": 2000, "vsys_max": 1},
  {"model": "VM-500", "vcpu": [2, 4, 8], "mem_gb": 16, "max_sessions": 2000000, "fw_bps": 8*G, "rules": 10000, "zones": 200, "ipsec_tunnels": 4000, "ssl_tunnels": 6000, "vsys_max": 1},
  {"model": "VM-700", "vcpu": [2, 4, 8, 16], "mem_gb": 56, "max_sessions": 10000000, "fw_bps": 16*G, "rules": 20000, "zones": 200, "ipsec_tunnels": 8000, "ssl_tunnels": 12000, "vsys_max": 1},
]
for v in VM:
    v.update({"form": "vm", "family": "VM-Series", "tp_bps": None, "cps": None, "vsys_base": 1,
              "dedicated_ha": [], "sources": ["vm_models", "vm_req", "vm_ds", "vm_vsys"], "min_panos": "10.1"})
    v["note"] = ("Sessions and object limits are from the VM-Series Models table. App-ID throughput is the older fixed-model datasheet figure; "
                 "real throughput depends on the host CPU, NICs and hypervisor. Threat Prevention throughput is not published per model.")
VM[-1]["vsys_note"] = "Multi-vsys on VM-Series needs a flexible (credit) license, PAN-OS 11.1.3+, Tier 3 or 4, and at least 16 vCPUs. Tier 3 = up to 25 vsys, Tier 4 = up to 100."

VM_MEM_TIERS_11_2 = [  # memory GB -> max sessions, default dataplane vCPUs (Software NGFW credits, PAN-OS 11.2+)
  [4.5, 20000, 1], [5, 40000, 1], [5.5, 50000, 1], [6, 100000, 1], [6.5, 200000, 2], [7, 250000, 2], [8, 300000, 2],
  [9, 400000, 4], [10, 500000, 4], [12, 800000, 4], [14, 1100000, 4], [16, 1100000, 12], [18, 1200000, 12], [20, 1800000, 12],
  [24, 2500000, 12], [28, 2800000, 12], [32, 3500000, 12], [36, 4500000, 12], [40, 5500000, 12], [44, 6750000, 12],
  [48, 7000000, 12], [52, 8150000, 12], [56, 8500000, 24], [64, 8250000, 47], [128, 10000000, 47]]


# ---- Power supplies (PSU) and dedicated HA port types -------------------------------------
# psu: base = included with the unit, max = most it can hold. Where the sources disagree the
# note says so. cli_status=False means the firewall CLI (and so a tech-support file) does not
# report PSU status for this model. None = not in the sources we read; the tool shows "not published".
def psu(base, mx, kind, feed, src, watts=None, cord=None, note=None, cli_status=True, text=None):
    return {"base": base, "max": mx, "kind": kind, "feed": feed, "watts": watts, "cord": cord,
            "note": note, "cli_status": cli_status, "text": text, "sources": src}
ADAPT = "External power adapter (AC in, DC out) with its own AC cord"
C13 = "AC inlet C14 (cord with C13 connector)"
PSU = {}
for m in ("PA-410",):
    PSU[m] = psu(1, 1, "adapter", "AC adapter", ["hw400", "ds400"], 25, ADAPT, "Single power adapter only; no redundant option.", cli_status=False)
for m in ("PA-415", "PA-415-5G", "PA-445", "PA-455", "PA-455-5G"):
    PSU[m] = psu(1, 2, "adapter", "AC adapter", ["hw400", "ds400"], None, ADAPT, "Ships with one adapter; a second adapter (PWR 2) is bought separately for redundancy.", cli_status=False)
for m in ("PA-440", "PA-450", "PA-460"):
    PSU[m] = psu(1, 2, "adapter", "AC adapter", ["hw400", "ds400"], 50, ADAPT, "Ships with one 50 W adapter; a second adapter (PWR 2) is bought separately for redundancy. The CLI does not report adapter status.", cli_status=False)
for m in ("PA-501", "PA-505"):
    PSU[m] = psu(1, 1, "adapter", "AC adapter", ["hw500", "ds500"], None, ADAPT, "Single power adapter only.", cli_status=False)
for m in ("PA-510", "PA-520", "PA-520-5G", "PA-540", "PA-545-POE", "PA-550", "PA-555-POE", "PA-560"):
    PSU[m] = psu(1, 2, "adapter", "AC adapter", ["hw500", "ds500"], None, ADAPT, "One adapter ships with the firewall; a second adapter is an optional accessory for redundancy.", cli_status=False)
for m in ("PA-1410", "PA-1420"):
    PSU[m] = psu(1, 2, "module", "AC or DC", ["ds1400", "hw1400"], 450, C13,
                 "Series datasheet: one 450 W AC supply, second is optional and bought separately. The summary spec sheet words it as '2; one is redundant', so confirm the quote includes the second supply if you want redundancy.")
for m in ("PA-1510", "PA-1520", "PA-1530"):
    PSU[m] = psu(2, 2, "module", "AC or DC", ["summary"], 1200, None, "Summary spec sheet: 1+1 redundant, 1200 W, 54 V AC/DC.", text="1+1 redundant 1200W 54V AC/DC")
for m in ("PA-3410", "PA-3420", "PA-3430", "PA-3440"):
    PSU[m] = psu(2, 2, "module", "AC or DC", ["hw3400", "ds3400"], 450, C13, "Two load-sharing supplies ship with the firewall; connect them to separate circuits. AC and DC supplies cannot be mixed.")
for m in ("PA-3510", "PA-3520", "PA-3530", "PA-3540"):
    PSU[m] = psu(2, 2, "module", "AC or DC", ["summary"], None, None, "Summary spec sheet: 1+1 redundant for 110-220 V and DC.", text="1+1 redundant for 110-220 V and DC")
for m in ("PA-3220", "PA-3250", "PA-3260"):
    PSU[m] = psu(2, 2, "module", "AC or DC", ["ds3200", "hw3200"], 650, C13, "Two hot-swappable supplies; AC supplies ship by default, DC supplies are ordered separately.")
for m in ("PA-5220", "PA-5250", "PA-5260", "PA-5280"):
    PSU[m] = psu(2, 2, "module", "AC or DC", ["ds5200", "hw5200"], 1100, C13, "Two hot-swappable supplies (1:1 fully redundant).")
for m in ("PA-5410", "PA-5420", "PA-5430", "PA-5440", "PA-5445"):
    PSU[m] = psu(2, 2, "module", "AC or DC", ["hw5400", "ds5400"], 1200, C13, "Two hot-swappable load-sharing supplies; if one fails the second carries the load.")
PSU["PA-5450"] = psu(2, 4, "module", "AC or DC", ["hw5400", "ds5400"], 2200, "AC inlet takes cords with C19 connectors",
                     "Needs at least 2 supplies. Full redundancy means double the minimum for your cards and input voltage (see the PA-5400 power supply chart); 120 V AC with 3 or more DPCs cannot be fully redundant.")
for m in ("PA-5510", "PA-5520", "PA-5530", "PA-5540", "PA-5550", "PA-5560", "PA-5570", "PA-5580"):
    PSU[m] = psu(None, None, "module", "AC or DC", ["summary"], None, None, "Summary spec sheet: 2+2 redundant for 220 V and DC, 3+1 redundant for 110 V. Confirm the supply count on the quote.", text="2+2 redundant for 220 V and DC; 3+1 redundant for 110 V")
PSU["PA-7500"] = psu(None, 10, "module", "AC or DC", ["summary"], None, None, "Summary spec sheet: M+N, up to 10 supplies. Size to the card configuration.", text="M+N (up to 10 PSUs)")
PSU["PA-7050"] = psu(4, 4, "module", "AC or DC", ["ds7000", "hw7000"], 2500, None, "Four 2500 W supplies.")
PSU["PA-7080"] = psu(4, 8, "module", "AC or DC", ["ds7000", "hw7000"], 2500, None, "Four 2500 W supplies as shipped, expandable to eight.")
PSU["PA-820"] = psu(1, 1, "fixed", "AC", ["ds800", "hw800"], 200, None, "Fixed (non-removable) 200 W AC supply; no redundant option.")
PSU["PA-850"] = psu(2, 2, "module", "AC", ["ds800", "hw800"], 450, None, "Two 450 W AC supplies; one is redundant.")
PSU["PA-220R"] = psu(None, 2, "fixed", "DC", ["ds220r"], None, None, "Optional dual redundant DC power feeds (12-48 VDC).", text="Optional: dual redundant DC power feeds")

def ha(label, n, media, mbps, role, ident=None):
    return {"id": ident or label.lower(), "label": label, "n": n, "media": media, "mbps": mbps, "role": role}
HAP = {}
for m in ("PA-820", "PA-850"):
    HAP[m] = ([ha("HA1", 1, "rj45", 1000, "control", "ha1"), ha("HA2", 1, "rj45", 1000, "data", "ha2")], ["ds800", "haports"])
for m in ("PA-1410", "PA-1420"):
    HAP[m] = ([ha("HSCI", 1, "sfp+", 10000, "data (HA2/HA3)", "hsci")], ["ds1400", "haports"])
for m in ("PA-3220", "PA-3250", "PA-3260"):
    HAP[m] = ([ha("HA1-A/B", 2, "rj45", 1000, "control", "ha1"), ha("HSCI", 1, "sfp+", 10000, "data (HA2/HA3)", "hsci")], ["ds3200", "haports"])
for m in ("PA-3410", "PA-3420", "PA-3430", "PA-3440"):
    HAP[m] = ([ha("HA1-A/B", 2, "rj45", 1000, "control", "ha1"), ha("HSCI", 1, "sfp+", 10000, "data (HA2/HA3)", "hsci")], ["ds3400", "haports"])
HAP["PA-5220"] = ([ha("HA1-A/B", 2, "rj45", 1000, "control", "ha1"), ha("HSCI", 1, "qsfp+", 40000, "data (HA2/HA3)", "hsci")], ["ds5200", "haports"])
for m in ("PA-5250", "PA-5260", "PA-5280"):
    HAP[m] = ([ha("HA1-A/B", 2, "rj45", 1000, "control", "ha1"), ha("HSCI", 1, "qsfp28", 100000, "data (HA2/HA3)", "hsci")], ["ds5200", "haports"])
for m in ("PA-5410", "PA-5420", "PA-5430", "PA-5440", "PA-5445"):
    HAP[m] = ([ha("HA1-A/B", 2, "sfp+", 10000, "control", "ha1"), ha("HSCI", 1, "qsfp+", 40000, "data (HA2/HA3)", "hsci")], ["ds5400", "haports"])
for d in HW:
    if d["model"] in PSU:
        d["psu"] = PSU[d["model"]]
    if d["model"] in HAP:
        d["ha_ports"], hs = HAP[d["model"]]
        d["sources"] = list(dict.fromkeys(d["sources"] + hs))
    elif d.get("dedicated_ha"):
        d["ha_ports"] = None  # dedicated ports exist but their type is not in the sources we read
    if d.get("psu"):
        d["sources"] = list(dict.fromkeys(d["sources"] + d["psu"]["sources"]))
HAS_NOTE = ("HA ports: models with no dedicated HA port (PA-400, PA-500 and others) use a data port for HA links. "
            "HA1 is the control link, HA2 the data link; HSCI carries HA2/HA3 on models that have it.")


# ---- Capacity limits and rack/power facts ----------------------------------------------------
# Keys: rules, nat, decrypt, zones, addr (address objects), addrgrp, svc, ike (IKE peers), s2s (site-to-site tunnels),
# gp (GlobalProtect client tunnels), mroutes (multicast routes), fib4 (IPv4 forwarding table). A missing key means "not in the sources we read".
LIM = {"PA-460": {"rules": 2500, "nat": 3000, "decrypt": 500, "zones": 100, "addr": 15000, "addrgrp": 500, "svc": 2000, "ike": 2800, "s2s": 2800, "gp": 1500, "mroutes": 1500, "fib4": 10000}, "PA-450": {"rules": 2500, "nat": 3000, "decrypt": 500, "zones": 75, "addr": 15000, "addrgrp": 500, "svc": 2000, "ike": 2800, "s2s": 2800, "gp": 1500, "mroutes": 1500, "fib4": 7500}, "PA-440": {"rules": 2000, "nat": 3000, "decrypt": 300, "zones": 50, "addr": 10000, "addrgrp": 250, "svc": 1500, "ike": 2800, "s2s": 2800, "gp": 1000, "mroutes": 1000, "fib4": 5000}, "PA-445": {"rules": 2000, "nat": 3000, "decrypt": 300, "zones": 50, "addr": 10000, "addrgrp": 250, "svc": 1500, "ike": 2800, "s2s": 2800, "gp": 1000, "mroutes": 1000, "fib4": 5000}, "PA-415": {"rules": 500, "nat": 400, "decrypt": 100, "zones": 25, "addr": 2500, "addrgrp": 125, "svc": 1000, "ike": 1000, "s2s": 1000, "gp": 250, "mroutes": 500, "fib4": 5000}, "PA-410": {"rules": 500, "nat": 400, "decrypt": 100, "zones": 25, "addr": 2500, "addrgrp": 125, "svc": 1000, "ike": 1000, "s2s": 1000, "gp": 250, "mroutes": 500, "fib4": 5000}, "PA-850": {"rules": 1500, "nat": 3000, "decrypt": 150, "zones": 40, "addr": 3500, "addrgrp": 350, "svc": 1000, "ike": 1000, "s2s": 2000, "gp": 1000, "mroutes": 1500, "fib4": 10000}, "PA-820": {"rules": 1500, "nat": 3000, "decrypt": 100, "zones": 30, "addr": 2500, "addrgrp": 250, "svc": 1000, "ike": 1000, "s2s": 2000, "gp": 1000, "mroutes": 1500, "fib4": 10000}, "PA-1420": {"rules": 1500, "nat": 3000, "decrypt": 750, "zones": 50, "addr": 20000, "addrgrp": 2000, "svc": 3000, "ike": 2800, "s2s": 2800, "gp": 1500, "mroutes": 2000, "fib4": 10000}, "PA-1410": {"rules": 1500, "nat": 3000, "decrypt": 750, "zones": 50, "addr": 20000, "addrgrp": 2000, "svc": 3000, "ike": 2800, "s2s": 2800, "gp": 1500, "mroutes": 2000, "fib4": 10000}, "PA-3410": {"rules": 10000, "nat": 3000, "decrypt": 750, "zones": 200, "addr": 30000, "addrgrp": 15000, "svc": 3000, "ike": 3000, "s2s": 5000, "gp": 1800, "mroutes": 2000, "fib4": 10000}, "PA-3420": {"rules": 10000, "nat": 3000, "decrypt": 750, "zones": 200, "addr": 30000, "addrgrp": 15000, "svc": 3000, "ike": 3000, "s2s": 5000, "gp": 1800, "mroutes": 2000, "fib4": 16000}, "PA-3430": {"rules": 10000, "nat": 3000, "decrypt": 1500, "zones": 200, "addr": 30000, "addrgrp": 15000, "svc": 4000, "ike": 4000, "s2s": 8000, "gp": 2000, "mroutes": 4000, "fib4": 24000}, "PA-3440": {"rules": 10000, "nat": 3000, "decrypt": 1500, "zones": 200, "addr": 30000, "addrgrp": 15000, "svc": 4000, "ike": 4000, "s2s": 8000, "gp": 2000, "mroutes": 4000, "fib4": 24000}, "PA-5410": {"rules": 30000, "nat": 6000, "decrypt": 3500, "zones": 4000, "addr": 80000, "addrgrp": 40000, "svc": 8000, "ike": 4000, "s2s": 10000, "gp": 15000, "mroutes": 4000, "fib4": 100000}, "PA-5420": {"rules": 45000, "nat": 6000, "decrypt": 5000, "zones": 6000, "addr": 120000, "addrgrp": 60000, "svc": 10000, "ike": 5000, "s2s": 12000, "gp": 22000, "mroutes": 4000, "fib4": 100000}, "PA-5430": {"rules": 65000, "nat": 6000, "decrypt": 5000, "zones": 17000, "addr": 160000, "addrgrp": 80000, "svc": 12000, "ike": 5000, "s2s": 12000, "gp": 30000, "mroutes": 4000, "fib4": 100000}, "PA-5440": {"rules": 65000, "nat": 6000, "decrypt": 5000, "zones": 17000, "addr": 160000, "addrgrp": 80000, "svc": 12000, "ike": 8000, "s2s": 24000, "gp": 60000, "mroutes": 4000, "fib4": 100000}}
LIM_MIRROR_MODELS = set(LIM)
# GlobalProtect client tunnels, Palo Alto KB (all platforms in the article)
KB_GP = {"PA-7080": 40000, "PA-7050": 40000, "PA-5280": 60000, "PA-5260": 60000, "PA-5250": 30000, "PA-5220": 15000, "PA-5450": 60000, "PA-5060": 20000, "PA-5050": 10000, "PA-5020": 5000,
         "PA-3260": 2048, "PA-3250": 2048, "PA-3220": 1024, "PA-3060": 2048, "PA-3050": 2048, "PA-3020": 1024, "PA-500": 100, "PA-220R": 250, "PA-220": 250}
# Security rule counts, Palo Alto KB (older platforms not in the datasheet tables above)
KB_RULES = {"PA-220": 500, "PA-500": 1000, "PA-3020": 2500, "PA-3050": 5000, "PA-3060": 5000, "PA-5020": 10000, "PA-5050": 20000, "PA-5060": 40000, "PA-5220": 20000, "PA-5250": 40000, "PA-5260": 40000, "PA-7050": 40000, "PA-7080": 40000, "PA-2020": 2500, "PA-2050": 5000}
for d in HW:
    m = d["model"]; L = {}; srcs = []
    if m in LIM:
        L.update(LIM[m]); srcs.append("lim_mirror")
    if m in KB_RULES and "rules" not in L:
        L["rules"] = KB_RULES[m]; srcs.append("kb_rules")
    if m in KB_GP:
        L["gp"] = KB_GP[m]; srcs.append("kb_gp")
    if L:
        d["limits"] = L
        d["limits_src"] = list(dict.fromkeys(srcs + ["pc_tool"]))
        d["sources"] = list(dict.fromkeys(d["sources"] + d["limits_src"]))

# Rack / power facts from the series datasheets (RU, size in inches H x D x W, weight standalone/shipped in lb, airflow, max watts, BTU/hr).
def rack(ru, dims, lbs=None, airflow=None, maxw=None, btu=None, mount=None, src=None, note=None):
    return {"ru": ru, "dims": dims, "lbs": lbs, "airflow": airflow, "max_w": maxw, "btu_hr": btu, "mount": mount, "sources": src or [], "note": note}
RACK = {
 "PA-410": rack(None, '1.63" H x 6.42" D x 9.53" W', "3.1 / 5.9", "Fanless (no airflow)", 23, 78, "Desktop unit", ["ds400"]),
 "PA-415": rack(None, '1.73" H x 9" D x 13" W', "7.85 / 12.2", "Fanless (no airflow)", 142, 117, "Desktop unit", ["ds400"]),
 "PA-415-5G": rack(None, '1.73" H x 9" D x 13" W', "7.85", None, None, 150, "Desktop unit", ["ds400"]),
 "PA-440": rack(None, '1.74" H x 8.83" D x 8.07" W', "5.0 / 7.8", "Fanless (no airflow)", 34.3, 117, "Desktop unit", ["ds400"]),
 "PA-445": rack(None, '1.66" H x 8.87" D x 13" W', "8.7 / 12.6", "Fanless (no airflow)", 146, 117, "Desktop unit", ["ds400"]),
 "PA-450": rack(None, '1.74" H x 8.83" D x 8.07" W', "5.0 / 7.8", "Fanless (no airflow)", 41.3, 141, "Desktop unit", ["ds400"]),
 "PA-455": rack(None, '1.7" H x 9.4" D x 15.4" W', "9.8 / 14.1", None, 143.4, 205, "Desktop unit", ["ds400"]),
 "PA-455-5G": rack(1, "283 mm D x 303 mm W (1RU height)", None, None, 212, 655, None, ["ds400"]),
 "PA-460": rack(None, '1.74" H x 8.83" D x 8.07" W', "5.0 / 7.8", "Fanless (no airflow)", 41.3, 141, "Desktop unit", ["ds400"]),
 "PA-820": rack(1, '1.75" H x 14" D x 17.125" W', "11 / 18", "Front to back", None, 256, "19-inch rack", ["ds800"]),
 "PA-850": rack(1, '1.75" H x 14.5" D x 17.125" W', "13.5 / 21.5", "Front to back", None, None, "19-inch rack", ["ds800"]),
 "PA-1410": rack(1, '1.70" H x 14.15" D x 17.15" W', "15.5", "Front to back", 290, None, "19-inch rack", ["ds1400"]),
 "PA-1420": rack(1, '1.70" H x 14.15" D x 17.15" W', "15.5", "Front to back", 300, None, "19-inch rack", ["ds1400"]),
 "PA-3220": rack(2, '3.5" H x 20.53" D x 17.34" W', "29 / 41.5", "Front to back", 240, 819, "19-inch rack", ["ds3200"]),
 "PA-3250": rack(2, '3.5" H x 20.53" D x 17.34" W', "29 / 41.5", "Front to back", 240, 819, "19-inch rack", ["ds3200"]),
 "PA-3260": rack(2, '3.5" H x 20.53" D x 17.34" W', "29 / 41.5", "Front to back", 240, 819, "19-inch rack", ["ds3200"]),
 "PA-3410": rack(1, '1.70" H x 14.15" D x 17.15" W', "15.5 / 25", "Front to back", 190, None, "19-inch rack", ["lim_mirror"]),
 "PA-3420": rack(1, '1.70" H x 14.15" D x 17.15" W', "15.5 / 25", "Front to back", 190, None, "19-inch rack", ["lim_mirror"]),
 "PA-3430": rack(1, '1.70" H x 14.15" D x 17.15" W', "15.5 / 25", "Front to back", 190, None, "19-inch rack", ["lim_mirror"]),
 "PA-3440": rack(1, '1.70" H x 14.15" D x 17.15" W', "15.5 / 25", "Front to back", 190, None, "19-inch rack", ["lim_mirror"]),
 "PA-5220": rack(3, None, "46 / 62", None, 870, 2340, "19-inch rack", ["ds5200"]),
 "PA-5250": rack(3, None, "46 / 62", None, 870, 2340, "19-inch rack", ["ds5200"]),
 "PA-5260": rack(3, None, "46 / 62", None, 870, 2340, "19-inch rack", ["ds5200"]),
 "PA-5280": rack(3, None, "46 / 62", None, 870, 2340, "19-inch rack", ["ds5200"]),
 "PA-5410": rack(2, '3.45" H x 22.5" D x 17.34" W', "35.2 / 48.8", "Front to back", 760, 1638, "19-inch rack", ["ds5400"]),
 "PA-5420": rack(2, '3.45" H x 22.5" D x 17.34" W', "35.2 / 48.8", "Front to back", 760, 1638, "19-inch rack", ["ds5400"]),
 "PA-5430": rack(2, '3.45" H x 22.5" D x 17.34" W', "35.2 / 48.8", "Front to back", 760, 1638, "19-inch rack", ["ds5400"]),
 "PA-5440": rack(2, '3.45" H x 22.5" D x 17.34" W', "35.2 / 48.8", "Front to back", 760, 1638, "19-inch rack", ["ds5400"]),
 "PA-5445": rack(2, '3.45" H x 22.5" D x 17.34" W', "35.2 / 48.8", "Front to back", 760, 1638, "19-inch rack", ["ds5400"], "Series figures; PA-5445 per-model values may differ."),
 "PA-5450": rack(5, '8.75" H x 30.25" D x 17.38" W', None, None, None, None, "19-inch rack", ["summary"]),
 "PA-7050": rack(9, '15.75" H x 24" D x 19" W', "187.4 AC / 185 DC", None, None, 10236, "19-inch rack", ["ds7000"]),
 "PA-7080": rack(19, '32.22" H x 24.6" D x 19" W', "299.3 AC / 298.3 DC", None, None, 20132, "19-inch rack", ["ds7000"]),
}
for d in HW:
    r = RACK.get(d["model"])
    if r:
        d["rack"] = r
        d["sources"] = list(dict.fromkeys(d["sources"] + r["sources"]))
RACK_NOTE = ("Rack facts (RU, size, weight, airflow, watts, BTU) are series figures from datasheets. Rail kits and mounting hardware are not in the sources: confirm on the quote. "
             "Power inlet type and wattage are in each model's psu block.")
LIM_NOTE = ("Capacity limits (limits): from the Palo Alto datasheet capacity tables as copied on a reseller site (an older revision: some session counts differ from the current datasheet), "
            "plus Palo Alto KB articles for GlobalProtect tunnels and older rule counts. A missing key means not published in the sources we read; check the Product Comparison tool.")

for d in HW + VM:
    for k in ("fw_bps", "tp_bps", "ipsec_bps", "cps", "max_sessions"):
        if d.get(k) is not None:
            d[k] = int(round(d[k]))
for d in HW:
    d.setdefault("min_panos", None)
    d.setdefault("eos_date", None)
    d.setdefault("eol_date", None)
    d.setdefault("replacement", None)
    d.setdefault("last_panos", None)
    if d.get("eos_date") is None:
        d.setdefault("status", "current")
    d.setdefault("status", None)
    d.setdefault("ports_verified", False)

out = {
  "schema": 1,
  "data_as_of": DATA_AS_OF,
  "notes": [
    "Throughput is the vendor 'appmix' figure (App-ID + logging). Threat Prevention throughput adds IPS, AV, anti-spyware, WildFire, file blocking and logging.",
    "Interface lists come from datasheets. Port numbering (which ethernet1/N is which media) is assumed in datasheet order unless ports_verified is true. Check the hardware reference guide and edit the target port list in the tool if needed.",
    "Status and end-of-sale dates are recomputed in the tool from eos_date against today's date.",
    "Power supply counts (psu) and dedicated HA port types (ha_ports) come from hardware references and datasheets; where sources disagree the model's psu.note says so. A null means not in the sources we read.",
    HAS_NOTE,
    LIM_NOTE,
    RACK_NOTE,
    "No prices. Quote quantities only."],
  "sources": SOURCES,
  "hardware": HW,
  "vm": VM,
  "vm_memory_tiers": {"panos": "11.2+", "columns": ["mem_gb", "max_sessions", "default_dp_vcpu"], "rows": VM_MEM_TIERS_11_2, "source": "vm_mem"},
}
dest = Path(__file__).resolve().parent.parent / "catalog" / "models.json"
dest.write_text(json.dumps(out, indent=1) + "\n")
print("wrote", dest, len(HW), "hardware models,", len(VM), "VM models")
