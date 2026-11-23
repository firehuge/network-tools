#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build synthetic Palo Alto tech-support (.tgz) bundles for the triage tool.

These are realistic-looking stand-ins, not captures from a live device.
File layout and CLI wording follow common PAN-OS 10.x/11.x tech-support
conventions, but real bundles vary by platform and release.

Usage:
  python3 generate_synthetic_tsf.py            # write into ./samples
  python3 generate_synthetic_tsf.py /path/out
"""
from __future__ import annotations

import io
import os
import sys
import tarfile
from pathlib import Path

STAMP = "20261110_120000"


def hdr(command: str) -> str:
    bar = "=" * 80
    return f"\n{bar}\n== {command}\n{bar}\n\n"


def log_line(ts: str, sev: str, proc: str, loc: str, msg: str) -> str:
    # Common mp-log form: 2026/11/10 12:00:00  12345  Error:  name(file.c:10): msg
    return f"{ts}  12345  {sev}:  {proc}({loc}): {msg}\n"


# ---------------------------------------------------------------------------
# Firewall — issues
# ---------------------------------------------------------------------------
def fw_issues_cli() -> str:
    parts = []
    parts.append("Palo Alto Networks tech support (SYNTHETIC TEST DATA — not a live device)\n")
    parts.append("Generated for the MMIT PAN TSF triage viewer test suite.\n")

    parts.append(hdr("show system info"))
    parts.append("""hostname: fw-example
ip-address: 192.0.2.10
public-ip-address: unknown
netmask: 255.255.255.0
default-gateway: 192.0.2.1
mac-address: 00:1b:17:00:44:01
time: Mon Nov 10 12:00:00 2026
uptime: 15 days, 3:22:11
family: 400
model: PA-440
serial: 012345678901
sw-version: 11.1.4
global-protect-client-package-version: 6.2.4
app-version: 8920-8901
app-release-date: 2026/09/15 16:00:00 PDT
av-version: 4890-5401
av-release-date: 2026/09/15 16:00:00 PDT
threat-version: 8920-8901
threat-release-date: 2026/09/15 16:00:00 PDT
wf-private-version: 0
wildfire-version: 902201
wildfire-release-date: 2026/09/20 08:00:00 PDT
url-filtering-version: 20240901.20111
url-filtering-release-date: 2024/09/01 00:00:00 PDT
logdb-version: 20240101.1
platform-family: 400
vpn-disable-mode: off
multi-vsys: off
operational-mode: normal
device-certificate-status: Valid
system-mode: normal
""")

    parts.append(hdr("show high-availability all"))
    parts.append("""Group 1:
    Mode: Active-Passive
    Local Information:
        Version: 1
        State: active
        Device Information:
            Management IPv4: 192.0.2.10
            Management IPv6: unknown
            HA1 IP: 10.255.1.1
        State Synchronization: complete
        Platform:
            Version: 11.1.4
            Model: PA-440
        Preemptive: yes
        Promotion Hold Time: 2000 ms
        Hello Interval: 8000 ms
        Heartbeat Interval: 2000 ms
        Preemption Hold Time: 1 min
        Monitor Fail Hold Up Time: 0 min
        Additional Master Hold Up Time: 500 ms
        Heartbeat Backup: disabled
        Links:
            HA1:      Up
            HA1-Backup: Up
            HA2:      Up
            HA2-Backup: Down
    Peer Information:
        Version: 1
        State: active
        Device Information:
            Management IPv4: 192.0.2.11
            HA1 IP: 10.255.1.2
        Connection Status:
            HA1:      Up
            HA1-Backup: Up
            HA2:      Up
        State Synchronization: complete
        Platform:
            Version: 11.1.4
            Model: PA-440
        Priority: 100
        Preemptive: yes
    Configuration Synchronization:
        Running Config: not synchronized
        Last Config Sync Time: 2026/11/01 04:12:08
    Election Option:
        Preemptive: yes
    Link Monitoring:
        Enabled: yes
        Failure Condition: any
        Groups:
            Group name: ha-link-untrust
            Enabled: yes
            Failure Condition: any
            Interfaces: ethernet1/1 (down)
            Status: fail
    Path Monitoring:
        Enabled: yes
        Failure Condition: any
        Destination: 8.8.8.8
        Status: fail
        Ping interval: 200 ms
        Ping count: 10
""")

    parts.append(hdr("show system resources"))
    parts.append("""top - 12:00:00 up 15 days,  3:22,  0 users,  load average: 4.82, 4.51, 4.10
Tasks: 198 total,   3 running, 195 sleeping,   0 stopped,   0 zombie
%Cpu(s): 82.0 us,  6.5 sy,  0.0 ni, 10.2 id,  0.8 wa,  0.0 hi,  0.5 si,  0.0 st
KiB Mem :  8165344 total,   198112 free,  7504112 used,   463120 buff/cache
KiB Swap:  2097148 total,  1048572 free,  1048576 used.   412000 avail Mem

  PID USER      PR  NI    VIRT    RES    SHR S  %CPU %MEM     TIME+ COMMAND
 2341 root      20   0  2.1g    1.1g   12m  S  42.0 14.1   999:12.01 devsrvr
 2348 root      20   0  1.4g    800m   8m   S  18.2 10.0   700:01.11 mgmtsrvr
 2401 root      20   0  900m    400m   6m   S  12.0  5.0   400:00.00 logrcvr
""")

    parts.append(hdr("show running resource-monitor"))
    parts.append("""Resource monitoring sampling data (per minute):

DP 0
CPU load sampling is done per minute
CPU    0    1    2    3    avg    max
  1   88   91   90   94     91     97
  5   85   88   87   90     87     95
 15   82   84   83   86     84     94
 60   80   81   80   84     81     97

MP
CPU load sampling is done per minute
CPU    avg    max
  1     86     95
  5     83     94
 15     79     95
 60     74     95

Resource utilization (%) during last 60 minutes:
Memory
  1min  92
  5min  91
 15min  90
 60min  88

Session
  1min  94
  5min  93
 15min  91
 60min  88

Packet Buffer
  1min  96
  5min  94
 15min  90
 60min  85

Packet Descriptor
  1min  91
  5min  89
 15min  86
 60min  80
""")

    parts.append(hdr("show session info"))
    parts.append("""target-dp:                                       *.dp0
Number of sessions supported:                     200000
Number of allocated sessions:                     188400
Number of active PRE-OPEN sessions:               12
Number of active UDP sessions:                    90000
Number of active TCP sessions:                    96000
Number of active ICMP sessions:                   1200
Number of active GTPc sessions:                   0
Session table utilization:                        94%
Number of sessions created since boot:            184422100
Packet rate:                                      85420/s
Throughput:                                       1850 mbps
New connection establish rate:                    6420/s
Session timeout
  TCP default timeout:                            3600
  TCP session timeout before SYN-ACK        :     5
  TCP session timeout after SYN-ACK         :     30
  TCP session timeout after half-close      :     120
  UDP default timeout:                            30
  ICMP timeout:                                   6
""")

    parts.append(hdr("show counter global"))
    parts.append("""Name                                   Value        Rate Severity   Category   Aspect     Description
----------------------------------------------------------------------------------------------------
pkt_recv                          1844221881      85420 info       packet     pktproc    Packets received
pkt_sent                          1801001122      83100 info       packet     pktproc    Packets transmitted
session_allocated                  184422100       6420 info       session    resource   Sessions allocated
session_freed                      184233700       6400 info       session    resource   Sessions freed
session_alloc_failure                  18421          8 drop       session    resource   Session allocation failed
pkt_alloc_failure                      22104         12 drop       packet     resource   Packet buffer allocation failed
flow_np_pktbuf_nomem                   19880         11 drop       packet     resource   No packet buffer from NP
flow_fpga_pkt_drop                      4201          2 drop       packet     drop       FPGA packet drop
flow_policy_deny                      120411         40 drop       flow       policy     Policy denied
flow_fwd_l3_ttl_zero                     812          0 drop       flow       drop       L3 TTL is zero
flow_tcp_non_syn_drop                  15420          3 drop       flow       drop       Non-SYN TCP drop
flow_host_pkt_drop                      2104          1 drop       flow       drop       Packets dropped toward host
appid_unknown_tcp                     882104        140 info       appid      pktproc    Unknown-TCP applications
appid_unknown_udp                     441022         70 info       appid      pktproc    Unknown-UDP applications
proxy_decrypt_error                    12880          6 error      proxy      decrypt    SSL decryption error
proxy_cert_expired                      1044          1 error      proxy      decrypt    Certificate expired
proxy_untrusted_cert                     880          1 error      proxy      decrypt    Untrusted certificate
""")

    parts.append(hdr("debug dataplane pool statistics"))
    parts.append("""Hardware Pools
Packet Buffers
  size                             128
  allocated                      31457
  available                       1311
  total                          32768
  utilization                      96%

Packet Descriptors
  size                             64
  allocated                      14909
  available                       1475
  total                          16384
  utilization                      91%

Software Pools
Work Queue 0
  allocated                        200
  available                       1848
  total                           2048
""")

    parts.append(hdr("show jobs all"))
    parts.append("""Enqueued            ID    Type           Status Result Completed
----------------------------------------------------------------
2026/11/10 08:14:22  401  Commit         FIN    FAIL   2026/11/10 08:14:51
2026/11/09 21:02:10  398  Commit         FIN    OK     2026/11/09 21:02:28
2026/11/08 16:40:00  390  Content        FIN    FAIL   2026/11/08 16:40:44
2026/11/07 09:00:01  381  Commit         FIN    OK     2026/11/07 09:00:19
""")

    parts.append(hdr("show jobs id 401"))
    parts.append("""Enqueued: 2026/11/10 08:14:22
ID: 401
Type: Commit
Status: FIN
Result: FAIL
Warnings:
Details: Validation Error:  rule 'allow-any-any' application dependency not met
Commit failed
""")

    parts.append(hdr("show routing summary"))
    parts.append("""Virtual router: default
  IPv4 routes in RIB: 142
  IPv4 routes in FIB: 138
  IPv6 routes in RIB: 4
  IPv6 routes in FIB: 4
  BGP router ID: 192.0.2.10
  BGP AS: 65010
  BGP peers: 2 (1 established)
""")

    parts.append(hdr("show routing protocol bgp summary"))
    parts.append("""Virtual router: default
BGP router ID: 192.0.2.10  local AS: 65010
Peer            AS      Flaps   Duration      State
10.20.20.2      65020      18   00:12:08      Connect
10.20.20.3      65030       0   14d 22h       Established
""")

    parts.append(hdr("show interface all"))
    parts.append("""total configured hardware interfaces: 8

name                id    speed/duplex/state           hw address
--------------------------------------------------------------------------
ethernet1/1         16    1000/full/up                 00:1b:17:00:44:01
ethernet1/2         17    1000/full/up                 00:1b:17:00:44:02
ethernet1/3         18    ukn/ukn/down(autoneg)        00:1b:17:00:44:03
ha1                 5     1000/full/up                 00:1b:17:00:44:f1
vlan                1     [n/a]
loopback            3     [n/a]
tunnel              4     [n/a]

physical interface counters:
  ethernet1/1
    packets input:  184422188
    packets output: 180100112
    errors:         15230
    drops:          8841
    discards:       2104
    collisions:     0
  ethernet1/2
    packets input:  99001122
    packets output: 101002331
    errors:         0
    drops:          0
    discards:       0
    collisions:     0
""")

    parts.append(hdr("show system disk-space"))
    parts.append("""Filesystem            Size  Used Avail Use% Mounted on
/dev/md2               12G  5.1G  6.2G  46% /
/dev/md5               16G  7.2G  8.1G  48% /opt/pancfg
/dev/md6               12G  3.0G  8.4G  27% /opt/panrepo
/dev/md8               32G   31G  420M  96% /opt/panlogs
tmpfs                 2.0G  44M  2.0G   3% /dev/shm
""")

    parts.append(hdr("request license info"))
    parts.append("""License entry:
Feature: Threat Prevention
Description: Palo Alto Networks Threat Prevention License
Expires: November 20, 2026
Expired: No

License entry:
Feature: WildFire License
Description: Palo Alto Networks WildFire License
Expires: November 10, 2028
Expired: No

License entry:
Feature: PAN-DB URL Filtering
Description: Palo Alto Networks URL Filtering License
Expires: October 01, 2026
Expired: Yes

License entry:
Feature: GlobalProtect Gateway
Description: GlobalProtect Gateway License
Expires: November 10, 2028
Expired: No
""")

    parts.append(hdr("show ntp"))
    parts.append("""NTP state:
    NTP configured: yes
    NTP synchronized: no
    NTP server: 10.0.0.123  status: unreachable
""")

    parts.append(hdr("show panorama-status"))
    parts.append("""Panorama Server 1: 10.50.1.20
    Connected: no
    HA state: unknown
    Last error: TCP connection timed out
Panorama Server 2: none
""")

    parts.append(hdr("show log-collector preference-list"))
    parts.append("""No log collector configured, forwarding to Panorama (disconnected).
""")

    parts.append(hdr("show rule-hit-count vsys vsys1 rule-base security rules all"))
    parts.append("""Rule                         Hits      Last Hit
------------------------------------------------
allow-dns                    1844221   2026/11/10 11:59:01
allow-web                    991200    2026/11/10 11:59:40
decrypt-any                  540110    2026/11/10 11:59:40
allow-any-any                0         never
old-temp-access              0         never
deny-threat                  120411    2026/11/10 11:58:22
""")

    return "".join(parts)


def fw_clean_cli() -> str:
    parts = []
    parts.append("Palo Alto Networks tech support (SYNTHETIC TEST DATA — not a live device)\n")

    parts.append(hdr("show system info"))
    parts.append("""hostname: fw-example-clean
ip-address: 192.0.2.20
public-ip-address: unknown
netmask: 255.255.255.0
default-gateway: 192.0.2.1
mac-address: 00:1b:17:00:44:20
time: Mon Nov 10 12:00:00 2026
uptime: 42 days, 1:04:00
family: 400
model: PA-440
serial: 012345678902
sw-version: 11.1.6
app-version: 8990-9100
app-release-date: 2026/11/08 16:00:00 PDT
av-version: 4920-5510
av-release-date: 2026/11/08 16:00:00 PDT
threat-version: 8990-9100
threat-release-date: 2026/11/08 16:00:00 PDT
wildfire-version: 911108
wildfire-release-date: 2026/11/08 08:00:00 PDT
url-filtering-version: 20261108.40111
url-filtering-release-date: 2026/11/08 00:00:00 PDT
platform-family: 400
operational-mode: normal
system-mode: normal
device-certificate-status: Valid
""")

    parts.append(hdr("show high-availability all"))
    parts.append("""Group 1:
    Mode: Active-Passive
    Local Information:
        State: active
        State Synchronization: complete
        Preemptive: no
        Links:
            HA1:      Up
            HA2:      Up
    Peer Information:
        State: passive
        Connection Status:
            HA1:      Up
            HA2:      Up
    Configuration Synchronization:
        Running Config: synchronized
        Last Config Sync Time: 2026/11/10 07:00:00
    Link Monitoring:
        Enabled: yes
        Status: up
        Groups:
            Group name: ha-link-untrust
            Interfaces: ethernet1/1 (up)
            Status: up
    Path Monitoring:
        Enabled: yes
        Destination: 8.8.8.8
        Status: up
""")

    parts.append(hdr("show system resources"))
    parts.append("""top - 12:00:00 up 42 days,  1:04,  0 users,  load average: 0.42, 0.38, 0.35
Tasks: 180 total,   1 running, 179 sleeping,   0 stopped,   0 zombie
%Cpu(s):  8.0 us,  2.0 sy,  0.0 ni, 89.5 id,  0.3 wa,  0.0 hi,  0.2 si,  0.0 st
KiB Mem :  8165344 total,  3200112 free,  2800224 used,  2165008 buff/cache
KiB Swap:  2097148 total,  2097148 free,        0 used.  4800000 avail Mem
""")

    parts.append(hdr("show running resource-monitor"))
    parts.append("""Resource monitoring sampling data (per minute):

DP 0
CPU load sampling is done per minute
CPU    0    1    2    3    avg    max
  1   12   14   11   15     13     22
  5   11   13   10   14     12     20
 15   10   12    9   13     11     24
 60    9   11    8   12     10     28

MP
CPU load sampling is done per minute
CPU    avg    max
  1     11     18
  5     10     17
 15      9     20
 60      8     22

Resource utilization (%) during last 60 minutes:
Memory
  1min  34
  5min  34
 15min  33
 60min  33

Session
  1min  22
  5min  21
 15min  20
 60min  19

Packet Buffer
  1min   8
  5min   7
 15min   7
 60min   6

Packet Descriptor
  1min   5
  5min   5
 15min   4
 60min   4
""")

    parts.append(hdr("show session info"))
    parts.append("""Number of sessions supported:                     200000
Number of allocated sessions:                     44000
Session table utilization:                        22%
Packet rate:                                      8200/s
New connection establish rate:                    410/s
Session timeout
  TCP default timeout:                            360
  UDP default timeout:                            30
""")

    parts.append(hdr("show counter global"))
    parts.append("""Name                                   Value        Rate Severity   Category   Aspect     Description
----------------------------------------------------------------------------------------------------
pkt_recv                           884221881       8200 info       packet     pktproc    Packets received
session_allocated                   18422100        410 info       session    resource   Sessions allocated
session_alloc_failure                    0          0 drop       session    resource   Session allocation failed
pkt_alloc_failure                        0          0 drop       packet     resource   Packet buffer allocation failed
flow_np_pktbuf_nomem                     0          0 drop       packet     resource   No packet buffer from NP
flow_policy_deny                      2104          1 drop       flow       policy     Policy denied
appid_unknown_tcp                      104          0 info       appid      pktproc    Unknown-TCP applications
appid_unknown_udp                       40          0 info       appid      pktproc    Unknown-UDP applications
proxy_decrypt_error                      0          0 error      proxy      decrypt    SSL decryption error
""")

    parts.append(hdr("debug dataplane pool statistics"))
    parts.append("""Hardware Pools
Packet Buffers
  allocated                       2621
  available                      30147
  total                          32768
  utilization                       8%

Packet Descriptors
  allocated                        819
  available                      15565
  total                          16384
  utilization                       5%
""")

    parts.append(hdr("show jobs all"))
    parts.append("""Enqueued            ID    Type           Status Result Completed
----------------------------------------------------------------
2026/11/10 07:00:00  220  Commit         FIN    OK     2026/11/10 07:00:12
2026/11/08 02:00:00  210  Content        FIN    OK     2026/11/08 02:00:40
""")

    parts.append(hdr("show routing summary"))
    parts.append("""Virtual router: default
  IPv4 routes in RIB: 24
  IPv4 routes in FIB: 24
  BGP peers: 1 (1 established)
""")

    parts.append(hdr("show routing protocol bgp summary"))
    parts.append("""Virtual router: default
Peer            AS      Flaps   Duration      State
10.20.20.3      65030       0   41d 4h        Established
""")

    parts.append(hdr("show interface all"))
    parts.append("""total configured hardware interfaces: 4

name                id    speed/duplex/state           hw address
--------------------------------------------------------------------------
ethernet1/1         16    1000/full/up                 00:1b:17:00:44:20
ethernet1/2         17    1000/full/up                 00:1b:17:00:44:21

physical interface counters:
  ethernet1/1
    errors:         0
    drops:          0
    discards:       0
  ethernet1/2
    errors:         0
    drops:          0
    discards:       0
""")

    parts.append(hdr("show system disk-space"))
    parts.append("""Filesystem            Size  Used Avail Use% Mounted on
/dev/md2               12G  3.1G  8.2G  28% /
/dev/md5               16G  4.0G 11.0G  27% /opt/pancfg
/dev/md8               32G  12G   19G   39% /opt/panlogs
""")

    parts.append(hdr("request license info"))
    parts.append("""License entry:
Feature: Threat Prevention
Expires: November 10, 2028
Expired: No

License entry:
Feature: PAN-DB URL Filtering
Expires: November 10, 2028
Expired: No

License entry:
Feature: WildFire License
Expires: November 10, 2028
Expired: No
""")

    parts.append(hdr("show ntp"))
    parts.append("""NTP state:
    NTP configured: yes
    NTP synchronized: yes
    NTP server: 10.0.0.123  status: reachable
""")

    parts.append(hdr("show panorama-status"))
    parts.append("""Panorama Server 1: 10.50.1.20
    Connected: yes
    HA state: primary-active
""")

    parts.append(hdr("show rule-hit-count vsys vsys1 rule-base security rules all"))
    parts.append("""Rule                         Hits      Last Hit
------------------------------------------------
allow-dns                    1004221   2026/11/10 11:59:01
allow-web                     512200   2026/11/10 11:59:40
deny-threat                    12011   2026/11/10 11:58:22
""")

    return "".join(parts)


def pano_issues_cli() -> str:
    parts = []
    parts.append("Palo Alto Networks tech support (SYNTHETIC TEST DATA — not a live device)\n")
    parts.append("Panorama management server bundle.\n")

    parts.append(hdr("show system info"))
    parts.append("""hostname: ex-panorama
ip-address: 10.50.1.20
netmask: 255.255.255.0
default-gateway: 10.50.1.1
mac-address: 00:1b:17:00:20:01
time: Mon Nov 10 12:00:00 2026
uptime: 120 days, 2:00:00
family: m
model: Panorama
serial: 0007PANO0001
sw-version: 11.1.4
app-version: 8920-8901
app-release-date: 2026/09/15 16:00:00 PDT
av-version: 4890-5401
av-release-date: 2026/09/15 16:00:00 PDT
threat-version: 8920-8901
threat-release-date: 2026/09/15 16:00:00 PDT
platform-family: m
operational-mode: normal
system-mode: panorama
device-certificate-status: Valid
""")

    parts.append(hdr("show system resources"))
    parts.append("""top - 12:00:00 up 120 days,  2:00,  0 users,  load average: 6.20, 5.80, 5.10
Tasks: 260 total,   4 running, 256 sleeping,   0 stopped,   0 zombie
%Cpu(s): 78.0 us,  8.0 sy,  0.0 ni, 13.0 id,  0.5 wa,  0.0 hi,  0.5 si,  0.0 st
KiB Mem : 32768000 total,  800000 free, 30100000 used,  1868000 buff/cache
KiB Swap:  4194304 total,  1000000 free,  3194304 used.  1200000 avail Mem
""")

    parts.append(hdr("show running resource-monitor"))
    parts.append("""Resource monitoring sampling data (per minute):

MP
CPU load sampling is done per minute
CPU    avg    max
  1     81     93
  5     79     92
 15     76     93
 60     72     93

Resource utilization (%) during last 60 minutes:
Memory
  1min  91
  5min  90
 15min  89
 60min  88
""")

    parts.append(hdr("show system disk-space"))
    parts.append("""Filesystem            Size  Used Avail Use% Mounted on
/dev/sda2              32G   20G   11G  65% /
/dev/sda5              64G   40G   22G  65% /opt/pancfg
/dev/sda8             500G  470G  5.0G  94% /opt/panlogs
""")

    parts.append(hdr("show jobs all"))
    parts.append("""Enqueued            ID    Type           Status Result Completed
----------------------------------------------------------------
2026/11/10 09:30:00  902  CommitAll      FIN    FAIL   2026/11/10 09:32:14
2026/11/10 09:00:00  900  Commit         FIN    OK     2026/11/10 09:00:22
2026/11/09 18:00:00  880  CommitAll      FIN    FAIL   2026/11/09 18:04:01
2026/11/08 12:00:00  860  CommitAll      FIN    OK     2026/11/08 12:03:10
""")

    parts.append(hdr("show jobs id 902"))
    parts.append("""Enqueued: 2026/11/10 09:30:00
ID: 902
Type: CommitAll
Status: FIN
Result: FAIL
Details: fw-example (serial 012345678901): commit failed — Validation Error
         ex-pa5220 (serial 012345678955): device not connected
""")

    parts.append(hdr("show devices all"))
    parts.append("""Serial          Hostname      IP              Connected  Version  Model    Last Seen
-------------------------------------------------------------------------------------------
012345678901    fw-example     192.0.2.10   no         11.1.4   PA-440   2026/11/10 08:10:00
012345678955    ex-pa5220    10.30.1.10      no         11.1.2   PA-5220  2026/11/09 22:00:00
012345678977    ex-pa1410    10.30.2.10      yes        11.1.4   PA-1410  2026/11/10 12:00:00
""")

    parts.append(hdr("show devices connected"))
    parts.append("""Serial          Hostname      IP              Connected  Version
----------------------------------------------------------------
012345678977    ex-pa1410    10.30.2.10      yes        11.1.4
""")

    parts.append(hdr("show log-collector all"))
    parts.append("""Serial          Hostname        IP            Connected  Status        Disk Used
--------------------------------------------------------------------------------
0007LC000001    lc-primary      10.50.1.30    no         disconnected  88%
0007LC000002    lc-secondary    10.50.1.31    yes        active        42%
""")

    parts.append(hdr("show log-collector connected"))
    parts.append("""Serial          Hostname        IP            Connected
-------------------------------------------------------
0007LC000002    lc-secondary    10.50.1.31    yes
""")

    parts.append(hdr("request license info"))
    parts.append("""License entry:
Feature: Panorama
Expires: November 10, 2028
Expired: No

License entry:
Feature: Logging Service
Expires: October 15, 2026
Expired: Yes
""")

    parts.append(hdr("show system software status"))
    parts.append("""Process      Status     Restarts
mgmtsrvr     running    0
devsrvr      running    4
logrcvr      running    3
configd      running    1
""")

    return "".join(parts)


def fw_issues_config() -> str:
    return """<?xml version="1.0"?>
<config version="11.1.0" urldb="paloaltonetworks">
  <mgt-config>
    <users>
      <entry name="admin"/>
      <entry name="jsmith"/>
    </users>
  </mgt-config>
  <shared>
    <certificate>
      <entry name="ex-decrypt-cert">
        <algorithm>RSA</algorithm>
        <not-valid-before>Nov 01 00:00:00 2024 GMT</not-valid-before>
        <not-valid-after>Nov 01 00:00:00 2026 GMT</not-valid-after>
      </entry>
    </certificate>
  </shared>
  <devices>
    <entry name="localhost.localdomain">
      <network>
        <interface>
          <ethernet>
            <entry name="ethernet1/1">
              <layer3>
                <ip><entry name="203.0.113.10/24"/></ip>
              </layer3>
            </entry>
            <entry name="ethernet1/2">
              <layer3>
                <ip><entry name="10.10.10.1/24"/></ip>
              </layer3>
            </entry>
          </ethernet>
          <tunnel>
            <units>
              <entry name="tunnel.1"/>
            </units>
          </tunnel>
        </interface>
        <virtual-router>
          <entry name="default">
            <interface>
              <member>ethernet1/1</member>
              <member>ethernet1/2</member>
            </interface>
          </entry>
        </virtual-router>
      </network>
      <deviceconfig>
        <system>
          <hostname>fw-example</hostname>
          <timezone>America/Chicago</timezone>
          <jumbo-frame><enable>yes</enable></jumbo-frame>
          <mtu>9192</mtu>
          <ntp-servers>
            <primary-ntp-server>
              <ntp-server-address>10.0.0.123</ntp-server-address>
            </primary-ntp-server>
          </ntp-servers>
          <panorama>
            <server>10.50.1.20</server>
          </panorama>
        </system>
        <setting>
          <session>
            <timeout-default>3600</timeout-default>
            <timeout-tcp>3600</timeout-tcp>
            <timeout-udp>30</timeout-udp>
          </session>
        </setting>
      </deviceconfig>
      <vsys>
        <entry name="vsys1">
          <zone>
            <entry name="untrust">
              <network><layer3><member>ethernet1/1</member></layer3></network>
            </entry>
            <entry name="trust">
              <network><layer3><member>ethernet1/2</member></layer3></network>
              <zone-protection-profile>zpp-trust</zone-protection-profile>
            </entry>
          </zone>
          <rulebase>
            <security>
              <rules>
                <entry name="allow-dns">
                  <from><member>trust</member></from>
                  <to><member>untrust</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <application><member>dns</member></application>
                  <service><member>application-default</member></service>
                  <action>allow</action>
                  <log-start>yes</log-start>
                  <log-end>yes</log-end>
                </entry>
                <entry name="allow-web">
                  <from><member>trust</member></from>
                  <to><member>untrust</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <application><member>web-browsing</member></application>
                  <application><member>ssl</member></application>
                  <service><member>application-default</member></service>
                  <action>allow</action>
                  <log-start>yes</log-start>
                  <log-end>yes</log-end>
                </entry>
                <entry name="allow-any-any">
                  <from><member>any</member></from>
                  <to><member>any</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <application><member>any</member></application>
                  <service><member>any</member></service>
                  <action>allow</action>
                  <log-end>yes</log-end>
                </entry>
                <entry name="old-temp-access">
                  <from><member>trust</member></from>
                  <to><member>untrust</member></to>
                  <source><member>10.10.10.50</member></source>
                  <destination><member>any</member></destination>
                  <application><member>unknown-tcp</member></application>
                  <application><member>unknown-udp</member></application>
                  <service><member>any</member></service>
                  <action>allow</action>
                </entry>
                <entry name="deny-threat">
                  <from><member>any</member></from>
                  <to><member>any</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <application><member>any</member></application>
                  <service><member>any</member></service>
                  <action>deny</action>
                </entry>
              </rules>
            </security>
            <nat>
              <rules>
                <entry name="outbound-nat">
                  <from><member>trust</member></from>
                  <to><member>untrust</member></to>
                  <source><member>10.10.10.0/24</member></source>
                  <destination><member>any</member></destination>
                  <source-translation>
                    <dynamic-ip-and-port>
                      <interface-address>
                        <interface>ethernet1/1</interface>
                      </interface-address>
                    </dynamic-ip-and-port>
                  </source-translation>
                </entry>
              </rules>
            </nat>
            <decryption>
              <rules>
                <entry name="decrypt-any">
                  <from><member>any</member></from>
                  <to><member>any</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <service><member>any</member></service>
                  <action>decrypt</action>
                  <type>ssl-forward-proxy</type>
                </entry>
              </rules>
            </decryption>
          </rulebase>
          <profiles>
            <virus>
              <entry name="default-av"/>
            </virus>
            <spyware>
              <entry name="default-as"/>
            </spyware>
            <vulnerability>
              <entry name="default-vp"/>
            </vulnerability>
          </profiles>
        </entry>
      </vsys>
    </entry>
  </devices>
</config>
"""


def fw_clean_config() -> str:
    return """<?xml version="1.0"?>
<config version="11.1.0">
  <mgt-config>
    <users>
      <entry name="admin"/>
    </users>
  </mgt-config>
  <devices>
    <entry name="localhost.localdomain">
      <network>
        <interface>
          <ethernet>
            <entry name="ethernet1/1"><layer3><ip><entry name="203.0.113.20/24"/></ip></layer3></entry>
            <entry name="ethernet1/2"><layer3><ip><entry name="10.10.20.1/24"/></ip></layer3></entry>
          </ethernet>
        </interface>
      </network>
      <deviceconfig>
        <system>
          <hostname>fw-example-clean</hostname>
          <jumbo-frame><enable>no</enable></jumbo-frame>
          <mtu>1500</mtu>
          <panorama><server>10.50.1.20</server></panorama>
        </system>
        <setting>
          <session>
            <timeout-default>360</timeout-default>
            <timeout-tcp>360</timeout-tcp>
            <timeout-udp>30</timeout-udp>
          </session>
        </setting>
      </deviceconfig>
      <vsys>
        <entry name="vsys1">
          <zone>
            <entry name="untrust">
              <network><layer3><member>ethernet1/1</member></layer3></network>
              <zone-protection-profile>zpp-untrust</zone-protection-profile>
            </entry>
            <entry name="trust">
              <network><layer3><member>ethernet1/2</member></layer3></network>
              <zone-protection-profile>zpp-trust</zone-protection-profile>
            </entry>
          </zone>
          <rulebase>
            <security>
              <rules>
                <entry name="allow-dns">
                  <from><member>trust</member></from>
                  <to><member>untrust</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <application><member>dns</member></application>
                  <service><member>application-default</member></service>
                  <action>allow</action>
                  <log-end>yes</log-end>
                </entry>
                <entry name="allow-web">
                  <from><member>trust</member></from>
                  <to><member>untrust</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <application><member>web-browsing</member></application>
                  <service><member>application-default</member></service>
                  <action>allow</action>
                  <log-end>yes</log-end>
                </entry>
                <entry name="deny-threat">
                  <from><member>any</member></from>
                  <to><member>any</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <application><member>any</member></application>
                  <service><member>any</member></service>
                  <action>deny</action>
                </entry>
              </rules>
            </security>
            <nat>
              <rules>
                <entry name="outbound-nat">
                  <from><member>trust</member></from>
                  <to><member>untrust</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                </entry>
              </rules>
            </nat>
            <decryption>
              <rules>
                <entry name="decrypt-fin">
                  <from><member>trust</member></from>
                  <to><member>untrust</member></to>
                  <source><member>10.10.20.0/24</member></source>
                  <destination><member>any</member></destination>
                  <category><member>financial-services</member></category>
                  <action>decrypt</action>
                </entry>
              </rules>
            </decryption>
          </rulebase>
        </entry>
      </vsys>
    </entry>
  </devices>
</config>
"""


def pano_config() -> str:
    return """<?xml version="1.0"?>
<config version="11.1.0">
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig>
        <system>
          <hostname>ex-panorama</hostname>
        </system>
      </deviceconfig>
    </entry>
  </devices>
  <device-group>
    <entry name="ex-dg">
      <devices>
        <entry name="012345678901"/>
        <entry name="012345678955"/>
        <entry name="012345678977"/>
      </devices>
    </entry>
  </device-group>
</config>
"""


def issues_logs() -> dict[str, str]:
    t = "2026/11/10"
    t2 = "2026/11/09"
    logs = {}
    logs["var/log/pan/mp-log/ms.log"] = (
        log_line(f"{t} 08:14:51", "Error", "ms_commit", "commit.c:410", "Commit job 401 failed: Validation Error")
        + log_line(f"{t} 09:01:00", "Error", "masterd", "proc.c:88", "Process devsrvr exited unexpectedly (status 139), restarting")
        + log_line(f"{t} 09:01:02", "Info", "masterd", "proc.c:120", "Process devsrvr started (restart count 3)")
        + log_line(f"{t} 09:40:00", "Error", "masterd", "proc.c:88", "Process logrcvr exited (core dumped), restarting")
        + log_line(f"{t} 09:40:01", "Info", "masterd", "proc.c:120", "Process logrcvr started (restart count 2)")
        + log_line(f"{t} 10:00:00", "Info", "ms", "sys.c:10", "management server heartbeat ok")
    )
    logs["var/log/pan/mp-log/devsrvr.log"] = (
        log_line(f"{t} 09:01:00", "Error", "devsrvr", "main.c:50", "SIGSEGV received, writing core")
        + log_line(f"{t} 09:01:03", "Info", "devsrvr", "main.c:20", "devsrvr starting")
        + log_line(f"{t} 11:00:00", "Info", "devsrvr", "dev.c:33", "device server ready")
    )
    logs["var/log/pan/mp-log/configd.log"] = (
        log_line(f"{t} 08:14:50", "Error", "configd", "commit.c:900", "Commit failed: rule 'allow-any-any' application dependency not met")
        + log_line(f"{t} 08:14:51", "Error", "configd", "commit.c:910", "aborting commit job 401")
    )
    logs["var/log/pan/mp-log/useridd.log"] = (
        log_line(f"{t} 07:15:00", "Error", "useridd", "agent.c:200", "User-ID agent 10.10.10.50 (ex-adc) disconnected: TCP connection reset")
        + log_line(f"{t} 07:15:10", "Warning", "useridd", "agent.c:240", "attempting reconnect to User-ID agent 10.10.10.50")
        + log_line(f"{t} 07:20:00", "Error", "useridd", "monitor.c:88", "AD server-monitor DC01 (10.10.10.11) disconnected: LDAP bind failed")
        + log_line(f"{t} 10:00:00", "Info", "useridd", "agent.c:10", "useridd running")
    )
    logs["var/log/pan/mp-log/routed.log"] = (
        log_line(f"{t} 06:00:01", "Error", "routed", "bgp.c:410", "BGP neighbor 10.20.20.2 went down (hold timer expired)")
        + log_line(f"{t} 06:00:30", "Warning", "routed", "bgp.c:455", "BGP neighbor 10.20.20.2 state Idle -> Connect (flap 17)")
        + log_line(f"{t} 06:12:00", "Error", "routed", "bgp.c:410", "BGP neighbor 10.20.20.2 went down (connect failed)")
        + log_line(f"{t} 06:12:08", "Warning", "routed", "bgp.c:455", "BGP neighbor 10.20.20.2 state Idle -> Connect (flap 18)")
        + log_line(f"{t} 11:00:00", "Info", "routed", "bgp.c:10", "BGP neighbor 10.20.20.3 Established")
    )
    logs["var/log/pan/mp-log/authd.log"] = (
        log_line(f"{t} 08:00:01", "Error", "authd", "auth.c:77", "Authentication failed for user jsmith from 10.10.10.88 (Invalid password)")
        + log_line(f"{t} 08:00:08", "Error", "authd", "auth.c:77", "Authentication failed for user jsmith from 10.10.10.88 (Invalid password)")
        + log_line(f"{t} 08:00:15", "Error", "authd", "auth.c:77", "Authentication failed for user jsmith from 10.10.10.88 (Invalid password)")
        + log_line(f"{t} 08:00:20", "Error", "authd", "auth.c:90", "Account lockout threshold reached for user jsmith")
        + log_line(f"{t} 08:10:00", "Error", "authd", "auth.c:77", "Authentication failed for user backup-admin from 203.0.113.50 (user not found)")
        + log_line(f"{t} 09:00:00", "Info", "authd", "auth.c:10", "Authentication succeeded for user admin from 192.0.2.2")
    )
    logs["var/log/pan/mp-log/sslmgr.log"] = (
        log_line(f"{t} 10:14:00", "Error", "sslmgr", "cert.c:55", "Certificate expired: ex-decrypt-cert not-valid-after Nov 01 00:00:00 2026 GMT")
        + log_line(f"{t} 10:14:01", "Error", "sslmgr", "proxy.c:300", "SSL decryption error for session 10.10.10.88 -> 203.0.113.80: certificate expired")
        + log_line(f"{t} 10:20:00", "Warning", "sslmgr", "proxy.c:310", "SSL decryption error: untrusted issuer for 203.0.113.81")
    )
    logs["var/log/pan/mp-log/ha_agent.log"] = (
        log_line(f"{t2} 23:10:00", "Error", "ha_agent", "path.c:40", "HA path-monitor destination 8.8.8.8 failed (10 consecutive missed pings)")
        + log_line(f"{t2} 23:10:01", "Error", "ha_agent", "link.c:22", "HA link-monitor group ha-link-untrust failed: ethernet1/1 down")
        + log_line(f"{t} 00:01:00", "Warning", "ha_agent", "state.c:90", "preempt: local priority 80 taking active from peer")
        + log_line(f"{t} 00:15:00", "Warning", "ha_agent", "state.c:90", "preempt flap: peer became active then local preempted again")
        + log_line(f"{t} 00:15:01", "Error", "ha_agent", "state.c:120", "possible split-brain: local state active, peer state active")
        + log_line(f"{t} 01:00:00", "Warning", "ha_agent", "cfg.c:18", "Running configuration is out of sync with peer")
    )
    logs["var/log/pan/mp-log/logrcvr.log"] = (
        log_line(f"{t} 08:10:00", "Error", "logrcvr", "fwd.c:60", "Failed to forward logs to Panorama 10.50.1.20: TCP connection timed out")
        + log_line(f"{t} 08:10:05", "Error", "logrcvr", "fwd.c:77", "log forwarding disconnected from Panorama, buffer 82% used")
        + log_line(f"{t} 09:40:00", "Error", "logrcvr", "main.c:10", "logrcvr core dumped")
    )
    logs["var/log/pan/mp-log/varrcvr.log"] = (
        log_line(f"{t} 08:10:02", "Error", "varrcvr", "pan.c:40", "Panorama connectivity issue: cannot send logging updates to 10.50.1.20")
    )
    logs["var/log/pan/mp-log/mprelay.log"] = (
        log_line(f"{t} 09:01:01", "Warning", "mprelay", "dp.c:12", "dataplane connection reset during devsrvr restart")
    )
    logs["var/log/pan/mp-log/appweb3-sslvpn.log"] = (
        log_line(f"{t} 11:00:00", "Info", "appweb", "http.c:1", "appweb started")
    )
    logs["var/log/pan/mp-log/gpsvc.log"] = (
        log_line(f"{t} 11:00:00", "Info", "gpsvc", "gp.c:1", "GlobalProtect service running, 12 current users")
    )
    logs["var/log/pan/dp-log/pan_packet_diag.log"] = (
        f"{t} 10:00:00  pkt alloc failure, pool packet-buffer exhausted (utilization 96%)\n"
        f"{t} 10:00:01  flow_np_pktbuf_nomem incrementing, packets dropped\n"
    )
    logs["var/log/pan/mp-log/authd.log.old"] = log_line(
        f"{t2} 18:00:00", "Info", "authd", "auth.c:10", "older rotated log, no issues"
    )
    return logs


def clean_logs() -> dict[str, str]:
    t = "2026/11/10"
    logs = {}
    logs["var/log/pan/mp-log/ms.log"] = log_line(f"{t} 07:00:12", "Info", "ms_commit", "commit.c:400", "Commit job 220 finished successfully")
    logs["var/log/pan/mp-log/devsrvr.log"] = log_line(f"{t} 07:00:00", "Info", "devsrvr", "dev.c:33", "device server ready")
    logs["var/log/pan/mp-log/configd.log"] = log_line(f"{t} 07:00:12", "Info", "configd", "commit.c:800", "commit job 220 succeeded")
    logs["var/log/pan/mp-log/useridd.log"] = log_line(f"{t} 07:00:00", "Info", "useridd", "agent.c:10", "User-ID agent 10.10.20.50 connected")
    logs["var/log/pan/mp-log/routed.log"] = log_line(f"{t} 07:00:00", "Info", "routed", "bgp.c:10", "BGP neighbor 10.20.20.3 Established")
    logs["var/log/pan/mp-log/authd.log"] = log_line(f"{t} 09:00:00", "Info", "authd", "auth.c:10", "Authentication succeeded for user admin from 192.0.2.2")
    logs["var/log/pan/mp-log/sslmgr.log"] = log_line(f"{t} 07:00:00", "Info", "sslmgr", "cert.c:10", "certificate ex-web-cert valid")
    logs["var/log/pan/mp-log/ha_agent.log"] = log_line(f"{t} 07:00:00", "Info", "ha_agent", "state.c:10", "local state active, peer state passive, config synchronized")
    logs["var/log/pan/mp-log/logrcvr.log"] = log_line(f"{t} 07:00:00", "Info", "logrcvr", "fwd.c:10", "forwarding logs to Panorama 10.50.1.20: connected")
    logs["var/log/pan/dp-log/pan_packet_diag.log"] = f"{t} 07:00:00  dataplane idle, no packet diag events\n"
    return logs


def pano_logs() -> dict[str, str]:
    t = "2026/11/10"
    logs = {}
    logs["var/log/pan/mp-log/ms.log"] = (
        log_line(f"{t} 09:32:14", "Error", "ms_commit", "commitall.c:50", "CommitAll job 902 failed for 2 devices")
        + log_line(f"{t} 10:00:00", "Error", "masterd", "proc.c:88", "Process devsrvr exited unexpectedly, restarting (restart count 4)")
        + log_line(f"{t} 10:10:00", "Error", "masterd", "proc.c:88", "Process logrcvr exited unexpectedly, restarting (restart count 3)")
    )
    logs["var/log/pan/mp-log/configd.log"] = (
        log_line(f"{t} 09:32:10", "Error", "configd", "push.c:22", "commit-all failed: fw-example Validation Error")
        + log_line(f"{t} 09:32:12", "Error", "configd", "push.c:22", "commit-all failed: ex-pa5220 device not connected")
    )
    logs["var/log/pan/mp-log/devsrvr.log"] = (
        log_line(f"{t} 08:10:00", "Error", "devsrvr", "dev.c:80", "device 012345678901 (fw-example) disconnected")
        + log_line(f"{t2 if False else '2026/11/09'} 22:00:00", "Error", "devsrvr", "dev.c:80", "device 012345678955 (ex-pa5220) disconnected")
        + log_line(f"{t} 10:00:00", "Error", "devsrvr", "main.c:50", "devsrvr restarted after unexpected exit")
    )
    logs["var/log/pan/mp-log/logrcvr.log"] = (
        log_line(f"{t} 08:00:00", "Error", "logrcvr", "lc.c:30", "log collector 0007LC000001 (lc-primary) disconnected")
        + log_line(f"{t} 10:10:00", "Error", "logrcvr", "main.c:10", "logrcvr restarted")
    )
    logs["var/log/pan/mp-log/authd.log"] = log_line(
        f"{t} 11:00:00", "Info", "authd", "auth.c:10", "Authentication succeeded for user admin from 10.50.1.2"
    )
    return logs


def add_text(tar: tarfile.TarFile, name: str, text: str, mtime: int = 1762790400) -> None:
    data = text.encode("utf-8")
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    info.mtime = mtime
    info.mode = 0o644
    tar.addfile(info, io.BytesIO(data))


def add_bytes(tar: tarfile.TarFile, name: str, data: bytes, mtime: int = 1762790400) -> None:
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    info.mtime = mtime
    info.mode = 0o644
    tar.addfile(info, io.BytesIO(data))


def write_tgz(path: Path, files: dict[str, str | bytes]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, "w:gz") as tar:
        for name, content in files.items():
            if isinstance(content, bytes):
                add_bytes(tar, name, content)
            else:
                add_text(tar, name, content)
    print(f"wrote {path} ({path.stat().st_size:,} bytes, {len(files)} members)")


def bundle_fw_issues(root: str) -> dict[str, str | bytes]:
    files: dict[str, str | bytes] = {}
    cli = fw_issues_cli()
    files[f"{root}/tmp/cli/techsupport_{root}.txt"] = cli
    files[f"{root}/opt/pancfg/mgmt/saved-configs/running-config.xml"] = fw_issues_config()
    for rel, text in issues_logs().items():
        files[f"{root}/{rel}"] = text
    # Placeholder "core" (ELF-like magic + note). Real cores are large binaries.
    files[f"{root}/var/cores/masterd/devsrvr_14100.core"] = (
        b"\x7fELF\x02\x01\x01" + b"\x00" * 64 + b"SYNTHETIC CORE PLACEHOLDER devsrvr 2026-11-10\n"
    )
    files[f"{root}/var/cores/masterd/logrcvr_14111.core"] = (
        b"\x7fELF\x02\x01\x01" + b"\x00" * 64 + b"SYNTHETIC CORE PLACEHOLDER logrcvr 2026-11-10\n"
    )
    return files


def bundle_fw_clean(root: str) -> dict[str, str | bytes]:
    files: dict[str, str | bytes] = {}
    files[f"{root}/tmp/cli/techsupport_{root}.txt"] = fw_clean_cli()
    files[f"{root}/opt/pancfg/mgmt/saved-configs/running-config.xml"] = fw_clean_config()
    for rel, text in clean_logs().items():
        files[f"{root}/{rel}"] = text
    return files


def bundle_pano_issues(root: str) -> dict[str, str | bytes]:
    files: dict[str, str | bytes] = {}
    files[f"{root}/tmp/cli/techsupport_{root}.txt"] = pano_issues_cli()
    files[f"{root}/opt/pancfg/mgmt/saved-configs/running-config.xml"] = pano_config()
    for rel, text in pano_logs().items():
        files[f"{root}/{rel}"] = text
    files[f"{root}/var/cores/masterd/devsrvr_pano.core"] = (
        b"\x7fELF\x02\x01\x01" + b"\x00" * 32 + b"SYNTHETIC CORE PLACEHOLDER panorama devsrvr\n"
    )
    return files


def write_nested(path: Path, inner_files: dict[str, str | bytes], inner_name: str) -> None:
    """Outer tgz whose only real payload is a nested techsupport tgz (plus a readme)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as inner:
        for name, content in inner_files.items():
            if isinstance(content, bytes):
                add_bytes(inner, name, content)
            else:
                add_text(inner, name, content)
    inner_bytes = buf.getvalue()
    outer_root = "outer_wrap"
    files = {
        f"{outer_root}/README.txt": "Nested synthetic TSF wrapper for parser tests.\n",
        f"{outer_root}/{inner_name}": inner_bytes,
    }
    write_tgz(path, files)


class _RegionStream:
    """Exactly `size` bytes: repeating fill, with short overlays at given offsets."""

    def __init__(self, size: int, fill: bytes, overlays: list[tuple[int, bytes]]):
        self.size = size
        self.fill = fill
        self.pos = 0
        self.spans = []
        for off, data in overlays:
            if off < 0 or off >= size:
                continue
            data = data[: max(0, size - off)]
            self.spans.append((off, off + len(data), data))
        self.spans.sort()

    def readable(self) -> bool:
        return True

    def read(self, n: int = -1) -> bytes:
        if self.pos >= self.size:
            return b""
        remaining = self.size - self.pos
        if n is None or n < 0:
            n = remaining
        n = min(n, remaining)
        out = bytearray()
        fill = self.fill
        flen = len(fill)
        while len(out) < n:
            pos = self.pos + len(out)
            want = n - len(out)
            hit = None
            nxt = self.size
            for a, b, data in self.spans:
                if a <= pos < b:
                    hit = data[pos - a : pos - a + want]
                    break
                if pos < a < nxt:
                    nxt = a
            if hit is not None:
                out.extend(hit)
                continue
            room = min(want, nxt - pos)
            start = pos % flen
            chunk = fill[start:] + fill * ((room // flen) + 1)
            out.extend(chunk[:room])
        self.pos += n
        return bytes(out)


def write_large_tgz(path: Path, padding_size: int = 1_600_000_000) -> None:
    """Synthetic multi-GB-ish bundle for streaming/memory tests. Not for the repo."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    root = f"techsupport_fw-example-large_{STAMP}"
    files = bundle_fw_issues(root)
    files[f"{root}/var/cores/masterd/synth.core"] = (
        b"\x7fELF\x02\x01\x01" + b"\x00" * 4096 + b"SYNTHETIC CORE PLACEHOLDER large-bundle\n"
    )
    files[f"{root}/tmp/capture.pcap"] = b"\xd4\xc3\xb2\xa1" + b"\x00" * 2048 + b"SYNTHETIC PCAP\n"
    head = log_line(
        "2026/11/10 11:00:00", "Error", "ha_agent", "ha.c:10",
        "HA peer left the cluster — possible split-brain (synthetic padding head)",
    ).encode()
    mid = log_line(
        "2026/11/10 12:00:00", "Error", "authd", "auth.c:20",
        "Authentication failed for user padding-mid (synthetic padding middle)",
    ).encode()
    tail = log_line(
        "2026/11/10 13:00:00", "Error", "devsrvr", "dev.c:30",
        "Process devsrvr exited unexpectedly, core dumped (synthetic padding tail)",
    ).encode()
    mid_at = max(len(head) + 1, (padding_size // 2) - len(mid) // 2)
    tail_at = max(mid_at + len(mid) + 1, padding_size - len(tail))
    fill = b"2026/11/10 12:00:00  1  Info:  pad(file.c:1): padding " + b"X" * 180 + b"\n"
    stream = _RegionStream(padding_size, fill, [(0, head), (mid_at, mid), (tail_at, tail)])
    pad_name = f"{root}/var/log/pan/padding.log"
    with tarfile.open(path, mode="w:gz", compresslevel=1) as tar:
        for name, content in files.items():
            if isinstance(content, bytes):
                add_bytes(tar, name, content)
            else:
                add_text(tar, name, content)
        info = tarfile.TarInfo(name=pad_name)
        info.size = padding_size
        info.mtime = 1762790400
        info.mode = 0o644
        tar.addfile(info, stream)
    print(f"large synthetic TSF written to {path} ({path.stat().st_size} bytes compressed, padding {padding_size} bytes)")



def _add_padding_log(tar: tarfile.TarFile, name: str, size: int, overlays: list[tuple[int, bytes]]) -> None:
    fill = b"2026/11/10 12:00:00  1  Info:  pad(file.c:1): padding " + b"X" * 180 + b"\n"
    stream = _RegionStream(size, fill, overlays)
    info = tarfile.TarInfo(name=name)
    info.size = size
    info.mtime = 1762790400
    info.mode = 0o644
    tar.addfile(info, stream)


def _add_binary_blob(tar: tarfile.TarFile, name: str, size: int, magic: bytes) -> None:
    fill = (magic + b"\x00" * 1024 + b"SYNTHETIC BINARY PADDING\n")
    stream = _RegionStream(size, fill, [(0, magic)])
    info = tarfile.TarInfo(name=name)
    info.size = size
    info.mtime = 1762790400
    info.mode = 0o644
    tar.addfile(info, stream)


def write_large_pano_tgz(path: Path, total_padding: int = 3_000_000_000) -> None:
    """Synthetic ~3 GB Panorama TSF with bulky logdb / ES / pan_logs trees. Not for the repo."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    root = f"techsupport_ex-panorama-large_{STAMP}"
    files = bundle_pano_issues(root)
    # Sizes add up to about total_padding, plus the small pano-issues files.
    panlogs = max(400_000_000, int(total_padding * 0.35))
    logdb = max(300_000_000, int(total_padding * 0.2))
    esdata = max(300_000_000, int(total_padding * 0.2))
    remain = max(200_000_000, total_padding - panlogs - logdb - esdata)
    ms_pad = remain // 2
    auth_pad = remain - ms_pad
    mid_issue = log_line(
        "2026/11/10 12:30:00", "Error", "authd", "auth.c:20",
        "Authentication failed for user pano-padding-mid (synthetic panorama padding)",
    ).encode()
    with tarfile.open(path, mode="w:gz", compresslevel=1) as tar:
        for name, content in files.items():
            if isinstance(content, bytes):
                add_bytes(tar, name, content)
            else:
                add_text(tar, name, content)
        _add_padding_log(
            tar,
            f"{root}/var/log/pan/ms-padding.log",
            ms_pad,
            [(max(0, ms_pad // 2), mid_issue)],
        )
        _add_padding_log(tar, f"{root}/var/log/pan/authd-padding.log", auth_pad, [])
        _add_padding_log(tar, f"{root}/opt/panlogs/traffic/huge-traffic.log", panlogs, [])
        _add_binary_blob(tar, f"{root}/opt/logdb/shard001.db", logdb, b"SQLite format 3\x00")
        _add_binary_blob(tar, f"{root}/opt/elasticsearch/data/nodes/0/big.dat", esdata, b"\x00\x00ESDATA")
    print(
        f"large panorama TSF written to {path} ({path.stat().st_size} bytes compressed, "
        f"padding ~{total_padding} bytes)"
    )


def main() -> int:
    if len(sys.argv) >= 2 and sys.argv[1] == "--large":
        dest = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("/tmp/pan-tsf-large/techsupport_fw-large.tgz")
        size = int(sys.argv[3]) if len(sys.argv) > 3 else 1_600_000_000
        write_large_tgz(dest, size)
        return 0
    if len(sys.argv) >= 2 and sys.argv[1] == "--large-pano":
        dest = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("/tmp/pan-tsf-large/techsupport_pano-large.tgz")
        size = int(sys.argv[3]) if len(sys.argv) > 3 else 3_000_000_000
        write_large_pano_tgz(dest, size)
        return 0

    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "samples"
    out.mkdir(parents=True, exist_ok=True)

    fw_root = f"techsupport_fw-example_{STAMP}"
    clean_root = f"techsupport_fw-example-clean_{STAMP}"
    pano_root = f"techsupport_ex-panorama_{STAMP}"

    fw_files = bundle_fw_issues(fw_root)
    clean_files = bundle_fw_clean(clean_root)
    pano_files = bundle_pano_issues(pano_root)

    write_tgz(out / "techsupport_fw-issues.tgz", fw_files)
    write_tgz(out / "techsupport_fw-clean.tgz", clean_files)
    write_tgz(out / "techsupport_pano-issues.tgz", pano_files)
    write_nested(out / "techsupport_fw-issues-nested.tgz", fw_files, f"{fw_root}.tgz")

    # Truncated / missing-cli bundle: config + a couple of logs only, no techsupport txt.
    thin_root = f"techsupport_ex-thin_{STAMP}"
    thin = {
        f"{thin_root}/opt/pancfg/mgmt/saved-configs/running-config.xml": fw_clean_config(),
        f"{thin_root}/var/log/pan/mp-log/ms.log": log_line(
            "2026/11/10 07:00:00", "Info", "ms", "sys.c:10", "management server heartbeat ok"
        ),
        f"{thin_root}/README.txt": "Synthetic thin bundle with no tmp/cli techsupport file.\n",
    }
    write_tgz(out / "techsupport_fw-thin.tgz", thin)
    print(f"samples written to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
