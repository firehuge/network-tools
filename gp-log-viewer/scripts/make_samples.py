#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate synthetic GlobalProtect log bundles in samples/ (made-up data only).

All names use example.com and all addresses are documentation addresses
(RFC 5737). Re-run this script to regenerate the bundles.
"""
import io, os, tarfile, time, zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "samples")

LOGS = {
    "PanGPS.log": """(T4412) 11/02/26 08:01:02:114 Debug(  512): GlobalProtect version is 6.2.4-683
(T4412) 11/02/26 08:01:02:120 Debug(  530): Computer name: WS-EXAMPLE-01
(T4412) 11/02/26 08:01:02:130 Debug(  540): OS version: Microsoft Windows 11 Enterprise 23H2
(T4412) 11/02/26 08:01:03:201 Debug( 1220): Portal address is vpn.example.com
(T4412) 11/02/26 08:01:03:410 Debug( 1301): local ip address: 192.0.2.44
(T4412) 11/02/26 08:01:04:002 Error( 1440): Failed to connect to portal vpn.example.com, error 12029 (connection refused)
(T4412) 11/02/26 08:02:10:002 Debug( 2201): Network change detected, interface changed
(T4412) 11/02/26 08:05:11:500 Debug( 1500): username=user1
(T4412) 11/02/26 08:05:12:777 Error( 1610): Authentication failed: invalid username or password (status=401)
(T4412) 11/02/26 08:07:30:100 Error( 1611): SAML authentication timed out waiting for IdP response
(T4412) 11/02/26 08:09:01:050 Debug( 1700): Portal login succeeded for user user1
(T4412) 11/02/26 08:09:02:300 Debug( 1820): gateway address is gw1.example.com
(T4412) 11/02/26 08:09:03:010 Warning( 1910): IPSec tunnel timed out, falling back to SSL
(T4412) 11/02/26 08:09:04:440 Debug( 1950): Connected to gateway gw1.example.com
(T4412) 11/02/26 08:09:04:500 Debug( 1960): assigned ip 198.51.100.21
(T4412) 11/02/26 08:09:04:600 Debug( 1990): Status is Connected
""",
    "PanGPA.log": """(P5520-T5524)Info (  301): 11/02/26 08:01:01:900 GlobalProtect agent starting
(P5520-T5524)Debug(  880): 11/02/26 08:05:11:450 user name: user1
(P5520-T5524)Error(  910): 11/02/26 08:07:00:020 Embedded browser failed to load SAML page
(P5520-T5524)Debug(  920): 11/02/26 08:08:40:200 public ip: 203.0.113.4
""",
    "pan_gp_event.log": """2026-11-02 08:08:55.001 Error: Server certificate is invalid: certificate expired
2026-11-02 08:08:58.001 Error: OTP challenge failed: invalid passcode
2026-11-02 08:30:00.001 Info: Session expired, disconnected by gateway
""",
    "PanGpHip.log": "(T6001) 11/02/26 08:09:20:100 Debug( 222): HIP check failed: disk encryption not compliant\n",
}
FIXED_TIME = 1793000000  # fixed so the bundles are reproducible


def make():
    os.makedirs(OUT, exist_ok=True)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for n, body in LOGS.items():
            data = body.encode()
            ti = tarfile.TarInfo("GlobalProtectLogs/" + n)
            ti.size, ti.mtime = len(data), FIXED_TIME
            t.addfile(ti, io.BytesIO(data))
    open(os.path.join(OUT, "GlobalProtectLogs.tgz"), "wb").write(buf.getvalue())
    with zipfile.ZipFile(os.path.join(OUT, "GlobalProtectLogs.zip"), "w", zipfile.ZIP_DEFLATED) as z:
        for n, body in LOGS.items():
            zi = zipfile.ZipInfo("GlobalProtectLogs/" + n, (2026, 11, 2, 8, 0, 0))
            z.writestr(zi, body)


if __name__ == "__main__":
    make()
    print("wrote samples/GlobalProtectLogs.tgz and .zip")
