#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate synthetic tech-support bundles for tests and demos.

Everything here is made up: hostnames, serials, IPs (10.x, 172.16.x and the RFC 5737
documentation ranges only), license dates and counters. Never copy real data in here.
"""
import io, tarfile, time, random
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "samples"
NOW = "2026-11-20 14:00:00"

def tar_add(tf, name, text):
    data = text.encode()
    ti = tarfile.TarInfo(name)
    ti.size = len(data)
    ti.mtime = 1795000000
    tf.addfile(ti, io.BytesIO(data))

def system_info(host, model, family, serial, ver, multi="off", uptime="41 days, 3:12:09", extra=""):
    return f"""
hostname: {host}
ip-address: 10.10.0.10
netmask: 255.255.255.0
default-gateway: 10.10.0.1
mac-address: 00:00:5e:00:53:10
time: Fri Nov 20 14:00:00 2026
uptime: {uptime}
family: {family}
model: {model}
serial: {serial}
sw-version: {ver}
app-version: 9001-9500
threat-version: 9001-9500
wildfire-version: 912345-915000
url-filtering-version: 20261120.20001
multi-vsys: {multi}
operational-mode: normal
advanced-routing: off
{extra}
"""

def lic(feature, desc, issued, expires, expired, serial):
    return f"""License entry:
Feature: {feature}
Description: {desc}
Serial: {serial}
Authcode: I0000000
Issued: {issued}
Expires: {expires}
Expired?: {expired}
"""

def session_info(supported, allocated, kbps, cps, pps):
    return f"""
target-dp:                                       *.dp0
--------------------------------------------------------------------------------
Number of sessions supported:                    {supported}
Number of allocated sessions:                    {allocated}
Number of active TCP sessions:                   {allocated//2}
Number of active UDP sessions:                   {allocated//3}
Session table utilization:                       {round(100*allocated/supported)}%
Number of sessions created since bootup:         98765432
Packet rate:                                     {pps}/s
Throughput:                                      {kbps} kbps
New connection establish rate:                   {cps} cps
--------------------------------------------------------------------------------
"""

def iface_detail(name, speed, up, ptype, cap, mode):
    st = "up" if up else "down"
    rs = f"{speed}/full/{st}" if up else "ukn/ukn/down(autoneg)"
    return f"""
--------------------------------------------------------------------------------
Name: {name}, ID: 16
Link status:
  Runtime link speed/duplex/state: {rs}
  Configured link speed/duplex/state: auto/auto/auto
MAC address:
  Port MAC address 00:00:5e:00:53:20
Interface Type :
  Port Type: {ptype}
Capability : {cap}
Operation mode: {mode}
--------------------------------------------------------------------------------
"""

CAP1G = "auto, 10Mb/s-half, 10Mb/s-full, 100Mb/s-half, 100Mb/s-full, 1Gb/s-full"
CAP1GF = "auto, 1Gb/s-full"
CAP10G = "auto, 1Gb/s-full, 10Gb/s-full"
CAP40G = "auto, 40Gb/s-full"

def iface_all(hw, logical):
    s = f"\ntotal configured hardware interfaces: {len(hw)}\nname                    id    speed/duplex/state            mac address\n--------------------------------------------------------------------------------\n"
    for i, (n, sp, up) in enumerate(hw):
        state = f"{sp}/full/up" if up else "ukn/ukn/down(autoneg)"
        s += f"{n:<24}{16+i:<6}{state:<30}00:00:5e:00:53:{30+i:02x}\n"
    s += "\naggregation groups: 1\n\n"
    s += f"total configured logical interfaces: {len(logical)}\n\nname                      id    vsys zone             forwarding               tag    address\n------------------- ----- ---- ---------------- ------------------------ ------ ------------------\n"
    for i, (n, vs, zone, fwd, tag, addr) in enumerate(logical):
        s += f"{n:<26}{256+i:<6}{vs:<5}{zone:<17}{fwd:<25}{tag:<7}{addr}\n"
    return s

def counters(rows):
    s = "\n\nHardware interface counters:\n--------------------------------------------------------------------------------\n"
    for n, rx, tx in rows:
        s += f"\nInterface: {n}\n--------------------------------------------------------------------------------\n\n--------------------------------------------------------------------------------\nPhysical port counters read from MAC:\n--------------------------------------------------------------------------------\nrx-broadcast                  0\nrx-bytes                      {rx}\nrx-multicast                  0\ntx-bytes                      {tx}\n--------------------------------------------------------------------------------\n"
    return s

def dp_monitor(start_hour, samples, base_sess, base_kbps, base_cps, seed):
    rnd = random.Random(seed)
    out = []
    for i in range(samples):
        h = (start_hour + i // 6) % 24
        day = 19 + (start_hour + i // 6) // 24
        mi = (i % 6) * 10
        # business-hours bump
        f = 1.0 + (0.9 if 13 <= h <= 22 else 0.1) * rnd.random()
        out.append(f"2026-11-{day:02d} {h:02d}:{mi:02d}:09.330 +0000  --- panio")
        out.append("pan_comm message statistics")
        out.append(":Number of sessions supported:                    999998")
        out.append(f":Number of allocated sessions:                    {int(base_sess*f)}")
        out.append(f":Packet rate:                                     {int(base_kbps*f/9)}/s")
        out.append(f":Throughput:                                      {int(base_kbps*f)} kbps")
        out.append(f":New connection establish rate:                   {int(base_cps*f)} cps")
        out.append(":")
    return "\n".join(out) + "\n"

def environmentals(psus, fans=2):
    """Synthetic 'show system environmentals' with power-supply rows. psus: list of (inserted, alarm)."""
    out = "\nThermal\nSlot    Description                 Alarm   Degrees C   Min Temp   Max Temp\n"
    out += "S1      Temperature near Fan #1     False   31.0        0.0        60.0\n"
    if psus:
        out += "\nPower Supply\nSlot    Description                 Alarm   Inserted   Volts\n"
        for i, (ins, alarm) in enumerate(psus, 1):
            out += f"S{i}      Power Supply #{i} ({'left' if i == 1 else 'right'})      {alarm}   {ins}       12.0\n"
    return out

def transceivers(items):
    out = "\n"
    for port, typ, comp, pn, wl in items:
        out += f"{port}\n  Transceiver type: {typ}\n  Vendor name: SYNTHETIC-OPTICS\n  Vendor PN: {pn}\n  Compliance: {comp}\n  Wavelength: {wl}\n\n"
    return out

def cli_file(sections):
    s = "> configure\n\n> exit\n\n"
    for cmd, body in sections:
        s += f"> {cmd}\n{body}\n\n"
    return s

# ------------------------------------------------------------------ configs
def cfg_pa3220():
    return """<?xml version="1.0"?>
<config version="10.2.0" urldb="paloaltonetworks" detail-version="10.2.10">
  <mgt-config><users><entry name="admin"><phash>$5$synthetic$notarealhash</phash><permissions><role-based><superuser>yes</superuser></role-based></permissions></entry></users></mgt-config>
  <shared>
    <address><entry name="srv-web"><ip-netmask>10.20.30.10/32</ip-netmask></entry></address>
    <certificate>
      <entry name="gp-portal-cert"><common-name>vpn.example.com</common-name><public-key>-----BEGIN CERTIFICATE-----SYNTHETIC-----END CERTIFICATE-----</public-key><private-key>-AQ==SYNTHETICENCRYPTEDKEY==</private-key><algorithm>RSA</algorithm></entry>
    </certificate>
    <ssl-tls-service-profile><entry name="gp-tls"><certificate>gp-portal-cert</certificate><protocol-settings><min-version>tls1-2</min-version><max-version>max</max-version></protocol-settings></entry></ssl-tls-service-profile>
    <authentication-profile><entry name="radius-auth"><method><radius><server-profile>corp-radius</server-profile></radius></method><allow-list><member>all</member></allow-list></entry></authentication-profile>
    <server-profile><radius><entry name="corp-radius"><server><entry name="r1"><ip-address>10.30.0.5</ip-address><secret>-AQ==SYNTHETICRADIUSSECRET</secret></entry></server></entry></radius></server-profile>
    <admin-role><entry name="api-ro"><role><device><webui><device><master-key>********</master-key></device></webui></device></role></entry></admin-role>
  </shared>
  <devices>
    <entry name="localhost.localdomain">
      <network>
        <interface>
          <ethernet>
            <entry name="ethernet1/1"><layer3><ip><entry name="203.0.113.10/29"/></ip><interface-management-profile>allow-ping</interface-management-profile><lldp><enable>yes</enable></lldp></layer3><comment>ISP-A</comment></entry>
            <entry name="ethernet1/2"><layer3><units>
                <entry name="ethernet1/2.10"><tag>10</tag><ip><entry name="10.20.10.1/24"/></ip><interface-management-profile>mgmt-inside</interface-management-profile></entry>
                <entry name="ethernet1/2.20"><tag>20</tag><ip><entry name="10.20.20.1/24"/></ip></entry>
              </units></layer3><link-speed>1000</link-speed><comment>core trunk</comment></entry>
            <entry name="ethernet1/3"><aggregate-group>ae1</aggregate-group></entry>
            <entry name="ethernet1/4"><aggregate-group>ae1</aggregate-group></entry>
            <entry name="ethernet1/5"><virtual-wire/></entry>
            <entry name="ethernet1/6"><virtual-wire/></entry>
            <entry name="ethernet1/7"><layer2><units><entry name="ethernet1/7.100"><tag>100</tag></entry></units></layer2></entry>
            <entry name="ethernet1/8"><ha/></entry>
            <entry name="ethernet1/17"><layer3><ip><entry name="172.16.50.1/24"/></ip></layer3><link-speed>10000</link-speed><comment>DMZ 10G</comment></entry>
            <entry name="ethernet1/18"><layer3><dhcp-client><enable>yes</enable></dhcp-client></layer3><comment>ISP-B</comment></entry>
          </ethernet>
          <aggregate-ethernet>
            <entry name="ae1"><layer3><ip><entry name="10.20.40.1/24"/></ip><lacp><enable>yes</enable></lacp><units><entry name="ae1.50"><tag>50</tag><ip><entry name="10.20.50.1/24"/></ip></entry></units></layer3></entry>
          </aggregate-ethernet>
          <vlan><units><entry name="vlan.100"><ip><entry name="10.20.100.1/24"/></ip></entry></units></vlan>
          <loopback><units><entry name="loopback.1"><ip><entry name="10.255.255.1/32"/></ip></entry></units></loopback>
          <tunnel><units><entry name="tunnel.1"><ip><entry name="169.254.10.1/30"/></ip></entry><entry name="tunnel.2"/></units></tunnel>
        </interface>
        <profiles>
          <interface-management-profile>
            <entry name="allow-ping"><ping>yes</ping></entry>
            <entry name="mgmt-inside"><https>yes</https><ssh>yes</ssh><permitted-ip><entry name="10.20.10.0/24"/></permitted-ip></entry>
          </interface-management-profile>
          <monitor-profile><entry name="default"><interval>3</interval><threshold>5</threshold><action>wait-recover</action></entry></monitor-profile>
          <zone-protection-profile><entry name="zpp-untrust"><flood><tcp-syn><enable>yes</enable></tcp-syn></flood></entry></zone-protection-profile>
        </profiles>
        <virtual-wire><entry name="vw-inline"><interface1>ethernet1/5</interface1><interface2>ethernet1/6</interface2></entry></virtual-wire>
        <vlan><entry name="lab-vlan"><interface><member>ethernet1/7.100</member></interface><virtual-interface><interface>vlan.100</interface></virtual-interface></entry></vlan>
        <virtual-router>
          <entry name="default">
            <interface><member>ethernet1/1</member><member>ethernet1/2.10</member><member>ethernet1/2.20</member><member>ae1</member><member>ae1.50</member><member>ethernet1/17</member><member>ethernet1/18</member><member>vlan.100</member><member>loopback.1</member><member>tunnel.1</member><member>tunnel.2</member></interface>
            <ecmp><enable>yes</enable><max-path>2</max-path></ecmp>
            <routing-table><ip><static-route>
              <entry name="default-isp-a"><destination>0.0.0.0/0</destination><interface>ethernet1/1</interface><nexthop><ip-address>203.0.113.9</ip-address></nexthop>
                <path-monitor><enable>yes</enable><monitor-destinations><entry name="pm1"><source>203.0.113.10/29</source><destination>198.51.100.53</destination><enable>yes</enable></entry></monitor-destinations></path-monitor></entry>
              <entry name="to-branch"><destination>10.99.0.0/16</destination><interface>tunnel.1</interface></entry>
              <entry name="inside-net"><destination>10.30.0.0/16</destination><interface>ethernet1/2.10</interface><nexthop><ip-address>10.20.10.254</ip-address></nexthop></entry>
            </static-route></ip></routing-table>
            <protocol>
              <bgp><enable>yes</enable><router-id>10.255.255.1</router-id><local-as>65010</local-as>
                <peer-group><entry name="core"><peer><entry name="core-sw"><peer-as>65020</peer-as><local-address><interface>ethernet1/2.10</interface><ip>10.20.10.1/24</ip></local-address><peer-address><ip>10.20.10.2</ip></peer-address></entry></peer></entry></peer-group>
                <redist-rules><entry name="connected"><address-family-identifier>ipv4</address-family-identifier><enable>yes</enable><set-origin>incomplete</set-origin></entry></redist-rules></bgp>
              <redist-profile><entry name="connected"><priority>1</priority><filter><type><member>connect</member></type></filter><action><redist/></action></entry></redist-profile>
              <ospf><enable>yes</enable><router-id>10.255.255.1</router-id><area><entry name="0.0.0.0"><type><normal/></type><interface><entry name="ae1.50"><enable>yes</enable><passive>no</passive></entry><entry name="loopback.1"><enable>yes</enable><passive>yes</passive></entry></interface></entry></area></ospf>
              <ospfv3><enable>no</enable><area><entry name="0.0.0.0"><type><normal/></type><interface><entry name="ethernet1/17"><enable>no</enable></entry></interface></entry></area></ospfv3>
              <rip><enable>no</enable><interface><entry name="ethernet1/18"><enable>no</enable></entry></interface></rip>
            </protocol>
          </entry>
        </virtual-router>
        <ike>
          <gateway><entry name="gw-branch"><local-address><interface>ethernet1/1</interface><ip>203.0.113.10/29</ip></local-address><peer-address><ip>198.51.100.20</ip></peer-address><authentication><pre-shared-key><key>-AQ==SYNTHETICPSK==</key></pre-shared-key></authentication><protocol><ikev1><ike-crypto-profile>default</ike-crypto-profile></ikev1><ikev2><ike-crypto-profile>default</ike-crypto-profile></ikev2></protocol></entry></gateway>
          <crypto-profiles>
            <ike-crypto-profiles><entry name="legacy-ike"><encryption><member>3des</member></encryption><hash><member>sha1</member></hash><dh-group><member>group2</member></dh-group></entry><entry name="default"><encryption><member>aes-128-cbc</member></encryption><hash><member>sha256</member></hash><dh-group><member>group14</member></dh-group><lifetime><hours>8</hours></lifetime></entry></ike-crypto-profiles>
            <ipsec-crypto-profiles><entry name="default"><esp><encryption><member>aes-128-cbc</member></encryption><authentication><member>sha256</member></authentication></esp><dh-group>group14</dh-group><lifetime><hours>1</hours></lifetime></entry></ipsec-crypto-profiles>
          </crypto-profiles>
        </ike>
        <tunnel><ipsec><entry name="ipsec-branch"><auto-key><ike-gateway><entry name="gw-branch"/></ike-gateway><ipsec-crypto-profile>default</ipsec-crypto-profile></auto-key><tunnel-interface>tunnel.1</tunnel-interface><tunnel-monitor><enable>yes</enable><destination-ip>10.99.0.1</destination-ip></tunnel-monitor></entry></ipsec></tunnel>
        <dhcp><interface>
          <entry name="ethernet1/2.20"><server><mode>enabled</mode><ip-pool><member>10.20.20.100-10.20.20.200</member></ip-pool></server></entry>
          <entry name="ae1.50"><relay><ip><enabled>yes</enabled><server><member>10.20.10.5</member></server></ip></relay></entry>
        </interface></dhcp>
        <dns-proxy><entry name="inside-dns"><enabled>yes</enabled><interface><member>ethernet1/2.10</member><member>ethernet1/2.20</member></interface><default><primary>198.51.100.53</primary></default></entry></dns-proxy>
        <qos><interface><entry name="ethernet1/1"><enabled>yes</enabled><interface-bandwidth><egress-max>500</egress-max></interface-bandwidth><regular-traffic><default-group><qos-profile>default</qos-profile></default-group></regular-traffic></entry></interface>
          <profile><entry name="default"><class-bandwidth-type><mbps><class><entry name="class4"><priority>medium</priority></entry></class></mbps></class-bandwidth-type></entry></profile></qos>
        <lldp><enable>yes</enable></lldp>
      </network>
      <deviceconfig>
        <system>
          <hostname>SYN-PA3220-A</hostname>
          <ip-address>10.10.0.10</ip-address><netmask>255.255.255.0</netmask><default-gateway>10.10.0.1</default-gateway>
          <panorama><local-panorama><panorama-server>10.10.0.50</panorama-server></local-panorama></panorama>
          <route><service>
            <entry name="dns"><source><interface>ethernet1/2.10</interface><address>10.20.10.1/24</address></source></entry>
            <entry name="syslog"><source><interface>ethernet1/2.10</interface><address>10.20.10.1/24</address></source></entry>
            <entry name="snmp"><source><interface>loopback.1</interface><address>10.255.255.1/32</address></source></entry>
          </service>
          <destination><entry name="10.50.0.10"><source><interface>ethernet1/17</interface><address>172.16.50.1/24</address></source></entry></destination></route>
          <dns-setting><servers><primary>198.51.100.53</primary></servers></dns-setting>
          <authentication-profile>radius-auth</authentication-profile>
          <permitted-ip><entry name="10.10.0.10"/><entry name="10.20.10.0/24"/></permitted-ip>
        </system>
        <setting><session><jumbo-frame>yes</jumbo-frame></session></setting>
        <high-availability>
          <enabled>yes</enabled>
          <group><group-id>1</group-id><peer-ip>10.254.1.2</peer-ip><mode><active-passive/></mode>
            <monitoring><link-monitoring><enabled>yes</enabled><link-group><entry name="uplinks"><interface><member>ethernet1/1</member><member>ethernet1/2</member></interface></entry></link-group></link-monitoring></monitoring>
          </group>
          <interface>
            <ha1><port>ha1-a</port><ip-address>10.254.1.1</ip-address><netmask>255.255.255.252</netmask></ha1>
            <ha1-backup><port>ha1-b</port><ip-address>10.254.2.1</ip-address><netmask>255.255.255.252</netmask></ha1-backup>
            <ha2><port>hsci</port></ha2>
            <ha2-backup><port>ethernet1/8</port><ip-address>10.254.3.1</ip-address><netmask>255.255.255.252</netmask></ha2-backup>
          </interface>
        </high-availability>
      </deviceconfig>
      <vsys>
        <entry name="vsys1">
          <zone>
            <entry name="untrust"><network><layer3><member>ethernet1/1</member><member>ethernet1/18</member></layer3><zone-protection-profile>zpp-untrust</zone-protection-profile></network></entry>
            <entry name="inside"><network><layer3><member>ethernet1/2.10</member><member>ethernet1/2.20</member><member>ae1</member><member>ae1.50</member></layer3></network></entry>
            <entry name="dmz"><network><layer3><member>ethernet1/17</member></layer3></network></entry>
            <entry name="lab-l2"><network><layer2><member>ethernet1/7.100</member></layer2></network></entry>
            <entry name="lab-l3"><network><layer3><member>vlan.100</member></layer3></network></entry>
            <entry name="inline"><network><virtual-wire><member>ethernet1/5</member><member>ethernet1/6</member></virtual-wire></network></entry>
            <entry name="vpn"><network><layer3><member>tunnel.1</member><member>tunnel.2</member></layer3></network></entry>
          </zone>
          <import><network><interface><member>ethernet1/1</member><member>ethernet1/2.10</member><member>ethernet1/2.20</member><member>ae1</member><member>ae1.50</member><member>ethernet1/5</member><member>ethernet1/6</member><member>ethernet1/7.100</member><member>ethernet1/17</member><member>ethernet1/18</member><member>vlan.100</member><member>loopback.1</member><member>tunnel.1</member><member>tunnel.2</member></interface></network></import>
          <profiles>
            <virus><entry name="av-default"/></virus>
            <url-filtering><entry name="url-corp"/></url-filtering>
            <wildfire-analysis><entry name="wf-all"/></wildfire-analysis>
          </profiles>
          <user-id-agent><entry name="dc1-agent"><host>10.30.0.20</host><port>5007</port></entry></user-id-agent>
          <rulebase>
            <security><rules>
              <entry name="inside-out"><from><member>inside</member></from><to><member>untrust</member></to><source><member>any</member></source><destination><member>any</member></destination><application><member>any</member></application><service><member>application-default</member></service><action>allow</action><profile-setting><profiles><virus><member>av-default</member></virus><wildfire-analysis><member>wf-all</member></wildfire-analysis></profiles></profile-setting></entry>
              <entry name="web-in"><from><member>untrust</member></from><to><member>dmz</member></to><source><member>any</member></source><destination><member>srv-web</member></destination><application><member>web-browsing</member></application><service><member>application-default</member></service><action>allow</action></entry>
            </rules></security>
            <nat><rules>
              <entry name="outbound-pat"><from><member>inside</member></from><to><member>untrust</member></to><to-interface>ethernet1/1</to-interface><source><member>any</member></source><destination><member>any</member></destination><service>any</service>
                <source-translation><dynamic-ip-and-port><interface-address><interface>ethernet1/1</interface><ip>203.0.113.10/29</ip></interface-address></dynamic-ip-and-port></source-translation></entry>
              <entry name="web-dnat"><from><member>untrust</member></from><to><member>untrust</member></to><to-interface>ethernet1/1</to-interface><source><member>any</member></source><destination><member>any</member></destination><service>service-http</service><destination-translation><translated-address>srv-web</translated-address></destination-translation></entry>
            </rules></nat>
            <pbf><rules>
              <entry name="guest-to-isp-b"><from><interface><member>ethernet1/2.20</member></interface></from><source><member>any</member></source><destination><member>any</member></destination><service><member>any</member></service><application/><action><forward><egress-interface>ethernet1/18</egress-interface><nexthop><ip-address>198.51.100.1</ip-address></nexthop><monitor><profile>default</profile><ip-address>198.51.100.1</ip-address></monitor></forward></action></entry>
            </rules></pbf>
          </rulebase>
          <global-protect>
            <global-protect-portal><entry name="gp-portal"><portal-config><ssl-tls-service-profile>gp-tls</ssl-tls-service-profile><custom-login-page>factory-default</custom-login-page><custom-home-page>factory-default</custom-home-page><local-address><interface>ethernet1/1</interface><ip><ipv4>203.0.113.10/29</ipv4></ip></local-address></portal-config></entry></global-protect-portal>
            <global-protect-gateway><entry name="gp-gw"><ssl-tls-service-profile>gp-tls</ssl-tls-service-profile><tunnel-mode>yes</tunnel-mode><local-address><interface>ethernet1/1</interface><ip><ipv4>203.0.113.10/29</ipv4></ip></local-address><tunnel-interface>tunnel.2</tunnel-interface></entry></global-protect-gateway>
          </global-protect>
        </entry>
      </vsys>
    </entry>
  </devices>
</config>
"""

def cfg_pa5220():
    vs = ""
    names = ["vsys1", "vsys2", "vsys3"]
    ifmap = {"vsys1": ["ethernet1/5", "ethernet1/6"], "vsys2": ["ethernet1/7", "ethernet1/8.200"], "vsys3": ["ethernet1/21"]}
    for v in names:
        mem = "".join(f"<member>{i}</member>" for i in ifmap[v])
        vs += f"""<entry name="{v}"><display-name>tenant-{v[-1]}</display-name><zone><entry name="{v}-out"><network><layer3><member>{ifmap[v][0]}</member></layer3></network></entry><entry name="{v}-in"><network><layer3>{"".join(f"<member>{i}</member>" for i in ifmap[v][1:])}</layer3></network></entry></zone>
<import><network><interface>{mem}</interface></network></import>
<rulebase><security><rules><entry name="{v}-allow"><from><member>{v}-in</member></from><to><member>{v}-out</member></to><source><member>any</member></source><destination><member>any</member></destination><application><member>any</member></application><service><member>application-default</member></service><action>allow</action></entry></rules></security></rulebase></entry>"""
    return f"""<?xml version="1.0"?>
<config version="11.1.0" urldb="paloaltonetworks" detail-version="11.1.4">
  <shared/>
  <devices><entry name="localhost.localdomain">
    <network>
      <interface><ethernet>
        <entry name="ethernet1/5"><layer3><ip><entry name="198.51.100.2/28"/></ip></layer3></entry>
        <entry name="ethernet1/6"><layer3><ip><entry name="10.1.6.1/24"/></ip></layer3><link-speed>10000</link-speed></entry>
        <entry name="ethernet1/7"><layer3><ip><entry name="198.51.100.18/28"/></ip></layer3></entry>
        <entry name="ethernet1/8"><layer3><units><entry name="ethernet1/8.200"><tag>200</tag><ip><entry name="10.2.200.1/24"/></ip></entry></units></layer3></entry>
        <entry name="ethernet1/21"><layer3><ip><entry name="10.3.21.1/24"/></ip></layer3><link-speed>40000</link-speed></entry>
      </ethernet></interface>
      <logical-router><entry name="lr-shared"><vrf><entry name="default"><interface><member>ethernet1/5</member><member>ethernet1/6</member><member>ethernet1/7</member><member>ethernet1/8.200</member><member>ethernet1/21</member></interface>
        <routing-table><ip><static-route><entry name="dflt"><destination>0.0.0.0/0</destination><interface>ethernet1/5</interface><nexthop><ip-address>198.51.100.1</ip-address></nexthop></entry></static-route></ip></routing-table>
        <bgp><enable>yes</enable><peer-group><entry name="pg"><peer><entry name="p1"><local-address><interface>ethernet1/21</interface></local-address></entry></peer></entry></peer-group></bgp></entry></vrf></entry></logical-router>
    </network>
    <deviceconfig><system><hostname>SYN-PA5220</hostname><ip-address>10.10.0.20</ip-address><netmask>255.255.255.0</netmask><default-gateway>10.10.0.1</default-gateway></system></deviceconfig>
    <vsys>{vs}</vsys>
  </entry></devices>
</config>
"""

def cfg_pa820():
    return """<?xml version="1.0"?>
<config version="10.1.0" urldb="paloaltonetworks" detail-version="10.1.14">
  <shared/>
  <devices><entry name="localhost.localdomain">
    <network>
      <interface><ethernet>
        <entry name="ethernet1/1"><layer3><dhcp-client><enable>yes</enable></dhcp-client></layer3></entry>
        <entry name="ethernet1/2"><layer3><ip><entry name="10.40.2.1/24"/></ip></layer3></entry>
        <entry name="ethernet1/3"><layer3><ip><entry name="10.40.3.1/24"/></ip></layer3></entry>
        <entry name="ethernet1/5"><layer3><ip><entry name="10.40.5.1/24"/></ip></layer3><comment>fiber to warehouse</comment></entry>
        <entry name="ethernet1/6"><layer3><ip><entry name="10.40.6.1/24"/></ip></layer3><comment>fiber to office 2</comment></entry>
      </ethernet></interface>
      <virtual-router><entry name="default"><interface><member>ethernet1/1</member><member>ethernet1/2</member><member>ethernet1/3</member><member>ethernet1/5</member><member>ethernet1/6</member></interface></entry></virtual-router>
    </network>
    <deviceconfig><system><hostname>SYN-PA820</hostname><ip-address>10.10.0.30</ip-address><netmask>255.255.255.0</netmask><default-gateway>10.10.0.1</default-gateway></system></deviceconfig>
    <vsys><entry name="vsys1"><zone>
      <entry name="untrust"><network><layer3><member>ethernet1/1</member></layer3></network></entry>
      <entry name="trust"><network><layer3><member>ethernet1/2</member><member>ethernet1/3</member><member>ethernet1/5</member><member>ethernet1/6</member></layer3></network></entry>
    </zone><import><network><interface><member>ethernet1/1</member><member>ethernet1/2</member><member>ethernet1/3</member><member>ethernet1/5</member><member>ethernet1/6</member></interface></network></import></entry></vsys>
  </entry></devices>
</config>
"""

# ------------------------------------------------------------------ bundles
def build(name, host, files):
    OUT.mkdir(exist_ok=True)
    p = OUT / name
    import gzip
    with open(p, "wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as gz, tarfile.open(fileobj=gz, mode="w") as tf:
        for fn, text in files:
            tar_add(tf, fn, text)
    print("wrote", p, p.stat().st_size, "bytes")

def pa3220():
    serial = "000000000001"
    lics = "".join([
        lic("Threat Prevention", "Threat Prevention", "Mar 01, 2024", "Mar 01, 2027", "no", serial),
        lic("PAN-DB URL Filtering", "Palo Alto Networks URL Filtering License", "Mar 01, 2024", "Mar 01, 2027", "no", serial),
        lic("WildFire License", "WildFire signature feed, integrated WildFire logs, WildFire API", "Mar 01, 2024", "Mar 01, 2027", "no", serial),
        lic("DNS Security", "Palo Alto Networks DNS Security License", "Mar 01, 2024", "Mar 01, 2027", "no", serial),
        lic("GlobalProtect Gateway", "GlobalProtect Gateway License", "Mar 01, 2024", "Mar 01, 2027", "no", serial),
        lic("SD WAN", "License to enable SD WAN feature", "Mar 01, 2022", "Mar 01, 2023", "yes", serial),
        lic("Premium", "24 x 7 phone support; advanced replacement hardware service", "Mar 01, 2024", "Mar 01, 2027", "no", serial),
    ])
    hw = [("ethernet1/1", 1000, True), ("ethernet1/2", 1000, True), ("ethernet1/3", 1000, True), ("ethernet1/4", 1000, True),
          ("ethernet1/5", 1000, True), ("ethernet1/6", 1000, True), ("ethernet1/7", 1000, False), ("ethernet1/8", 1000, True),
          ("ethernet1/17", 10000, True), ("ethernet1/18", 1000, True), ("ae1", 2000, True)]
    logical = [("ethernet1/1", 1, "untrust", "vr:default", 0, "203.0.113.10/29"), ("ethernet1/2.10", 1, "inside", "vr:default", 10, "10.20.10.1/24"),
               ("ethernet1/17", 1, "dmz", "vr:default", 0, "172.16.50.1/24"), ("ae1", 1, "inside", "vr:default", 0, "10.20.40.1/24")]
    det = []
    types = {"ethernet1/17": ("SFP+", CAP10G, 10000), "ethernet1/18": ("SFP", CAP1GF, 1000), "ethernet1/3": ("SFP", CAP1GF, 1000), "ethernet1/4": ("SFP", CAP1GF, 1000)}
    for n, sp, up in hw:
        if n.startswith("ae"): continue
        pt, cap, spd = types.get(n, ("RJ45", CAP1G, 1000))
        det.append((f"show interface {n}", iface_detail(n, spd, up, pt, cap, "layer3")))
    ctr = counters([("ethernet1/1", 9_500_000_000_000, 2_100_000_000_000), ("ethernet1/2", 2_200_000_000_000, 8_800_000_000_000),
                    ("ethernet1/17", 4_000_000_000_000, 3_000_000_000_000), ("ethernet1/18", 400_000_000_000, 90_000_000_000)])
    ha = """
Group 1:
  Mode: Active-Passive
  Local Information:
    Version: 1
    Mode: Active-Passive
    State: active (last 41 days)
    Device Information:
      Management IPv4 Address: 10.10.0.10/24
  Peer Information:
    Connection status: up
    Version: 1
    Mode: Active-Passive
    State: passive (last 41 days)
    Model: PA-3220
    Build Release: 10.2.10
    Serial Number: 000000000002
"""
    sections = [("show system info", system_info("SYN-PA3220-A", "PA-3220", "3200", serial, "10.2.10")),
                ("request license info", "\n" + lics),
                ("show session info", session_info(999998, 141234, 1650000, 3100, 260000)),
                ("show system environmentals", environmentals([("True", "False"), ("True", "False")])),
                ("show counter interface all", ctr), *det,
                ("show high-availability all", ha),
                ("show interface all", iface_all([(n, sp, up) for n, sp, up in hw], logical)),
                ("show panorama-status", "\nPanorama Server 1 : 10.10.0.50\n    Connected     : yes\n    HA state      : disconnected\n")]
    files = [("tmp/cli/techsupport_SYN-PA3220-A_20261120_1400.txt", cli_file(sections)),
             ("opt/pancfg/mgmt/saved-configs/running-config.xml", cfg_pa3220()),
             ("opt/pancfg/mgmt/saved-configs/.ha-remote-rc.xml", "<config/>"),
             ("var/log/pan/dp-monitor.log", dp_monitor(10, 60, 150000, 1_800_000, 3200, 1)),
             ("var/log/pan/dp-monitor.log.1", dp_monitor(0, 60, 120000, 1_400_000, 2500, 2)),
             ("var/log/pan/mp-monitor.log", "unused\n"),
             ("opt/pancfg/mgmt/tmp/panorama_pushed/newsp.xml", "<config>" + "<x/>" * 100 + "</config>"),
             ("opt/pancfg/mgmt/tmp/panorama_pushed/mergesp.xml", "<config>" + "<x/>" * 100 + "</config>")]
    build("techsupport_pa3220-ha.tgz", "SYN-PA3220-A", files)

def pa5220():
    serial = "000000000005"
    lics = "".join([
        lic("Threat Prevention", "Threat Prevention", "Jan 10, 2025", "Jan 10, 2028", "no", serial),
        lic("Advanced URL Filtering", "Palo Alto Networks Advanced URL License", "Jan 10, 2025", "Jan 10, 2028", "no", serial),
        lic("Virtual Systems", "Virtual Systems 5", "Jan 10, 2025", "Never", "no", serial),
        lic("Standard", "10 x 5 phone support; repair and replace hardware service", "Jan 10, 2025", "Jan 10, 2028", "no", serial),
    ])
    hw = [("ethernet1/5", 1000, True), ("ethernet1/6", 10000, True), ("ethernet1/7", 1000, True), ("ethernet1/8", 1000, True), ("ethernet1/21", 40000, True)]
    det = [(f"show interface {n}", iface_detail(n, sp, up, {"ethernet1/21": "QSFP+"}.get(n, "SFP+"), CAP40G if n == "ethernet1/21" else CAP10G, "layer3")) for n, sp, up in hw]
    sections = [("show system info", system_info("SYN-PA5220", "PA-5220", "5200", serial, "11.1.4", multi="on")),
                ("request license info", "\n" + lics),
                ("show session info", session_info(3999998, 1450000, 6100000, 42000, 900000)), *det,
                ("show high-availability all", "\nHA not enabled\n"),
                ("show system environmentals", environmentals([("True", "False"), ("False", "False")])),
                ("show transceiver-detail all", transceivers([("ethernet1/5", "SFP", "1000BASE-SX", "SYN-SFP1G-SX", "850 nm"), ("ethernet1/6", "SFP+", "10GBASE-LR", "SYN-SFP10-LR", "1310 nm"), ("ethernet1/21", "QSFP+", "40GBASE-SR4", "SYN-QSFP40-SR4", "850 nm")])),
                ("show interface all", iface_all(hw, [])),
                ("show counter interface all", counters([("ethernet1/6", 30_000_000_000_000, 20_000_000_000_000), ("ethernet1/21", 90_000_000_000_000, 70_000_000_000_000)]))]
    files = [("tmp/cli/techsupport_SYN-PA5220_20261120_1400.txt", cli_file(sections)),
             ("opt/pancfg/mgmt/saved-configs/running-config.xml", cfg_pa5220()),
             ("var/log/pan/dp-monitor.log", dp_monitor(8, 72, 1400000, 6_500_000, 45000, 3))]
    build("techsupport_pa5220-multivsys.tgz", "SYN-PA5220", files)

def pa820():
    serial = "000000000008"
    lics = "".join([
        lic("Threat Prevention", "Threat Prevention", "Feb 01, 2022", "Feb 01, 2025", "yes", serial),
        lic("WildFire License", "WildFire signature feed", "Feb 01, 2022", "Feb 01, 2025", "yes", serial),
        lic("Standard", "10 x 5 phone support", "Feb 01, 2022", "Feb 01, 2027", "no", serial),
    ])
    hw = [("ethernet1/1", 1000, True), ("ethernet1/2", 1000, True), ("ethernet1/3", 100, True), ("ethernet1/5", 1000, True), ("ethernet1/6", 1000, False)]
    det = [(f"show interface {n}", iface_detail(n, sp, up, "SFP" if n in ("ethernet1/5", "ethernet1/6") else "RJ45", CAP1GF if n in ("ethernet1/5", "ethernet1/6") else CAP1G, "layer3")) for n, sp, up in hw]
    sections = [("show system info", system_info("SYN-PA820", "PA-820", "800", serial, "10.1.14", uptime="210 days, 1:00:00")),
                ("request license info", "\n" + lics),
                ("show session info", session_info(127998, 21000, 310000, 900, 50000)),
                ("show system environmentals", environmentals([])), *det,
                ("show interface all", iface_all(hw, [])),
                ("show high-availability all", "\nHA not enabled\n")]
    files = [("tmp/cli/techsupport_SYN-PA820_20261120_1400.txt", cli_file(sections)),
             ("opt/pancfg/mgmt/saved-configs/running-config.xml", cfg_pa820())]
    build("techsupport_pa820-small.tgz", "SYN-PA820", files)


# ------------------------------------------------------------------ real-file-shaped bundles
# These two mimic how real exports behave (masked secrets, Panorama-managed VM, banner-only optics),
# using only invented names and documentation-range addresses.
def cfg_pa440_masked():
    return """<?xml version="1.0"?>
<config version="11.1.0" urldb="paloaltonetworks" detail-version="11.1.6">
  <mgt-config>
    <users>
      <entry name="synadmin"><phash>********</phash><permissions><role-based><superuser>yes</superuser></role-based></permissions></entry>
      <entry name="syn-readonly"><phash>********</phash><permissions><role-based><custom><profile>syn-ro</profile></custom></role-based></permissions></entry>
    </users>
    <admin-role><entry name="syn-ro"><role><device><webui>
      <policies><sdwan-rulebase>enable</sdwan-rulebase><security-rulebase>read-only</security-rulebase></policies>
      <network><sdwan-interface-profile>enable</sdwan-interface-profile></network>
    </webui></device></role></entry></admin-role>
  </mgt-config>
  <shared>
    <certificate>
      <entry name="syn-server-cert"><private-key>********</private-key><common-name>syn.example.invalid</common-name></entry>
      <entry name="syn-root-ca"><common-name>Synthetic Root CA</common-name></entry>
      <entry name="syn-root-ca-2"><common-name>Synthetic Root CA 2</common-name></entry>
    </certificate>
  </shared>
  <devices><entry name="localhost.localdomain">
    <network>
      <interface><ethernet>
        <entry name="ethernet1/1"><layer3><ip><entry name="203.0.113.2/30"/></ip><sdwan-link-settings><enable>no</enable></sdwan-link-settings></layer3></entry>
        <entry name="ethernet1/2"><layer3><ip><entry name="10.50.2.1/24"/></ip></layer3></entry>
        <entry name="ethernet1/3"><layer3><ip><entry name="10.50.3.1/24"/></ip></layer3></entry>
      </ethernet></interface>
      <ike><gateway><entry name="syn-gw"><authentication><pre-shared-key><key>********</key></pre-shared-key></authentication><peer-address><ip>198.51.100.9</ip></peer-address></entry></gateway></ike>
      <virtual-router><entry name="default"><interface><member>ethernet1/1</member><member>ethernet1/2</member><member>ethernet1/3</member></interface></entry></virtual-router>
    </network>
    <deviceconfig><system><hostname>SYN-PA440</hostname><ip-address>10.10.0.40</ip-address><netmask>255.255.255.0</netmask><default-gateway>10.10.0.1</default-gateway><route><service><entry name="radius"><source><address>10.10.0.40</address><interface>management</interface></source></entry></service></route></system></deviceconfig>
    <vsys><entry name="vsys1">
      <zone>
        <entry name="untrust"><network><layer3><member>ethernet1/1</member></layer3></network></entry>
        <entry name="trust"><network><layer3><member>ethernet1/2</member><member>ethernet1/3</member></layer3></network></entry>
      </zone>
      <server-profile><radius><entry name="syn-radius"><server><entry name="r1"><ip-address>198.51.100.20</ip-address><secret>********</secret></entry></server></entry></radius></server-profile>
      <rulebase><security><rules>
        <entry name="allow-out"><from><member>trust</member></from><to><member>untrust</member></to><source><member>any</member></source><destination><member>any</member></destination><application><member>any</member></application><service><member>application-default</member></service><action>allow</action></entry>
      </rules></security></rulebase>
      <import><network><interface><member>ethernet1/1</member><member>ethernet1/2</member><member>ethernet1/3</member></interface></network></import>
    </entry></vsys>
  </entry></devices>
</config>
"""

def cfg_vm_local():
    return """<?xml version="1.0"?>
<config version="11.1.0" detail-version="11.1.13"><shared/><devices><entry name="localhost.localdomain">
<deviceconfig><system><hostname>SYN-VM</hostname><panorama-server>10.10.0.80</panorama-server></system></deviceconfig>
<vsys><entry name="vsys1"/></vsys></entry></devices></config>
"""

def cfg_vm_merged():
    return """<?xml version="1.0"?>
<config version="11.1.0" detail-version="11.1.13"><mgt-config><users><entry name="synadmin"><phash>********</phash><permissions><role-based><superuser>yes</superuser></role-based></permissions></entry></users></mgt-config>
<shared/><devices><entry name="localhost.localdomain">
<network>
  <interface><ethernet>
    <entry name="ethernet1/1"><layer3><ip><entry name="10.60.1.1/24"/></ip></layer3></entry>
    <entry name="ethernet1/2"><layer3><ip><entry name="10.60.2.1/24"/></ip></layer3></entry>
    <entry name="ethernet1/3"><layer3><ip><entry name="10.60.3.1/24"/></ip></layer3></entry>
  </ethernet></interface>
  <virtual-router><entry name="default"><interface><member>ethernet1/1</member><member>ethernet1/2</member><member>ethernet1/3</member></interface></entry></virtual-router>
</network>
<deviceconfig><system><hostname>SYN-VM</hostname><panorama-server>10.10.0.80</panorama-server></system></deviceconfig>
<vsys>
  <entry name="vsys1"><zone><entry name="a"><network><layer3><member>ethernet1/1</member></layer3></network></entry><entry name="b"><network><layer3><member>ethernet1/2</member></layer3></network></entry></zone>
  <rulebase><security><rules>
    <entry name="r1"><from><member>a</member></from><to><member>b</member></to><source><member>any</member></source><destination><member>any</member></destination><application><member>any</member></application><service><member>application-default</member></service><action>allow</action></entry>
    <entry name="r2"><from><member>b</member></from><to><member>a</member></to><source><member>any</member></source><destination><member>any</member></destination><application><member>any</member></application><service><member>application-default</member></service><action>allow</action></entry>
  </rules></security></rulebase>
  <import><network><interface><member>ethernet1/1</member><member>ethernet1/2</member></interface></network></import></entry>
  <entry name="vsys2"><zone><entry name="c"><network><layer3><member>ethernet1/3</member></layer3></network></entry></zone>
  <import><network><interface><member>ethernet1/3</member></interface></network></import></entry>
</vsys></entry></devices></config>
"""

def pa440_masked():
    serial = "000000000044"
    lics = "".join([
        lic("Threat Prevention", "Threat Prevention", "Jan 17, 2024", "Jan 17, 2025", "yes", serial),
        lic("Standard", "10 x 5 phone support", "Jan 17, 2024", "Jan 17, 2025", "yes", serial),
    ])
    hw = [("ethernet1/1", 1000, True), ("ethernet1/2", 1000, True), ("ethernet1/3", 1000, False), ("ethernet1/5", 1000, False)]
    det = [(f"show interface {n}", iface_detail(n, sp, up, "RJ45", CAP1G, "layer3")) for n, sp, up in hw]
    banner = "\nTransceiver information is printed per port; none installed.\n"
    sections = [("show system info", system_info("SYN-PA440", "PA-440", "400", serial, "11.1.6-h40", uptime="3 days, 1:00:00")),
                ("request license info", "\n" + lics),
                ("show session info", session_info(64000, 12, 4, 0, 3)),
                ("show system environmentals", environmentals([])), *det,
                ("show transceiver-detail all", banner),
                ("show interface all", iface_all(hw, [])),
                ("show high-availability all", "\nHA not enabled\n")]
    files = [("tmp/cli/techsupport_SYN-PA440_20261120_1400.txt", cli_file(sections)),
             ("opt/pancfg/mgmt/saved-configs/running-config.xml", cfg_pa440_masked()),
             ("opt/pancfg/mgmt/tmp/panorama_pushed/newsp.xml", "<config>55 bytes</config>"[:25]),
             ("opt/pancfg/mgmt/tmp/panorama_pushed/lastsp.xml", "<config/>"),
             ("opt/pancfg/mgmt/tmp/panorama_pushed/mergesp.xml", "<config>" + "<x/>" * 100 + "</config>")]
    build("techsupport_pa440-masked-standalone.tgz", "SYN-PA440", files)

def vm_managed():
    serial = "000000000077"
    lics = "".join([
        lic("Threat Prevention", "Threat Prevention", "Jan 17, 2026", "Jan 17, 2027", "no", serial),
        lic("VM-Series Virtual Systems", "Virtual Systems 2", "Jan 17, 2026", "Never", "no", serial),
    ])
    hw = [("ethernet1/1", 10000, True), ("ethernet1/2", 10000, True), ("ethernet1/3", 10000, True)]
    det = [(f"show interface {n}", iface_detail(n, sp, up, "Ethernet", "auto, 10Gb/s-full", "layer3")) for n, sp, up in hw]
    extra = "vm-mac-base: 00:00:5e:00:53:00\nvm-uuid: 00000000-0000-0000-0000-000000000000\nvm-cpuid: ESX:00000000\nvm-license: VM-SERIES-16\nvm-mode: VMware ESXi\nvm-cap-tier: T3-24GB\nvm-cpu-count: 16\nvm-memory: 33554432 kB"
    sections = [("show system info", system_info("SYN-VM", "PA-VM", "vm", serial, "11.1.13-h17", multi="on", extra=extra)),
                ("request license info", "\n" + lics),
                ("show session info", session_info(2500000, 0, 36, 0, 58)),
                ("show system environmentals", "\nThermal\n"), *det,
                ("show interface all", iface_all(hw, [("ethernet1/1", 1, "a", "vr:default", 0, "10.60.1.1/24")])),
                ("show high-availability all", "\nHA not enabled\n"),
                ("show panorama-status", "\nPanorama Server 1 : 10.10.0.80\n    Connected     : yes\n")]
    files = [("tmp/cli/techsupport_SYN-VM_20261120_1400.txt", cli_file(sections)),
             ("opt/pancfg/mgmt/saved-configs/techsupport-saved-currcfg.xml", cfg_vm_local()),
             ("opt/pancfg/mgmt/saved-configs/.merged-running-config.xml", cfg_vm_merged()),
             ("opt/pancfg/mgmt/tmp/panorama_pushed/newsp.xml", "<config>" + "<x/>" * 100 + "</config>"),
             ("opt/pancfg/mgmt/tmp/panorama_pushed/lastsp.xml", "<config>" + "<x/>" * 100 + "</config>")]
    build("techsupport_vm-managed.tgz", "SYN-VM", files)

if __name__ == "__main__":
    pa3220(); pa5220(); pa820(); pa440_masked(); vm_managed()
    (OUT / "running-config_pa3220-ha.xml").write_text(cfg_pa3220())
    print("wrote", OUT / "running-config_pa3220-ha.xml")
    # the same PA-440 config as a real export would hold it: secrets present, not masked
    (OUT / "running-config_pa440-exported.xml").write_text(cfg_pa440_masked().replace("<phash>********</phash>", "<phash>$5$synsalt$abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG</phash>").replace("<key>********</key>", "<key>-AQ==syntheticpsk==</key>").replace("<secret>********</secret>", "<secret>-AQ==syntheticsecret==</secret>").replace("<private-key>********</private-key>", "<private-key>-----BEGIN SYNTHETIC-----</private-key>"))
