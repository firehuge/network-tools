# Usage: GlobalProtect Log Viewer

## 1. Open the tool
Double-click `gp-log-viewer.html`. It opens in your web browser. It doesn't need internet access, and nothing you load into it is uploaded anywhere.

## 2. Load the log file
Drag the user's **GlobalProtectLogs.zip** (Windows) or **.tgz** (Mac or Linux) onto the dashed box, or click the box to choose the file. You don't need to unzip it first. A large file takes a few seconds to load.

At the bottom of the summary card, the tool lists every file it read. It also lists any it skipped, such as password-protected or binary files.

## 3. Read the summary card
The colored bar at the top shows the **last VPN status** found in the logs:
- 🟢 Connected
- 🔴 Disconnected
- 🟡 Unclear

| Field | What it means |
|---|---|
| Username | Who signed in |
| Local (client) IP | The computer's own network address, for example on home Wi-Fi |
| Public IP | The client's internet address, only when the client logs happen to include it. They usually do **not**. When it's missing, the tool tells you to check the firewall GlobalProtect logs. |
| VPN tunnel IP | The address the VPN gave the computer |
| Portal | The VPN address the user connects to |
| Gateway | The VPN server they actually connected through |
| Last successful login | The last time the VPN connected or signed in OK. Click it to see the log line. |
| Last failure | The last real error, with its reason. Click it to see the log line. |
| Version, OS, Computer name | Useful for tickets |

If a field shows **"Not found in logs"**, the log files don't contain that information. Public IP is called out separately as **"Not recorded in client logs — check the firewall GlobalProtect logs"**, because the client bundle almost never has that address — the firewall does.

## 4. Problem cards
🔴 Red cards are likely to be the cause of the problem. 🟡 Yellow cards are worth knowing about but are often normal. Each card shows how many log lines matched, the time of the last match, and an example line.

**Click a card** to show only its log lines. To go back, click **Show all lines**.

| Card | Meaning | What to try |
|---|---|---|
| Wrong username or password | The sign-in was rejected | Retype the password and check Caps Lock. Check in AD that the account isn't locked or expired. |
| Single sign-on (SAML/SSO) failed | The Okta/Azure sign-in didn't finish, or it timed out | Sign in to the SSO page in a normal browser, then retry. If it keeps happening, the SSO admin should check the SAML app. |
| Cannot reach the VPN portal | The computer couldn't contact the portal (DNS, timeout, refused) | Check that the internet works and the portal address is right. Try a phone hotspot. |
| Security certificate problem | The server certificate wasn't trusted, has expired, or the name doesn't match | Check the PC's date and time. Use the portal name, not an IP. Otherwise the firewall team needs to fix the certificate or the trusted root CA. |
| Client certificate missing | The machine or user certificate wasn't found | Have IT install or renew the certificate. |
| Gateway connection failed | The portal worked, but the gateway didn't | Reconnect or pick another gateway. Otherwise the firewall team should check the gateway. |
| Could not connect to any gateway | Every gateway was tried and all of them failed | Check the network and try a hotspot. Escalate to the firewall team with the log file. |
| Portal address invalid | The portal address is wrong or isn't answering | Check the portal address in the app's settings. |
| HIP (device health) check failed | The security check failed or didn't send (antivirus, patches, encryption) | Turn antivirus on, install updates, and enable disk encryption. Then reconnect. |
| Tunnel problem / fallback to SSL | IPSec failed, so the app used SSL instead | This is usually fine. If the connection is slow, the network team should allow UDP 4501. |
| MFA / one-time code failed | The MFA push or code failed or timed out | Approve the push quickly, or use a fresh code. Check the time on the phone. |
| License / disconnected by server | The session lifetime ran out, or the server ended the session | Reconnect. If it happens often, check the login lifetime and licenses. |
| Saved sign-in expired | The remembered login (auth cookie) was no longer valid | This is normal. Sign in again. |
| No internet / name lookup failed | No internet, DNS failed, or a hotel/airport login page is in the way | Open a website in the browser and finish any Wi-Fi login page. Then reconnect. |
| VPN tunnel went down | The tunnel dropped, or the user was logged out | Reconnect. Note the times, and check Wi-Fi and sleep settings. |
| Network changed | The Wi-Fi or network changed or dropped | This is normal when moving around. If it happens a lot, check the Wi-Fi signal. |

Tip: the **time** on the card helps a lot. A red card from three weeks ago is probably not today's problem. Compare it with the time the user says the problem happened.

## 5. Filters and search
Above the log lines:
- **All files:** show one log file only. The most useful ones are PanGPS.log (the service) and pan_gp_event.log (a short event history).
- **All severities:** show errors only, or errors and warnings. Error rows are red and warning rows are yellow.
- **Search box:** type any word, for example the user's name, `gateway`, `certificate`, or a time like `11:05`.

## 6. Print or save a report
Click **🖨️ Report / PDF**. The printout contains the summary and the problem cards, without the raw log lines. To make a PDF, choose "Save as PDF" in the print window, then attach it to the ticket.

## 7. Limitations
- **No public IP:** GlobalProtect client logs almost never include the user's public internet address. That address is what the gateway/firewall sees as the source of the VPN tunnel. Look it up in the firewall or Panorama GlobalProtect logs (source address), not in this bundle.
- **Times are the user's computer clock**, exactly as written in the logs. They have no time zone.
- **The log view shows up to 5,000 lines at a time.** Use the filters, search, or a problem card to narrow it down. The problem cards always check every line.
- **Problem detection matches known wording** in the logs. A new GlobalProtect version may word errors differently, so if the cards look wrong, check the raw lines.
- **Last status** is the last VPN event in the logs. The app may have reconnected after the logs were collected.
- `.7z` files and password-protected zips aren't supported.
- The rules were tuned on Windows GlobalProtect 6.2 logs. Mac and Linux logs are read, but they were tested less.
