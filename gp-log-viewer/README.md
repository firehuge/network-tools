# GlobalProtect Log Viewer

> **Read [../LEGAL.md](../LEGAL.md) first (draft).** Provided AS IS, no warranty; use only legally licensed Palo Alto Networks products and do not use it to violate any vendor terms; organizations must have their security team approve it before use. Not affiliated with Palo Alto Networks.

A single web page that reads the log bundle from the Palo Alto Networks **GlobalProtect** VPN app and tells you, in plain English, what went wrong.

## What it does
- **Summary card:** username, local IP, VPN tunnel IP, portal, gateway, last successful login, last failure and its reason, app version, OS and computer name.
- **Problems found:** a red or yellow card per issue (wrong password, SSO/SAML failure, portal unreachable, certificate errors, gateway failures, HIP check failures, IPSec fallback to SSL, MFA failures, expired sessions, DNS or no internet, tunnel drops, network changes), each with what it means and what to try.
- **All log lines:** every log file merged into one timeline, filterable and searchable.
- **Report:** print or save the summary as PDF.

## Privacy
It runs entirely in your browser. It works offline, has no server and uploads nothing.

## Quick start
1. Open `gp-log-viewer.html` in Chrome, Edge, Firefox or Safari (double-click it).
2. Drag a GlobalProtect log bundle onto the page (`.zip`, `.tgz`, `.tar.gz`, `.log`, `.txt`).
3. Read the summary and problem cards.

To try it, load `samples/GlobalProtectLogs.tgz` (synthetic data).

## Documentation
- [Install](INSTALL.md)
- [Usage and problem-card reference](USAGE.md)
- [How end users collect logs](docs/collect-logs.md)

## Development
```
node tests/test_viewer.mjs          # tests, Node 18+, no dependencies
python3 scripts/make_samples.py     # regenerate the synthetic samples
```
