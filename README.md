# network-tools

Practical tools for people who run **Palo Alto Networks** firewalls and Panorama: plan and trace firewall changes, triage
tech-support files, and read GlobalProtect logs. Each tool lives in its own folder with its own README, install and usage guide.

> ## Read first: [LEGAL.md](LEGAL.md) (DRAFT, pending legal review)
>
> - **Use at your own risk. Provided AS IS, without warranty of any kind.** The owner and maintainers are not liable for any damages,
>   outages, security incidents or legal issues arising from use on any network.
> - **Corporations, businesses, and state, local or federal governments:** your organization's **security team must review and approve**
>   these tools before you install or use them.
> - **Use only legally licensed Palo Alto Networks products** (firewalls, Panorama, VM-Series, GlobalProtect, and so on). **Do not use these
>   tools to violate any Palo Alto Networks terms of service, EULA or support agreement**, or the terms of any other vendor.
> - You are responsible for following your own policies and every vendor's terms.
> - Not affiliated with or endorsed by Palo Alto Networks. All trademarks belong to their owners.
> - Third-party credits: [LEGAL.md section 7](LEGAL.md#7-third-party-and-open-source-components) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Tools

| Tool | What it is | How you run it | Docs |
|---|---|---|---|
| [**PAAT**](paat/) | Policy Automation and Analysis Tool: turns a firewall change request (FCR) into a traced, planned, approved and audited change for PAN-OS and Panorama. Web GUI, CLI and API. | Linux server or Docker/Podman container | [README](paat/README.md) · [Install](paat/INSTALL.md) · [Usage](paat/USAGE.md) |
| [**FlowMapper**](flowmapper/) | Offline, single-page flow tracer: load your firewall/Panorama XML configs in the browser, trace a flow hop by hop across vsys and routers, draw diagrams and plan decommissions. Nothing is uploaded. | Open one HTML file in a browser | [README](flowmapper/README.md) · [Install](flowmapper/INSTALL.md) · [Usage](flowmapper/USAGE.md) |
| [**TSF Reader**](tsf-reader/) | Offline triage of a PAN-OS tech-support file (`.tgz`): finds problems and summarizes the device. Nothing is uploaded. | Open one HTML file in a browser | [README](tsf-reader/README.md) · [Install](tsf-reader/INSTALL.md) · [Usage](tsf-reader/USAGE.md) |
| [**GP Log Viewer**](gp-log-viewer/) | Offline viewer for GlobalProtect client logs (`PanGPA`/`PanGPS`): timeline and problem finder. Nothing is uploaded. | Open one HTML file in a browser | [README](gp-log-viewer/README.md) · [Install](gp-log-viewer/INSTALL.md) · [Usage](gp-log-viewer/USAGE.md) |

<!-- To add a tool: add one row above (see CONTRIBUTING.md, "Adding a tool"). -->

## Your data is not included

The repository ships **no customer data and no real devices or logs**. Samples and test fixtures are synthetic (documentation-range
IPs and `example.com` names). A fresh PAAT install is an **empty system**: you create the first admin and then add your own customers,
devices and users. The single-page tools run on files you load yourself.

## Repository layout

```
paat/            PAAT (Python package, web app, Dockerfile, install.sh)
flowmapper/      FlowMapper (single HTML + build + tests)
tsf-reader/      TSF Reader (single HTML + build + tests)
gp-log-viewer/   GP Log Viewer (single HTML + tests)
scripts/         public_guard.py: blocks private addresses, serials and customer markers
.githooks/       pre-commit hook template (enable: git config core.hooksPath .githooks)
.github/         CI: secret scan + guard + per-tool tests (path-filtered)
LEGAL.md  THIRD_PARTY_NOTICES.md  LICENSE  SECURITY.md  CONTRIBUTING.md
```

## Quick start

- **Single-page tools:** download the `.html` file from the tool's folder and open it in a current browser. No install.
- **PAAT:** `cd paat && sudo ./install.sh` on Ubuntu 22.04/24.04 or Rocky/RHEL 9, or `docker compose up -d --build`. See [paat/INSTALL.md](paat/INSTALL.md).

## License

**TBD pending legal review.** See [LICENSE](LICENSE). Until a license is published, no permission to use, copy or distribute is granted.

## Security and contributing

[SECURITY.md](SECURITY.md) · [CONTRIBUTING.md](CONTRIBUTING.md)
