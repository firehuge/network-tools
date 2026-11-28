# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Use GitHub's private vulnerability reporting ("Security" tab, then "Report a vulnerability") on this repository. If that is not available, contact the maintainers at the address listed in the organization profile (TBD: maintainers to publish a security contact).

Include what you found, the version, and steps to reproduce. Do **not** attach real firewall configurations, tech-support files or logs. Redact or synthesize any data first.

We aim to acknowledge reports within 5 business days. (TBD: maintainers to confirm the response targets before launch.)

## Supported versions

Only the latest release is supported.

## Handling of your data

These tools are designed to run locally. The single-page tools (FlowMapper, TSF Reader, GP Log Viewer, PAN Physical Upgrade Planner) keep everything in your
browser and make no network requests. PAAT runs on your own server or container and stores its data (users, change sets, uploaded
backups, audit records) under `/etc/paat` and `/var/lib/paat`; it sends nothing to the maintainers.

Tech-support files, logs and configurations can contain secrets and customer data. Handle them under your organization's policies.
See [LEGAL.md](LEGAL.md), including the requirement that your security team approves the tools before use.
