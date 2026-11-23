# Contributing

Thanks for helping. A few rules keep this project safe to publish.

## Never include customer or production data

Do **not** put any of the following in a commit, issue, pull request, comment or screenshot:

- real firewall or Panorama configuration exports, tech-support files, or logs;
- real hostnames, serial numbers, public or private IP addresses, customer or agency names;
- credentials, API keys, certificates, tokens.

Use made-up data. For addresses use the documentation ranges `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` and `2001:db8::/32`; for names use `example.com`. Serial numbers in tests must be obviously fake (for example `007000000001`).

## Set up

```
git clone <your fork>
cd <repo>
git config core.hooksPath .githooks     # enables the pre-commit guard
# PAAT:            cd paat && pip install -e ".[web,offsite,dev]" && pytest
# FlowMapper:      cd flowmapper && npm ci && npm test     (needs Google Chrome or Chromium; set CHROME_PATH if needed)
# TSF Reader:      cd tsf-reader && npm ci && npm test
# GP Log Viewer:   cd gp-log-viewer && node tests/test_viewer.mjs
```

The pre-commit hook runs `scripts/public_guard.py`, which blocks private addresses (192.168.x.x), serial-like numbers, personal e-mail addresses and any customer words listed in your private `~/.public-guard-terms` file (one word or regex per line; keep that file out of the repository).

## Pull requests

- Keep changes focused and add or update a test.
- Run the test suite before you open the PR.
- By contributing you agree your contribution may be distributed under this project's license (see `LICENSE`; the license is still to be decided: TBD pending legal review). A DCO or CLA may be required, to be decided by the maintainers.
- Be respectful. A code of conduct will be added before the public launch.

## Adding a tool

Add a folder at the top level with its own `README.md`, `INSTALL.md`, `USAGE.md`, source, and tests that use only synthetic
data. Then add a row to the **Tools** table in the top-level `README.md`, a path filter and test job in `.github/workflows/ci.yml`,
the tool's dependencies to `LEGAL.md` and `THIRD_PARTY_NOTICES.md`, and its folder to `private_ok_paths` in `.public-guard.json` if it uses
10.x/172.16-31.x example addresses.

## FlowMapper engine and PAAT

`paat/vendor/flowmapper/` is a copy of `flowmapper/build/{core,render,decom}.js`. Change the engine in `flowmapper/build/`, then run
`python3 paat/tools/sync-flowmapper.py` (CI runs `--check`).
