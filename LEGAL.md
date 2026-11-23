# LEGAL

> **This document is not legal advice.** It describes the terms on which this software is offered. The software is
> licensed under the [Apache License 2.0](LICENSE). See also [NOTICE](NOTICE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

This repository ("network-tools") contains four independent tools: **PAAT**, **FlowMapper**, **TSF Reader** and
**GP Log Viewer**. This document applies to all of them. The Apache License 2.0 is the license that governs use, copying,
modification and distribution of the software. The provisions below are additional terms and notices. If any provision of
this document is unenforceable, the rest remain in effect.

## 1. Use at your own risk; provided AS IS

THE TOOLS, DOCUMENTATION, SAMPLES AND EVERYTHING ELSE IN THIS REPOSITORY ARE PROVIDED **"AS IS", WITHOUT WARRANTY OF ANY KIND**,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, ACCURACY,
NON-INFRINGEMENT AND SECURITY. You use them **at your own risk**. Output (traces, plans, change plans, diagnoses, upgrade
plans) can be wrong or incomplete. Review everything before acting on it.

## 2. No liability

To the maximum extent permitted by law, the authors (Matthew McHugh and network-tools contributors) and any other copyright
holders, maintainers and contributors are **not liable for any damages, outages, security incidents, data loss, or legal issues**
arising from the use of, or inability to use, these tools on any network, whether in contract, tort or otherwise, even if
advised of the possibility. This includes (without limitation) misconfiguration or outage of firewalls, Panorama or other
devices; exposure of configuration or customer data; and regulatory, contractual or licensing consequences.

## 3. Indemnification

To the extent permitted by law, anyone who uses, copies, modifies, distributes or otherwise deals with these tools agrees
**to indemnify and hold harmless the authors** (Matthew McHugh and network-tools contributors) from and against any claims,
damages, losses, costs and expenses (including reasonable legal fees) arising out of or relating to that use, including any
use on a network or with third-party products or data.

## 4. Governing terms; severability

These terms and your use of the tools are **governed by the Apache License 2.0** in [LICENSE](LICENSE). If any provision of
this document or of the license is held unenforceable, the remaining provisions remain in full force and effect.

## 5. Organizations and governments: security review first

**Anyone using these tools to support a corporation, business, or a state, local or federal government must have their
organization's security team review and approve the tools before installing or using them.** That review should cover at least:
the source, the dependencies in section 9, the install method (server or container), network exposure, credential handling,
data retention, and any live-push or OS-upgrade features (which are off by default). Do not install or run them on a
production or customer network until that approval is in writing.

## 6. Licensed products and vendor terms

- **Use only legally licensed versions of Palo Alto Networks products** (firewalls, Panorama, VM-Series, GlobalProtect, and any other
  Palo Alto Networks product or service the tools touch). Do not use these tools with unlicensed, pirated, cracked, expired or
  otherwise unauthorized software or subscriptions.
- **Do not use these tools to violate any Palo Alto Networks terms of service, End User License Agreement (EULA), support
  agreement or other terms**, including terms on automation, API use, scraping, benchmarking, reverse engineering, sharing
  of support files, or redistribution of software, content or documentation.
- The same applies to **every other vendor and service** you use with the tools (other network, cloud, storage, identity and
  ticketing vendors, git hosts, S3-compatible storage, and so on): use only legitimately licensed products and do not use
  the tools in a way that breaks that vendor's terms of service, EULA or support agreement.
- **You are responsible for complying with your own organization's policies, contracts, laws and regulations** and with the
  terms of every vendor whose products or data you touch. That includes data-handling rules for tech-support files (TSFs),
  logs and configurations, which can contain secrets, personal data and customer data. Remove or protect sensitive data
  before sharing any sample or support file.

## 7. Not affiliated; trademarks

These tools are independent projects. They are **not affiliated with, endorsed by, sponsored by or supported by Palo Alto Networks**,
Inc. or any other vendor named in them. "Palo Alto Networks", "PAN-OS", "Panorama", "GlobalProtect", "VM-Series", "App-ID"
and other product names are trademarks or registered trademarks of their respective owners. Names are used only to describe
what the tools work with.

## 8. Data in this repository

The repository contains **synthetic** data only (documentation-range IP addresses such as 192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24 and 2001:db8::/32, private-range examples, and `example.com` names). It does not include any customer's
configuration, logs, support files or credentials. Do not commit yours. The repository's `.gitignore`, the pre-commit hook and
the CI guard exist to help prevent that, but they are not a guarantee.

## 9. Third-party and open-source components

Generated from the actual dependency files (`paat/pyproject.toml`, `paat/requirements.txt`, `tsf-reader/package-lock.json`,
`flowmapper/package-lock.json`, the `Dockerfile` and `docker-compose.yml`) and from `pip-licenses` run against a clean
virtual environment with `pip install ".[web,offsite]"` (runtime) and `".[web,offsite,dev]"` (development). Full license
texts and notices are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). **Licenses are as reported by each package's
metadata; verify before relying on them.**

### Apache-2.0 compatibility

Every Python and npm package listed below is **compatible with the Apache License 2.0** when used as an unmodified
dependency installed from PyPI or npm:

- Permissive licenses (MIT, MIT-0, BSD-2-Clause, BSD-3-Clause, ISC, Apache-2.0, PSF-2.0, and the Python Software Foundation
  License) may be combined with Apache-2.0 without change to this project's license.
- **paramiko** (LGPL-2.1, optional SFTP destination) and **certifi** (MPL-2.0, development only) use weak, file- or
  library-level copyleft. They are used unmodified from their package registries and are compatible with Apache-2.0; those
  copyleft terms apply only to those components, not to this repository. See the notes under 9.1 and 9.2.
- **No Python or npm dependency in this project is licensed under the GPL** (or another license that would require this
  repository to be distributed under the GPL).

Container base images and OS packages pulled at install or build time (section 9.5) are **not redistributed in this
repository**. They include Debian, Alpine and other system packages, some of which are under GPL, LGPL or other licenses.
Those components stay under their own licenses; they do not change the license of this repository's source. Check the image
or OS package copyright files if you redistribute a built container or a packaged install.

If you add a dependency, confirm its license is Apache-2.0-compatible and update this section and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

### 9.1 PAAT: Python packages (runtime: installed by `install.sh` and in the container image)

| Name | Version | License | URL | Relationship |
|---|---|---|---|---|
| PyNaCl | 1.6.2 | Apache Software License | https://github.com/pyca/pynacl | transitive |
| PyYAML | 6.0.4 | MIT License | https://pyyaml.org/ | direct |
| annotated-doc | 0.0.7 | MIT | https://github.com/fastapi/annotated-doc | transitive |
| annotated-types | 0.8.0 | MIT | https://github.com/annotated-types/annotated-types | transitive |
| anyio | 4.16.0 | MIT | https://anyio.readthedocs.io/en/stable/versionhistory.html | transitive |
| attrs | 26.1.0 | MIT | https://www.attrs.org/en/stable/changelog.html | transitive |
| bcrypt | 5.0.0 | Apache Software License | https://github.com/pyca/bcrypt/ | transitive |
| boto3 | 1.44.9 | Apache-2.0 | https://github.com/boto/boto3 | direct |
| botocore | 1.44.9 | Apache-2.0 | https://github.com/boto/botocore | transitive |
| cffi | 2.1.1 | MIT-0 | https://cffi.readthedocs.io/en/latest/whatsnew.html | transitive |
| click | 8.5.1 | BSD-3-Clause | https://github.com/pallets/click/ | transitive |
| cryptography | 50.0.2 | Apache-2.0 OR BSD-3-Clause | https://github.com/pyca/cryptography | transitive |
| defusedxml | 0.7.1 | Python Software Foundation License | https://github.com/tiran/defusedxml | direct |
| et_xmlfile | 2.0.0 | MIT License | https://foss.heptapod.net/openpyxl/et_xmlfile | transitive |
| fastapi | 0.165.0 | MIT | https://github.com/fastapi/fastapi | direct |
| h11 | 0.16.0 | MIT License | https://github.com/python-hyper/h11 | transitive |
| idna | 3.20 | BSD-3-Clause | https://github.com/kjd/idna | transitive |
| invoke | 3.0.3 | BSD-2-Clause | https://github.com/pyinvoke/invoke | transitive |
| jmespath | 1.1.0 | MIT License | https://github.com/jmespath/jmespath.py | transitive |
| jsonschema | 4.26.0 | MIT | https://github.com/python-jsonschema/jsonschema | direct |
| jsonschema-specifications | 2025.9.1 | MIT | https://github.com/python-jsonschema/jsonschema-specifications | transitive |
| openpyxl | 3.1.5 | MIT License | https://openpyxl.readthedocs.io | direct |
| opentelemetry-api | 1.45.2 | Apache-2.0 | https://github.com/open-telemetry/opentelemetry-python/tree/main/opentelemetry-api | transitive |
| pan-os-python | 1.13.1 | ISC License (ISCL) | https://github.com/PaloAltoNetworks/pan-os-python | direct |
| pan-python | 0.17.0 | ISC License (ISCL) | https://github.com/kevinsteves/pan-python | direct |
| paramiko | 5.1.0 | LGPL-2.1 | https://github.com/paramiko/paramiko | direct |
| pycparser | 3.12 | BSD-3-Clause | https://github.com/eliben/pycparser | transitive |
| pydantic | 2.14.4 | MIT | https://github.com/pydantic/pydantic | transitive |
| pydantic_core | 2.50.5 | MIT | https://github.com/pydantic | transitive |
| python-dateutil | 2.9.0.post0 | Apache Software License; BSD License | https://github.com/dateutil/dateutil | transitive |
| python-dotenv | 1.2.4 | BSD-3-Clause | https://github.com/theskumar/python-dotenv | direct |
| python-multipart | 0.0.34 | Apache-2.0 | https://github.com/Kludex/python-multipart | direct |
| referencing | 0.37.0 | MIT | https://github.com/python-jsonschema/referencing | transitive |
| rpds-py | 2026.9.1 | MIT | https://github.com/crate-py/rpds | transitive |
| s3transfer | 0.19.3 | Apache Software License | https://github.com/boto/s3transfer | transitive |
| six | 1.17.0 | MIT License | https://github.com/benjaminp/six | transitive |
| starlette | 1.10.0 | BSD-3-Clause | https://github.com/Kludex/starlette | transitive |
| typing-inspection | 0.4.5 | MIT | https://github.com/pydantic/typing-inspection | transitive |
| typing_extensions | 4.16.0 | PSF-2.0 | https://github.com/python/typing_extensions | transitive |
| tzdata | 2026.6 | Apache-2.0 | https://github.com/python/tzdata | direct |
| urllib3 | 2.8.0 | MIT | https://github.com/urllib3/urllib3/blob/main/CHANGES.rst | transitive |
| uvicorn | 0.54.0 | BSD-3-Clause | https://uvicorn.dev/ | direct |

Notes:

- **paramiko (5.1.0)** is licensed under LGPL-2.1. It is used unmodified, as a dynamically imported PyPI dependency, and
  is not copied into this repository. Used this way, it is compatible with the Apache License 2.0: paramiko itself stays
  under LGPL-2.1, and this project stays under Apache-2.0. It is only needed for the optional SFTP backup destination
  (`pip install ".[offsite]"`).
- `cryptography` is dual-licensed (Apache-2.0 OR BSD-3-Clause); `python-dateutil` is dual-licensed (Apache-2.0 and BSD).
- `pan-os-python` and `pan-python` are third-party community SDKs (ISC). Palo Alto Networks is named as their upstream; that
  does not imply endorsement of this project.
- PAAT itself (package `panlab`) is licensed under Apache-2.0, as is the rest of this repository.

### 9.2 PAAT: development and test only (not installed in the container image, not installed by `install.sh`)

| Name | Version | License | URL |
|---|---|---|---|
| MarkupSafe | 3.0.4 | BSD-3-Clause | https://github.com/pallets/markupsafe/ |
| Pygments | 2.21.0 | BSD-2-Clause | https://pygments.org |
| Werkzeug | 3.1.9 | BSD-3-Clause | https://github.com/pallets/werkzeug/ |
| certifi | 2026.11.20 | Mozilla Public License 2.0 (MPL 2.0) | https://github.com/certifi/python-certifi |
| charset-normalizer | 3.5.3 | MIT | https://github.com/jawah/charset_normalizer/blob/master/CHANGELOG.md |
| httpcore | 1.0.9 | BSD-3-Clause | https://www.encode.io/httpcore/ |
| httpx | 0.28.1 | BSD License | https://github.com/encode/httpx |
| iniconfig | 2.3.1 | MIT | https://github.com/pytest-dev/iniconfig |
| moto | 5.2.6 | Apache-2.0 | https://github.com/getmoto/moto |
| packaging | 26.3 | Apache-2.0 OR BSD-2-Clause | https://github.com/pypa/packaging |
| pluggy | 1.7.0 | MIT License | https://github.com/pytest-dev/pluggy |
| pytest | 9.2.0 | MIT | https://docs.pytest.org/en/latest/ |
| requests | 2.34.2 | Apache Software License | https://github.com/psf/requests |
| responses | 0.26.3 | Apache-2.0 | https://github.com/getsentry/responses |
| xmltodict | 1.0.4 | MIT | https://github.com/martinblech/xmltodict |

Note: `certifi` is MPL-2.0 (file-level copyleft; installed unmodified from PyPI by `moto`/`requests`, development only). MPL-2.0 is compatible with Apache-2.0; the MPL terms apply only to certifi's own files.

### 9.3 npm packages (tests only; not shipped inside any tool)

| Tool | Name | Version | License | URL |
|---|---|---|---|---|
| TSF Reader | playwright-core | 1.65.0 | Apache-2.0 | https://github.com/microsoft/playwright |
| FlowMapper | playwright-core | 1.65.1 | Apache-2.0 | https://github.com/microsoft/playwright |
| GP Log Viewer | *(none; tests run in Node's built-in `vm`)* | | | |

`playwright-core` is a dev dependency that is downloaded by `npm install`; it is **not** committed to or bundled in this
repository. Its own bundled third-party notices ship inside the npm package as `ThirdPartyNotices.txt`.

### 9.4 Vendored, bundled or copied code

| Item | Where | License / status |
|---|---|---|
| FlowMapper engine (`core.js`, `render.js`, `decom.js`) | `flowmapper/build/`, copied verbatim to `paat/vendor/flowmapper/` | Apache-2.0 (this repository). Same project; not third-party. |
| Python port of the FlowMapper engine | `paat/src/panlab/netmodel.py`, `placement.py` | Apache-2.0 (this repository). |
| Single-file HTML tools (`pan-flowmapper.html`, `pan-tsf-triage.html`, `gp-log-viewer.html`) | tool roots | Apache-2.0 (this repository). **No third-party JavaScript, CSS, fonts, icons or images are bundled** (checked: no `<script src>`, `<link href>`, `@font-face` or CDN references; icons are inline SVG drawn for the project; the web GUI uses system fonts). |
| Sample data | `*/samples`, `paat/tests/fixtures` | Synthetic; generated by scripts in the repository. |
| FCR request form (`paat/templates/customer-rule-request-form.xlsx`) | generated by `paat/tools/make_fcr_template.py` (openpyxl) | This repository. |

### 9.5 Container base images and system packages (pulled by you at build time; not redistributed here)

| Image / package | Where used | License (as published) | URL |
|---|---|---|---|
| `docker.io/library/python:3.12-slim-bookworm` | `paat/Dockerfile` (base) | Python: PSF-2.0; Debian bookworm packages: various (GPL/LGPL/BSD/MIT and others; see `/usr/share/doc/*/copyright` in the image) | https://hub.docker.com/_/python |
| `docker.io/library/node:22-bookworm-slim` | `paat/Dockerfile` (only the `node` binary is copied) | Node.js: MIT and the licenses of its bundled dependencies (V8, OpenSSL, ICU, and others) | https://github.com/nodejs/node/blob/main/LICENSE |
| `docker.io/library/nginx:1.27-alpine` | `paat/docker-compose.yml`, optional `tls` profile | nginx: BSD-2-Clause; Alpine packages: various | https://hub.docker.com/_/nginx |
| Node.js (nodejs.org build) | downloaded by `paat/install.sh` if the server has no Node 18+ | MIT and bundled licenses (as above) | https://nodejs.org |
| nginx, openssl, python3, venv, pip | installed by `paat/install.sh` from the OS package manager (apt/dnf) | per OS package | your OS vendor |

### 9.6 Other tools and services referenced

Palo Alto Networks documentation links (for example Applipedia) are links only. No Palo Alto Networks content is copied into the
repository.

