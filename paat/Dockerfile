# SPDX-License-Identifier: Apache-2.0
# PAAT (Policy Automation and Analysis Tool) container image.
# For Palo Alto Networks PAN-OS firewalls and Panorama. Slim, non-root, with Node.js for the shared FlowMapper engine.
#   docker build -t paat .        (or: podman build -t paat .)
# Guide: INSTALL.md
ARG PYTHON_IMAGE=docker.io/library/python:3.12-slim-bookworm
ARG NODE_IMAGE=docker.io/library/node:22-bookworm-slim

FROM ${NODE_IMAGE} AS node

FROM ${PYTHON_IMAGE}
LABEL org.opencontainers.image.title="PAAT" \
      org.opencontainers.image.description="PAAT: Policy Automation and Analysis Tool, for Palo Alto Networks PAN-OS firewalls and Panorama" \
      org.opencontainers.image.licenses="Apache-2.0"

# Node.js runs the vendored FlowMapper path engine (flow tracing). Only the binary is copied.
COPY --from=node /usr/local/bin/node /usr/local/bin/node

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PAAT_ETC_DIR=/etc/paat \
    PAAT_USERS_FILE=/etc/paat/users.yaml \
    PAAT_SESSION_KEY_FILE=/etc/paat/session.key \
    PAAT_CUSTOMERS_DIR=/etc/paat/customers \
    PAAT_DATA_DIR=/var/lib/paat/data \
    PAAT_BACKUPS_DIR=/var/lib/paat/backups \
    PAAT_NODE=/usr/local/bin/node \
    PAAT_PORT=8080

RUN groupadd --system --gid 10001 paat \
 && useradd --system --uid 10001 --gid paat --home-dir /var/lib/paat --no-create-home --shell /usr/sbin/nologin paat \
 && install -d -o paat -g paat -m 700 /etc/paat /etc/paat/customers /var/lib/paat /var/lib/paat/data /var/lib/paat/backups

WORKDIR /opt/paat/app
COPY . .
RUN pip install --no-compile -e ".[web,offsite]" \
 && rm -rf /root/.cache \
 && chmod 755 docker/entrypoint.sh \
 && node --version && python -c "import panlab, fastapi; print('PAAT', panlab.__version__)"

USER paat
EXPOSE 8080
VOLUME ["/etc/paat", "/var/lib/paat/data", "/var/lib/paat/backups"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('PAAT_PORT', '8080'), timeout=4)"]
ENTRYPOINT ["/opt/paat/app/docker/entrypoint.sh"]
CMD ["serve"]
