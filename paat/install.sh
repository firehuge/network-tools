#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# PAAT (Policy Automation and Analysis Tool) server installer.
# For Palo Alto Networks PAN-OS firewalls and Panorama. Supports Ubuntu 22.04/24.04 and RHEL/Rocky/Alma 9.
#
#   sudo ./install.sh                 install or re-run (idempotent; asks for the first admin password)
#   sudo ./install.sh --tls           same, with nginx on HTTPS and a self-signed certificate
#   sudo ./install.sh --upgrade       install the code in this folder over an existing install, keep config/data
#   sudo ./install.sh --uninstall     remove the service, nginx site and /opt/paat; keep config and data
#   sudo ./install.sh --uninstall --purge   also delete /etc/paat, /var/lib/paat and the paat user
#
# Full guide: INSTALL.md. Run ./install.sh --help for every option.
set -euo pipefail
umask 022

PAAT_USER=paat
APP_ROOT=/opt/paat
APP_DIR=$APP_ROOT/app
VENV=$APP_ROOT/venv
NODE_DIR=$APP_ROOT/node
ETC=/etc/paat
VAR=/var/lib/paat
UNIT=/etc/systemd/system/paat.service
STATE=$ETC/install.conf
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

MODE=install YES=0 PURGE=0 TLS="" NGINX=1 HTTP_PORT="" HTTPS_PORT="" APP_PORT="" SERVER_NAME="" ADMIN=""
ADMIN_PW_FILE="" ADMIN_SET="" OPEN_FW=0 SKIP_NODE=0 NODE_MAJOR=22 TLS_CERT="" TLS_KEY=""

usage() {
  cat <<'USAGE'
PAAT installer (Policy Automation and Analysis Tool), for Ubuntu 22.04/24.04 and RHEL/Rocky/Alma 9.

Usage: sudo ./install.sh [options]

Modes (default: install, safe to re-run):
  --upgrade                 Install this folder's code over an existing install. Keeps config, users and data.
  --uninstall               Stop and remove the service, nginx site and /opt/paat. Keeps /etc/paat and /var/lib/paat.
  --purge                   With --uninstall: also delete /etc/paat, /var/lib/paat and the paat user.

Web access:
  --tls                     HTTPS on nginx with a self-signed certificate (HTTP redirects to HTTPS).
  --tls-cert FILE --tls-key FILE   Use your own certificate and key instead of a self-signed one (implies --tls).
  --no-tls                  Plain HTTP (default for a new install; fine on a private management LAN only).
  --server-name NAME        Name for nginx and the certificate (default: this host's FQDN).
  --http-port N / --https-port N   nginx ports (default 80 / 443).
  --app-port N              Local port uvicorn listens on, 127.0.0.1 only (default 8080).
  --no-nginx                Do not install or configure nginx (put your own proxy in front of 127.0.0.1:APP_PORT).
  --open-firewall           Open the web port in ufw or firewalld (otherwise the installer only tells you how).

First admin (only when no users exist yet):
  --admin NAME              Admin user name (default: admin).
  --admin-password-file F   Read the admin password from the first line of F (non-interactive installs).
                            Without it and without a terminal, a random password is written to
                            /etc/paat/INITIAL_ADMIN_PASSWORD (mode 600, never printed).

Other:
  -y, --yes                 Do not ask questions (assume yes; see --admin-password-file).
  --skip-node               Do not install Node.js (flow tracing will be unavailable).
  -h, --help                This help.

Passwords are never echoed, put on a command line, or written to a log.
USAGE
}

say()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '    \033[32mok\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --upgrade) MODE=upgrade ;;
    --uninstall) MODE=uninstall ;;
    --purge) PURGE=1 ;;
    --tls) TLS=1 ;;
    --no-tls) TLS=0 ;;
    --tls-cert) TLS_CERT="${2:?}"; TLS=1; shift ;;
    --tls-key) TLS_KEY="${2:?}"; TLS=1; shift ;;
    --server-name) SERVER_NAME="${2:?}"; shift ;;
    --http-port) HTTP_PORT="${2:?}"; shift ;;
    --https-port) HTTPS_PORT="${2:?}"; shift ;;
    --app-port) APP_PORT="${2:?}"; shift ;;
    --no-nginx) NGINX=0 ;;
    --open-firewall) OPEN_FW=1 ;;
    --admin) ADMIN="${2:?}"; ADMIN_SET=1; shift ;;
    --admin-password-file) ADMIN_PW_FILE="${2:?}"; shift ;;
    -y|--yes) YES=1 ;;
    --skip-node) SKIP_NODE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown option: $1" ;;
  esac
  shift
done

[ "$(id -u)" -eq 0 ] || die "run as root (sudo ./install.sh ...)"
[ "$PURGE" -eq 0 ] || [ "$MODE" = uninstall ] || die "--purge only goes with --uninstall"

# ------------------------------------------------------------------ OS detection
[ -r /etc/os-release ] || die "cannot read /etc/os-release"
# shellcheck disable=SC1091
. /etc/os-release
OS_ID="${ID:-}"; OS_LIKE="${ID_LIKE:-}"; OS_VER="${VERSION_ID:-}"
case " $OS_ID $OS_LIKE " in
  *" ubuntu "*|*" debian "*) FAMILY=debian ;;
  *" rhel "*|*" rocky "*|*" almalinux "*|*" centos "*|*" fedora "*) FAMILY=rhel ;;
  *) die "unsupported OS '$OS_ID $OS_VER' (supported: Ubuntu 22.04/24.04, RHEL/Rocky/Alma 9)" ;;
esac
case "$OS_ID:$OS_VER" in
  ubuntu:22.04|ubuntu:24.04) ;;
  rhel:9*|rocky:9*|almalinux:9*) ;;
  *) warn "$OS_ID $OS_VER is not a tested release; continuing (tested: Ubuntu 22.04/24.04, RHEL/Rocky 9)" ;;
esac

# Saved choices from an earlier run win over defaults (so --upgrade keeps TLS/ports); flags win over both.
if [ -r "$STATE" ]; then
  # shellcheck disable=SC1090
  . "$STATE"
  TLS="${TLS:-${S_TLS:-0}}"; HTTP_PORT="${HTTP_PORT:-${S_HTTP_PORT:-}}"; HTTPS_PORT="${HTTPS_PORT:-${S_HTTPS_PORT:-}}"
  APP_PORT="${APP_PORT:-${S_APP_PORT:-}}"; SERVER_NAME="${SERVER_NAME:-${S_SERVER_NAME:-}}"
  [ "${S_NGINX:-1}" = 1 ] || NGINX=0
fi
TLS="${TLS:-0}"; HTTP_PORT="${HTTP_PORT:-80}"; HTTPS_PORT="${HTTPS_PORT:-443}"; APP_PORT="${APP_PORT:-8080}"
SERVER_NAME="${SERVER_NAME:-$(hostname -f 2>/dev/null || hostname)}"
for p in "$HTTP_PORT" "$HTTPS_PORT" "$APP_PORT"; do
  [[ "$p" =~ ^[0-9]+$ ]] && [ "$p" -ge 1 ] && [ "$p" -le 65535 ] || die "bad port: $p"
done
[[ "$SERVER_NAME" =~ ^[A-Za-z0-9.-]+$ ]] || die "bad --server-name: $SERVER_NAME"
if [ -n "$TLS_CERT$TLS_KEY" ]; then
  [ -r "$TLS_CERT" ] && [ -r "$TLS_KEY" ] || die "--tls-cert and --tls-key must both be readable files"
fi

nginx_site() { if [ "$FAMILY" = debian ]; then echo /etc/nginx/sites-available/paat; else echo /etc/nginx/conf.d/paat.conf; fi; }

# ------------------------------------------------------------------ uninstall
if [ "$MODE" = uninstall ]; then
  say "Uninstalling PAAT"
  if systemctl list-unit-files paat.service >/dev/null 2>&1 && [ -f "$UNIT" ]; then
    systemctl disable --now paat.service >/dev/null 2>&1 || true
  fi
  rm -f "$UNIT"; systemctl daemon-reload || true; ok "service removed"
  site="$(nginx_site)"
  if [ -e "$site" ] || [ -e /etc/nginx/sites-enabled/paat ]; then
    rm -f "$site" /etc/nginx/sites-enabled/paat
    if command -v nginx >/dev/null && nginx -t >/dev/null 2>&1; then systemctl reload nginx 2>/dev/null || true; fi
    ok "nginx site removed (nginx itself is left installed)"
  fi
  rm -rf "$APP_ROOT" /usr/local/bin/paat /usr/bin/paat; ok "removed $APP_ROOT and the paat command"
  if [ "$PURGE" -eq 1 ]; then
    rm -rf "$ETC" "$VAR" /etc/paat-tls; ok "removed $ETC, $VAR and /etc/paat-tls (users, config, data, certificate)"
    if id "$PAAT_USER" >/dev/null 2>&1; then userdel "$PAAT_USER" 2>/dev/null || true; ok "removed user $PAAT_USER"; fi
  else
    echo "    kept $ETC (users, config) and $VAR (data). Remove them with: sudo ./install.sh --uninstall --purge"
  fi
  say "PAAT is uninstalled"
  exit 0
fi

if [ "$MODE" = upgrade ] && [ ! -f "$UNIT" ]; then die "--upgrade: PAAT is not installed here (run without --upgrade first)"; fi
[ -f "$SRC/pyproject.toml" ] && [ -d "$SRC/src/panlab" ] || die "run install.sh from the PAAT source folder ($SRC has no src/panlab)"

# ------------------------------------------------------------------ prerequisites
say "Checking prerequisites ($PRETTY_NAME)"
command -v systemctl >/dev/null && [ -d /run/systemd/system ] || die "systemd is required (for containers use the Dockerfile; see INSTALL.md)"

PKGS_DEB=(python3 python3-venv python3-pip openssl curl ca-certificates tar xz-utils tzdata)
PKGS_RHEL=(openssl curl ca-certificates tar xz tzdata)
[ "$NGINX" -eq 1 ] && PKGS_DEB+=(nginx) && PKGS_RHEL+=(nginx)
if [ "$FAMILY" = debian ]; then
  missing=(); for p in "${PKGS_DEB[@]}"; do dpkg -s "$p" >/dev/null 2>&1 || missing+=("$p"); done
  if [ ${#missing[@]} -gt 0 ]; then
    say "Installing packages: ${missing[*]}"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq && apt-get install -y -qq "${missing[@]}" >/dev/null
  fi
else
  PY_RHEL=python3.11; command -v python3.12 >/dev/null && PY_RHEL=python3.12
  PKGS_RHEL+=("$PY_RHEL" "$PY_RHEL-pip")
  # Rocky/RHEL images ship curl-minimal, which conflicts with the full curl package: keep whichever curl exists.
  missing=(); for p in "${PKGS_RHEL[@]}"; do
    [ "$p" = curl ] && command -v curl >/dev/null 2>&1 && continue
    rpm -q "$p" >/dev/null 2>&1 || missing+=("$p")
  done
  if [ ${#missing[@]} -gt 0 ]; then say "Installing packages: ${missing[*]}"; dnf install -y -q "${missing[@]}" >/dev/null; fi
fi
ok "packages"

PY=""
for c in python3.13 python3.12 python3.11 python3.10 python3; do
  if command -v "$c" >/dev/null && "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then PY="$(command -v "$c")"; break; fi
done
[ -n "$PY" ] || die "Python 3.10 or newer is required"
ok "python: $("$PY" -V 2>&1) ($PY)"

# Node.js >= 18 runs the shared FlowMapper path engine (flow tracing).
NODE_BIN=""
node_ok() { [ -x "$1" ] && "$1" -e 'process.exit(+process.versions.node.split(".")[0] >= 18 ? 0 : 1)' 2>/dev/null; }
if [ "$SKIP_NODE" -eq 0 ]; then
  if node_ok "$NODE_DIR/bin/node"; then NODE_BIN="$NODE_DIR/bin/node"
  elif node_ok "$(command -v node 2>/dev/null || echo /nonexistent)"; then NODE_BIN="$(command -v node)"
  else
    if [ "$FAMILY" = debian ] && [ "$OS_VER" != 22.04 ]; then apt-get install -y -qq nodejs >/dev/null 2>&1 || true
    elif [ "$FAMILY" = rhel ]; then { dnf module -y -q reset nodejs && dnf module -y -q enable "nodejs:$NODE_MAJOR" && dnf install -y -q nodejs; } >/dev/null 2>&1 || true
    fi
    if node_ok "$(command -v node 2>/dev/null || echo /nonexistent)"; then NODE_BIN="$(command -v node)"
    else
      # Official Node.js LTS build, checked against the release's SHASUMS256.txt, into /opt/paat/node.
      arch="$(uname -m)"; case "$arch" in x86_64) narch=x64 ;; aarch64) narch=arm64 ;; *) die "no Node.js build for $arch; use --skip-node" ;; esac
      base="https://nodejs.org/dist/latest-v${NODE_MAJOR}.x"
      say "Downloading Node.js ${NODE_MAJOR} LTS ($narch) from nodejs.org"
      tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
      curl -fsSL "$base/SHASUMS256.txt" -o "$tmp/SHASUMS256.txt"
      file="$(grep -oE "node-v[0-9.]+-linux-${narch}\.tar\.xz" "$tmp/SHASUMS256.txt" | head -1)"
      [ -n "$file" ] || die "could not find a Node.js $NODE_MAJOR build in $base"
      curl -fsSL "$base/$file" -o "$tmp/$file"
      (cd "$tmp" && grep " $file\$" SHASUMS256.txt | sha256sum -c --quiet -) || die "Node.js checksum mismatch"
      rm -rf "$NODE_DIR.new"; mkdir -p "$NODE_DIR.new"
      tar -xJf "$tmp/$file" -C "$NODE_DIR.new" --strip-components=1
      rm -rf "$NODE_DIR"; mv "$NODE_DIR.new" "$NODE_DIR"
      NODE_BIN="$NODE_DIR/bin/node"
    fi
  fi
  node_ok "$NODE_BIN" || die "Node.js 18+ is required for flow tracing (or use --skip-node)"
  ok "node: $("$NODE_BIN" --version) ($NODE_BIN)"
else
  warn "--skip-node: flow tracing will show an error until Node.js 18+ is installed"
fi

# ------------------------------------------------------------------ user and folders
if ! id "$PAAT_USER" >/dev/null 2>&1; then
  useradd --system --home-dir "$VAR" --shell "$(command -v nologin || echo /sbin/nologin)" --user-group "$PAAT_USER"
  ok "created service user $PAAT_USER"
fi
install -d -m 755 -o root -g root "$APP_ROOT"
install -d -m 700 -o "$PAAT_USER" -g "$PAAT_USER" "$ETC" "$ETC/customers" "$VAR" "$VAR/data" "$VAR/backups"
ok "folders: $APP_ROOT (code, root-owned), $ETC (config), $VAR (data)"

# ------------------------------------------------------------------ code and venv
CUR_VER="$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$APP_DIR/src/panlab/__init__.py" 2>/dev/null || true)"
NEW_VER="$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$SRC/src/panlab/__init__.py")"
if [ "$(readlink -f "$SRC")" != "$(readlink -f "$APP_DIR" 2>/dev/null || echo none)" ]; then
  say "Copying PAAT $NEW_VER into $APP_DIR${CUR_VER:+ (was $CUR_VER)}"
  rm -rf "$APP_DIR.new"; mkdir -p "$APP_DIR.new"
  tar -C "$SRC" --exclude=.git --exclude=venv --exclude=.venv --exclude=__pycache__ --exclude='*.egg-info' \
      --exclude=.pytest_cache --exclude='backups/*' --exclude=data -cf - . | tar -C "$APP_DIR.new" -xf -
  chown -R root:root "$APP_DIR.new"; chmod -R go-w "$APP_DIR.new"
  rm -rf "$APP_ROOT/app.prev"
  [ -d "$APP_DIR" ] && mv "$APP_DIR" "$APP_ROOT/app.prev"
  mv "$APP_DIR.new" "$APP_DIR"
fi
if [ -x "$VENV/bin/python" ] && ! "$VENV/bin/python" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then rm -rf "$VENV"; fi
[ -x "$VENV/bin/python" ] || { "$PY" -m venv "$VENV"; ok "created venv $VENV"; }
say "Installing Python packages (this can take a minute)"
"$VENV/bin/pip" install -q --disable-pip-version-check --upgrade pip 'setuptools>=68' wheel
"$VENV/bin/pip" install -q --disable-pip-version-check -e "${APP_DIR}[web,offsite]"
# `paat` on the PATH: loads /etc/paat/paat.env and always runs as the paat user (so files keep the right owner).
cat > /usr/local/bin/paat <<'WRAPEOF'
#!/bin/bash
# PAAT command (written by install.sh). Runs as the paat service user with /etc/paat/paat.env loaded.
if [ "$(id -un)" != paat ]; then
  [ "$(id -u)" -eq 0 ] || { echo "Run PAAT commands with sudo:  sudo paat $*" >&2; exit 1; }
  exec runuser -u paat -- "$0" "$@"
fi
set -a; . /etc/paat/paat.env; set +a
exec /opt/paat/venv/bin/paat "$@"
WRAPEOF
chmod 755 /usr/local/bin/paat
ln -sf /usr/local/bin/paat /usr/bin/paat   # RHEL's sudo secure_path does not include /usr/local/bin
ok "PAAT $("$VENV/bin/python" -c 'import panlab; print(panlab.__version__)') installed; run admin commands as: sudo paat --help"

# ------------------------------------------------------------------ config
if [ ! -f "$ETC/paat.env" ]; then
  {
    echo "# PAAT settings (read by the paat service). PAAT_* and PANLAB_* names both work."
    echo "PAAT_ETC_DIR=$ETC"
    echo "PAAT_DATA_DIR=$VAR/data"
    echo "PAAT_BACKUPS_DIR=$VAR/backups"
    echo "PAAT_CUSTOMERS_DIR=$ETC/customers"
    echo "PAAT_USERS_FILE=$ETC/users.yaml"
    echo "PAAT_SESSION_KEY_FILE=$ETC/session.key"
    echo "# Live OS upgrades stay off until an admin sets this to 1:"
    echo "# PAAT_UPGRADE_EXECUTE=1"
  } > "$ETC/paat.env"
  ok "wrote $ETC/paat.env"
fi
if [ -n "$NODE_BIN" ]; then
  if grep -q '^PAAT_NODE=' "$ETC/paat.env"; then sed -i "s|^PAAT_NODE=.*|PAAT_NODE=$NODE_BIN|" "$ETC/paat.env"; else echo "PAAT_NODE=$NODE_BIN" >> "$ETC/paat.env"; fi
fi
if [ ! -s "$ETC/session.key" ]; then
  (umask 077; head -c 48 /dev/urandom | base64 > "$ETC/session.key"); ok "created session key"
fi
# No customers are created: a new server is empty. Add your own profiles to $ETC/customers (see INSTALL.md).
chown -R "$PAAT_USER:$PAAT_USER" "$ETC" "$VAR"
chmod 600 "$ETC/paat.env" "$ETC/session.key"

# ------------------------------------------------------------------ systemd unit
cat > "$UNIT.new" <<UNITEOF
# Written by PAAT install.sh. Re-run the installer to change it.
[Unit]
Description=PAAT - Policy Automation and Analysis Tool (web GUI)
Documentation=file://$APP_DIR/INSTALL.md
After=network-online.target
Wants=network-online.target

[Service]
User=$PAAT_USER
Group=$PAAT_USER
EnvironmentFile=$ETC/paat.env
WorkingDirectory=$VAR
ExecStart=$VENV/bin/uvicorn panlab.web.app:app --host 127.0.0.1 --port $APP_PORT --proxy-headers --timeout-keep-alive 5
Restart=on-failure
RestartSec=3
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$ETC $VAR
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
UMask=0077

[Install]
WantedBy=multi-user.target
UNITEOF
mv "$UNIT.new" "$UNIT"; chmod 644 "$UNIT"
systemctl daemon-reload
ok "systemd unit $UNIT"

# ------------------------------------------------------------------ first admin
as_paat() { runuser -u "$PAAT_USER" -- bash -c 'set -a; . /etc/paat/paat.env; set +a; exec "$@"' _ "$@"; }
have_users="$(as_paat "$VENV/bin/python" -c 'from panlab.web import auth; print(len(auth.load_users()))' 2>/dev/null || echo 0)"
if [ "${have_users:-0}" -gt 0 ]; then
  ok "users file already has $have_users user(s); not touching it"
else
  ADMIN="${ADMIN:-admin}"
  [[ "$ADMIN" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || die "bad --admin name"
  if [ -n "$ADMIN_PW_FILE" ]; then
    [ -r "$ADMIN_PW_FILE" ] || die "cannot read $ADMIN_PW_FILE"
    head -n1 "$ADMIN_PW_FILE" | as_paat "$VENV/bin/paat" users add "$ADMIN" --role admin --password-stdin >/dev/null
    ok "created admin '$ADMIN' (password from $ADMIN_PW_FILE)"
  elif [ "$YES" -eq 0 ] && [ -t 0 ]; then
    say "Create the first PAAT admin"
    if [ -z "$ADMIN_SET" ]; then read -r -p "    Admin user name [$ADMIN]: " a || true; ADMIN="${a:-$ADMIN}"; fi
    [[ "$ADMIN" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || die "bad admin name"
    for _try in 1 2 3; do
      read -r -s -p "    Password (12+ characters, not shown): " pw1; echo
      read -r -s -p "    Same password again: " pw2; echo
      if [ "$pw1" != "$pw2" ]; then warn "the passwords did not match"; continue; fi
      if [ "${#pw1}" -lt 12 ]; then warn "use at least 12 characters"; continue; fi
      break
    done
    [ "${pw1:-}" = "${pw2:-x}" ] && [ "${#pw1}" -ge 12 ] || { unset pw1 pw2; die "no admin created; re-run the installer"; }
    printf '%s\n' "$pw1" | as_paat "$VENV/bin/paat" users add "$ADMIN" --role admin --password-stdin >/dev/null
    unset pw1 pw2
    ok "created admin '$ADMIN'"
  else
    rm -f "$ETC/INITIAL_ADMIN_PASSWORD"
    as_paat "$VENV/bin/paat" users add "$ADMIN" --role admin --password-file "$ETC/INITIAL_ADMIN_PASSWORD" >/dev/null
    ok "created admin '$ADMIN'; its random password is in $ETC/INITIAL_ADMIN_PASSWORD (mode 600; read it with sudo, then delete it)"
  fi
fi

# ------------------------------------------------------------------ nginx
SCHEME=http; WEB_PORT="$HTTP_PORT"
if [ "$NGINX" -eq 1 ]; then
  site="$(nginx_site)"
  if [ "$TLS" = 1 ]; then
    SCHEME=https; WEB_PORT="$HTTPS_PORT"
    install -d -m 755 -o root -g root /etc/paat-tls
    if [ -n "$TLS_CERT" ]; then
      install -m 644 "$TLS_CERT" /etc/paat-tls/paat.crt; install -m 600 "$TLS_KEY" /etc/paat-tls/paat.key
      ok "installed your TLS certificate"
    elif [ ! -s /etc/paat-tls/paat.crt ]; then
      altnames="DNS:$SERVER_NAME,DNS:localhost,IP:127.0.0.1"
      for ip in $(hostname -I 2>/dev/null); do [[ "$ip" =~ ^[0-9.]+$ ]] && altnames="$altnames,IP:$ip"; done
      (umask 077; openssl req -x509 -newkey rsa:3072 -nodes -days 825 -sha256 -subj "/CN=$SERVER_NAME/O=PAAT self-signed" \
        -addext "subjectAltName=$altnames" -keyout /etc/paat-tls/paat.key -out /etc/paat-tls/paat.crt 2>/dev/null)
      chmod 644 /etc/paat-tls/paat.crt
      ok "self-signed certificate for $SERVER_NAME (valid 825 days): /etc/paat-tls/paat.crt"
    fi
    command -v restorecon >/dev/null && restorecon -R /etc/paat-tls 2>/dev/null || true
  fi
  proxy="    location / {
        proxy_pass http://127.0.0.1:$APP_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 900s;  # pushes and upgrades can take minutes
    }"
  {
    echo "# PAAT (Policy Automation and Analysis Tool). Written by install.sh; re-run it to change this file."
    if [ "$TLS" = 1 ]; then
      echo "server {"
      echo "    listen $HTTP_PORT; listen [::]:$HTTP_PORT;"
      echo "    server_name $SERVER_NAME _;"
      echo "    location = /healthz { proxy_pass http://127.0.0.1:$APP_PORT; }"
      echo "    location / { return 301 https://\$host:$HTTPS_PORT\$request_uri; }"
      echo "}"
      echo "server {"
      echo "    listen $HTTPS_PORT ssl; listen [::]:$HTTPS_PORT ssl;"
      echo "    server_name $SERVER_NAME _;"
      echo "    ssl_certificate /etc/paat-tls/paat.crt;"
      echo "    ssl_certificate_key /etc/paat-tls/paat.key;"
      echo "    ssl_protocols TLSv1.2 TLSv1.3;"
      echo "    add_header Strict-Transport-Security \"max-age=31536000\" always;"
    else
      echo "server {"
      echo "    listen $HTTP_PORT; listen [::]:$HTTP_PORT;"
      echo "    server_name $SERVER_NAME _;"
    fi
    echo "    client_max_body_size 200m;  # backup XML / tgz uploads"
    echo "    add_header X-Content-Type-Options nosniff always;"
    echo "    add_header X-Frame-Options SAMEORIGIN always;"
    echo "$proxy"
    echo "}"
  } > "$site.new"
  mv "$site.new" "$site"
  if [ "$FAMILY" = debian ]; then
    ln -sf "$site" /etc/nginx/sites-enabled/paat
    # The stock "Welcome to nginx" site would win port 80; disable it only if it is the untouched default.
    if [ -L /etc/nginx/sites-enabled/default ] && [ "$HTTP_PORT" = 80 ]; then rm -f /etc/nginx/sites-enabled/default; ok "disabled the stock nginx default site"; fi
  else
    # RHEL's nginx.conf has a built-in port-80 server; conf.d is read first, so PAAT answers by IP as well.
    if command -v getenforce >/dev/null && [ "$(getenforce)" = Enforcing ]; then
      setsebool -P httpd_can_network_connect 1 && ok "SELinux: allowed nginx to reach 127.0.0.1:$APP_PORT"
      if command -v semanage >/dev/null; then
        for p in "$HTTP_PORT" "$HTTPS_PORT"; do semanage port -a -t http_port_t -p tcp "$p" 2>/dev/null || true; done
      fi
    fi
  fi
  nginx -t >/dev/null 2>&1 || { nginx -t; die "nginx config test failed (see above)"; }
  systemctl enable --now nginx >/dev/null 2>&1
  systemctl reload nginx
  ok "nginx: $SCHEME on port $WEB_PORT -> 127.0.0.1:$APP_PORT ($site)"
fi

# ------------------------------------------------------------------ start / restart
if systemctl is-active --quiet paat && [ "${FORCE_RESTART:-0}" != 1 ]; then
  if ! as_paat "$VENV/bin/python" -m panlab.activity; then
    warn "PAAT is busy (an upgrade step or a push is running); not restarting. Re-run when idle, or FORCE_RESTART=1."
    exit 1
  fi
fi
systemctl enable paat >/dev/null 2>&1
systemctl restart paat
up=0; for _ in $(seq 1 30); do curl -fsS "http://127.0.0.1:$APP_PORT/healthz" >/dev/null 2>&1 && { up=1; break; }; sleep 1; done
[ "$up" -eq 1 ] || { journalctl -u paat -n 30 --no-pager >&2 || true; die "PAAT did not answer on 127.0.0.1:$APP_PORT/healthz"; }
ok "paat service is running (healthz ok)"
if [ "$NGINX" -eq 1 ]; then
  curl -fsSk "$SCHEME://127.0.0.1:$WEB_PORT/healthz" >/dev/null || die "nginx is not passing requests to PAAT ($SCHEME://127.0.0.1:$WEB_PORT/healthz)"
  ok "nginx -> PAAT ok ($SCHEME://127.0.0.1:$WEB_PORT/healthz)"
fi

# Remember choices for --upgrade and re-runs.
cat > "$STATE" <<STATEEOF
# PAAT install.sh choices (sourced by the next run). Edit by re-running install.sh with flags.
S_VERSION=$NEW_VER
S_TLS=$TLS
S_NGINX=$NGINX
S_HTTP_PORT=$HTTP_PORT
S_HTTPS_PORT=$HTTPS_PORT
S_APP_PORT=$APP_PORT
S_SERVER_NAME=$SERVER_NAME
STATEEOF
chown "$PAAT_USER:$PAAT_USER" "$STATE"; chmod 600 "$STATE"

# ------------------------------------------------------------------ host firewall
fw_port="$WEB_PORT"; [ "$NGINX" -eq 1 ] || fw_port=""
if [ -n "$fw_port" ]; then
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
    if [ "$OPEN_FW" -eq 1 ]; then ufw allow "$fw_port/tcp" >/dev/null; [ "$TLS" = 1 ] && ufw allow "$HTTP_PORT/tcp" >/dev/null; ok "ufw: opened $fw_port/tcp"
    else echo "    firewall: ufw is active. Open the web port with:  sudo ufw allow $fw_port/tcp"; fi
  elif systemctl is-active --quiet firewalld 2>/dev/null; then
    if [ "$OPEN_FW" -eq 1 ]; then firewall-cmd -q --permanent --add-port="$fw_port/tcp" && firewall-cmd -q --reload; ok "firewalld: opened $fw_port/tcp"
    else echo "    firewall: firewalld is active. Open the web port with:  sudo firewall-cmd --permanent --add-port=$fw_port/tcp && sudo firewall-cmd --reload"; fi
  else
    echo "    firewall: no ufw/firewalld found active; make sure TCP $fw_port is reachable from your users' network."
  fi
fi

ip1="$(hostname -I 2>/dev/null | awk '{print $1}')"
portpart=""; { [ "$SCHEME" = http ] && [ "$WEB_PORT" != 80 ]; } || { [ "$SCHEME" = https ] && [ "$WEB_PORT" != 443 ]; } && portpart=":$WEB_PORT"
say "PAAT $NEW_VER is ready"
if [ "$NGINX" -eq 1 ]; then echo "    Open: $SCHEME://${ip1:-$SERVER_NAME}$portpart/   (or $SCHEME://$SERVER_NAME$portpart/)"; else echo "    PAAT listens on 127.0.0.1:$APP_PORT; point your reverse proxy at it."; fi
[ "$TLS" = 1 ] && [ -z "$TLS_CERT" ] && echo "    The certificate is self-signed: your browser will warn once. Replace it with --tls-cert/--tls-key."
echo "    Config: $ETC/paat.env   Data: $VAR   Logs: journalctl -u paat   Upgrade: sudo ./install.sh --upgrade"
