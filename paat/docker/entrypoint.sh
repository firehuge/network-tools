#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# PAAT container entrypoint: first-start setup, then the web app (or any paat command).
#   serve (default)      start the web GUI on 0.0.0.0:$PAAT_PORT
#   paat <args>          run a PAAT command, e.g.  docker compose exec paat paat users list
# Secrets come from files (Docker/Podman secrets) or environment variables; they are never printed.
set -eu
ETC="${PAAT_ETC_DIR:-/etc/paat}"

if [ "${1:-serve}" = paat ]; then shift; exec paat "$@"; fi
if [ "${1:-serve}" != serve ]; then exec "$@"; fi

mkdir -p "$ETC/customers" "$PAAT_DATA_DIR" "$PAAT_BACKUPS_DIR"

# Session signing key: a mounted secret (PAAT_SESSION_KEY_FILE) or one generated once into the config volume.
if [ ! -s "$PAAT_SESSION_KEY_FILE" ]; then
  case "$PAAT_SESSION_KEY_FILE" in
    "$ETC"/*) (umask 077; head -c 48 /dev/urandom | base64 > "$PAAT_SESSION_KEY_FILE"); echo "paat: created session key in the config volume" ;;
    *) echo "paat: PAAT_SESSION_KEY_FILE=$PAAT_SESSION_KEY_FILE is missing or empty" >&2; exit 1 ;;
  esac
fi

# No customers are created: a new container is an empty system. Add profiles to $ETC/customers (see INSTALL.md).

# First admin, only when there are no users yet.
n="$(python -c 'from panlab.web import auth; print(len(auth.load_users()))')"
if [ "$n" = 0 ]; then
  user="${PAAT_ADMIN_USER:-admin}"
  if [ -n "${PAAT_ADMIN_PASSWORD_FILE:-}" ] && [ -e "$PAAT_ADMIN_PASSWORD_FILE" ] && [ ! -r "$PAAT_ADMIN_PASSWORD_FILE" ]; then
    echo "paat: cannot read $PAAT_ADMIN_PASSWORD_FILE as uid $(id -u). On the host run:" >&2
    echo "      sudo chown 10001 docker/secrets/admin_password.txt && sudo chmod 400 docker/secrets/admin_password.txt" >&2
    echo "      (rootless Podman: podman unshare chown 10001 docker/secrets/admin_password.txt && chmod 400 docker/secrets/admin_password.txt)" >&2
    exit 1
  fi
  if [ -n "${PAAT_ADMIN_PASSWORD_FILE:-}" ] && [ -s "$PAAT_ADMIN_PASSWORD_FILE" ]; then
    head -n1 "$PAAT_ADMIN_PASSWORD_FILE" | paat users add "$user" --role admin --password-stdin >/dev/null
    echo "paat: created admin '$user' from PAAT_ADMIN_PASSWORD_FILE"
  elif [ -n "${PAAT_ADMIN_PASSWORD:-}" ]; then
    printf '%s\n' "$PAAT_ADMIN_PASSWORD" | paat users add "$user" --role admin --password-stdin >/dev/null
    echo "paat: created admin '$user' from PAAT_ADMIN_PASSWORD (prefer a secret file)"
  else
    paat users add "$user" --role admin --password-file "$ETC/INITIAL_ADMIN_PASSWORD" >/dev/null
    echo "paat: created admin '$user'; random password in $ETC/INITIAL_ADMIN_PASSWORD (read it with: docker compose exec paat cat $ETC/INITIAL_ADMIN_PASSWORD)"
  fi
fi
unset PAAT_ADMIN_PASSWORD

echo "paat: PAAT $(python -c 'import panlab; print(panlab.__version__)') listening on 0.0.0.0:${PAAT_PORT}"
exec uvicorn panlab.web.app:app --host 0.0.0.0 --port "${PAAT_PORT}" --proxy-headers \
  --forwarded-allow-ips "${PAAT_FORWARDED_ALLOW_IPS:-127.0.0.1}" --timeout-keep-alive 5
