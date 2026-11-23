#!/bin/sh
# Make a self-signed certificate for the compose TLS profile: docker/tls/paat.crt and paat.key.
# usage: docker/make-self-signed-cert.sh [server-name]
set -eu
NAME="${1:-$(hostname -f 2>/dev/null || hostname)}"
DIR="$(cd "$(dirname "$0")" && pwd)/tls"
mkdir -p "$DIR"
[ -s "$DIR/paat.crt" ] && { echo "already exists: $DIR/paat.crt (delete it to make a new one)"; exit 0; }
(umask 077; openssl req -x509 -newkey rsa:3072 -nodes -days 825 -sha256 -subj "/CN=$NAME/O=PAAT self-signed" \
  -addext "subjectAltName=DNS:$NAME,DNS:localhost,IP:127.0.0.1" -keyout "$DIR/paat.key" -out "$DIR/paat.crt" 2>/dev/null)
chmod 644 "$DIR/paat.crt"; chmod 644 "$DIR/paat.key"  # nginx in the container reads it as its own user
echo "wrote $DIR/paat.crt and paat.key for $NAME (self-signed; browsers will warn once)"
