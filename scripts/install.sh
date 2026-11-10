#!/usr/bin/env bash
# Install the vault broker: system user, /opt tree, venv, TLS cert, systemd unit.
#
#   sudo ./scripts/install.sh
#
# Idempotent: re-running upgrades the code and keeps the store and the cert.
set -euo pipefail

SERVICE_USER="${SERVICE_USER:-vaultd}"
PREFIX="${PREFIX:-/opt/hermes-vault-broker}"
STATE="${STATE:-/var/lib/hermes-vault-broker}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root (it creates a system user and installs a unit)" >&2
  exit 1
fi

if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --home-dir "$STATE" --shell /usr/sbin/nologin "$SERVICE_USER"
  echo "created user $SERVICE_USER"
fi

install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_USER" "$STATE"
install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_USER" "$STATE/tls"
install -d -m 0755 "$PREFIX"

# Code: replace the package, keep whatever else lives in PREFIX.
rm -rf "$PREFIX/broker" "$PREFIX/plugin" "$PREFIX/systemd" "$PREFIX/scripts"
cp -r "$HERE/broker" "$HERE/plugin" "$HERE/systemd" "$HERE/scripts" "$HERE/requirements.txt" "$PREFIX/"
chmod -R a+rX "$PREFIX"

if [ ! -x "$PREFIX/venv/bin/python" ]; then
  # The venv interpreter must be reachable by the service user: a venv built
  # from a pyenv/uv interpreter under /root breaks the unit (ProtectHome=yes,
  # status=203/EXEC). System python is the only safe base here.
  "${PYTHON:-/usr/bin/python3}" -m venv "$PREFIX/venv"
fi
"$PREFIX/venv/bin/pip" install --quiet --upgrade pip
"$PREFIX/venv/bin/pip" install --quiet -r "$PREFIX/requirements.txt"

if ! sudo -u "$SERVICE_USER" "$PREFIX/venv/bin/python" -c "import cryptography, websockets" 2>/dev/null; then
  echo "the venv interpreter is not usable by $SERVICE_USER (check its symlink target)" >&2
  exit 1
fi

if [ ! -f "$STATE/tls/server.crt" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
    -keyout "$STATE/tls/server.key" -out "$STATE/tls/server.crt" \
    -subj "/CN=hermes-vault-broker" >/dev/null 2>&1
  chown -R "$SERVICE_USER:$SERVICE_USER" "$STATE/tls"
  chmod 0600 "$STATE/tls/server.key"
  echo "generated self-signed certificate in $STATE/tls"
fi

install -m 0644 "$HERE/systemd/hermes-vault-broker.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now hermes-vault-broker.service

cat <<EOF

Installed.

  1. create the store (asks twice; the passphrase is never stored):
       sudo -u $SERVICE_USER $PREFIX/venv/bin/python -m broker --state $STATE/store.json init

  2. unlock it for this session (one-time HTTPS page, phone friendly):
       sudo -u $SERVICE_USER $PREFIX/venv/bin/python -m broker unlock-form \\
         --cert $STATE/tls/server.crt --key $STATE/tls/server.key \\
         --port 58104 --public-url https://<your-host>:58104

  3. install the Hermes plugin:
       hermes plugins install $HERE/plugin

EOF
