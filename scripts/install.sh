#!/usr/bin/env bash
# Install the vault broker: system user, /opt tree, venv, TLS cert, systemd unit.
#
#   sudo HERMES_USER=<gateway-user> ./scripts/install.sh
#
# Idempotent: re-running upgrades the code and keeps the store, cert and the
# operator's cdp.json. HERMES_USER defaults to $SUDO_USER.
set -euo pipefail

SERVICE_USER="${SERVICE_USER:-vaultd}"
PREFIX="${PREFIX:-/opt/hermes-vault-broker}"
STATE="${STATE:-/var/lib/hermes-vault-broker}"
ETC="${ETC:-/etc/hermes-vault-broker}"
# The user that runs the Hermes gateway. It gets status/list/fill only, and
# is added to the broker's group so it can open the 0660 socket.
HERMES_USER="${HERMES_USER:-${SUDO_USER:-}}"
CDP_HOST="${CDP_HOST:-127.0.0.1}"
CDP_PORT="${CDP_PORT:-9223}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root (it creates a system user and installs a unit)" >&2
  exit 1
fi

if [ -z "$HERMES_USER" ]; then
  echo "set HERMES_USER to the account running the Hermes gateway" >&2
  exit 1
fi
if ! id "$HERMES_USER" >/dev/null 2>&1; then
  echo "no such user: $HERMES_USER" >&2
  exit 1
fi
HERMES_UID="$(id -u "$HERMES_USER")"

if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --home-dir "$STATE" --shell /usr/sbin/nologin "$SERVICE_USER"
  echo "created user $SERVICE_USER"
fi

# Group membership is what gives the gateway access to the 0660 socket in the
# 0750 runtime directory. It takes effect for NEW processes: restart the
# gateway (or re-login) after installing.
if [ "$HERMES_UID" -ne 0 ] && ! id -nG "$HERMES_USER" | tr ' ' '\n' | grep -qx "$SERVICE_USER"; then
  usermod -aG "$SERVICE_USER" "$HERMES_USER"
  echo "added $HERMES_USER to group $SERVICE_USER (restart the gateway to pick it up)"
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

AS_USER=(sudo -u "$SERVICE_USER")
if command -v runuser >/dev/null 2>&1; then
  AS_USER=(runuser -u "$SERVICE_USER" --)
fi
if ! "${AS_USER[@]}" "$PREFIX/venv/bin/python" -c "import cryptography, websockets" 2>/dev/null; then
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

# Root-owned config: vaultd may READ it but never write it. The agent cannot
# influence the DevTools endpoint at all. Re-running never overwrites an
# operator-chosen endpoint.
case "$CDP_HOST" in
  127.*|localhost) ;;
  *) echo "CDP_HOST must be an IPv4 loopback address (got $CDP_HOST)" >&2; exit 1 ;;
esac
case "$CDP_PORT" in
  ''|*[!0-9]*) echo "CDP_PORT must be numeric (got $CDP_PORT)" >&2; exit 1 ;;
esac
if [ "$CDP_PORT" -lt 1 ] || [ "$CDP_PORT" -gt 65535 ]; then
  echo "CDP_PORT must be between 1 and 65535 (got $CDP_PORT)" >&2
  exit 1
fi
install -d -m 0755 -o root -g root "$ETC"
if [ ! -f "$ETC/cdp.json" ]; then
  printf '{"cdp": "http://%s:%s"}\n' "$CDP_HOST" "$CDP_PORT" > "$ETC/cdp.json"
fi
chown root:"$SERVICE_USER" "$ETC/cdp.json"
chmod 0640 "$ETC/cdp.json"

printf 'BROKER_ALLOW_UID=%s\n' "$HERMES_UID" > "$ETC/daemon.env"
chown root:"$SERVICE_USER" "$ETC/daemon.env"
chmod 0640 "$ETC/daemon.env"

install -m 0644 "$HERE/systemd/hermes-vault-broker.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now hermes-vault-broker.service

cat <<EOF

Installed.

  1. create the store (asks twice; the passphrase is never stored):
       sudo -u $SERVICE_USER $PREFIX/venv/bin/python -m broker --state $STATE/store.json init

  2. unlock it for this session (one-time HTTPS page):
       sudo -u $SERVICE_USER $PREFIX/venv/bin/python -m broker unlock-form \\
         --cert $STATE/tls/server.crt --key $STATE/tls/server.key \\
         --port 58104 --host 0.0.0.0 --public-url https://<your-host>:58104
     (omit --host 0.0.0.0 if you open the link on this machine only)

  3. install the Hermes plugin:
       hermes plugins install $HERE/plugin

  4. restart the Hermes gateway so $HERMES_USER picks up the $SERVICE_USER
     group (needed to open the socket). The broker now reads its DevTools
     endpoint from $ETC/cdp.json (root-owned, read-only to the service), and
     grants only status/list/fill to uid $HERMES_UID.

EOF
