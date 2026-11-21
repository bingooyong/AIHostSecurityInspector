#!/bin/sh
# Start a lab-only OpenSSH daemon on 127.0.0.1:2222.
# This script must never start the packaged system sshd or listen on 0.0.0.0.
set -eu

STATE_DIR="${HOSTSEC_LAB_SSH_DIR:-/tmp/hostsec-lab-ssh}"
PORT="${HOSTSEC_LIVE_SSH_PORT:-2222}"
USER_NAME="${HOSTSEC_LIVE_SSH_USER:-hostsec-lab}"
COLLECTOR_SRC="${HOSTSEC_COLLECTOR_BIN:-}"
LISTEN=127.0.0.1

if [ "$(id -u)" -eq 0 ]; then
  SUDO=""
else
  SUDO="sudo"
fi

ss_listen() {
  ss -lnt 2>/dev/null | awk '{print $4}'
}

if ss_listen | grep -E "(:|^)${PORT}$|:${PORT}$" | grep -v '127.0.0.1' | grep -q .; then
  echo "refusing to start: port ${PORT} is already bound on a non-loopback address" >&2
  exit 1
fi

if ! command -v sshd >/dev/null 2>&1 && [ ! -x /usr/sbin/sshd ]; then
  echo "openssh-server is not installed" >&2
  exit 1
fi
SSHD="${HOSTSEC_SSHD_BIN:-/usr/sbin/sshd}"
# Privilege separation directory is required by OpenSSH and is not a listen socket.
$SUDO mkdir -p /run/sshd
$SUDO chmod 755 /run/sshd

mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"

if [ ! -f "$STATE_DIR/ssh_host_ed25519_key" ]; then
  ssh-keygen -t ed25519 -f "$STATE_DIR/ssh_host_ed25519_key" -N "" -C "hostsec-lab-host" >/dev/null
fi
if [ ! -f "$STATE_DIR/id_ed25519" ]; then
  ssh-keygen -t ed25519 -f "$STATE_DIR/id_ed25519" -N "" -C "hostsec-lab-user" >/dev/null
fi
chmod 600 "$STATE_DIR/ssh_host_ed25519_key" "$STATE_DIR/id_ed25519"
chmod 644 "$STATE_DIR/ssh_host_ed25519_key.pub" "$STATE_DIR/id_ed25519.pub"

if ! id "$USER_NAME" >/dev/null 2>&1; then
  $SUDO useradd --system --create-home --home-dir "/home/$USER_NAME" --shell /bin/bash "$USER_NAME"
fi
# System accounts are locked with "!". OpenSSH rejects those for any auth.
# "*" keeps password login disabled while allowing pubkey authentication.
$SUDO usermod -p "*" "$USER_NAME"
$SUDO chage -E -1 "$USER_NAME"

HOME_DIR=$(getent passwd "$USER_NAME" | cut -d: -f6)
$SUDO mkdir -p "$HOME_DIR/bin" "$HOME_DIR/.ssh"
$SUDO chmod 700 "$HOME_DIR" "$HOME_DIR/.ssh"
AUTH_KEYS="$STATE_DIR/authorized_keys"
{
  printf 'restrict,command="%s/bin/hostsec-collector" ' "$HOME_DIR"
  cat "$STATE_DIR/id_ed25519.pub"
  printf '\n'
} > "$AUTH_KEYS"
chmod 600 "$AUTH_KEYS"
$SUDO cp "$AUTH_KEYS" "$HOME_DIR/.ssh/authorized_keys"
$SUDO chown -R "$USER_NAME:$USER_NAME" "$HOME_DIR/.ssh"
$SUDO chmod 600 "$HOME_DIR/.ssh/authorized_keys"

if [ -n "$COLLECTOR_SRC" ] && [ -f "$COLLECTOR_SRC" ]; then
  $SUDO cp "$COLLECTOR_SRC" "$HOME_DIR/bin/hostsec-collector"
  $SUDO chown "$USER_NAME:$USER_NAME" "$HOME_DIR/bin/hostsec-collector"
  $SUDO chmod 755 "$HOME_DIR/bin/hostsec-collector"
fi

KNOWN="$STATE_DIR/known_hosts"
{
  printf '[127.0.0.1]:%s ' "$PORT"
  awk '{print $1, $2}' "$STATE_DIR/ssh_host_ed25519_key.pub"
  printf '\n'
} > "$KNOWN"
chmod 600 "$KNOWN"

cat > "$STATE_DIR/sshd_config" <<CFG
Port $PORT
ListenAddress $LISTEN
Protocol 2
HostKey $STATE_DIR/ssh_host_ed25519_key
PidFile $STATE_DIR/sshd.pid
AllowUsers $USER_NAME
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
UsePAM no
X11Forwarding no
AllowTcpForwarding no
PermitTunnel no
GatewayPorts no
PermitTTY no
PrintMotd no
StrictModes yes
AuthorizedKeysFile $HOME_DIR/.ssh/authorized_keys
CFG
chmod 600 "$STATE_DIR/sshd_config"

# Defensive: never start if ListenAddress is missing or is a wildcard.
if grep -Eq 'ListenAddress[[:space:]]+(0\.0\.0\.0|::)([[:space:]]|$)' "$STATE_DIR/sshd_config"; then
  echo "refusing wildcard ListenAddress" >&2
  exit 1
fi
if ! grep -q "ListenAddress $LISTEN" "$STATE_DIR/sshd_config"; then
  echo "ListenAddress 127.0.0.1 is required" >&2
  exit 1
fi

if [ -f "$STATE_DIR/sshd.pid" ] && $SUDO kill -0 "$(cat "$STATE_DIR/sshd.pid")" 2>/dev/null; then
  echo "lab sshd already running pid=$(cat "$STATE_DIR/sshd.pid")"
else
  $SUDO "$SSHD" -f "$STATE_DIR/sshd_config" -E "$STATE_DIR/sshd.log"
fi

# Confirm the daemon is loopback-only.
if ss_listen | grep -E ":${PORT}$" | grep -v "127.0.0.1:$PORT" | grep -q .; then
  echo "lab sshd is listening beyond loopback; stopping" >&2
  if [ -f "$STATE_DIR/sshd.pid" ]; then
    $SUDO kill "$(cat "$STATE_DIR/sshd.pid")" || true
  fi
  exit 1
fi

echo "HOSTSEC_LIVE_SSH=1"
echo "HOSTSEC_LIVE_SSH_ADDRESS=127.0.0.1"
echo "HOSTSEC_LIVE_SSH_PORT=$PORT"
echo "HOSTSEC_LIVE_SSH_USER=$USER_NAME"
echo "HOSTSEC_LIVE_SSH_IDENTITY=$STATE_DIR/id_ed25519"
echo "HOSTSEC_LIVE_SSH_KNOWN_HOSTS=$KNOWN"
echo "HOSTSEC_LAB_SSH_DIR=$STATE_DIR"
