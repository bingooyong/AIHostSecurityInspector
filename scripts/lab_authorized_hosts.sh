#!/bin/sh
# Start two loopback OpenSSH daemons as stand-ins for distinct authorized hosts.
# This script must never start the packaged system sshd, never listen on
# 0.0.0.0 or ::, and never bind port 22.
set -eu

ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT/scripts/lab_sshd.sh"
STATE_ROOT="${HOSTSEC_LAB_SSH_ROOT:-/tmp/hostsec-lab-ssh-multi}"
BINDINGS="${HOSTSEC_LAB_BINDINGS:-$STATE_ROOT/bindings.yaml}"
COLLECTOR_SRC="${HOSTSEC_COLLECTOR_BIN:-$ROOT/build/hostsec}"

if [ ! -x "$SCRIPT" ]; then
  echo "lab_sshd.sh is missing" >&2
  exit 1
fi

# Refuse to proceed if either lab port is already bound off-loopback.
for port in 2222 2223; do
  if ss -lnt 2>/dev/null | awk '{print $4}' | grep -E ":${port}$" | grep -v '127.0.0.1' | grep -q .; then
    echo "refusing to start: port ${port} is already bound on a non-loopback address" >&2
    exit 1
  fi
done

if [ ! -x "$COLLECTOR_SRC" ]; then
  echo "collector binary is missing: $COLLECTOR_SRC (run make build)" >&2
  exit 1
fi

mkdir -p "$STATE_ROOT"
chmod 700 "$STATE_ROOT"

# Distinct users, ports, host keys, and identities.
HOSTSEC_LAB_SSH_DIR="$STATE_ROOT/linux-box-lab-ssh-001" \
  HOSTSEC_LIVE_SSH_PORT=2222 \
  HOSTSEC_LIVE_SSH_USER=hostsec-lab \
  HOSTSEC_COLLECTOR_BIN="$COLLECTOR_SRC" \
  "$SCRIPT"

HOSTSEC_LAB_SSH_DIR="$STATE_ROOT/linux-box-lab-ssh-002" \
  HOSTSEC_LIVE_SSH_PORT=2223 \
  HOSTSEC_LIVE_SSH_USER=hostsec-lab-b \
  HOSTSEC_COLLECTOR_BIN="$COLLECTOR_SRC" \
  "$SCRIPT"

# Point the collector force-command at a hardlink/copy named hostsec-collector.
# lab_sshd.sh already installs $HOME/bin/hostsec-collector when COLLECTOR_SRC is set.

cat > "$BINDINGS" <<YAML
version: 1
hosts:
  - host_id: linux-box-lab-ssh-001
    identity_path: $STATE_ROOT/linux-box-lab-ssh-001/id_ed25519
    known_hosts_path: $STATE_ROOT/linux-box-lab-ssh-001/known_hosts
  - host_id: linux-box-lab-ssh-002
    identity_path: $STATE_ROOT/linux-box-lab-ssh-002/id_ed25519
    known_hosts_path: $STATE_ROOT/linux-box-lab-ssh-002/known_hosts
YAML
chmod 600 "$BINDINGS"

# Final listen check: both ports must be loopback-only.
for port in 2222 2223; do
  if ! ss -lnt 2>/dev/null | awk '{print $4}' | grep -q "127.0.0.1:${port}$"; then
    echo "lab sshd is not listening on 127.0.0.1:${port}" >&2
    exit 1
  fi
  if ss -lnt 2>/dev/null | awk '{print $4}' | grep -E ":${port}$" | grep -v "127.0.0.1:${port}" | grep -q .; then
    echo "lab sshd is listening beyond loopback on port ${port}" >&2
    exit 1
  fi
done

echo "HOSTSEC_LIVE_SSH_MULTI=1"
echo "HOSTSEC_LAB_BINDINGS=$BINDINGS"
echo "HOSTSEC_LIVE_SSH_001_IDENTITY=$STATE_ROOT/linux-box-lab-ssh-001/id_ed25519"
echo "HOSTSEC_LIVE_SSH_001_KNOWN_HOSTS=$STATE_ROOT/linux-box-lab-ssh-001/known_hosts"
echo "HOSTSEC_LIVE_SSH_001_USER=hostsec-lab"
echo "HOSTSEC_LIVE_SSH_001_PORT=2222"
echo "HOSTSEC_LIVE_SSH_002_IDENTITY=$STATE_ROOT/linux-box-lab-ssh-002/id_ed25519"
echo "HOSTSEC_LIVE_SSH_002_KNOWN_HOSTS=$STATE_ROOT/linux-box-lab-ssh-002/known_hosts"
echo "HOSTSEC_LIVE_SSH_002_USER=hostsec-lab-b"
echo "HOSTSEC_LIVE_SSH_002_PORT=2223"
