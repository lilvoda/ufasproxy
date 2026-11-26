#!/usr/bin/env bash
set -euo pipefail

export PATH="$PATH:/usr/sbin:/sbin"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Error: run install.sh as root (e.g. sudo bash install.sh)" >&2
  exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
  echo "Error: apt-get not found (Ubuntu/Debian required)" >&2
  exit 1
fi

echo "[1/4] Installing required packages..."
DEBIAN_FRONTEND=noninteractive apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  python3 openvpn microsocks iproute2 iptables procps util-linux ca-certificates

echo "[2/4] Checking /dev/net/tun..."
if [[ ! -c /dev/net/tun ]]; then
  echo "Error: /dev/net/tun missing or not a character device (enable TUN/TAP on VPS)" >&2
  exit 1
fi

echo "[3/4] Checking ip netns support..."
CHK_NS="_ufp_chk_$$"
cleanup_ns() {
  ip netns del "$CHK_NS" >/dev/null 2>&1 || true
}
trap cleanup_ns EXIT
ip netns add "$CHK_NS"
ip netns exec "$CHK_NS" ip link set lo up
cleanup_ns
trap - EXIT

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

echo "[4/4] Running server.py --selftest..."
python3 "$SCRIPT_DIR/server.py" --selftest

PUB_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true)"
[[ -n "$PUB_IP" ]] || PUB_IP="<GATEWAY_IP>"

cat <<EOF

[OK] ufasproxy prerequisites verified!
Start the gateway with:
  sudo python3 "$SCRIPT_DIR/server.py" --ovpn-dir /path/to/vpns-surfshark --port 8080 --public-ip "$PUB_IP"

Optional: pass --token "<SECRET>" (or set UFASPROXY_TOKEN), --base-proxy-port 20001, --max-slots 45, --ttl-s 180
EOF
