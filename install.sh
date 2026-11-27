#!/usr/bin/env bash
set -euo pipefail

export PATH="$PATH:/usr/sbin:/sbin"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

MODE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --client|-c) MODE="client"; shift ;;
    --server|-s) MODE="server"; shift ;;
    --all|-a)    MODE="all"; shift ;;
    -h|--help)
      echo "Usage: bash install.sh [--client | --server | --all]"
      exit 0
      ;;
    *)
      echo "Error: unknown option '$1' (use --client, --server, or --all)" >&2
      exit 1
      ;;
  esac
done

if [[ -z "$MODE" ]]; then
  if [[ -t 0 ]]; then
    echo "Pilih mode install ufasproxy:"
    echo "  [1] Client Checker (old_browser_vpn.py - untuk CT / worker)"
    echo "  [2] Server Gateway (server.py - untuk VPS OpenVPN)"
    echo "  [3] Keduanya (Server + Client)"
    read -r -p "Pilihan (1-3) [1]: " _sel || true
    case "${_sel:-1}" in
      1|client) MODE="client" ;;
      2|server) MODE="server" ;;
      3|all)    MODE="all" ;;
      *) echo "Error: pilihan tidak valid: $_sel" >&2; exit 1 ;;
    esac
  else
    echo "Error: non-interactive shell requires --client, --server, or --all" >&2
    exit 1
  fi
fi

SUDO=""
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
  else
    SUDO="__NEED_ROOT__"
  fi
fi

APT_UPDATED=0
apt_install() {
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "Error: apt-get not found (Ubuntu/Debian required)" >&2
    exit 1
  fi
  if [[ "$SUDO" == "__NEED_ROOT__" ]]; then
    echo "Error: root/sudo required to install system packages ($*)" >&2
    exit 1
  fi
  if [[ "$APT_UPDATED" -eq 0 ]]; then
    $SUDO env DEBIAN_FRONTEND=noninteractive apt-get update -y
    APT_UPDATED=1
  fi
  $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@"
}

CHK_NS="_ufp_chk_$$"
cleanup_ns() {
  ${SUDO/#__NEED_ROOT__/} ip netns del "$CHK_NS" >/dev/null 2>&1 || true
}

install_server() {
  echo "[*] Installing ufasproxy SERVER gateway prerequisites..."
  if [[ "$SUDO" == "__NEED_ROOT__" ]]; then
    echo "Error: run server install as root (e.g. sudo bash install.sh --server)" >&2
    exit 1
  fi

  echo "[1/4] Installing required server packages..."
  apt_install python3 openvpn microsocks iproute2 iptables procps util-linux ca-certificates

  echo "[2/4] Checking /dev/net/tun..."
  if [[ ! -c /dev/net/tun ]]; then
    echo "Error: /dev/net/tun missing or not a character device (enable TUN/TAP on VPS)" >&2
    exit 1
  fi

  echo "[3/4] Checking ip netns support..."
  trap cleanup_ns EXIT
  $SUDO ip netns add "$CHK_NS"
  $SUDO ip netns exec "$CHK_NS" ip link set lo up
  cleanup_ns
  trap - EXIT

  echo "[4/4] Running server.py --selftest..."
  python3 "$SCRIPT_DIR/server.py" --selftest

  local pub_ip
  pub_ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true)"
  [[ -n "$pub_ip" ]] || pub_ip="<GATEWAY_IP>"

  cat <<EOF

[OK] ufasproxy SERVER prerequisites verified!
Start the gateway with:
  sudo python3 "$SCRIPT_DIR/server.py" --ovpn-dir /path/to/vpns-surfshark --udp-only --port 8080 --public-ip "$pub_ip"
Optional: multiple --ovpn-dir paths, --token "<SECRET>" (or UFASPROXY_TOKEN), --base-proxy-port 20001, --max-slots 45, --ttl-s 180
EOF
}

install_client() {
  echo "[*] Installing ufasproxy CLIENT checker prerequisites..."

  echo "[1/4] Checking Python 3.10+, venv, and pip..."
  if ! command -v python3 >/dev/null 2>&1 || ! python3 -c "import ensurepip" >/dev/null 2>&1; then
    apt_install python3 python3-venv python3-pip curl ca-certificates
  fi
  if ! python3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" >/dev/null 2>&1; then
    echo "Error: Python 3.10+ required" >&2
    exit 1
  fi

  echo "[2/4] Setting up .venv and Python packages..."
  if [[ ! -x "$SCRIPT_DIR/.venv/bin/python" ]] || ! "$SCRIPT_DIR/.venv/bin/python" -m pip --version >/dev/null 2>&1; then
    rm -rf "$SCRIPT_DIR/.venv"
    python3 -m venv "$SCRIPT_DIR/.venv"
  fi
  local vpy="$SCRIPT_DIR/.venv/bin/python"
  "$vpy" -m pip install --upgrade pip setuptools wheel
  "$vpy" -m pip install -r "$SCRIPT_DIR/requirements.txt"

  echo "[3/4] Installing Chromium OS dependencies & CloakBrowser binary..."
  if [[ "$(uname -s)" = "Linux" ]]; then
    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
      env DEBIAN_FRONTEND=noninteractive "$vpy" -m playwright install-deps chromium
    elif [[ -n "$SUDO" && "$SUDO" != "__NEED_ROOT__" ]]; then
      $SUDO env "PATH=$PATH" DEBIAN_FRONTEND=noninteractive "$vpy" -m playwright install-deps chromium
    else
      echo "Error: root/sudo required for playwright install-deps chromium" >&2
      exit 1
    fi
  fi
  CLOAKBROWSER_CACHE_DIR="$SCRIPT_DIR/.cloak_old_cache" \
    "$vpy" -c "from cloakbrowser.download import ensure_binary; ensure_binary(license_key=None)" || true

  echo "[4/4] Running old_browser_vpn.py --selftest..."
  "$vpy" "$SCRIPT_DIR/old_browser_vpn.py" --selftest

  cat <<EOF

[OK] ufasproxy CLIENT ready!
Set $SCRIPT_DIR/token.env (UFASPROXY_URL & UFASPROXY_TOKEN) then run:
  source "$SCRIPT_DIR/.venv/bin/activate"
  python "$SCRIPT_DIR/old_browser_vpn.py" -c "$SCRIPT_DIR/input/<combo>.txt" -w auto
EOF
}

case "$MODE" in
  client) install_client ;;
  server) install_server ;;
  all)    install_server; install_client ;;
esac
