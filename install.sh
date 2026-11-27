#!/usr/bin/env bash
set -euo pipefail

export PATH="$PATH:/usr/sbin:/sbin"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

DEFAULT_URL="http://168.144.36.170:8080"
DEFAULT_TOKEN="bN7X9l38hw-O-lL1iyBHZWPauPBc3jwM"

MODE=""
ARG_URL="${UFASPROXY_URL:-}"
ARG_TOKEN="${UFASPROXY_TOKEN:-}"
ROLL_TOKEN=0
NO_GIT_PUSH=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --client|-c)   MODE="client"; shift ;;
    --server|-s)   MODE="server"; shift ;;
    --all|-a)      MODE="all"; shift ;;
    --roll-token)  ROLL_TOKEN=1; shift ;;
    --no-git-push) NO_GIT_PUSH=1; shift ;;
    --url)
      [[ $# -ge 2 ]] || { echo "Error: --url requires a value" >&2; exit 1; }
      ARG_URL="$2"; shift 2 ;;
    --token)
      [[ $# -ge 2 ]] || { echo "Error: --token requires a value" >&2; exit 1; }
      ARG_TOKEN="$2"; shift 2 ;;
    -h|--help)
      echo "Usage: bash install.sh [--client | --server | --all] [--url URL] [--token TOKEN] [--roll-token] [--no-git-push]"
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

TOKEN_FILE="$SCRIPT_DIR/token.env"

_read_env_val() {
  local key="$1"
  [[ -f "$TOKEN_FILE" ]] || return 0
  awk -F= -v k="$key" '
    $0 !~ /^[[:space:]]*#/ && $1 ~ "^[[:space:]]*" k "[[:space:]]*$" {
      v = substr($0, index($0, "=") + 1)
      gsub(/^[[:space:]"'\'']+|[[:space:]"'\'']+$/, "", v)
      print v; exit
    }
  ' "$TOKEN_FILE"
}

_norm_url() {
  local u="${1//[[:space:]]/}"
  [[ -n "$u" ]] || return 0
  [[ "$u" =~ ^https?:// ]] || u="http://$u"
  u="${u%/}"
  if [[ "$u" == http://* && "${u#http://}" != *:* ]]; then
    u="$u:8080"
  fi
  printf '%s' "$u"
}

write_token_env() {
  local url token cur_u cur_t
  cur_u="$(_read_env_val UFASPROXY_URL)"
  cur_t="$(_read_env_val UFASPROXY_TOKEN)"
  url="$(_norm_url "${1:-$cur_u}")"
  token="${2:-$cur_t}"
  token="${token//$'\r'/}"
  token="${token//$'\n'/}"
  umask 077
  {
    [[ -n "$url" ]] && printf 'UFASPROXY_URL=%s\n' "$url"
    [[ -n "$token" ]] && printf 'UFASPROXY_TOKEN=%s\n' "$token"
  } > "$TOKEN_FILE"
  chmod 600 "$TOKEN_FILE" 2>/dev/null || true
}

sync_defaults_to_github() {
  local new_url="$1" new_tok="$2"
  local target_sh="$SCRIPT_DIR/install.sh"
  [[ -f "$target_sh" && -n "$new_url" && -n "$new_tok" ]] || return 0
  if [[ "$new_url" == "$DEFAULT_URL" && "$new_tok" == "$DEFAULT_TOKEN" ]]; then
    return 0
  fi

  NEW_URL="$new_url" NEW_TOK="$new_tok" TARGET_SH="$target_sh" python3 - << 'PY'
import os, re
p = os.environ["TARGET_SH"]
u = re.sub(r'[\r\n"$`\\]', '', os.environ["NEW_URL"]).strip()
t = re.sub(r'[\r\n"$`\\]', '', os.environ["NEW_TOK"]).strip()
txt = open(p, "r", encoding="utf-8").read()
txt2, n1 = re.subn(r'(?m)^DEFAULT_URL=".*"$', f'DEFAULT_URL="{u}"', txt, count=1)
txt2, n2 = re.subn(r'(?m)^DEFAULT_TOKEN=".*"$', f'DEFAULT_TOKEN="{t}"', txt2, count=1)
if n1 == 1 and n2 == 1 and txt2 != txt:
    with open(p, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(txt2)
PY
  DEFAULT_URL="$new_url"
  DEFAULT_TOKEN="$new_tok"
  bash -n "$target_sh"

  [[ "$NO_GIT_PUSH" -eq 0 ]] || return 0
  if ! command -v git >/dev/null 2>&1 || ! git -C "$SCRIPT_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "[*] Default URL/token diperbarui di $target_sh (bukan repo git, lewati push)"
    return 0
  fi

  git -C "$SCRIPT_DIR" add -- install.sh
  if git -C "$SCRIPT_DIR" diff --cached --quiet -- install.sh; then
    return 0
  fi

  git -C "$SCRIPT_DIR" -c user.name="ufasproxy" -c user.email="ufasproxy@local" \
    commit --only install.sh -m "chore(install): update default gateway URL and token" >/dev/null

  local askpass_f="" gh_tok="${GH_TOKEN:-${GITHUB_TOKEN:-}}" orig_url="" push_ok=0
  orig_url="$(git -C "$SCRIPT_DIR" remote get-url origin 2>/dev/null || true)"
  if [[ -n "$gh_tok" && "$orig_url" == https://* ]]; then
    askpass_f="$(mktemp)"
    chmod 700 "$askpass_f"
    printf '#!/usr/bin/env sh\ncase "$1" in *Username*) echo "x-access-token";; *) printf "%%s\\n" "$UFP_GH_TOK";; esac\n' > "$askpass_f"
    if UFP_GH_TOK="$gh_tok" GIT_ASKPASS="$askpass_f" GIT_TERMINAL_PROMPT=0 git -C "$SCRIPT_DIR" push origin HEAD; then
      push_ok=1
    fi
    rm -f "$askpass_f"
  else
    if GIT_TERMINAL_PROMPT=0 git -C "$SCRIPT_DIR" push origin HEAD; then
      push_ok=1
    fi
  fi

  if [[ "$push_ok" -eq 1 ]]; then
    echo "[*] Default URL & token di install.sh berhasil di-push ke GitHub ✓"
  else
    echo "[!] Auto-push install.sh ke GitHub gagal (butuh SSH key / git credential / GH_TOKEN) — token.env lokal tetap aktif, jalankan 'git push' manual." >&2
  fi
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

  local pub_ip srv_url srv_tok
  pub_ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true)"
  [[ -n "$pub_ip" ]] || pub_ip="<GATEWAY_IP>"

  srv_url="${ARG_URL:-$([[ "$pub_ip" != "<GATEWAY_IP>" ]] && echo "http://${pub_ip}:8080" || echo "$DEFAULT_URL")}"
  if [[ -n "$ARG_TOKEN" ]]; then
    srv_tok="$ARG_TOKEN"
  elif [[ "$ROLL_TOKEN" -eq 1 ]]; then
    srv_tok="$(python3 -c "import secrets; print(secrets.token_urlsafe(24))")"
  else
    srv_tok="$(_read_env_val UFASPROXY_TOKEN)"
    [[ -n "$srv_tok" ]] || srv_tok="$DEFAULT_TOKEN"
  fi
  write_token_env "$srv_url" "$srv_tok"
  ARG_URL="$(_read_env_val UFASPROXY_URL)"
  ARG_TOKEN="$(_read_env_val UFASPROXY_TOKEN)"

  sync_defaults_to_github "$ARG_URL" "$ARG_TOKEN"

  cat <<EOF

[OK] ufasproxy SERVER prerequisites verified!
Saved gateway URL/token -> $TOKEN_FILE (chmod 600)
Start the gateway with:
  sudo env UFASPROXY_TOKEN="$ARG_TOKEN" python3 "$SCRIPT_DIR/server.py" --ovpn-dir /path/to/vpns-surfshark --udp-only --port 8080 --public-ip "$pub_ip"
Sync other clients to this server with:
  bash install.sh --client --url "$ARG_URL" --token "$ARG_TOKEN"
Optional: --roll-token (new random token), --no-git-push, multiple --ovpn-dir paths, --base-proxy-port 20001, --max-slots 45, --ttl-s 180
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

  local cli_url cli_tok
  cli_url="${ARG_URL:-$DEFAULT_URL}"
  cli_tok="${ARG_TOKEN:-$DEFAULT_TOKEN}"
  write_token_env "$cli_url" "$cli_tok"
  echo "[*] Konfigurasi API disimpan -> $TOKEN_FILE"

  cat <<EOF

[OK] ufasproxy CLIENT ready!
API config ready in $TOKEN_FILE; run:
  source "$SCRIPT_DIR/.venv/bin/activate"
  python "$SCRIPT_DIR/old_browser_vpn.py" -c "$SCRIPT_DIR/input/<combo>.txt" -w auto
Tip: jika pindah server/token nanti, jalankan:
  bash install.sh --client --url http://<IP_BARU>:8080 --token <TOKEN_BARU>
EOF
}

case "$MODE" in
  client) install_client ;;
  server) install_server ;;
  all)    install_server; install_client ;;
esac
