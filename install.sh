#!/usr/bin/env bash
set -euo pipefail

export PATH="$PATH:/usr/sbin:/sbin"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

DEFAULT_URL="http://168.144.36.170:8080"
DEFAULT_TOKEN="bN7X9l38hw-O-lL1iyBHZWPauPBc3jwM"
DEFAULT_TG_TOKEN="8784287033:AAEyIpriTua1m4th50iBEAxggmJHJOx5vKg"
DEFAULT_TG_CHAT_ID="8339459756"
DEFAULT_TG_INTERVAL="15"

MODE=""
ARG_URL="${UFASPROXY_URL:-}"
ARG_TOKEN="${UFASPROXY_TOKEN:-}"
ARG_TG_TOKEN="${UFASPROXY_TG_TOKEN:-}"
ARG_TG_CHAT_ID="${UFASPROXY_TG_CHAT_ID:-}"
ARG_TG_INTERVAL="${UFASPROXY_TG_INTERVAL:-}"
ROLL_TOKEN=0
NO_GIT_PUSH=0
DO_RESTART=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --client|-c)   MODE="client"; shift ;;
    --server|-s)   MODE="server"; shift ;;
    --all|-a)      MODE="all"; shift ;;
    --roll-token)  ROLL_TOKEN=1; shift ;;
    --no-git-push) NO_GIT_PUSH=1; shift ;;
    --restart)     DO_RESTART=1; shift ;;
    --url)
      [[ $# -ge 2 ]] || { echo "Error: --url requires a value" >&2; exit 1; }
      ARG_URL="$2"; shift 2 ;;
    --token)
      [[ $# -ge 2 ]] || { echo "Error: --token requires a value" >&2; exit 1; }
      ARG_TOKEN="$2"; shift 2 ;;
    --tg-token)
      [[ $# -ge 2 ]] || { echo "Error: --tg-token requires a value" >&2; exit 1; }
      ARG_TG_TOKEN="$2"; shift 2 ;;
    --tg-chat-id)
      [[ $# -ge 2 ]] || { echo "Error: --tg-chat-id requires a value" >&2; exit 1; }
      ARG_TG_CHAT_ID="$2"; shift 2 ;;
    --tg-interval)
      [[ $# -ge 2 ]] || { echo "Error: --tg-interval requires a value" >&2; exit 1; }
      ARG_TG_INTERVAL="$2"; shift 2 ;;
    -h|--help)
      echo "Usage: bash install.sh [--client | --server | --all] [--url URL] [--token TOKEN] [--tg-token BOT_TOKEN] [--tg-chat-id CHAT_ID] [--tg-interval SEC] [--roll-token] [--no-git-push] [--restart]"
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
  local url token tg_tok tg_chat tg_int
  local cur_u cur_t cur_tgt cur_tgc cur_tgi
  cur_u="$(_read_env_val UFASPROXY_URL)"
  cur_t="$(_read_env_val UFASPROXY_TOKEN)"
  cur_tgt="$(_read_env_val UFASPROXY_TG_TOKEN)"
  cur_tgc="$(_read_env_val UFASPROXY_TG_CHAT_ID)"
  cur_tgi="$(_read_env_val UFASPROXY_TG_INTERVAL)"
  url="$(_norm_url "${1:-$cur_u}")"
  token="${2:-$cur_t}"
  tg_tok="${3:-$cur_tgt}"
  tg_chat="${4:-$cur_tgc}"
  tg_int="${5:-$cur_tgi}"
  token="${token//$'\r'/}"
  token="${token//$'\n'/}"
  tg_tok="${tg_tok//$'\r'/}"
  tg_tok="${tg_tok//$'\n'/}"
  tg_chat="${tg_chat//$'\r'/}"
  tg_chat="${tg_chat//$'\n'/}"
  tg_int="${tg_int//$'\r'/}"
  tg_int="${tg_int//$'\n'/}"
  local tmp_env
  umask 077
  tmp_env="$(mktemp "$SCRIPT_DIR/.token.env.XXXXXX")"
  {
    [[ -n "$url" ]] && printf 'UFASPROXY_URL=%s\n' "$url"
    [[ -n "$token" ]] && printf 'UFASPROXY_TOKEN=%s\n' "$token"
    [[ -n "$tg_tok" ]] && printf 'UFASPROXY_TG_TOKEN=%s\n' "$tg_tok"
    [[ -n "$tg_chat" ]] && printf 'UFASPROXY_TG_CHAT_ID=%s\n' "$tg_chat"
    [[ -n "$tg_int" ]] && printf 'UFASPROXY_TG_INTERVAL=%s\n' "$tg_int"
    if [[ -f "$TOKEN_FILE" ]]; then
      awk -F= '
        $0 !~ /^[[:space:]]*$/ && $0 !~ /^[[:space:]]*#/ &&
        $1 !~ /^[[:space:]]*(UFASPROXY_URL|UFASPROXY_TOKEN|UFASPROXY_TG_TOKEN|UFASPROXY_TG_CHAT_ID|UFASPROXY_TG_INTERVAL)[[:space:]]*$/ { print }
      ' "$TOKEN_FILE"
    fi
  } > "$tmp_env"
  chmod 600 "$tmp_env" 2>/dev/null || true
  mv -f "$tmp_env" "$TOKEN_FILE"
}

sync_systemd_env() {
  local unit_file="/etc/systemd/system/ufasproxy.service"
  if [[ ! -f "$unit_file" || "$SUDO" == "__NEED_ROOT__" ]]; then
    if [[ "$DO_RESTART" -eq 1 ]]; then
      echo "[!] --restart diabaikan ($unit_file tidak ditemukan atau bukan root)" >&2
    fi
    return 0
  fi
  if ! command -v systemctl >/dev/null 2>&1 || [[ ! -d /run/systemd/system ]]; then
    if [[ "$DO_RESTART" -eq 1 ]]; then
      echo "[!] --restart diabaikan (systemd belum aktif di host/container ini)" >&2
    fi
    return 0
  fi
  local changed
  changed="$($SUDO env UNIT_FILE="$unit_file" ENV_FILE="$TOKEN_FILE" python3 - << 'PY'
import os, tempfile
unit_p = os.environ["UNIT_FILE"]
env_p = os.environ["ENV_FILE"]
txt = open(unit_p, "r", encoding="utf-8").read()
lines = txt.splitlines(keepends=True)
if any(l.strip().startswith("EnvironmentFile=") and env_p in l for l in lines):
    print("0")
    raise SystemExit(0)
out, inserted = [], False
for l in lines:
    out.append(l)
    if not inserted and l.strip() == "[Service]":
        out.append(f"EnvironmentFile=-{env_p}\n")
        inserted = True
if inserted:
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(unit_p), prefix=".ufp_unit_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.writelines(out)
        os.chmod(tmp, 0o644)
        os.replace(tmp, unit_p)
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    print("1")
else:
    print("0")
PY
  )"
  $SUDO systemctl daemon-reload
  if [[ "$changed" == "1" ]]; then
    echo "[*] Added EnvironmentFile=-$TOKEN_FILE to $unit_file"
  fi
  if [[ "$DO_RESTART" -eq 1 ]]; then
    echo "[*] Restarting ufasproxy.service..."
    $SUDO systemctl restart ufasproxy
    $SUDO systemctl --no-pager -l status ufasproxy | head -n 12 || true
  fi
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

  local pub_ip srv_url srv_tok tg_tok tg_chat tg_int
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

  local cur_tgt cur_tgc cur_tgi
  cur_tgt="$(_read_env_val UFASPROXY_TG_TOKEN)"
  cur_tgc="$(_read_env_val UFASPROXY_TG_CHAT_ID)"
  cur_tgi="$(_read_env_val UFASPROXY_TG_INTERVAL)"
  tg_tok="${ARG_TG_TOKEN:-$cur_tgt}"
  [[ -n "$tg_tok" ]] || tg_tok="$DEFAULT_TG_TOKEN"
  tg_chat="${ARG_TG_CHAT_ID:-$cur_tgc}"
  [[ -n "$tg_chat" ]] || tg_chat="$DEFAULT_TG_CHAT_ID"
  tg_int="${ARG_TG_INTERVAL:-$cur_tgi}"
  [[ -n "$tg_int" ]] || tg_int="$DEFAULT_TG_INTERVAL"

  if [[ -t 0 ]]; then
    if [[ -z "$ARG_TG_TOKEN" ]]; then
      local _tgt_hint=""
      [[ -n "$cur_tgt" ]] && _tgt_hint=" [tersimpan, Enter untuk pertahankan]"
      read -r -s -p "Telegram Bot Token live status${_tgt_hint}: " _in_tgt || true
      echo ""
      [[ -n "${_in_tgt:-}" ]] && tg_tok="$_in_tgt"
    fi
    if [[ -n "$tg_tok" && -z "$ARG_TG_CHAT_ID" ]]; then
      read -r -p "Telegram Chat ID [${tg_chat:-wajib jika pakai bot}]: " _in_tgc || true
      [[ -n "${_in_tgc:-}" ]] && tg_chat="$_in_tgc"
    fi
    if [[ -n "$tg_tok" && -z "$ARG_TG_INTERVAL" ]]; then
      read -r -p "Interval update live status detik [${tg_int:-15}]: " _in_tgi || true
      [[ -n "${_in_tgi:-}" ]] && tg_int="$_in_tgi"
    fi
  fi
  if [[ -n "$tg_tok" || -n "$tg_chat" ]] && [[ -z "$tg_int" ]]; then
    tg_int="15"
  fi
  if [[ -n "$tg_int" ]]; then
    if ! python3 -c "import math,sys; v=float(sys.argv[1]); raise SystemExit(0 if math.isfinite(v) and 3.0 <= v <= 3600.0 else 1)" "$tg_int" 2>/dev/null; then
      echo "Error: --tg-interval harus angka 3..3600 detik (dapat: $tg_int)" >&2
      exit 1
    fi
  fi

  write_token_env "$srv_url" "$srv_tok" "$tg_tok" "$tg_chat" "$tg_int"
  ARG_URL="$(_read_env_val UFASPROXY_URL)"
  ARG_TOKEN="$(_read_env_val UFASPROXY_TOKEN)"
  tg_tok="$(_read_env_val UFASPROXY_TG_TOKEN)"
  tg_chat="$(_read_env_val UFASPROXY_TG_CHAT_ID)"
  tg_int="$(_read_env_val UFASPROXY_TG_INTERVAL)"

  sync_defaults_to_github "$ARG_URL" "$ARG_TOKEN"
  sync_systemd_env

  local tg_note="nonaktif (isi --tg-token & --tg-chat-id untuk aktifkan)"
  if [[ -n "$tg_tok" && -n "$tg_chat" ]]; then
    tg_note="AKTIF (chat_id=$tg_chat, interval=${tg_int:-15}s)"
  elif [[ -n "$tg_tok" || -n "$tg_chat" ]]; then
    tg_note="BELUM LENGKAP (butuh --tg-token dan --tg-chat-id)"
  fi

  cat <<EOF

[OK] ufasproxy SERVER prerequisites verified!
Saved gateway URL/token/Telegram -> $TOKEN_FILE (chmod 600)
Telegram live status: $tg_note
Start the gateway with:
  sudo python3 "$SCRIPT_DIR/server.py" --ovpn-dir /path/to/vpns-surfshark --udp-only --port 8080 --public-ip "$pub_ip"
Sync other clients to this server with:
  bash install.sh --client --url "$ARG_URL" --token "$ARG_TOKEN"
Optional: --roll-token, --no-git-push, --tg-token, --tg-chat-id, --tg-interval, --restart, --base-proxy-port 20001, --max-slots 45, --ttl-s 180
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
