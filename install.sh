#!/usr/bin/env bash
set -euo pipefail

export PATH="$PATH:/usr/sbin:/sbin"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

DEFAULT_URL="http://168.144.36.170:8080"
DEFAULT_TOKEN="bN7X9l38hw-O-lL1iyBHZWPauPBc3jwM"
DEFAULT_TG_TOKEN="8784287033:AAEyIpriTua1m4th50iBEAxggmJHJOx5vKg"
DEFAULT_TG_CHAT_ID="8339459756"
DEFAULT_TG_INTERVAL="15"

DO_CLIENT=0
DO_SERVER=0
DO_INDUK=0
ARG_URL="${UFASPROXY_URL:-}"
ARG_TOKEN="${UFASPROXY_TOKEN:-}"
ARG_TG_TOKEN="${UFASPROXY_TG_TOKEN:-}"
ARG_TG_CHAT_ID="${UFASPROXY_TG_CHAT_ID:-}"
ARG_TG_INTERVAL="${UFASPROXY_TG_INTERVAL:-}"
INDUK_PORT="${INDUK_PORT:-8000}"
ARG_INDUK_API_KEY="${INDUK_API_KEY:-}"
RESTORE_BUNDLE=""
INDUK_URL="${INDUK_URL:-}"
AGENT_TOKEN="${AGENT_TOKEN:-}"
VPS_ID="${VPS_ID:-}"
INDUK_POINTER_URL="${INDUK_POINTER_URL:-}"
ROLL_TOKEN=0
NO_GIT_PUSH=0
DO_RESTART=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --client|-c)   DO_CLIENT=1; shift ;;
    --server|-s)   DO_SERVER=1; shift ;;
    --induk|-i)    DO_INDUK=1; shift ;;
    --all|-a)      DO_SERVER=1; DO_INDUK=1; DO_CLIENT=1; shift ;;
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
    --induk-port)
      [[ $# -ge 2 ]] || { echo "Error: --induk-port requires a value" >&2; exit 1; }
      INDUK_PORT="$2"; shift 2 ;;
    --induk-api-key)
      [[ $# -ge 2 ]] || { echo "Error: --induk-api-key requires a value" >&2; exit 1; }
      ARG_INDUK_API_KEY="$2"; shift 2 ;;
    --restore)
      [[ $# -ge 2 ]] || { echo "Error: --restore requires a value" >&2; exit 1; }
      RESTORE_BUNDLE="$2"; shift 2 ;;
    --induk-url)
      [[ $# -ge 2 ]] || { echo "Error: --induk-url requires a value" >&2; exit 1; }
      INDUK_URL="$2"; shift 2 ;;
    --agent-token)
      [[ $# -ge 2 ]] || { echo "Error: --agent-token requires a value" >&2; exit 1; }
      AGENT_TOKEN="$2"; shift 2 ;;
    --vps-id)
      [[ $# -ge 2 ]] || { echo "Error: --vps-id requires a value" >&2; exit 1; }
      VPS_ID="$2"; shift 2 ;;
    --induk-pointer-url)
      [[ $# -ge 2 ]] || { echo "Error: --induk-pointer-url requires a value" >&2; exit 1; }
      INDUK_POINTER_URL="$2"; shift 2 ;;
    -h|--help)
      echo "Usage: bash install.sh [--client] [--server] [--induk] [--all] [--url URL] [--token TOKEN] [--tg-token BOT_TOKEN] [--tg-chat-id CHAT_ID] [--tg-interval SEC] [--induk-port PORT] [--induk-api-key KEY] [--restore BUNDLE] [--induk-url URL --agent-token TOK --vps-id ID] [--roll-token] [--no-git-push] [--restart]"
      exit 0
      ;;
    *)
      echo "Error: unknown option '$1' (use --client, --server, --induk, or --all)" >&2
      exit 1
      ;;
  esac
done

if [[ "$DO_CLIENT$DO_SERVER$DO_INDUK" == "000" ]]; then
  if [[ -t 0 ]]; then
    echo "Pilih mode install ufasproxy:"
    echo "  [1] Client Checker (old_browser_vpn.py + opsional agent Induk)"
    echo "  [2] Server VPN Gateway (server.py :8080)"
    echo "  [3] Server Induk Controller (induk.app:app :8000 - kontrol multi-VPS)"
    echo "  [4] Server VPN + Server Induk (1 VPS)"
    echo "  [5] Semua (Server VPN + Server Induk + Client)"
    read -r -p "Pilihan (1-5) [1]: " _sel || true
    case "${_sel:-1}" in
      1|client) DO_CLIENT=1 ;;
      2|server) DO_SERVER=1 ;;
      3|induk)  DO_INDUK=1 ;;
      4)        DO_SERVER=1; DO_INDUK=1 ;;
      5|all)    DO_SERVER=1; DO_INDUK=1; DO_CLIENT=1 ;;
      *) echo "Error: pilihan tidak valid: $_sel" >&2; exit 1 ;;
    esac
  else
    echo "Error: non-interactive shell requires --client, --server, --induk, or --all" >&2
    exit 1
  fi
fi

if [[ -n "$INDUK_URL" || -n "$AGENT_TOKEN" ]] && [[ -z "$INDUK_URL" || -z "$AGENT_TOKEN" ]]; then
  echo "Error: --induk-url dan --agent-token harus diisi bersama" >&2
  exit 1
fi

SUDO=""
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
  else
    SUDO="__NEED_ROOT__"
  fi
fi

PKG_MGR=""
for _pm in apt-get pacman dnf yum apk zypper; do
  if command -v "$_pm" >/dev/null 2>&1; then
    PKG_MGR="$_pm"
    break
  fi
done

PKG_UPDATED=0
pkg_install() {
  if [[ -z "$PKG_MGR" ]]; then
    echo "Error: package manager tidak dikenali (butuh apt-get, pacman, dnf, yum, apk, atau zypper) untuk install: $*" >&2
    exit 1
  fi
  if [[ "$SUDO" == "__NEED_ROOT__" ]]; then
    echo "Error: root/sudo required to install system packages ($*)" >&2
    exit 1
  fi
  case "$PKG_MGR" in
    apt-get)
      if [[ "$PKG_UPDATED" -eq 0 ]]; then
        $SUDO env DEBIAN_FRONTEND=noninteractive apt-get update -y
        PKG_UPDATED=1
      fi
      $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@"
      ;;
    pacman)
      if [[ "$PKG_UPDATED" -eq 0 ]]; then
        $SUDO pacman -Sy --noconfirm
        PKG_UPDATED=1
      fi
      $SUDO pacman -S --noconfirm --needed "$@"
      ;;
    dnf)
      $SUDO dnf install -y "$@"
      ;;
    yum)
      $SUDO yum install -y "$@"
      ;;
    apk)
      $SUDO apk add --no-cache "$@"
      ;;
    zypper)
      $SUDO zypper --non-interactive install -y "$@"
      ;;
  esac
}

pkg_install_group() {
  local group="$1"
  case "${PKG_MGR}:${group}" in
    apt-get:python)   pkg_install python3 python3-venv python3-pip curl ca-certificates ;;
    pacman:python)    pkg_install python python-pip curl ca-certificates ;;
    dnf:python|yum:python) pkg_install python3 python3-pip curl ca-certificates ;;
    apk:python)       pkg_install python3 py3-pip curl ca-certificates ;;
    zypper:python)    pkg_install python3 python3-pip curl ca-certificates ;;

    apt-get:server)   pkg_install python3 openvpn microsocks iproute2 iptables procps util-linux ca-certificates ;;
    pacman:server)    pkg_install python openvpn microsocks iproute2 iptables procps-ng util-linux ca-certificates ;;
    dnf:server|yum:server)
      pkg_install python3 openvpn iproute iptables procps-ng util-linux ca-certificates
      pkg_install microsocks || echo "[!] Paket microsocks tidak ada di repo default; install manual atau pakai EPEL/source." >&2
      ;;
    apk:server)       pkg_install python3 openvpn microsocks iproute2 iptables procps util-linux ca-certificates ;;
    zypper:server)
      pkg_install python3 openvpn iproute2 iptables procps util-linux ca-certificates
      pkg_install microsocks || echo "[!] Paket microsocks tidak ada di repo default; install manual jika dibutuhkan server." >&2
      ;;

    pacman:chromium)
      pkg_install nss nspr at-spi2-core libcups libdrm mesa libxkbcommon \
        libxcomposite libxdamage libxfixes libxrandr libx11 libxext libxcb \
        libxshmfence pango cairo alsa-lib dbus expat glib2 ttf-liberation
      ;;
    dnf:chromium|yum:chromium)
      pkg_install nss nspr atk at-spi2-atk cups-libs libdrm mesa-libgbm libxkbcommon \
        libXcomposite libXdamage libXfixes libXrandr libX11 libXext libxcb \
        libxshmfence pango cairo alsa-lib dbus-libs expat glib2 liberation-sans-fonts
      ;;
    apk:chromium)
      pkg_install chromium nss nspr at-spi2-core cups-libs libdrm mesa-gl mesa-gbm \
        libxkbcommon libxcomposite libxdamage libxfixes libxrandr libx11 libxext \
        libxcb libxshmfence pango cairo alsa-lib dbus-libs expat glib ttf-liberation
      ;;
    zypper:chromium)
      pkg_install mozilla-nss mozilla-nspr libatk-1_0-0 libatk-bridge-2_0-0 libcups2 \
        libdrm2 Mesa-libGL1 libgbm1 libxkbcommon0 libXcomposite1 libXdamage1 \
        libXfixes3 libXrandr2 libX11-6 libXext6 libxcb1 libxshmfence1 \
        libpango-1_0-0 libcairo2 libasound2 libdbus-1-3 libexpat1 libglib-2_0-0 liberation-fonts
      ;;
    *)
      pkg_install
      ;;
  esac
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
  local def_port="${2:-8080}"
  [[ -n "$u" ]] || return 0
  [[ "$u" =~ ^https?:// ]] || u="http://$u"
  u="${u%/}"
  if [[ "$u" == http://* && "${u#http://}" != *:* ]]; then
    u="$u:$def_port"
  fi
  printf '%s' "$u"
}

_write_secret_file() {
  local dst="$1" payload="$2" use_sudo="${3:-0}"
  local dir old_u tmp_f
  dir="$(dirname -- "$dst")"
  old_u="$(umask)"
  umask 077
  tmp_f="$(mktemp)"
  printf '%s\n' "$payload" > "$tmp_f"
  chmod 600 "$tmp_f"
  umask "$old_u"
  if [[ "$use_sudo" -eq 1 && "$SUDO" != "__NEED_ROOT__" ]]; then
    $SUDO mkdir -p "$dir"
    $SUDO install -m 600 "$tmp_f" "$dst"
    rm -f "$tmp_f"
  else
    mkdir -p "$dir"
    mv -f "$tmp_f" "$dst"
    chmod 600 "$dst" 2>/dev/null || true
  fi
}

validate_induk_port() {
  if ! [[ "$INDUK_PORT" =~ ^[0-9]+$ ]] || (( INDUK_PORT < 1025 || INDUK_PORT > 65535 )); then
    echo "Error: --induk-port must be in 1025..65535 (got: $INDUK_PORT)" >&2
    exit 1
  fi
  local gw_port=8080 gw_base=20001 gw_max=45
  if [[ -f /etc/systemd/system/ufasproxy.service ]]; then
    local ex
    ex="$(cat /etc/systemd/system/ufasproxy.service 2>/dev/null || true)"
    if [[ "$ex" =~ --port[[:space:]]+([0-9]+) ]]; then gw_port="${BASH_REMATCH[1]}"; fi
    if [[ "$ex" =~ --base-proxy-port[[:space:]]+([0-9]+) ]]; then gw_base="${BASH_REMATCH[1]}"; fi
    if [[ "$ex" =~ --max-slots[[:space:]]+([0-9]+) ]]; then gw_max="${BASH_REMATCH[1]}"; fi
  fi
  local gw_end=$(( gw_base + gw_max - 1 ))
  if [[ "$DO_SERVER" -eq 1 || -f /etc/systemd/system/ufasproxy.service ]]; then
    if (( INDUK_PORT == gw_port || (INDUK_PORT >= gw_base && INDUK_PORT <= gw_end) )); then
      echo "Error: --induk-port $INDUK_PORT collides with Gateway VPN ports ($gw_port / $gw_base..$gw_end)" >&2
      exit 1
    fi
  fi
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
  local tmp_env old_u
  old_u="$(umask)"
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
  umask "$old_u"
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
  pkg_install_group server

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

install_induk() {
  echo "[*] Installing ufasproxy INDUK Controller prerequisites..."
  validate_induk_port

  echo "[1/4] Checking Python 3.10+, venv, git, and curl..."
  local py_bin
  py_bin="$(command -v python3 || command -v python || true)"
  if [[ -z "$py_bin" ]] || ! "$py_bin" -c "import ensurepip" >/dev/null 2>&1; then
    pkg_install_group python
    py_bin="$(command -v python3 || command -v python || true)"
  fi
  if ! command -v git >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1; then
    pkg_install git curl
  fi
  if [[ -z "$py_bin" ]] || ! "$py_bin" -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" >/dev/null 2>&1; then
    echo "Error: Python 3.10+ required" >&2
    exit 1
  fi

  echo "[2/4] Setting up .venv_induk and Induk packages..."
  if [[ ! -x "$SCRIPT_DIR/.venv_induk/bin/python" ]] || ! "$SCRIPT_DIR/.venv_induk/bin/python" -m pip --version >/dev/null 2>&1; then
    rm -rf "$SCRIPT_DIR/.venv_induk"
    "$py_bin" -m venv "$SCRIPT_DIR/.venv_induk"
  fi
  local ivpy="$SCRIPT_DIR/.venv_induk/bin/python"
  "$ivpy" -m pip install --upgrade pip setuptools wheel
  "$ivpy" -m pip install -r "$SCRIPT_DIR/induk/requirements_induk.txt"

  echo "[3/4] Running Induk controller self-tests..."
  PYTHONPATH="$SCRIPT_DIR" "$ivpy" -m pytest \
    "$SCRIPT_DIR/tests/test_induk_db.py" \
    "$SCRIPT_DIR/tests/test_induk_api.py" \
    "$SCRIPT_DIR/tests/test_induk_e2e.py" \
    "$SCRIPT_DIR/tests/test_migration.py" \
    "$SCRIPT_DIR/tests/test_splitters_provisioner.py" \
    "$SCRIPT_DIR/tests/test_audit_fixes.py" -q

  echo "[4/4] Initializing induk_data, env, and service..."
  mkdir -p "$SCRIPT_DIR/induk_data"
  if [[ -n "$RESTORE_BUNDLE" ]]; then
    if [[ ! -f "$RESTORE_BUNDLE" ]]; then
      echo "Error: restore bundle not found: $RESTORE_BUNDLE" >&2
      exit 1
    fi
    if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]] && [[ "$SUDO" != "__NEED_ROOT__" ]]; then
      $SUDO systemctl stop ufasproxy-induk.service 2>/dev/null || true
    fi
    echo "[*] Restoring backup $RESTORE_BUNDLE..."
    rm -f "$SCRIPT_DIR/induk_data/induk.db-wal" "$SCRIPT_DIR/induk_data/induk.db-shm"
    "$ivpy" - "$RESTORE_BUNDLE" "$SCRIPT_DIR/induk_data" << 'PY'
import os, sys, tarfile
bundle, dest = sys.argv[1], sys.argv[2]
with tarfile.open(bundle, "r:gz") as tf:
    members = []
    for m in tf.getmembers():
        norm = os.path.normpath(m.name)
        if norm.startswith("..") or os.path.isabs(norm) or norm == ".":
            raise SystemExit(f"Unsafe archive path: {m.name}")
        if not (m.isreg() or m.isdir()):
            raise SystemExit(f"Unsafe archive entry type: {m.name}")
        m.mode &= 0o777
        members.append(m)
    tf.extractall(dest, members=members)
PY
  fi

  local env_dir="/etc/ufasproxy-induk"
  local env_file="$env_dir/env"
  local use_sudo=1
  if [[ "$SUDO" == "__NEED_ROOT__" ]]; then
    env_dir="$SCRIPT_DIR/induk_data"
    env_file="$env_dir/induk.env"
    use_sudo=0
  fi

  local api_key="${ARG_INDUK_API_KEY:-}"
  if [[ -z "$api_key" ]]; then
    if [[ "$use_sudo" -eq 1 && -f "$env_file" ]]; then
      api_key="$($SUDO awk -F= '$1=="INDUK_API_KEY"{print substr($0,index($0,"=")+1); exit}' "$env_file" 2>/dev/null || true)"
    elif [[ -f "$env_file" ]]; then
      api_key="$(awk -F= '$1=="INDUK_API_KEY"{print substr($0,index($0,"=")+1); exit}' "$env_file" 2>/dev/null || true)"
    fi
  fi
  if [[ -z "$api_key" ]]; then
    api_key="$("$ivpy" -c "import secrets; print(secrets.token_urlsafe(24))")"
  fi

  local env_payload
  env_payload="$(printf 'INDUK_API_KEY=%s\nINDUK_DATA_DIR=%s\nINDUK_REPO_DIR=%s\nINDUK_PORT=%s' \
    "$api_key" "$SCRIPT_DIR/induk_data" "$SCRIPT_DIR" "$INDUK_PORT")"
  _write_secret_file "$env_file" "$env_payload" "$use_sudo"

  if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]] && [[ "$SUDO" != "__NEED_ROOT__" ]]; then
    cat <<EOF | $SUDO tee /etc/systemd/system/ufasproxy-induk.service >/dev/null
[Unit]
Description=ufasproxy Induk Multi-VPS Controller
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$SCRIPT_DIR
EnvironmentFile=$env_file
ExecStart="$SCRIPT_DIR/.venv_induk/bin/uvicorn" induk.app:app --host 0.0.0.0 --port $INDUK_PORT
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    $SUDO systemctl daemon-reload
    $SUDO systemctl enable ufasproxy-induk.service >/dev/null 2>&1 || true
    $SUDO systemctl restart ufasproxy-induk.service
    echo "[OK] ufasproxy-induk.service aktif di port $INDUK_PORT ✓"
  else
    echo "[OK] ufasproxy INDUK ready (systemd tidak aktif; jalankan manual):"
    echo "  set -a && source \"$env_file\" && set +a && \"$SCRIPT_DIR/.venv_induk/bin/uvicorn\" induk.app:app --host 0.0.0.0 --port $INDUK_PORT"
  fi
  echo "INDUK env saved -> $env_file (chmod 600)"
}

install_client() {
  echo "[*] Installing ufasproxy CLIENT checker prerequisites..."

  echo "[1/4] Checking Python 3.10+, venv, and pip..."
  local py_bin
  py_bin="$(command -v python3 || command -v python || true)"
  if [[ -z "$py_bin" ]] || ! "$py_bin" -c "import ensurepip" >/dev/null 2>&1; then
    pkg_install_group python
    py_bin="$(command -v python3 || command -v python || true)"
  fi
  if [[ -z "$py_bin" ]] || ! "$py_bin" -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" >/dev/null 2>&1; then
    echo "Error: Python 3.10+ required" >&2
    exit 1
  fi

  echo "[2/4] Setting up .venv and Python packages..."
  if [[ ! -x "$SCRIPT_DIR/.venv/bin/python" ]] || ! "$SCRIPT_DIR/.venv/bin/python" -m pip --version >/dev/null 2>&1; then
    rm -rf "$SCRIPT_DIR/.venv"
    "$py_bin" -m venv "$SCRIPT_DIR/.venv"
  fi
  local vpy="$SCRIPT_DIR/.venv/bin/python"
  "$vpy" -m pip install --upgrade pip setuptools wheel
  "$vpy" -m pip install -r "$SCRIPT_DIR/requirements.txt"

  echo "[3/4] Installing Chromium OS dependencies & CloakBrowser binary..."
  if [[ "$(uname -s)" = "Linux" ]]; then
    if [[ "$PKG_MGR" = "apt-get" ]]; then
      if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
        env DEBIAN_FRONTEND=noninteractive "$vpy" -m playwright install-deps chromium
      elif [[ -n "$SUDO" && "$SUDO" != "__NEED_ROOT__" ]]; then
        $SUDO env "PATH=$PATH" DEBIAN_FRONTEND=noninteractive "$vpy" -m playwright install-deps chromium
      else
        echo "Error: root/sudo required for playwright install-deps chromium" >&2
        exit 1
      fi
    elif [[ -n "$PKG_MGR" ]]; then
      pkg_install_group chromium
    else
      echo "[!] Package manager tidak dikenali; lewati instalasi library OS Chromium (install manual jika gagal launch)." >&2
    fi
  fi
  CLOAKBROWSER_CACHE_DIR="$SCRIPT_DIR/.cloak_old_cache" \
    "$vpy" -c "from cloakbrowser.download import ensure_binary; p=ensure_binary(license_key=None); print('[*] CloakBrowser binary:', p)" || true

  echo "[4/4] Running old_browser_vpn.py --selftest..."
  "$vpy" "$SCRIPT_DIR/old_browser_vpn.py" --selftest

  local cur_u cur_t cli_url cli_tok
  cur_u="$(_read_env_val UFASPROXY_URL)"
  cur_t="$(_read_env_val UFASPROXY_TOKEN)"
  cli_url="${ARG_URL:-$cur_u}"
  [[ -n "$cli_url" ]] || cli_url="$DEFAULT_URL"
  cli_tok="${ARG_TOKEN:-$cur_t}"
  [[ -n "$cli_tok" ]] || cli_tok="$DEFAULT_TOKEN"
  if [[ "${cli_url,,}" == "off" || "${cli_url,,}" == "none" ]]; then
    cli_url=""
  fi
  if [[ -n "$cli_url" ]]; then
    write_token_env "$cli_url" "$cli_tok"
    cli_url="$(_read_env_val UFASPROXY_URL)"
    echo "[*] Konfigurasi API disimpan -> $TOKEN_FILE"
  fi

  if [[ -t 0 && -z "$INDUK_URL" && -z "$AGENT_TOKEN" ]]; then
    read -r -p "Hubungkan worker ke Server Induk? INDUK_URL (Enter untuk lewati): " _in_induk_url || true
    if [[ -n "${_in_induk_url:-}" ]]; then
      INDUK_URL="$_in_induk_url"
      read -r -s -p "Agent Token dari Induk: " _in_ag_tok || true
      echo ""
      AGENT_TOKEN="${_in_ag_tok:-}"
      read -r -p "VPS ID [$(hostname 2>/dev/null || echo worker-1)]: " _in_vid || true
      [[ -n "${_in_vid:-}" ]] && VPS_ID="$_in_vid"
      read -r -p "INDUK_POINTER_URL (opsional): " _in_ptr || true
      [[ -n "${_in_ptr:-}" ]] && INDUK_POINTER_URL="$_in_ptr"
    fi
  fi

  if [[ -n "$INDUK_URL" || -n "$AGENT_TOKEN" ]]; then
    if [[ -z "$INDUK_URL" || -z "$AGENT_TOKEN" ]]; then
      echo "Error: --induk-url dan --agent-token harus diisi bersama" >&2
      exit 1
    fi
    INDUK_URL="${INDUK_URL//$'\r'/}"; INDUK_URL="${INDUK_URL//$'\n'/}"
    INDUK_URL="$(_norm_url "$INDUK_URL" 8000)"
    AGENT_TOKEN="${AGENT_TOKEN//$'\r'/}"; AGENT_TOKEN="${AGENT_TOKEN//$'\n'/}"
    INDUK_POINTER_URL="${INDUK_POINTER_URL//$'\r'/}"; INDUK_POINTER_URL="${INDUK_POINTER_URL//$'\n'/}"

    "$vpy" -m pip install --upgrade "websockets>=13.0"
    git config --global --add safe.directory "$SCRIPT_DIR" 2>/dev/null || true
    local vid="${VPS_ID:-$(hostname 2>/dev/null || echo worker-1)}"
    local ag_dir="/etc/ufasproxy-agent"
    local ag_env="$ag_dir/env"
    local ag_sudo=1
    if [[ "$SUDO" == "__NEED_ROOT__" ]]; then
      ag_dir="$SCRIPT_DIR/.agent_state"
      ag_env="$ag_dir/agent.env"
      ag_sudo=0
    fi
    local ag_payload
    ag_payload="$(printf 'VPS_ID=%s\nINDUK_URL=%s\nAGENT_TOKEN=%s\nWORK_DIR=%s\nENV_FILE=%s\nINDUK_POINTER_URL=%s\nUFASPROXY_URL=%s' \
      "$vid" "$INDUK_URL" "$AGENT_TOKEN" "$SCRIPT_DIR" "$ag_env" "$INDUK_POINTER_URL" "$cli_url")"
    _write_secret_file "$ag_env" "$ag_payload" "$ag_sudo"

    if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]] && [[ "$SUDO" != "__NEED_ROOT__" ]]; then
      $SUDO mkdir -p /etc/systemd/journald.conf.d
      cat <<EOF | $SUDO tee /etc/systemd/journald.conf.d/ufasproxy.conf >/dev/null
[Journal]
SystemMaxUse=100M
MaxRetentionSec=7day
EOF
      $SUDO systemctl restart systemd-journald || true
      cat <<EOF | $SUDO tee /etc/systemd/system/ufasproxy-agent.service >/dev/null
[Unit]
Description=ufasproxy Worker Agent ($vid)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$SCRIPT_DIR
EnvironmentFile=$ag_env
ExecStart="$SCRIPT_DIR/.venv/bin/python" "$SCRIPT_DIR/agent.py"
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
      $SUDO systemctl daemon-reload
      $SUDO systemctl enable ufasproxy-agent.service >/dev/null 2>&1 || true
      $SUDO systemctl restart ufasproxy-agent.service
      echo "[OK] ufasproxy-agent.service aktif ($vid -> $INDUK_URL) ✓"
    else
      echo "[OK] Agent config saved -> $ag_env (systemd tidak aktif; jalankan manual):"
      echo "  set -a && source \"$ag_env\" && set +a && \"$vpy\" \"$SCRIPT_DIR/agent.py\""
    fi
  fi

  cat <<EOF

[OK] ufasproxy CLIENT ready!
API config ready in $TOKEN_FILE; run:
  source "$SCRIPT_DIR/.venv/bin/activate"
  python "$SCRIPT_DIR/old_browser_vpn.py" -c "$SCRIPT_DIR/input/<combo>.txt" -w auto
Tip: jika pindah server/token nanti, jalankan:
  bash install.sh --client --url http://<IP_BARU>:8080 --token <TOKEN_BARU>
EOF
}

if [[ "$DO_INDUK" -eq 1 ]]; then
  validate_induk_port
fi
if [[ "$DO_SERVER" -eq 1 ]]; then
  install_server
fi
if [[ "$DO_INDUK" -eq 1 ]]; then
  install_induk
fi
if [[ "$DO_CLIENT" -eq 1 ]]; then
  install_client
fi
