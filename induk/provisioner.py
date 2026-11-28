"""Multi-distro Linux SSH provisioner with auto-benchmark VPS worker sizing."""

from __future__ import annotations

import json
import shlex
from typing import Awaitable, Callable


class UnsupportedOSError(RuntimeError):
    """Raised when target host OS/package manager is unknown or unsupported."""


_DISTRO_PKG_MGR = {
    "ubuntu": "apt-get",
    "debian": "apt-get",
    "linuxmint": "apt-get",
    "pop": "apt-get",
    "kali": "apt-get",
    "raspbian": "apt-get",
    "arch": "pacman",
    "manjaro": "pacman",
    "endeavouros": "pacman",
    "cachyos": "pacman",
    "garuda": "pacman",
    "fedora": "dnf",
    "rhel": "dnf",
    "rocky": "dnf",
    "almalinux": "dnf",
    "centos": "dnf",
    "ol": "dnf",
    "alpine": "apk",
    "opensuse-leap": "zypper",
    "opensuse-tumbleweed": "zypper",
    "sles": "zypper",
}


def validate_supported_os_release(os_release_text: str) -> tuple[str, str]:
    """Parse /etc/os-release and return (os_tag, pkg_mgr) across major Linux distros."""
    kv: dict[str, str] = {}
    for ln in (os_release_text or "").splitlines():
        if "=" in ln:
            k, v = ln.strip().split("=", 1)
            kv[k] = v.strip('"').strip("'")
    os_id = kv.get("ID", "").lower()
    ver = kv.get("VERSION_ID", "")
    if not os_id:
        raise UnsupportedOSError("Unsupported OS: missing ID in /etc/os-release")
    pkg_mgr = _DISTRO_PKG_MGR.get(os_id, "")
    if not pkg_mgr:
        id_like = kv.get("ID_LIKE", "").lower().split()
        for cand in id_like:
            if cand in _DISTRO_PKG_MGR:
                pkg_mgr = _DISTRO_PKG_MGR[cand]
                break
    if not pkg_mgr:
        raise UnsupportedOSError(f"Unsupported OS: {os_id} {ver or 'unknown'} (no known package manager)")
    os_tag = f"{os_id}-{ver}".strip("-")
    return os_tag, pkg_mgr


def compute_recommended_workers(cpu_cores: int, ram_mb: int, cpu_ops_per_ms: float) -> dict:
    cores = max(1, int(cpu_cores))
    mem = max(256, int(ram_mb))
    ops = float(cpu_ops_per_ms)
    speed_factor = max(0.6, min(1.5, ops / 180.0))
    ram_cap = max(1, int((mem - 600) // 350))
    cpu_cap = max(1, int(round(cores * speed_factor * 1.5)))
    rec = max(1, min(20, ram_cap, cpu_cap))
    return {
        "cpu_cores": cores,
        "ram_mb": mem,
        "cpu_ops_per_ms": round(ops, 2),
        "recommended_workers": rec,
    }


_REMOTE_BENCH_PY = (
    "import hashlib,json,os,time;"
    "c=os.cpu_count() or 1;"
    "m=4096;"
    "try:\n"
    " for l in open('/proc/meminfo'):\n"
    "  if l.startswith('MemTotal:'): m=int(l.split()[1])//1024\n"
    "except Exception: pass\n"
    "t0=time.perf_counter();ops=0;s=b'b';dl=t0+0.25\n"
    "while time.perf_counter()<dl:\n"
    " for _ in range(200): s=hashlib.sha256(s).digest();ops+=1\n"
    "el=max(1.0,(time.perf_counter()-t0)*1000.0);"
    "print(json.dumps({'cpu_cores':c,'ram_mb':m,'cpu_ops_per_ms':round(ops/el,2)}))"
)


def render_bootstrap_script(
    induk_url: str,
    vps_id: str,
    token: str,
    repo_url: str = "https://github.com/lilvoda/ufasproxy.git",
    pointer_url: str = "",
    ufasproxy_url: str = "",
    ufasproxy_token: str = "",
) -> str:
    # Secrets passed via 0600 temp env inside shell (hidden from ps /proc/<pid>/cmdline)
    env_lines = [
        f"INDUK_URL={shlex.quote(induk_url)}",
        f"AGENT_TOKEN={shlex.quote(token)}",
        f"VPS_ID={shlex.quote(vps_id)}",
    ]
    if pointer_url.strip():
        env_lines.append(f"INDUK_POINTER_URL={shlex.quote(pointer_url.strip())}")
    if ufasproxy_url.strip():
        env_lines.append(f"UFASPROXY_URL={shlex.quote(ufasproxy_url.strip())}")
    if ufasproxy_token.strip():
        env_lines.append(f"UFASPROXY_TOKEN={shlex.quote(ufasproxy_token.strip())}")
    env_block = "\n".join(env_lines)
    return f"""#!/usr/bin/env sh
set -eu
SUDO=""
if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
  SUDO="sudo"
fi
if command -v apt-get >/dev/null 2>&1; then
  $SUDO env DEBIAN_FRONTEND=noninteractive apt-get update -y
  $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends bash git curl ca-certificates python3 python3-venv python3-pip
elif command -v pacman >/dev/null 2>&1; then
  $SUDO pacman -Sy --noconfirm --needed bash git curl ca-certificates python python-pip
elif command -v dnf >/dev/null 2>&1; then
  $SUDO dnf install -y bash git curl ca-certificates python3 python3-pip
elif command -v yum >/dev/null 2>&1; then
  $SUDO yum install -y bash git curl ca-certificates python3 python3-pip
elif command -v apk >/dev/null 2>&1; then
  $SUDO apk add --no-cache bash git curl ca-certificates python3 py3-pip
elif command -v zypper >/dev/null 2>&1; then
  $SUDO zypper --non-interactive install -y bash git curl ca-certificates python3 python3-pip
else
  echo "[!] Package manager tidak dikenali" >&2
  exit 1
fi
WORK_DIR="/opt/ufasproxy"
if [ ! -d "$WORK_DIR/.git" ]; then
  $SUDO git clone {shlex.quote(repo_url)} "$WORK_DIR"
  $SUDO chown -R "$(id -un):$(id -gn)" "$WORK_DIR"
else
  git -C "$WORK_DIR" pull --ff-only || true
fi
cd "$WORK_DIR"
ENV_TMP="$(mktemp)"
chmod 600 "$ENV_TMP"
trap 'rm -f "$ENV_TMP"' EXIT
cat > "$ENV_TMP" <<'UFP_ENV'
{env_block}
UFP_ENV
set -a
. "$ENV_TMP"
set +a
rm -f "$ENV_TMP"
bash install.sh --client --no-git-push
"""


async def provision_via_ssh(
    host: str,
    port: int,
    username: str,
    password: str | None,
    private_key: str | None,
    vps_id: str,
    token: str,
    induk_url: str,
    repo_url: str = "https://github.com/lilvoda/ufasproxy.git",
    pointer_url: str = "",
    ufasproxy_url: str = "",
    ufasproxy_token: str = "",
    on_log: Callable[[str], Awaitable[None]] | None = None,
) -> dict:
    import asyncssh

    async def _log(msg: str) -> None:
        if on_log is not None:
            await on_log(msg)

    conn_kw: dict = {"host": host, "port": int(port or 22), "username": username, "known_hosts": None}
    if private_key and private_key.strip():
        conn_kw["client_keys"] = [asyncssh.import_private_key(private_key.strip())]
    elif password:
        conn_kw["password"] = password

    await _log(f"[{vps_id}] Connecting SSH {username}@{host}:{port}...")
    async with asyncssh.connect(**conn_kw) as conn:
        os_res = await conn.run("cat /etc/os-release", check=False)
        os_tag, pkg_mgr = validate_supported_os_release(os_res.stdout or "")
        await _log(f"[{vps_id}] OS verified: {os_tag} ({pkg_mgr})")

        bench_cmd = f"(command -v python3 || command -v python) | head -n1 | xargs -I{{}} {{}} -c {shlex.quote(_REMOTE_BENCH_PY)}"
        b_res = await conn.run(bench_cmd, check=False)
        if b_res.exit_status == 0 and (b_res.stdout or "").strip():
            raw_b = json.loads((b_res.stdout or "").strip().splitlines()[-1])
        else:
            raw_b = {"cpu_cores": 2, "ram_mb": 2048, "cpu_ops_per_ms": 150.0}
        bench = compute_recommended_workers(raw_b["cpu_cores"], raw_b["ram_mb"], raw_b["cpu_ops_per_ms"])
        await _log(
            f"[{vps_id}] Auto-benchmark: {bench['cpu_cores']} vCPU, {bench['ram_mb']} MB RAM -> {bench['recommended_workers']} workers"
        )

        script = render_bootstrap_script(
            induk_url, vps_id, token, repo_url, pointer_url, ufasproxy_url, ufasproxy_token
        )
        await _log(f"[{vps_id}] Installing ufasproxy client + agent...")
        proc = await conn.create_process("sh -s", input=script, stderr=asyncssh.STDOUT)
        async for line in proc.stdout:
            await _log(f"[{vps_id}] {line.rstrip()}")
        res = await proc.wait()
        if res.exit_status != 0:
            raise RuntimeError(f"Provision failed (exit {res.exit_status})")
        await _log(f"[{vps_id}] Provision complete ✓")
        return {"os_info": os_tag, "benchmark": bench}
