"""Lightweight 2-way worker agent for Linux/Windows VPS running ufasproxy old_browser_vpn.py."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import threading
import time
import urllib.parse
import urllib.request
import zipfile
from collections import deque

_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def _is_pid_alive(pid: int) -> bool:
    if not pid or pid <= 0:
        return False
    if os.name == "nt":
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            h = kernel32.OpenProcess(0x1000, False, int(pid))
            if not h:
                return False
            try:
                code = ctypes.c_ulong()
                if kernel32.GetExitCodeProcess(h, ctypes.byref(code)):
                    return code.value == 259  # STILL_ACTIVE
                return False
            finally:
                kernel32.CloseHandle(h)
        except Exception:
            return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    stat_path = f"/proc/{pid}/stat"
    if os.path.isfile(stat_path):
        try:
            txt = open(stat_path, "r", encoding="utf-8", errors="ignore").read()
            rp = txt.rfind(")")
            if rp != -1 and len(txt) > rp + 2 and txt[rp + 2] == "Z":
                return False
        except OSError:
            pass
    return True


def _read_os_info() -> str:
    if os.path.isfile("/etc/os-release"):
        kv: dict[str, str] = {}
        for ln in open("/etc/os-release", encoding="utf-8", errors="ignore"):
            if "=" in ln:
                k, v = ln.strip().split("=", 1)
                kv[k] = v.strip('"').strip("'")
        if kv.get("ID"):
            return f"{kv['ID']}-{kv.get('VERSION_ID', '')}".strip("-")
    return sys.platform


def _read_mem_mb() -> tuple[int, float]:
    if os.path.isfile("/proc/meminfo"):
        info: dict[str, int] = {}
        for ln in open("/proc/meminfo", encoding="utf-8", errors="ignore"):
            parts = ln.split(":")
            if len(parts) == 2:
                vals = parts[1].strip().split()
                if vals and vals[0].isdigit():
                    info[parts[0]] = int(vals[0])
        tot_kb = info.get("MemTotal", 0)
        avail_kb = info.get("MemAvailable", info.get("MemFree", 0))
        if tot_kb > 0:
            pct = round((1.0 - avail_kb / tot_kb) * 100.0, 1)
            return max(256, tot_kb // 1024), max(0.0, min(100.0, pct))
    return 4096, 0.0


def _ws_url_from_http(base_url: str) -> str:
    u = base_url.rstrip("/")
    if u.startswith("https://"):
        return "wss://" + u[8:] + "/ws/agent"
    if u.startswith("http://"):
        return "ws://" + u[7:] + "/ws/agent"
    return u + "/ws/agent"


class MuseAgent:
    def __init__(
        self,
        vps_id: str,
        induk_url: str,
        token: str,
        work_dir: str = ".",
        env_file: str = "",
        pointer_url: str = "",
        ufasproxy_url: str = "",
    ) -> None:
        self.vps_id = vps_id
        self.induk_url = induk_url.rstrip("/")
        self.token = token
        self.work_dir = os.path.abspath(work_dir)
        self.env_file = env_file
        self.pointer_url = pointer_url.strip()
        self.ufasproxy_url = ufasproxy_url.strip()
        self.state_dir = os.path.join(self.work_dir, ".agent_state")
        os.makedirs(self.state_dir, exist_ok=True)
        self.active_job_path = os.path.join(self.state_dir, "active_job.json")
        self.manual_job_path = os.path.join(self.state_dir, "manual_job.json")
        self.seen_cmds_path = os.path.join(self.state_dir, "seen_cmds.json")
        self.bench_path = os.path.join(self.state_dir, "benchmark.json")
        self._job_lock = threading.Lock()
        self.seen_cmds: deque[str] = self._load_seen_cmds()
        self.proc: subprocess.Popen | None = None
        self.active_job: dict | None = None
        self.os_info = _read_os_info()
        self.benchmark: dict | None = self._load_benchmark()
        self._prev_cpu: tuple[int, int] | None = None
        self._reconnect_needed = False

    def _resolve_checker_python(self) -> str:
        cands = (
            os.path.join(self.work_dir, ".venv", "bin", "python"),
            os.path.join(self.work_dir, ".venv", "Scripts", "python.exe"),
            os.path.join(self.work_dir, ".venv_old", "bin", "python"),
            os.path.join(self.work_dir, ".venv_old", "Scripts", "python.exe"),
        )
        for p in cands:
            if os.path.isfile(p):
                return p
        return sys.executable

    def _load_seen_cmds(self) -> deque[str]:
        if os.path.isfile(self.seen_cmds_path):
            try:
                return deque(json.loads(open(self.seen_cmds_path, encoding="utf-8").read()), maxlen=200)
            except Exception:
                pass
        return deque(maxlen=200)

    def mark_cmd_seen(self, cmd_id: str) -> bool:
        if not cmd_id or cmd_id in self.seen_cmds:
            return False
        self.seen_cmds.append(cmd_id)
        try:
            with open(self.seen_cmds_path, "w", encoding="utf-8") as f:
                json.dump(list(self.seen_cmds), f)
        except OSError:
            pass
        return True

    def _load_benchmark(self) -> dict | None:
        if os.path.isfile(self.bench_path):
            try:
                return json.loads(open(self.bench_path, encoding="utf-8").read())
            except Exception:
                pass
        return None

    def run_benchmark(self, duration_s: float = 0.25) -> dict:
        cpu_cores = os.cpu_count() or 1
        ram_mb, _ = _read_mem_mb()
        t0 = time.perf_counter()
        ops = 0
        seed = b"muse-vps-bench"
        deadline = t0 + max(0.02, float(duration_s))
        while time.perf_counter() < deadline:
            for _ in range(200):
                seed = hashlib.sha256(seed).digest()
                ops += 1
        elapsed_ms = max(1.0, (time.perf_counter() - t0) * 1000.0)
        ops_per_ms = round(ops / elapsed_ms, 2)
        speed_factor = max(0.6, min(1.5, ops_per_ms / 180.0))
        ram_cap = max(1, int((ram_mb - 600) // 350))
        cpu_cap = max(1, int(round(cpu_cores * speed_factor * 1.5)))
        rec_workers = max(1, min(20, ram_cap, cpu_cap))
        res = {
            "cpu_cores": cpu_cores,
            "ram_mb": ram_mb,
            "cpu_ops_per_ms": ops_per_ms,
            "recommended_workers": rec_workers,
            "benchmarked_at": time.time(),
        }
        self.benchmark = res
        try:
            with open(self.bench_path, "w", encoding="utf-8") as f:
                json.dump(res, f)
        except OSError:
            pass
        return res

    def save_active_job(self, info: dict | None) -> None:
        self.active_job = info
        if info is None:
            if os.path.isfile(self.active_job_path):
                try:
                    os.remove(self.active_job_path)
                except OSError:
                    pass
            return
        tmp = f"{self.active_job_path}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(info, f)
        os.replace(tmp, self.active_job_path)

    def _register_manual_job_if_needed(self) -> None:
        with self._job_lock:
            job = dict(self.active_job) if self.active_job else None
        if not job or not job.get("manual") or job.get("manual_registered"):
            return
        cname = str((job.get("payload") or {}).get("combo_name") or "")
        self._http_request("POST", "/api/v1/agent/register-job", {"job_id": job["job_id"], "filename": cname})
        with self._job_lock:
            if self.active_job and self.active_job.get("job_id") == job.get("job_id"):
                self.active_job["manual_registered"] = True
                self.save_active_job(self.active_job)

    def adopt_manual_job_sync(self) -> bool:
        if not os.path.isfile(self.manual_job_path):
            return False
        with self._job_lock:
            if self.active_job:
                proc_alive = self.proc is not None and self.proc.poll() is None
                pid_prev = int(self.active_job.get("pid") or 0)
                if proc_alive or (self.proc is None and pid_prev and _is_pid_alive(pid_prev)):
                    return False
                need_prev_flush = not self.active_job.get("output_uploaded")
            else:
                need_prev_flush = False
        if need_prev_flush:
            self._safe_flush_hits()
            self._safe_upload_finished_output(force=True)
        adopted = False
        with self._job_lock:
            if not os.path.isfile(self.manual_job_path):
                return False
            try:
                info = json.loads(open(self.manual_job_path, encoding="utf-8").read())
            except Exception:
                return False
            jid = str(info.get("job_id") or "").strip()
            pid = int(info.get("pid") or 0)
            if not jid or not pid:
                return False
            with contextlib.suppress(OSError):
                os.remove(self.manual_job_path)
            self.proc = None
            self.save_active_job(
                {
                    "pid": pid,
                    "job_id": jid,
                    "output_dir": str(info.get("output_dir") or ""),
                    "status_json": str(info.get("status_json") or ""),
                    "offsets": {},
                    "manual": True,
                    "manual_registered": False,
                    "payload": {
                        "job_id": jid,
                        "local_combo_path": str(info.get("combo_path") or ""),
                        "combo_name": str(info.get("combo_name") or ""),
                    },
                }
            )
            adopted = True
        if adopted:
            with contextlib.suppress(Exception):
                self._register_manual_job_if_needed()
        return adopted

    def _safe_sync_manual_job(self) -> None:
        try:
            self.adopt_manual_job_sync()
            self._register_manual_job_if_needed()
        except Exception:
            pass

    def load_or_reattach_job(self) -> dict | None:
        if not os.path.isfile(self.active_job_path):
            self.adopt_manual_job_sync()
            return self.active_job
        try:
            info = json.loads(open(self.active_job_path, encoding="utf-8").read())
        except Exception:
            return None
        pid = int(info.get("pid") or 0)
        if _is_pid_alive(pid):
            self.active_job = info
            return info
        self.active_job = info
        try:
            self.flush_hits_sync()
            self.upload_finished_output_sync(force=True)
            self.save_active_job(None)
        except Exception:
            pass
        self.adopt_manual_job_sync()
        return self.active_job

    def apply_new_induk(self, new_url: str) -> None:
        clean = new_url.strip().rstrip("/")
        if not clean:
            return
        self.induk_url = clean
        if self.env_file and os.path.isfile(self.env_file):
            lines = open(self.env_file, "r", encoding="utf-8").read().splitlines()
            out: list[str] = []
            found = False
            for ln in lines:
                if ln.startswith("INDUK_URL="):
                    out.append(f"INDUK_URL={clean}")
                    found = True
                else:
                    out.append(ln)
            if not found:
                out.append(f"INDUK_URL={clean}")
            with open(self.env_file, "w", encoding="utf-8") as f:
                f.write("\n".join(out) + "\n")
        if os.name != "nt" and sys.platform.startswith("linux"):
            self._ensure_linux_bypass_route(clean)
        self._reconnect_needed = True

    @staticmethod
    def _ensure_linux_bypass_route(url: str) -> None:
        try:
            import socket

            host = urllib.parse.urlparse(url).hostname or ""
            if not host:
                return
            ip_addr = socket.gethostbyname(host)
            ip_bin = shutil.which("ip") or ("/sbin/ip" if os.path.isfile("/sbin/ip") else "")
            if not ip_bin or not ip_addr:
                return
            rt = subprocess.run([ip_bin, "-4", "route", "show", "default"], capture_output=True, text=True, timeout=3)
            for ln in rt.stdout.splitlines():
                parts = ln.split()
                if parts and parts[0] == "default" and "dev" in parts:
                    dev = parts[parts.index("dev") + 1]
                    if dev.startswith(("tun", "tap")):
                        continue
                    gw = parts[parts.index("via") + 1] if "via" in parts else ""
                    cmd = [ip_bin, "route", "replace", f"{ip_addr}/32"] + (["via", gw] if gw else []) + ["dev", dev]
                    subprocess.run(cmd, capture_output=True, timeout=3)
                    break
        except Exception:
            pass

    def resolve_pointer_url(self, pointer_url: str) -> str | None:
        if not pointer_url:
            return None
        try:
            req = urllib.request.Request(pointer_url, headers={"User-Agent": "ufasproxy-agent/1.0"})
            with urllib.request.urlopen(req, timeout=8) as r:
                data = json.loads(r.read().decode("utf-8"))
            cand = str(data.get("induk_url") or "").strip().rstrip("/")
            return cand or None
        except Exception:
            return None

    def read_host_metrics(self) -> dict:
        _, ram_pct = _read_mem_mb()
        cpu_pct = 0.0
        if os.path.isfile("/proc/stat"):
            try:
                ln = open("/proc/stat", "r", encoding="utf-8").readline().split()
                vals = [int(x) for x in ln[1:8]]
                idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
                total = sum(vals)
                if self._prev_cpu is not None:
                    pi, pt = self._prev_cpu
                    dt = max(1, total - pt)
                    cpu_pct = round((1.0 - (idle - pi) / dt) * 100.0, 1)
                self._prev_cpu = (idle, total)
            except Exception:
                pass
        return {"cpu_pct": max(0.0, min(100.0, cpu_pct)), "ram_pct": ram_pct}

    @staticmethod
    def tail_new_hits(output_dir: str, offsets: dict[str, int]) -> tuple[dict[str, list[str]], dict[str, int]]:
        batches = {"VALID": [], "OTP": []}
        next_offsets = dict(offsets)
        mapping = (("VALID", "hit_valid.txt"), ("OTP", "hit_2fa.txt"))
        for htype, fname in mapping:
            fp = os.path.join(output_dir, fname)
            if not os.path.isfile(fp):
                continue
            off = int(offsets.get(fname, 0))
            size = os.path.getsize(fp)
            if size <= off:
                continue
            with open(fp, "rb") as f:
                f.seek(off)
                chunk = f.read()
            last_nl = chunk.rfind(b"\n")
            if last_nl == -1:
                continue
            complete = chunk[: last_nl + 1]
            next_offsets[fname] = off + len(complete)
            lines = [ln.strip() for ln in complete.decode("utf-8", errors="ignore").splitlines() if ln.strip()]
            batches[htype] = lines
        return batches, next_offsets

    def _http_request(self, method: str, path_or_url: str, body: dict | None = None, timeout: float = 15.0) -> bytes:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        ctype = "application/json" if body is not None else ""
        return self._http_request_raw(method, path_or_url, data=data, content_type=ctype, timeout=timeout)

    def _http_request_raw(
        self, method: str, path_or_url: str, data: bytes | None = None, content_type: str = "", timeout: float = 15.0
    ) -> bytes:
        url = path_or_url if path_or_url.startswith(("http://", "https://")) else f"{self.induk_url}{path_or_url}"
        headers = {"Authorization": f"Bearer {self.token}"}
        if content_type:
            headers["Content-Type"] = content_type
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()

    def _stop_checker_proc(self) -> None:
        pid = self.proc.pid if self.proc is not None else int((self.active_job or {}).get("pid") or 0)
        if not pid or not _is_pid_alive(pid):
            self.proc = None
            return
        try:
            os.kill(pid, signal.SIGTERM)
        except Exception:
            pass
        deadline = time.monotonic() + 8.0
        while time.monotonic() < deadline and _is_pid_alive(pid):
            time.sleep(0.25)
        if _is_pid_alive(pid):
            try:
                sig = getattr(signal, "SIGKILL", signal.SIGTERM)
                os.kill(pid, sig)
            except Exception:
                pass
        if self.proc is not None:
            try:
                self.proc.wait(timeout=1.0)
            except Exception:
                pass
        self.proc = None

    def _sync_vpn_bundle(self) -> str:
        raw = self._http_request("GET", f"/api/v1/agent/vpn-bundle/{self.vps_id}", timeout=30.0)
        dest = os.path.join(self.work_dir, "vpns_assigned")
        staging = os.path.join(self.work_dir, "vpns_staging")
        shutil.rmtree(staging, ignore_errors=True)
        os.makedirs(staging, exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tf:
            safe_members: list[tarfile.TarInfo] = []
            for member in tf.getmembers():
                norm = os.path.normpath(member.name)
                if norm.startswith("..") or os.path.isabs(norm) or norm == ".":
                    continue
                if not (member.isreg() or member.isdir()):
                    continue
                member.mode &= 0o777
                safe_members.append(member)
            tf.extractall(staging, members=safe_members)
        backup = os.path.join(self.work_dir, "vpns_assigned_old")
        shutil.rmtree(backup, ignore_errors=True)
        if os.path.exists(dest):
            os.replace(dest, backup)
        try:
            os.replace(staging, dest)
        except Exception:
            if os.path.exists(backup) and not os.path.exists(dest):
                os.replace(backup, dest)
            raise
        shutil.rmtree(backup, ignore_errors=True)
        return dest

    def _build_checker_cmd(self, combo_path: str, out_dir: str, status_json: str, rotate_trig: str, payload: dict) -> list[str]:
        py_bin = self._resolve_checker_python()
        args = [str(a) for a in (payload.get("args") or [])]
        if not any(a in ("--workers", "-w") or a.startswith(("--workers=", "-w=")) for a in args):
            args.extend(["--workers", "auto"])
        has_net_flag = any(
            a == f or a.startswith(f + "=")
            for a in args
            for f in ("--vpn-ovpn-dir", "--vpn-api-url", "--no-proxy")
        )
        vpns_dir = os.path.join(self.work_dir, "vpns_assigned")
        use_local_ovpn = any(a == "--vpn-ovpn-dir" or a.startswith("--vpn-ovpn-dir=") for a in args)
        if not has_net_flag:
            if payload.get("sync_vpn") or (os.path.isdir(vpns_dir) and not self.ufasproxy_url):
                args.extend(["--vpn-ovpn-dir", vpns_dir])
                use_local_ovpn = True
            elif self.ufasproxy_url:
                args.extend(["--vpn-api-url", self.ufasproxy_url])
        cmd = [
            py_bin,
            os.path.join(self.work_dir, "old_browser_vpn.py"),
            combo_path,
            "--no-prompt",
            "--out",
            out_dir,
            "--status-json",
            status_json,
            "--rotate-trigger",
            rotate_trig,
        ]
        induk_host = urllib.parse.urlparse(self.induk_url).hostname or ""
        if induk_host and use_local_ovpn:
            cmd.extend(["--induk-host", induk_host])
        cmd.extend(args)
        return cmd

    def _start_checker(self, payload: dict, upload_prev: bool = True) -> str:
        raw_jid = str(payload.get("job_id") or f"job_{int(time.time())}").strip()
        if not _SAFE_ID_RE.match(raw_jid) or ".." in raw_jid:
            raise ValueError(f"Invalid job_id: {raw_jid!r}")
        job_id = raw_jid
        local_combo = str(payload.get("local_combo_path") or "").strip()
        combo_url = str(payload.get("combo_url") or "")
        if local_combo and not combo_url and os.path.isfile(local_combo):
            combo_raw = open(local_combo, "rb").read()
        else:
            combo_raw = self._http_request("GET", combo_url or f"/api/v1/agent/combo/{job_id}/{self.vps_id}", timeout=30.0)
        with self._job_lock:
            prev_alive = bool(self.active_job and _is_pid_alive(int(self.active_job.get("pid") or 0)))
            if self.active_job and prev_alive:
                self._stop_checker_proc()
            had_prev = bool(self.active_job)
        if had_prev:
            self._safe_flush_hits()
            if upload_prev:
                self._safe_upload_finished_output(force=True)
        with self._job_lock:
            job_dir = os.path.join(self.state_dir, "jobs", job_id)
            out_dir = os.path.join(self.work_dir, "output", job_id)
            os.makedirs(job_dir, exist_ok=True)
            os.makedirs(out_dir, exist_ok=True)
            combo_path = os.path.join(job_dir, "combo.txt")
            with open(combo_path, "wb") as f:
                f.write(combo_raw)
            if payload.get("sync_vpn"):
                self._sync_vpn_bundle()

            status_json = os.path.join(job_dir, "status.json")
            rotate_trig = os.path.join(job_dir, "rotate.trig")
            cmd = self._build_checker_cmd(combo_path, out_dir, status_json, rotate_trig, payload)

            log_fp = open(os.path.join(job_dir, "checker.log"), "a", encoding="utf-8")
            try:
                self.proc = subprocess.Popen(cmd, cwd=self.work_dir, stdout=log_fp, stderr=subprocess.STDOUT)
            finally:
                log_fp.close()
            self.save_active_job(
                {
                    "pid": self.proc.pid,
                    "job_id": job_id,
                    "output_dir": out_dir,
                    "status_json": status_json,
                    "rotate_trigger": rotate_trig,
                    "offsets": {},
                    "payload": payload,
                }
            )
            return f"started pid={self.proc.pid}"

    def execute_command(self, cmd: dict) -> tuple[bool, str]:
        ctype = str(cmd.get("type") or "").upper()
        payload = cmd.get("payload") or {}
        try:
            if ctype == "START":
                return True, self._start_checker(payload)
            if ctype == "STOP":
                with self._job_lock:
                    self._stop_checker_proc()
                self._safe_flush_hits()
                self._safe_upload_finished_output(force=True)
                with self._job_lock:
                    self.save_active_job(None)
                return True, "stopped"
            if ctype == "RESTART":
                with self._job_lock:
                    prev_payload = (self.active_job or {}).get("payload") or payload
                    self._stop_checker_proc()
                    if self.active_job:
                        self.active_job["output_uploaded"] = False
                self._safe_flush_hits()
                return True, self._start_checker(prev_payload, upload_prev=False)
            if ctype == "ROTATE_VPN":
                with self._job_lock:
                    job = self.active_job
                    pid = int((job or {}).get("pid") or 0)
                    trig = (job or {}).get("rotate_trigger")
                    if not trig or not _is_pid_alive(pid):
                        return False, "no active job"
                    open(trig, "w").close()
                return True, "rotate triggered"
            if ctype == "SYNC_VPN":
                with self._job_lock:
                    if self.active_job and _is_pid_alive(int(self.active_job.get("pid") or 0)):
                        return False, "cannot sync vpn while job running"
                    self._sync_vpn_bundle()
                return True, "vpn synced"
            if ctype == "UPDATE_CODE":
                rc = subprocess.run(
                    ["git", "-c", f"safe.directory={self.work_dir}", "-C", self.work_dir, "pull", "--ff-only"],
                    capture_output=True,
                    text=True,
                )
                return rc.returncode == 0, (rc.stdout or rc.stderr).strip()[:200]
            if ctype == "BENCHMARK":
                b = self.run_benchmark()
                return True, f"workers={b['recommended_workers']}"
            if ctype == "SET_INDUK":
                new_url = str(payload.get("new_induk_url") or "")
                self.apply_new_induk(new_url)
                return True, f"switched to {self.induk_url}"
            return False, f"unknown command {ctype}"
        except Exception as exc:
            return False, str(exc)[:250]

    def build_telemetry(self) -> dict:
        with self._job_lock:
            if self.proc is not None:
                self.proc.poll()
            job = dict(self.active_job) if self.active_job else None
        pid = int((job or {}).get("pid") or 0)
        alive = _is_pid_alive(pid) if job else False
        snap = {}
        if job and os.path.isfile(job.get("status_json", "")):
            try:
                snap = json.loads(open(job["status_json"], "r", encoding="utf-8").read())
            except Exception:
                pass
        stats_s = snap.get("stats") or {}
        if job and alive:
            agent_state = "ROTATING" if (snap.get("vpn") or {}).get("rotating") else "RUNNING"
        elif job and not alive:
            st = str(stats_s.get("status") or "").upper()
            agent_state = "ERROR" if st == "ABORTED" else "IDLE"
            stats_s["workers_live"] = 0
            if st in ("", "RUNNING"):
                stats_s["status"] = "STOPPED"
        else:
            agent_state = "IDLE"
        return {
            "type": "telemetry",
            "agent_state": agent_state,
            "os_info": self.os_info,
            "job_id": (job or {}).get("job_id", ""),
            "progress": stats_s,
            "smart": snap.get("smart") or {},
            "vpn": snap.get("vpn") or {},
            "top_hits": snap.get("top_hits") or [],
            "log_tail": (snap.get("log_tail") or [])[-50:],
            "host": self.read_host_metrics(),
            "benchmark": self.benchmark,
        }

    def flush_hits_sync(self) -> None:
        with self._job_lock:
            job = dict(self.active_job) if self.active_job else None
        if not job:
            return
        out_dir = job.get("output_dir") or ""
        offsets = job.get("offsets") or {}
        batches, next_offsets = self.tail_new_hits(out_dir, offsets)
        updated = False
        for htype, lines in batches.items():
            if not lines:
                continue
            self._http_request(
                "POST",
                "/api/v1/agent/hits",
                {"job_id": job["job_id"], "hit_type": htype, "lines": lines},
            )
            updated = True
        if updated:
            with self._job_lock:
                if self.active_job and self.active_job.get("job_id") == job.get("job_id"):
                    self.active_job["offsets"] = next_offsets
                    self.save_active_job(self.active_job)

    async def run_forever(self) -> None:
        import websockets

        if self.benchmark is None:
            self.run_benchmark()
        self.load_or_reattach_job()

        backoff = 2.0
        disconnected_since: float | None = None
        while True:
            self._reconnect_needed = False
            ws_url = _ws_url_from_http(self.induk_url)
            try:
                async with websockets.connect(
                    ws_url, additional_headers={"Authorization": f"Bearer {self.token}"}, ping_interval=20
                ) as ws:
                    backoff = 2.0
                    disconnected_since = None

                    async def _sender() -> None:
                        while not self._reconnect_needed:
                            await asyncio.to_thread(self._safe_sync_manual_job)
                            await asyncio.to_thread(self._safe_flush_hits)
                            await asyncio.to_thread(self._safe_sync_partial_output)
                            await asyncio.to_thread(self._safe_upload_finished_output)
                            await ws.send(json.dumps(self.build_telemetry()))
                            for _ in range(30):
                                if self._reconnect_needed:
                                    break
                                await asyncio.sleep(0.1)
                        await ws.close()

                    async def _receiver() -> None:
                        async for raw in ws:
                            msg = json.loads(raw)
                            if msg.get("type") == "command":
                                cmd = msg.get("command") or {}
                                cmd_id = str(cmd.get("cmd_id") or "")
                                if cmd_id and cmd_id in self.seen_cmds:
                                    ok, detail = True, "duplicate ignored"
                                else:
                                    ok, detail = await asyncio.to_thread(self.execute_command, cmd)
                                    if ok and cmd_id:
                                        self.mark_cmd_seen(cmd_id)
                                await ws.send(json.dumps({"type": "cmd_ack", "cmd_id": cmd_id, "ok": ok, "message": detail}))

                    t_send = asyncio.create_task(_sender())
                    t_recv = asyncio.create_task(_receiver())
                    done, pending = await asyncio.wait((t_send, t_recv), return_when=asyncio.FIRST_COMPLETED)
                    for t in pending:
                        t.cancel()
                    await asyncio.gather(*pending, return_exceptions=True)
                    for t in done:
                        t.result()
            except Exception:
                if disconnected_since is None:
                    disconnected_since = time.monotonic()
                if self.pointer_url and (time.monotonic() - disconnected_since) >= 60.0:
                    cand = await asyncio.to_thread(self.resolve_pointer_url, self.pointer_url)
                    if cand and cand != self.induk_url:
                        self.apply_new_induk(cand)
                        disconnected_since = time.monotonic()
                await asyncio.sleep(backoff)
                backoff = min(30.0, backoff * 1.5)

    def _safe_flush_hits(self) -> None:
        try:
            self.flush_hits_sync()
        except Exception:
            pass

    @staticmethod
    def _build_output_zip_bytes(out_dir: str) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for fname in ("hit_valid.txt", "hit_2fa.txt", "invalid.txt", "err.txt", "full_info_upas_valid.txt"):
                fp = os.path.join(out_dir, fname)
                if os.path.isfile(fp) and os.path.getsize(fp) > 0:
                    zf.write(fp, arcname=fname)
            col_dir = os.path.join(out_dir, "full_info_by_collector")
            if os.path.isdir(col_dir):
                for fn in sorted(os.listdir(col_dir)):
                    fp = os.path.join(col_dir, fn)
                    if fn.endswith(".txt") and os.path.isfile(fp) and os.path.getsize(fp) > 0:
                        zf.write(fp, arcname=f"full_info_by_collector/{fn}")
        return buf.getvalue()

    def _safe_sync_partial_output(self) -> None:
        try:
            with self._job_lock:
                job = dict(self.active_job) if self.active_job else None
            if not job or job.get("output_uploaded"):
                return
            out_dir = job.get("output_dir") or ""
            full_fp = os.path.join(out_dir, "full_info_upas_valid.txt")
            hit_fp = os.path.join(out_dir, "hit_valid.txt")
            sig = (
                os.path.getsize(full_fp) if os.path.isfile(full_fp) else 0,
                os.path.getsize(hit_fp) if os.path.isfile(hit_fp) else 0,
            )
            if sig == (0, 0) or sig == tuple(job.get("_last_partial_sig") or ()):
                return
            zbytes = self._build_output_zip_bytes(out_dir)
            self._http_request_raw(
                "POST",
                f"/api/v1/agent/output/{job['job_id']}?partial=1",
                data=zbytes,
                content_type="application/zip",
                timeout=30.0,
            )
            with self._job_lock:
                if self.active_job and self.active_job.get("job_id") == job.get("job_id"):
                    self.active_job["_last_partial_sig"] = list(sig)
        except Exception:
            pass

    def upload_finished_output_sync(self, force: bool = False) -> bool:
        with self._job_lock:
            proc_alive = False
            if self.proc is not None:
                proc_alive = self.proc.poll() is None
            job = dict(self.active_job) if self.active_job else None
        if not job or job.get("output_uploaded"):
            return False
        pid = int(job.get("pid") or 0)
        if not force and (proc_alive or (self.proc is None and pid and _is_pid_alive(pid))):
            return False
        out_dir = job.get("output_dir") or ""
        self._http_request_raw(
            "POST",
            f"/api/v1/agent/output/{job['job_id']}",
            data=self._build_output_zip_bytes(out_dir),
            content_type="application/zip",
            timeout=30.0,
        )
        with self._job_lock:
            if self.active_job and self.active_job.get("job_id") == job.get("job_id"):
                self.active_job["output_uploaded"] = True
                self.save_active_job(self.active_job)
        return True

    def _safe_upload_finished_output(self, force: bool = False) -> None:
        try:
            self.upload_finished_output_sync(force=force)
        except Exception:
            pass


def main() -> None:
    ag = MuseAgent(
        vps_id=os.environ["VPS_ID"],
        induk_url=os.environ["INDUK_URL"],
        token=os.environ["AGENT_TOKEN"],
        work_dir=os.environ.get("WORK_DIR", os.path.dirname(os.path.abspath(__file__))),
        env_file=os.environ.get("ENV_FILE", ""),
        pointer_url=os.environ.get("INDUK_POINTER_URL", ""),
        ufasproxy_url=os.environ.get("UFASPROXY_URL", ""),
    )
    asyncio.run(ag.run_forever())


if __name__ == "__main__":
    main()
