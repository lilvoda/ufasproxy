"""SQLite WAL state store for Induk multi-VPS controller."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import sqlite3
import time
import uuid


def _hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _extract_account_key(raw_line: str) -> str:
    prefix = raw_line.strip().split("|", 1)[0].strip()
    if ":" in prefix:
        u, p = prefix.split(":", 1)
        return f"{u.strip().lower()}:{p}"
    return prefix.lower()


class IndukDB:
    """Async-safe SQLite WAL store for nodes, jobs, ACKed commands, and deduplicated hits."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._lock = asyncio.Lock()
        self._conn: sqlite3.Connection | None = None
        self._closed = False

    def _ensure_conn(self) -> sqlite3.Connection:
        if self._closed:
            raise RuntimeError("IndukDB is closed")
        if self._conn is None:
            parent = os.path.dirname(os.path.abspath(self.db_path))
            if parent:
                os.makedirs(parent, exist_ok=True)
            conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=5.0)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute("PRAGMA busy_timeout=5000;")
            conn.execute("PRAGMA foreign_keys=ON;")
            self._conn = conn
        return self._conn

    async def init(self) -> None:
        self._closed = False

        def _init() -> None:
            conn = self._ensure_conn()
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS nodes (
                    vps_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    os_info TEXT NOT NULL DEFAULT '',
                    token_hash TEXT NOT NULL,
                    default_workers INTEGER NOT NULL DEFAULT 4,
                    benchmark_json TEXT NOT NULL DEFAULT '{}',
                    state TEXT NOT NULL DEFAULT 'OFFLINE',
                    last_seen REAL NOT NULL DEFAULT 0,
                    last_telemetry_at REAL NOT NULL DEFAULT 0,
                    telemetry_json TEXT NOT NULL DEFAULT '{}',
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS jobs (
                    job_id TEXT PRIMARY KEY,
                    mode TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'CREATED',
                    config_json TEXT NOT NULL DEFAULT '{}',
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS commands (
                    cmd_id TEXT PRIMARY KEY,
                    vps_id TEXT NOT NULL,
                    type TEXT NOT NULL,
                    payload_json TEXT NOT NULL DEFAULT '{}',
                    status TEXT NOT NULL DEFAULT 'PENDING',
                    ack_message TEXT NOT NULL DEFAULT '',
                    created_at REAL NOT NULL,
                    delivered_at REAL,
                    acked_at REAL
                );
                CREATE INDEX IF NOT EXISTS idx_cmd_vps_status
                    ON commands(vps_id, status, created_at);
                CREATE TABLE IF NOT EXISTS hits (
                    job_id TEXT NOT NULL,
                    hit_type TEXT NOT NULL,
                    account_key TEXT NOT NULL,
                    raw_line TEXT NOT NULL,
                    vps_id TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    PRIMARY KEY (job_id, hit_type, account_key)
                );
                """
            )
            conn.commit()

        async with self._lock:
            await asyncio.to_thread(_init)

    async def close(self) -> None:
        def _close() -> None:
            self._closed = True
            if self._conn is not None:
                self._conn.close()
                self._conn = None

        async with self._lock:
            await asyncio.to_thread(_close)

    async def replace_from_file(self, src_db_path: str) -> None:
        import shutil

        def _replace() -> None:
            if self._conn is not None:
                self._conn.close()
                self._conn = None
            for suffix in ("", "-wal", "-shm"):
                p = self.db_path + suffix
                if os.path.exists(p):
                    os.remove(p)
            shutil.copy2(src_db_path, self.db_path)
            self._closed = False
            conn = self._ensure_conn()
            conn.execute("SELECT 1").fetchone()

        async with self._lock:
            await asyncio.to_thread(_replace)

    async def wal_mode(self) -> str:
        async with self._lock:
            return await asyncio.to_thread(
                lambda: str(self._ensure_conn().execute("PRAGMA journal_mode;").fetchone()[0])
            )

    async def register_node(
        self,
        vps_id: str,
        name: str,
        default_workers: int,
        raw_token: str,
        os_info: str = "",
        benchmark: dict | None = None,
    ) -> dict:
        now = time.time()
        thash = _hash_token(raw_token)
        bjson = json.dumps(benchmark or {})

        def _op() -> dict:
            conn = self._ensure_conn()
            conn.execute(
                """
                INSERT INTO nodes(vps_id, name, os_info, token_hash, default_workers, benchmark_json, created_at)
                VALUES(?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(vps_id) DO UPDATE SET
                    name=excluded.name,
                    os_info=CASE WHEN excluded.os_info != '' THEN excluded.os_info ELSE nodes.os_info END,
                    token_hash=excluded.token_hash,
                    default_workers=excluded.default_workers,
                    benchmark_json=CASE WHEN excluded.benchmark_json != '{}' THEN excluded.benchmark_json ELSE nodes.benchmark_json END
                """,
                (vps_id, name or vps_id, os_info, thash, max(1, int(default_workers)), bjson, now),
            )
            conn.commit()
            return {"vps_id": vps_id, "name": name or vps_id, "default_workers": max(1, int(default_workers))}

        async with self._lock:
            return await asyncio.to_thread(_op)

    async def update_node_benchmark(self, vps_id: str, benchmark: dict, os_info: str = "") -> None:
        rec_w = max(1, min(30, int(benchmark.get("recommended_workers", 4))))
        bjson = json.dumps(benchmark)

        def _op() -> None:
            conn = self._ensure_conn()
            conn.execute(
                """
                UPDATE nodes
                SET default_workers = ?,
                    benchmark_json = ?,
                    os_info = CASE WHEN ? != '' THEN ? ELSE os_info END
                WHERE vps_id = ?
                """,
                (rec_w, bjson, os_info, os_info, vps_id),
            )
            conn.commit()

        async with self._lock:
            await asyncio.to_thread(_op)

    async def rotate_node_token(self, vps_id: str, raw_token: str) -> bool:
        thash = _hash_token(raw_token)

        def _op() -> bool:
            conn = self._ensure_conn()
            cur = conn.execute("UPDATE nodes SET token_hash = ? WHERE vps_id = ?", (thash, vps_id))
            conn.commit()
            return cur.rowcount > 0

        async with self._lock:
            return await asyncio.to_thread(_op)

    async def delete_node(self, vps_id: str) -> bool:
        def _op() -> bool:
            conn = self._ensure_conn()
            conn.execute("DELETE FROM commands WHERE vps_id = ?", (vps_id,))
            cur = conn.execute("DELETE FROM nodes WHERE vps_id = ?", (vps_id,))
            conn.commit()
            return cur.rowcount > 0

        async with self._lock:
            return await asyncio.to_thread(_op)

    async def verify_agent_token(self, raw_token: str) -> str | None:
        if not raw_token:
            return None
        cand = _hash_token(raw_token)

        def _op() -> str | None:
            rows = self._ensure_conn().execute("SELECT vps_id, token_hash FROM nodes").fetchall()
            matched: str | None = None
            for row in rows:
                if hmac.compare_digest(row["token_hash"], cand):
                    matched = row["vps_id"]
            return matched

        async with self._lock:
            return await asyncio.to_thread(_op)

    async def update_telemetry(self, vps_id: str, payload: dict) -> dict:
        now = time.time()
        clean = dict(payload)
        if isinstance(clean.get("log_tail"), list):
            clean["log_tail"] = [str(x)[:220] for x in clean["log_tail"][-50:]]
        state = str(clean.get("agent_state") or "ONLINE").upper()
        os_info = str(clean.get("os_info") or "")
        benchmark = clean.get("benchmark")

        def _op() -> dict:
            conn = self._ensure_conn()
            row_prev = conn.execute(
                "SELECT state, last_telemetry_at, telemetry_json FROM nodes WHERE vps_id = ?",
                (vps_id,),
            ).fetchone()
            new_prog = clean.get("progress") if isinstance(clean.get("progress"), dict) else {}
            new_checked = int(new_prog.get("checked") or 0)
            tel_at = now
            if row_prev is not None:
                prev_state = str(row_prev["state"] or "").upper()
                prev_at = float(row_prev["last_telemetry_at"] or 0.0)
                if prev_at > 0 and state in ("RUNNING", "ROTATING") and prev_state in ("RUNNING", "ROTATING"):
                    try:
                        prev_tel = json.loads(row_prev["telemetry_json"] or "{}")
                        prev_checked = int(((prev_tel.get("progress") or {}).get("checked")) or 0)
                        if new_checked <= prev_checked:
                            tel_at = prev_at
                    except Exception:
                        pass
            if isinstance(benchmark, dict) and benchmark.get("recommended_workers"):
                rec_w = max(1, min(30, int(benchmark["recommended_workers"])))
                conn.execute(
                    "UPDATE nodes SET default_workers = ?, benchmark_json = ? WHERE vps_id = ?",
                    (rec_w, json.dumps(benchmark), vps_id),
                )
            conn.execute(
                """
                UPDATE nodes
                SET state = ?,
                    last_seen = ?,
                    last_telemetry_at = ?,
                    telemetry_json = ?,
                    os_info = CASE WHEN ? != '' THEN ? ELSE os_info END
                WHERE vps_id = ?
                """,
                (state, now, tel_at, json.dumps(clean), os_info, os_info, vps_id),
            )
            conn.commit()
            return {"vps_id": vps_id, "state": state, "last_seen": now}

        async with self._lock:
            return await asyncio.to_thread(_op)

    async def touch_seen(self, vps_id: str, state: str | None = None) -> None:
        now = time.time()

        def _op() -> None:
            conn = self._ensure_conn()
            if state:
                conn.execute("UPDATE nodes SET last_seen = ?, state = ? WHERE vps_id = ?", (now, state, vps_id))
            else:
                conn.execute("UPDATE nodes SET last_seen = ? WHERE vps_id = ?", (now, vps_id))
            conn.commit()

        async with self._lock:
            await asyncio.to_thread(_op)

    async def list_nodes(
        self, offline_after_s: float = 20.0, stall_after_s: float = 180.0
    ) -> tuple[list[dict], dict]:
        now = time.time()

        def _op() -> tuple[list[dict], dict]:
            rows = self._ensure_conn().execute("SELECT * FROM nodes ORDER BY created_at, vps_id").fetchall()
            nodes: list[dict] = []
            summary = {
                "total_nodes": len(rows),
                "online_nodes": 0,
                "running_nodes": 0,
                "checked": 0,
                "total": 0,
                "valid": 0,
                "otp": 0,
                "invalid": 0,
                "error": 0,
                "waf": 0,
                "waf_solved": 0,
                "rate_per_sec": 0.0,
                "workers_live": 0,
                "workers_total": 0,
            }
            for r in rows:
                telem = json.loads(r["telemetry_json"] or "{}")
                bench = json.loads(r["benchmark_json"] or "{}")
                last_seen = float(r["last_seen"] or 0.0)
                last_tel = float(r["last_telemetry_at"] or 0.0)
                raw_state = str(r["state"] or "OFFLINE").upper()
                if last_seen <= 0 or (now - last_seen) > offline_after_s:
                    eff_state = "OFFLINE"
                elif raw_state in ("RUNNING", "ROTATING", "STARTING") and last_tel > 0 and (now - last_tel) > stall_after_s:
                    eff_state = "STALLED"
                else:
                    eff_state = raw_state
                if eff_state != "OFFLINE":
                    summary["online_nodes"] += 1
                if eff_state in ("RUNNING", "ROTATING", "STARTING"):
                    summary["running_nodes"] += 1
                prog = telem.get("progress") or {}
                for k in ("checked", "total", "valid", "otp", "invalid", "error", "waf", "waf_solved", "workers_live", "workers_total"):
                    summary[k] += int(prog.get(k) or 0)
                if eff_state in ("RUNNING", "ROTATING"):
                    summary["rate_per_sec"] += float(prog.get("rate_per_sec") or 0.0)
                nodes.append(
                    {
                        "vps_id": r["vps_id"],
                        "name": r["name"],
                        "os_info": r["os_info"],
                        "default_workers": r["default_workers"],
                        "benchmark": bench,
                        "state": raw_state,
                        "effective_state": eff_state,
                        "last_seen": last_seen,
                        "last_seen_ago_s": round(now - last_seen, 1) if last_seen > 0 else None,
                        "telemetry": telem,
                    }
                )
            summary["rate_per_sec"] = round(summary["rate_per_sec"], 2)
            return nodes, summary

        async with self._lock:
            return await asyncio.to_thread(_op)

    async def enqueue_command(self, vps_id: str, cmd_type: str, payload: dict | None = None) -> dict:
        cmd_id = f"cmd_{uuid.uuid4().hex[:12]}"
        now = time.time()
        pjson = json.dumps(payload or {})

        def _op() -> dict:
            conn = self._ensure_conn()
            conn.execute(
                "INSERT INTO commands(cmd_id, vps_id, type, payload_json, status, created_at) VALUES(?, ?, ?, ?, 'PENDING', ?)",
                (cmd_id, vps_id, cmd_type.upper(), pjson, now),
            )
            conn.commit()
            return {"cmd_id": cmd_id, "vps_id": vps_id, "type": cmd_type.upper(), "payload": payload or {}, "created_at": now}

        async with self._lock:
            return await asyncio.to_thread(_op)

    async def get_unacked_commands(self, vps_id: str) -> list[dict]:
        def _op() -> list[dict]:
            rows = self._ensure_conn().execute(
                "SELECT * FROM commands WHERE vps_id = ? AND status IN ('PENDING', 'DELIVERED') ORDER BY created_at ASC",
                (vps_id,),
            ).fetchall()
            return [
                {
                    "cmd_id": r["cmd_id"],
                    "vps_id": r["vps_id"],
                    "type": r["type"],
                    "payload": json.loads(r["payload_json"] or "{}"),
                    "status": r["status"],
                    "created_at": r["created_at"],
                }
                for r in rows
            ]

        async with self._lock:
            return await asyncio.to_thread(_op)

    async def mark_delivered(self, cmd_ids: list[str]) -> None:
        if not cmd_ids:
            return
        now = time.time()

        def _op() -> None:
            conn = self._ensure_conn()
            placeholders = ",".join("?" for _ in cmd_ids)
            conn.execute(
                f"UPDATE commands SET status = 'DELIVERED', delivered_at = ? WHERE cmd_id IN ({placeholders}) AND status = 'PENDING'",
                [now, *cmd_ids],
            )
            conn.commit()

        async with self._lock:
            await asyncio.to_thread(_op)

    async def ack_command(self, vps_id: str, cmd_id: str, ok: bool = True, message: str = "") -> bool:
        now = time.time()
        new_status = "ACKED" if ok else "FAILED"

        def _op() -> bool:
            conn = self._ensure_conn()
            cur = conn.execute(
                "UPDATE commands SET status = ?, ack_message = ?, acked_at = ? WHERE cmd_id = ? AND vps_id = ?",
                (new_status, message[:300], now, cmd_id, vps_id),
            )
            conn.commit()
            return cur.rowcount > 0

        async with self._lock:
            return await asyncio.to_thread(_op)

    async def create_job(self, job_id: str, mode: str, config: dict | None = None) -> None:
        now = time.time()

        def _op() -> None:
            conn = self._ensure_conn()
            conn.execute(
                "INSERT OR IGNORE INTO jobs(job_id, mode, status, config_json, created_at) VALUES(?, ?, 'RUNNING', ?, ?)",
                (job_id, mode, json.dumps(config or {}), now),
            )
            conn.commit()

        async with self._lock:
            await asyncio.to_thread(_op)

    async def upsert_manual_job(self, job_id: str, vps_id: str, filename: str = "") -> None:
        now = time.time()
        cfg_json = json.dumps({"vps_ids": [vps_id], "filename": filename, "workers": "manual"})

        def _op() -> None:
            conn = self._ensure_conn()
            conn.execute(
                """
                INSERT INTO jobs(job_id, mode, status, config_json, created_at)
                VALUES(?, 'manual', 'RUNNING', ?, ?)
                ON CONFLICT(job_id) DO UPDATE SET
                    config_json = CASE WHEN jobs.config_json = '{}' THEN excluded.config_json ELSE jobs.config_json END
                """,
                (job_id, cfg_json, now),
            )
            conn.commit()

        async with self._lock:
            await asyncio.to_thread(_op)

    async def get_job(self, job_id: str) -> dict | None:
        def _op() -> dict | None:
            row = self._ensure_conn().execute(
                "SELECT job_id, mode, status, config_json, created_at FROM jobs WHERE job_id = ?",
                (job_id,),
            ).fetchone()
            if not row:
                return None
            d = dict(row)
            d["config"] = json.loads(d.pop("config_json") or "{}")
            return d

        async with self._lock:
            return await asyncio.to_thread(_op)

    async def list_jobs(self, limit: int = 30) -> list[dict]:
        def _op() -> list[dict]:
            conn = self._ensure_conn()
            rows = conn.execute(
                """
                SELECT j.job_id, j.mode, j.status, j.config_json, j.created_at,
                       COALESCE(SUM(CASE WHEN h.hit_type = 'VALID' THEN 1 ELSE 0 END), 0) AS valid_count,
                       COALESCE(SUM(CASE WHEN h.hit_type = 'OTP' THEN 1 ELSE 0 END), 0) AS otp_count
                FROM jobs j
                LEFT JOIN hits h ON h.job_id = j.job_id
                GROUP BY j.job_id
                ORDER BY j.created_at DESC
                LIMIT ?
                """,
                (max(1, min(100, int(limit))),),
            ).fetchall()
            out: list[dict] = []
            for r in rows:
                cfg = json.loads(r["config_json"] or "{}")
                out.append(
                    {
                        "job_id": r["job_id"],
                        "mode": r["mode"],
                        "status": r["status"],
                        "created_at": r["created_at"],
                        "filename": str(cfg.get("filename") or ""),
                        "vps_ids": list(cfg.get("vps_ids") or []),
                        "workers": cfg.get("workers", "auto"),
                        "two_tab": cfg.get("two_tab"),
                        "valid_count": int(r["valid_count"] or 0),
                        "otp_count": int(r["otp_count"] or 0),
                    }
                )
            return out

        async with self._lock:
            return await asyncio.to_thread(_op)

    async def insert_hits(self, job_id: str, vps_id: str, hit_type: str, lines: list[str]) -> tuple[int, int]:
        now = time.time()
        ht = hit_type.upper()
        cleaned = [ln.strip() for ln in lines if ln and ln.strip()]

        def _op() -> tuple[int, int]:
            conn = self._ensure_conn()
            conn.execute(
                "INSERT OR IGNORE INTO jobs(job_id, mode, status, config_json, created_at) VALUES(?, 'manual', 'RUNNING', '{}', ?)",
                (job_id, now),
            )
            inserted = 0
            for ln in cleaned:
                key = _extract_account_key(ln)
                cur = conn.execute(
                    "INSERT OR IGNORE INTO hits(job_id, hit_type, account_key, raw_line, vps_id, created_at) VALUES(?, ?, ?, ?, ?, ?)",
                    (job_id, ht, key, ln, vps_id, now),
                )
                inserted += cur.rowcount
            conn.commit()
            return inserted, len(cleaned)

        async with self._lock:
            return await asyncio.to_thread(_op)

    async def export_hits(
        self, job_id: str | None, hit_type: str = "VALID", dedup: str = "per_job"
    ) -> list[dict]:
        ht = hit_type.upper()

        def _op() -> list[dict]:
            conn = self._ensure_conn()
            if dedup == "global":
                if job_id:
                    rows = conn.execute(
                        "SELECT account_key, raw_line, vps_id, job_id, MIN(created_at) AS created_at FROM hits WHERE hit_type = ? AND job_id = ? GROUP BY account_key ORDER BY created_at ASC",
                        (ht, job_id),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT account_key, raw_line, vps_id, job_id, MIN(created_at) AS created_at FROM hits WHERE hit_type = ? GROUP BY account_key ORDER BY created_at ASC",
                        (ht,),
                    ).fetchall()
            else:
                if job_id:
                    rows = conn.execute(
                        "SELECT account_key, raw_line, vps_id, job_id, created_at FROM hits WHERE hit_type = ? AND job_id = ? ORDER BY created_at ASC",
                        (ht, job_id),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT account_key, raw_line, vps_id, job_id, created_at FROM hits WHERE hit_type = ? ORDER BY created_at ASC",
                        (ht,),
                    ).fetchall()
            return [dict(r) for r in rows]

        async with self._lock:
            return await asyncio.to_thread(_op)

    async def backup_to(self, dest_path: str) -> None:
        def _op() -> None:
            src = self._ensure_conn()
            dst = sqlite3.connect(dest_path)
            try:
                src.backup(dst)
            finally:
                dst.close()

        async with self._lock:
            await asyncio.to_thread(_op)
