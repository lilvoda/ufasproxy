#!/usr/bin/env python3
"""ufasproxy: OpenVPN netns slot manager, MT API probe, HTTP CONNECT bridge, and Lease API."""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
from dataclasses import dataclass
import hmac
import inspect
import ipaddress
import json
import logging
import math
import os
import random
import re
import secrets
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable
import urllib.parse

try:
    import pwd
except ImportError:
    pwd = None  # type: ignore[assignment]

LOG = logging.getLogger("ufasproxy")

MT_API_HOST = "accountmtapi.mobilelegends.com"
MT_API_PORT = 443
MAX_HEADER_BYTES = 16384
MAX_TTL_S = 86400.0
AUTH_FILENAMES = ("auth.txt", ".auth", "credentials.txt", "pass.txt")
PROXY_407_RESPONSE = (
    b"HTTP/1.1 407 Proxy Authentication Required\r\n"
    b'Proxy-Authenticate: Basic realm="ufasproxy"\r\n'
    b"Connection: close\r\n\r\n"
)


def discover_ovpn_configs(ovpn_dir: str, shuffle: bool = False) -> tuple[list[str], str]:
    """Scan ovpn_dir case-insensitively for *.ovpn (UDP-first) and credentials file."""
    if not os.path.isdir(ovpn_dir):
        raise FileNotFoundError(f"ovpn_dir not found: {ovpn_dir}")

    udp_cfgs: list[str] = []
    other_cfgs: list[str] = []
    named_auth: dict[str, str] = {}
    dot_auth: list[str] = []

    # ponytail: flat ovpn_dir scan; switch to os.walk if nested provider trees are added.
    with os.scandir(ovpn_dir) as entries:
        for entry in entries:
            if not entry.is_file():
                continue
            low = entry.name.lower()
            if low.endswith(".ovpn"):
                (udp_cfgs if low.endswith("udp.ovpn") else other_cfgs).append(entry.path)
            elif low in AUTH_FILENAMES:
                named_auth[low] = entry.path
            elif low.endswith(".auth"):
                dot_auth.append(entry.path)

    if shuffle:
        random.shuffle(udp_cfgs)
        random.shuffle(other_cfgs)
    else:
        udp_cfgs.sort(key=lambda p: os.path.basename(p).lower())
        other_cfgs.sort(key=lambda p: os.path.basename(p).lower())

    auth_file = next((named_auth[n] for n in AUTH_FILENAMES if n in named_auth), "")
    if not auth_file and dot_auth:
        auth_file = sorted(dot_auth, key=lambda p: os.path.basename(p).lower())[0]
    return udp_cfgs + other_cfgs, auth_file


def _probe_mt_response_ok(status: int) -> bool:
    """Return True iff HTTP status indicates reachable, unblocked MT API endpoint."""
    return 100 <= status < 500 and status not in (400, 402, 403, 405, 407, 429)


def make_basic_auth_fn(expected_user: str, expected_pass: str) -> Callable[[str, str], bool]:
    """Return constant-time BasicAuth credential verifier."""
    exp_u = expected_user.encode("utf-8")
    exp_p = expected_pass.encode("utf-8")

    def _verify(user: str, passwd: str) -> bool:
        u_ok = hmac.compare_digest(user.encode("utf-8"), exp_u)
        p_ok = hmac.compare_digest(passwd.encode("utf-8"), exp_p)
        return bool(u_ok & p_ok)

    return _verify


async def _close_writer(writer: asyncio.StreamWriter | None) -> None:
    if writer is None:
        return
    try:
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
    except asyncio.TimeoutError:
        tr = getattr(writer, "transport", None)
        if tr is not None:
            with contextlib.suppress(Exception):
                tr.abort()
    except Exception:
        pass


async def _send_resp(writer: asyncio.StreamWriter, payload: bytes) -> None:
    writer.write(payload)
    await writer.drain()


async def _pipe(
    src: asyncio.StreamReader,
    dst: asyncio.StreamWriter,
    idle_timeout_s: float = 180.0,
    close_dst: bool = False,
) -> bool:
    """Relay src -> dst; return True on clean EOF, False on timeout or error."""
    try:
        while True:
            chunk = await asyncio.wait_for(src.read(16384), timeout=idle_timeout_s)
            if not chunk:
                break
            dst.write(chunk)
            await dst.drain()
        if close_dst:
            dst.close()
        elif dst.can_write_eof():
            dst.write_eof()
        return True
    except Exception:
        if close_dst:
            with contextlib.suppress(Exception):
                dst.close()
        return False


async def _socks5_connect(
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_port: int,
    timeout_s: float = 10.0,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Open SOCKS5 no-auth tunnel to target_host:target_port."""
    if not (1 <= target_port <= 65535):
        raise ValueError(f"Invalid target port: {target_port}")

    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(socks_host, socks_port),
        timeout=timeout_s,
    )
    try:
        await _send_resp(writer, b"\x05\x01\x00")
        auth_rep = await asyncio.wait_for(reader.readexactly(2), timeout=timeout_s)
        if auth_rep != b"\x05\x00":
            raise OSError(f"SOCKS5 auth rejected: {auth_rep!r}")

        try:
            ip = ipaddress.ip_address(target_host)
            addr_part = (b"\x01" if ip.version == 4 else b"\x04") + ip.packed
        except ValueError:
            host_b = target_host.encode("idna")
            if not (1 <= len(host_b) <= 255):
                raise ValueError(f"Invalid SOCKS5 domain length: {target_host}")
            addr_part = b"\x03" + bytes([len(host_b)]) + host_b

        await _send_resp(writer, b"\x05\x01\x00" + addr_part + struct.pack("!H", target_port))

        rep = await asyncio.wait_for(reader.readexactly(4), timeout=timeout_s)
        if rep[0] != 5 or rep[1] != 0:
            raise OSError(f"SOCKS5 connect failed ver={rep[0]} rep=0x{rep[1]:02x}")

        atyp = rep[3]
        if atyp == 1:
            await asyncio.wait_for(reader.readexactly(6), timeout=timeout_s)
        elif atyp == 4:
            await asyncio.wait_for(reader.readexactly(18), timeout=timeout_s)
        elif atyp == 3:
            ln = (await asyncio.wait_for(reader.readexactly(1), timeout=timeout_s))[0]
            await asyncio.wait_for(reader.readexactly(ln + 2), timeout=timeout_s)
        else:
            raise OSError(f"SOCKS5 invalid bind atyp={atyp}")

        return reader, writer
    except BaseException:
        await _close_writer(writer)
        raise


async def _upgrade_tls(
    writer: asyncio.StreamWriter,
    ssl_ctx: ssl.SSLContext,
    server_hostname: str,
) -> None:
    if hasattr(writer, "start_tls"):
        await writer.start_tls(ssl_ctx, server_hostname=server_hostname)
        return
    # Python 3.10 compatibility fallback (StreamWriter.start_tls added in 3.11).
    await writer.drain()
    loop = asyncio.get_running_loop()
    proto = writer._protocol  # type: ignore[attr-defined]
    new_tr = await loop.start_tls(
        writer._transport,  # type: ignore[attr-defined]
        proto,
        ssl_ctx,
        server_hostname=server_hostname,
    )
    writer._transport = new_tr  # type: ignore[attr-defined]
    proto._transport = new_tr
    proto._over_ssl = True
    sr = getattr(proto, "_stream_reader", None)
    if sr is not None:
        sr.set_transport(new_tr)


async def probe_socks_mt_api(
    socks_host: str,
    socks_port: int,
    timeout_s: float = 5.0,
    max_rtt_ms: int = 3500,
) -> tuple[bool, int, str]:
    """Probe Moonton API over SOCKS5+TLS and enforce HTTP status + RTT budget."""
    t0 = time.monotonic()

    async def _do_probe() -> tuple[bool, int, str]:
        writer: asyncio.StreamWriter | None = None
        try:
            reader, writer = await _socks5_connect(
                socks_host, socks_port, MT_API_HOST, MT_API_PORT, timeout_s
            )
            await _upgrade_tls(writer, ssl.create_default_context(), MT_API_HOST)
            req = (
                f"HEAD / HTTP/1.1\r\n"
                f"Host: {MT_API_HOST}\r\n"
                f"User-Agent: ufasproxy/1.0\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("ascii")
            await _send_resp(writer, req)

            status_line = await reader.readline()
            parts = status_line.decode("latin-1", "replace").split()
            if len(parts) < 2 or not parts[0].startswith("HTTP/"):
                rtt_ms = int((time.monotonic() - t0) * 1000)
                return False, rtt_ms, f"bad status line: {status_line[:64]!r}"

            status = int(parts[1])
            rtt_ms = int((time.monotonic() - t0) * 1000)
            if not _probe_mt_response_ok(status):
                return False, rtt_ms, f"HTTP {status}"
            if rtt_ms > max_rtt_ms:
                return False, rtt_ms, f"RTT {rtt_ms}ms > {max_rtt_ms}ms"
            return True, rtt_ms, f"HTTP {status}"
        finally:
            await _close_writer(writer)

    try:
        return await asyncio.wait_for(_do_probe(), timeout=timeout_s)
    except Exception as exc:
        rtt_ms = int((time.monotonic() - t0) * 1000)
        return False, rtt_ms, f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__


def _nobody_uid_gid() -> tuple[int, int]:
    if pwd is not None:
        with contextlib.suppress(KeyError):
            pw = pwd.getpwnam("nobody")
            return pw.pw_uid, pw.pw_gid
    return 65534, 65534


_OVPN_STRIP_DIRECTIVES = {
    "up", "down", "down-pre", "route-up", "route-pre-down",
    "ipchange", "tls-verify", "plugin", "script-security",
    "block-outside-dns", "ncp-disable",
}


def _sanitize_ovpn_content(text: str) -> tuple[str, bool]:
    """Strip unsafe/OpenVPN-2.6-incompatible directives while preserving inline cert blocks."""
    kept: list[str] = []
    is_tcp = False
    for ln in text.splitlines():
        s = ln.strip()
        head = s.split(None, 1)[0].lower() if s and not s.startswith(("#", ";")) else ""
        if head in _OVPN_STRIP_DIRECTIVES:
            continue
        if head == "proto" and re.search(r"\btcp", s, re.I):
            is_tcp = True
        kept.append(ln)
    return ("\n".join(kept) + "\n") if kept else "", is_tcp


class OvpnSlotManager:
    """Manage isolated ip netns OpenVPN slots with microsocks and kill-switch."""

    MAX_SLOTS = 200
    HANDSHAKE_TIMEOUT_S = 18.0
    STOP_WAIT_S = 0.5

    def __init__(
        self,
        ovpn_dir: str = "",
        auth_file: str = "",
        state_dir: str = "/tmp/ufasproxy",
        on_unexpected_exit: Callable[[int, str], Any] | None = None,
    ) -> None:
        self.ovpn_dir = ovpn_dir
        self.auth_file = os.path.abspath(auth_file) if auth_file else ""
        self.state_dir = os.path.abspath(state_dir)
        self._on_unexpected_exit = on_unexpected_exit
        self._slots: dict[int, tuple[str, list[asyncio.subprocess.Process]]] = {}
        self._watchers: dict[int, asyncio.Task[None]] = {}
        self._setup_lock = asyncio.Lock()
        self._wan_iface = ""

    @staticmethod
    def _validate_slot(slot: int) -> None:
        if not (1 <= slot <= OvpnSlotManager.MAX_SLOTS):
            raise ValueError(f"Slot {slot} out of range 1..{OvpnSlotManager.MAX_SLOTS}")

    def _log_path(self, slot: int) -> str:
        return os.path.abspath(os.path.join(self.state_dir, f"ovns{slot}.log"))

    def _sanitized_cfg_path(self, slot: int) -> str:
        return os.path.abspath(os.path.join(self.state_dir, f"ovns{slot}.ovpn"))

    def _build_ovpn_cmd(
        self,
        slot: int,
        cfg: str,
        auth_file: str = "",
        config_override: str = "",
        is_tcp: bool | None = None,
    ) -> list[str]:
        self._validate_slot(slot)
        abs_cfg = os.path.abspath(cfg)
        cfg_arg = os.path.abspath(config_override) if config_override else abs_cfg
        auth = auth_file or self.auth_file
        abs_auth = os.path.abspath(auth) if auth else ""
        tcp_mode = is_tcp if is_tcp is not None else bool(re.search(r"tcp", os.path.basename(abs_cfg), re.I))
        cmd = [
            "openvpn",
            "--ignore-unknown-option", "block-outside-dns",
            "--cd", os.path.dirname(abs_cfg),
            "--config", cfg_arg,
            "--pull-filter", "ignore", "block-outside-dns",
            "--pull-filter", "ignore", "ping-restart",
            "--pull-filter", "ignore", "ifconfig-ipv6",
            "--pull-filter", "ignore", "route-ipv6",
            "--data-ciphers", "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-256-CBC",
            "--data-ciphers-fallback", "AES-256-CBC",
            "--script-security", "1",
            "--ping-exit", "60",
            "--connect-retry", "1", "2",
            "--resolv-retry", "2",
            "--auth-nocache",
        ]
        if not tcp_mode:
            cmd.extend(["--mssfix", "1360", "--fast-io"])
        if abs_auth:
            cmd.extend(["--auth-user-pass", abs_auth])
        return cmd

    async def _run(self, *args: str) -> tuple[int, str, str]:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out_b, err_b = await proc.communicate()
        return (
            proc.returncode or 0,
            out_b.decode("utf-8", "replace"),
            err_b.decode("utf-8", "replace"),
        )

    async def _run_checked(self, *args: str) -> str:
        rc, out, err = await self._run(*args)
        if rc != 0:
            raise RuntimeError(f"Command failed ({rc}): {' '.join(args)} -> {err.strip() or out.strip()}")
        return out

    async def _ensure_iptables_rule(self, table: str | None, check_args: list[str], apply_args: list[str]) -> None:
        base = ["iptables", "-w", "5"] + (["-t", table] if table else [])
        rc, _, _ = await self._run(*base, *check_args)
        if rc != 0:
            await self._run_checked(*base, *apply_args)

    async def _ensure_host_setup(self) -> None:
        async with self._setup_lock:
            rc, out, err = await self._run("ip", "-4", "route", "show", "default")
            matches = list(re.finditer(r"^default\b.*\bdev\s+(\S+)", out, re.MULTILINE))
            m = next((mm for mm in matches if not re.match(r"^(?:tun|tap)", mm.group(1), re.I)), None)
            if m is None and matches:
                m = matches[0]
            if rc != 0 or m is None:
                raise RuntimeError(f"Host IPv4 default route missing: {err.strip() or out.strip()}")
            wan_iface = m.group(1)
            if self._wan_iface == wan_iface:
                return

            await self._run_checked("sysctl", "-w", "net.ipv4.ip_forward=1")
            await self._ensure_iptables_rule(
                "nat",
                ["-C", "POSTROUTING", "-s", "198.18.0.0/16", "-o", wan_iface, "-j", "MASQUERADE"],
                ["-A", "POSTROUTING", "-s", "198.18.0.0/16", "-o", wan_iface, "-j", "MASQUERADE"],
            )
            await self._ensure_iptables_rule(
                None,
                ["-C", "FORWARD", "-s", "198.18.0.0/16", "-o", wan_iface, "-j", "ACCEPT"],
                ["-I", "FORWARD", "1", "-s", "198.18.0.0/16", "-o", wan_iface, "-j", "ACCEPT"],
            )
            await self._ensure_iptables_rule(
                None,
                ["-C", "FORWARD", "-d", "198.18.0.0/16", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
                ["-I", "FORWARD", "1", "-d", "198.18.0.0/16", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
            )
            self._wan_iface = wan_iface

    async def _setup_slot_netns(self, slot: int) -> bool:
        await self.stop_slot(slot)
        ns, vh, vw = f"ovns{slot}", f"ovh{slot}", f"ovw{slot}"
        ip_h, ip_w = f"198.18.{slot}.1", f"198.18.{slot}.2"

        os.makedirs(self.state_dir, exist_ok=True)
        ns_etc = f"/etc/netns/{ns}"
        os.makedirs(ns_etc, exist_ok=True)
        with open(os.path.join(ns_etc, "resolv.conf"), "w", encoding="utf-8") as fh:
            fh.write("nameserver 1.1.1.1\nnameserver 8.8.8.8\n")

        for cmd in (
            ("ip", "netns", "add", ns),
            ("ip", "link", "add", vh, "type", "veth", "peer", "name", vw),
            ("ip", "link", "set", vw, "netns", ns),
            ("ip", "addr", "add", f"{ip_h}/30", "dev", vh),
            ("ip", "link", "set", vh, "up"),
            ("ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up"),
            ("ip", "netns", "exec", ns, "ip", "addr", "add", f"{ip_w}/30", "dev", vw),
            ("ip", "netns", "exec", ns, "ip", "link", "set", vw, "up"),
            ("ip", "netns", "exec", ns, "ip", "route", "add", "default", "via", ip_h, "dev", vw),
        ):
            await self._run_checked(*cmd)

        # Host may boot with ipv6.disable=1; ignore non-zero sysctl rc in that case.
        await self._run(
            "ip", "netns", "exec", ns,
            "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1", "net.ipv6.conf.default.disable_ipv6=1",
        )

        uid, _ = _nobody_uid_gid()
        rc, _, err = await self._run(
            "ip", "netns", "exec", ns,
            "iptables", "-w", "5", "-A", "OUTPUT", "-o", vw,
            "-m", "owner", "--uid-owner", str(uid),
            "-m", "conntrack", "--ctstate", "NEW", "-j", "DROP",
        )
        if rc != 0:
            LOG.warning("KILL-SWITCH FAILED in %s (%s); deferring microsocks until tun0 up", ns, err.strip())
            return False
        return True

    @staticmethod
    def _fallback_host_drop_cmds(slot: int) -> tuple[tuple[str, ...], ...]:
        ns = f"ovns{slot}"
        host_ip = f"198.18.{slot}.1/32"
        return (
            # Allow replies from bound microsocks :1080 back to host bridge while dropping host-subnet initiation.
            ("ip", "netns", "exec", ns, "iptables", "-w", "5", "-A", "OUTPUT", "-d", host_ip, "-p", "tcp", "--sport", "1080", "-j", "ACCEPT"),
            ("ip", "netns", "exec", ns, "iptables", "-w", "5", "-A", "OUTPUT", "-d", host_ip, "-j", "DROP"),
        )

    async def _spawn_microsocks(self, slot: int) -> asyncio.subprocess.Process:
        uid, gid = _nobody_uid_gid()
        return await asyncio.create_subprocess_exec(
            "ip", "netns", "exec", f"ovns{slot}",
            "setpriv", f"--reuid={uid}", f"--regid={gid}", "--clear-groups",
            "microsocks", "-i", f"198.18.{slot}.2", "-p", "1080",
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )

    async def _wait_tcp_ready(
        self,
        host: str,
        port: int,
        proc: asyncio.subprocess.Process,
        timeout_s: float = 1.0,
    ) -> bool:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if proc.returncode is not None:
                return False
            try:
                _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=0.25)
                await _close_writer(writer)
                return True
            except Exception:
                await asyncio.sleep(0.05)
        return False

    async def _netns_pids(self, slot: int) -> list[int]:
        rc, out, _ = await self._run("ip", "netns", "pids", f"ovns{slot}")
        if rc != 0:
            return []
        return [int(tok) for tok in out.split() if tok.isdigit()]

    async def _tun_is_up(self, slot: int) -> bool:
        rc, out, _ = await self._run("ip", "-n", f"ovns{slot}", "-o", "link", "show")
        return rc == 0 and bool(re.search(r"^\d+:\s+tun\S*[:@].*<[^>]*\bUP\b", out, re.MULTILINE))

    async def _watch_ovpn_exit(
        self,
        slot: int,
        ovpn_proc: asyncio.subprocess.Process,
        ms_proc: asyncio.subprocess.Process | None = None,
    ) -> None:
        wait_tasks: dict[asyncio.Task[int], str] = {
            asyncio.create_task(ovpn_proc.wait()): "OpenVPN",
        }
        if ms_proc is not None:
            wait_tasks[asyncio.create_task(ms_proc.wait())] = "microsocks"
        try:
            done, pending = await asyncio.wait(wait_tasks.keys(), return_when=asyncio.FIRST_COMPLETED)
            for p_task in pending:
                p_task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            first_task = next(iter(done))
            proc_name = wait_tasks[first_task]
            rc = first_task.result()
            cur = asyncio.current_task()
            entry = self._slots.get(slot)
            if self._watchers.get(slot) is cur and entry is not None and ovpn_proc in entry[1]:
                cfg = entry[0]
                LOG.warning("slot %d %s exited unexpectedly (rc=%s); tearing down", slot, proc_name, rc)
                await self.stop_slot(slot)
                if self._on_unexpected_exit is not None:
                    try:
                        res = self._on_unexpected_exit(slot, cfg)
                        if inspect.isawaitable(res):
                            await res
                    except Exception as exc:
                        LOG.warning("slot %d unexpected exit handler error: %s", slot, exc)
        except asyncio.CancelledError:
            for wt in wait_tasks:
                if not wt.done():
                    wt.cancel()
            await asyncio.gather(*wait_tasks.keys(), return_exceptions=True)
            pass

    async def start_slot(self, slot: int, cfg: str) -> bool:
        self._validate_slot(slot)
        abs_cfg = os.path.abspath(cfg)
        if not os.path.isfile(abs_cfg):
            raise FileNotFoundError(f"ovpn config not found: {abs_cfg}")

        with open(abs_cfg, "r", encoding="utf-8", errors="replace") as fh:
            cfg_txt = fh.read()
        if not self.auth_file and re.search(r"(?im)^[ \t]*auth-user-pass[ \t]*(?:#.*)?$", cfg_txt):
            LOG.warning("slot %d config %s has bare auth-user-pass without auth_file", slot, abs_cfg)
            return False

        await self._ensure_host_setup()

        try:
            killswitch_ok = await self._setup_slot_netns(slot)
            sanitized_txt, is_tcp = _sanitize_ovpn_content(cfg_txt)
            san_cfg = self._sanitized_cfg_path(slot)
            with open(san_cfg, "w", encoding="utf-8", errors="replace") as fh:
                fh.write(sanitized_txt)
            log_path = self._log_path(slot)
            ovpn_cmd = self._build_ovpn_cmd(slot, abs_cfg, self.auth_file, config_override=san_cfg, is_tcp=is_tcp)
            log_fh = open(log_path, "w", encoding="utf-8", errors="replace")
            try:
                ovpn_proc = await asyncio.create_subprocess_exec(
                    "ip", "netns", "exec", f"ovns{slot}", *ovpn_cmd,
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=log_fh,
                    stderr=asyncio.subprocess.STDOUT,
                )
            finally:
                log_fh.close()

            procs = [ovpn_proc]
            ms_proc: asyncio.subprocess.Process | None = None
            if killswitch_ok:
                ms_proc = await self._spawn_microsocks(slot)
                procs.append(ms_proc)
            self._slots[slot] = (abs_cfg, procs)

            deadline = time.monotonic() + self.HANDSHAKE_TIMEOUT_S
            ready = False
            while time.monotonic() < deadline:
                if ovpn_proc.returncode is not None:
                    break
                if ms_proc is not None and ms_proc.returncode is not None:
                    break
                log_txt = ""
                if os.path.isfile(log_path):
                    with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
                        log_txt = fh.read()
                if "AUTH_FAILED" in log_txt:
                    LOG.warning("slot %d auth failed for %s", slot, abs_cfg)
                    break
                if "Initialization Sequence Completed" in log_txt:
                    pids, tun_up = await asyncio.gather(self._netns_pids(slot), self._tun_is_up(slot))
                    if ovpn_proc.returncode is None and ovpn_proc.pid in set(pids) and tun_up:
                        ready = True
                        break
                await asyncio.sleep(0.25)

            if not ready:
                await self.stop_slot(slot)
                return False

            if ms_proc is None:
                # Deferred kill-switch fallback: drop non-VPN default route and isolate host /30 gateway once tun0 is up.
                await self._run(
                    "ip", "-n", f"ovns{slot}", "route", "del",
                    "default", "via", f"198.18.{slot}.1", "dev", f"ovw{slot}",
                )
                for fb_cmd in self._fallback_host_drop_cmds(slot):
                    await self._run(*fb_cmd)
                ms_proc = await self._spawn_microsocks(slot)
                procs.append(ms_proc)
            if not await self._wait_tcp_ready(f"198.18.{slot}.2", 1080, ms_proc, timeout_s=1.0):
                await self.stop_slot(slot)
                return False

            ok, rtt_ms, detail = await probe_socks_mt_api(f"198.18.{slot}.2", 1080)
            if not ok:
                LOG.warning("slot %d MT probe failed (%s, %dms) on %s", slot, detail, rtt_ms, abs_cfg)
                await self.stop_slot(slot)
                return False

            self._watchers[slot] = asyncio.create_task(self._watch_ovpn_exit(slot, ovpn_proc, ms_proc))
            return True
        except asyncio.CancelledError:
            await self.stop_slot(slot)
            raise
        except Exception as exc:
            LOG.warning("slot %d start failed (%s): %s", slot, abs_cfg, exc)
            await self.stop_slot(slot)
            return False

    async def rotate_slot(self, slot: int, cfg: str) -> bool:
        await self.stop_slot(slot)
        return await self.start_slot(slot, cfg)

    async def stop_slots_batch(self, slots: list[int]) -> None:
        unique_slots = sorted({s for s in slots if 1 <= s <= self.MAX_SLOTS})
        if not unique_slots:
            return

        cur_task = asyncio.current_task()
        watchers_to_cancel: list[asyncio.Task[None]] = []
        for s in unique_slots:
            w = self._watchers.pop(s, None)
            if w is not None and w is not cur_task and not w.done():
                w.cancel()
                watchers_to_cancel.append(w)
        if watchers_to_cancel:
            await asyncio.gather(*watchers_to_cancel, return_exceptions=True)

        procs: list[asyncio.subprocess.Process] = []
        netns_pids: set[int] = set()
        pids_lists = await asyncio.gather(*(self._netns_pids(s) for s in unique_slots))
        for slot, pids in zip(unique_slots, pids_lists):
            entry = self._slots.get(slot)
            if entry is not None:
                procs.extend(p for p in entry[1] if p.returncode is None)
            netns_pids.update(pids)

        tracked_pids = {p.pid for p in procs}
        for p in procs:
            with contextlib.suppress(ProcessLookupError, OSError):
                p.terminate()
        for pid in netns_pids - tracked_pids:
            with contextlib.suppress(ProcessLookupError, OSError):
                os.kill(pid, signal.SIGTERM)

        deadline = time.monotonic() + self.STOP_WAIT_S
        if procs:
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(
                    asyncio.gather(*(p.wait() for p in procs), return_exceptions=True),
                    timeout=self.STOP_WAIT_S,
                )
        while time.monotonic() < deadline:
            cur_lists = await asyncio.gather(*(self._netns_pids(s) for s in unique_slots))
            if not any(cur_lists):
                break
            await asyncio.sleep(0.05)

        sigkill = getattr(signal, "SIGKILL", signal.SIGTERM)
        for p in procs:
            if p.returncode is None:
                with contextlib.suppress(ProcessLookupError, OSError):
                    p.kill()
        rem_lists = await asyncio.gather(*(self._netns_pids(s) for s in unique_slots))
        for pids in rem_lists:
            for pid in pids:
                with contextlib.suppress(ProcessLookupError, OSError):
                    os.kill(pid, sigkill)
        if procs:
            await asyncio.gather(*(p.wait() for p in procs), return_exceptions=True)

        async def _cleanup_one(s: int) -> None:
            await self._run("ip", "netns", "del", f"ovns{s}")
            await self._run("ip", "link", "del", f"ovh{s}")
            shutil.rmtree(f"/etc/netns/ovns{s}", ignore_errors=True)
            with contextlib.suppress(FileNotFoundError):
                os.remove(self._log_path(s))
            with contextlib.suppress(FileNotFoundError):
                os.remove(self._sanitized_cfg_path(s))
            self._slots.pop(s, None)

        await asyncio.gather(*(_cleanup_one(s) for s in unique_slots))

    async def stop_slot(self, slot: int) -> None:
        self._validate_slot(slot)
        await self.stop_slots_batch([slot])

    async def stop_all(self) -> None:
        slots = set(self._slots.keys())
        rc, out, _ = await self._run("ip", "netns", "list")
        if rc == 0:
            for m in re.finditer(r"^ovns(\d+)\b", out, re.MULTILINE):
                slots.add(int(m.group(1)))
        await self.stop_slots_batch(sorted(slots))
        rc, out, _ = await self._run("ip", "-o", "link", "show")
        if rc == 0:
            for m in re.finditer(r"^\d+:\s+(ovh\d+)[:@]", out, re.MULTILINE):
                await self._run("ip", "link", "del", m.group(1))


async def _read_http_head(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    timeout_s: float = 10.0,
) -> tuple[str, str, str, dict[str, str], bytes, float] | None:
    """Read HTTP/1.x request head with bounded header size and total deadline."""
    buf = bytearray()
    idx = -1
    deadline = time.monotonic() + timeout_s
    while True:
        rem = deadline - time.monotonic()
        if rem <= 0:
            raise asyncio.TimeoutError()
        chunk = await asyncio.wait_for(reader.read(4096), timeout=rem)
        if not chunk:
            break
        buf.extend(chunk)
        idx = buf.find(b"\r\n\r\n")
        if idx > MAX_HEADER_BYTES or (idx < 0 and len(buf) > MAX_HEADER_BYTES):
            await _send_resp(writer, b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n")
            return None
        if idx >= 0:
            break

    if idx < 0:
        await _send_resp(writer, b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
        return None

    lines = bytes(buf[:idx]).decode("latin-1").split("\r\n")
    req_parts = lines[0].split()
    if len(req_parts) != 3:
        await _send_resp(writer, b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
        return None

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return req_parts[0], req_parts[1], req_parts[2], headers, bytes(buf[idx + 4 :]), deadline


async def _stop_server(srv: asyncio.AbstractServer | None, tasks: set[asyncio.Task[Any]]) -> None:
    """Close listener, cancel/await active handler tasks first, then wait_closed with timeout."""
    if srv is not None:
        srv.close()
    pending = list(tasks)
    for t in pending:
        t.cancel()
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)
    if srv is not None:
        with contextlib.suppress(asyncio.TimeoutError, Exception):
            await asyncio.wait_for(srv.wait_closed(), timeout=2.0)


class HttpToSocksBridge:
    """Authenticated HTTP CONNECT to SOCKS5 bridge."""

    def __init__(self, host: str = "0.0.0.0", idle_timeout_s: float = 180.0) -> None:
        self.host = host
        self.idle_timeout_s = idle_timeout_s
        self.port = 0
        self._socks_host = ""
        self._socks_port = 0
        self._auth_fn: Callable[[str, str], bool] = lambda _u, _p: False
        self._server: asyncio.AbstractServer | None = None
        self._tasks: set[asyncio.Task[None]] = set()

    async def start(
        self,
        port: int,
        socks_host: str,
        socks_port: int,
        auth_fn: Callable[[str, str], bool],
    ) -> None:
        if port <= 1024 or port > 65535:
            raise ValueError(f"Refusing privileged/invalid port {port} (must be > 1024)")
        if self._server is not None:
            await self.stop()
        self.port = port
        self._socks_host = socks_host
        self._socks_port = socks_port
        self._auth_fn = auth_fn
        self._server = await asyncio.start_server(self._on_client, self.host, port)

    def _on_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.create_task(self._handle_client(reader, writer))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    @staticmethod
    def _parse_basic_auth(header_val: str) -> tuple[str, str] | None:
        parts = header_val.split(None, 1)
        if len(parts) != 2 or parts[0].lower() != "basic":
            return None
        try:
            raw = base64.b64decode(parts[1].strip(), validate=True).decode("utf-8")
        except Exception:
            return None
        if ":" not in raw:
            return None
        user, passwd = raw.split(":", 1)
        return user, passwd

    @staticmethod
    def _parse_target(target: str) -> tuple[str, int] | None:
        if target.startswith("["):
            m = re.fullmatch(r"\[([^\]]+)\]:(\d+)", target)
            if not m:
                return None
            host, port_s = m.group(1), m.group(2)
            try:
                ipaddress.IPv6Address(host)
            except ValueError:
                return None
        else:
            if ":" not in target:
                return None
            host, port_s = target.rsplit(":", 1)
        if not host or not (port_s.isascii() and port_s.isdigit()):
            return None
        port = int(port_s)
        return (host, port) if 1 <= port <= 65535 else None

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        socks_writer: asyncio.StreamWriter | None = None
        t1: asyncio.Task[bool] | None = None
        t2: asyncio.Task[bool] | None = None
        try:
            head = await _read_http_head(reader, writer, timeout_s=10.0)
            if head is None:
                return
            method, target, _proto, headers, trailing, _deadline = head

            creds = self._parse_basic_auth(headers.get("proxy-authorization", ""))
            if creds is None or not self._auth_fn(*creds):
                await _send_resp(writer, PROXY_407_RESPONSE)
                return

            if method.upper() != "CONNECT":
                await _send_resp(writer, b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n")
                return

            parsed = self._parse_target(target)
            if parsed is None:
                await _send_resp(writer, b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                return

            try:
                socks_reader, socks_writer = await _socks5_connect(
                    self._socks_host, self._socks_port, parsed[0], parsed[1], timeout_s=10.0
                )
            except Exception:
                await _send_resp(writer, b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                return

            await _send_resp(writer, b"HTTP/1.1 200 Connection Established\r\n\r\n")
            if trailing:
                await _send_resp(socks_writer, trailing)

            t1 = asyncio.create_task(_pipe(reader, socks_writer, self.idle_timeout_s))
            t2 = asyncio.create_task(_pipe(socks_reader, writer, self.idle_timeout_s))
            done, pending = await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
            first = next(iter(done))
            clean_eof = not first.cancelled() and first.exception() is None and bool(first.result())
            for p in pending:
                if clean_eof:
                    with contextlib.suppress(asyncio.TimeoutError, Exception):
                        await asyncio.wait_for(p, timeout=10.0)
                else:
                    p.cancel()
        except Exception:
            pass
        finally:
            for t in (t1, t2):
                if t is not None:
                    if not t.done():
                        t.cancel()
                    with contextlib.suppress(BaseException):
                        await t
            await asyncio.gather(_close_writer(writer), _close_writer(socks_writer), return_exceptions=True)

    async def stop(self) -> None:
        srv, self._server = self._server, None
        await _stop_server(srv, self._tasks)


def validate_gateway_config(
    port: int,
    base_proxy_port: int,
    max_slots: int,
    ttl_s: float = 180.0,
) -> None:
    """Validate API/proxy ports, slot bounds, port overlap, and TTL invariants."""
    if not (1 <= max_slots <= OvpnSlotManager.MAX_SLOTS):
        raise ValueError(f"max_slots must be in 1..{OvpnSlotManager.MAX_SLOTS}, got {max_slots}")
    if port <= 1024 or port > 65535:
        raise ValueError(f"API port {port} must be in 1025..65535 (privileged ports refused)")
    if base_proxy_port <= 1024 or base_proxy_port > 65535:
        raise ValueError(f"base_proxy_port {base_proxy_port} must be in 1025..65535")
    end_proxy_port = base_proxy_port + max_slots - 1
    if end_proxy_port > 65535:
        raise ValueError(f"Proxy port range {base_proxy_port}..{end_proxy_port} exceeds 65535")
    if base_proxy_port <= port <= end_proxy_port:
        raise ValueError(f"API port {port} overlaps proxy range {base_proxy_port}..{end_proxy_port}")
    if not math.isfinite(ttl_s) or ttl_s <= 0 or ttl_s > MAX_TTL_S:
        raise ValueError(f"ttl_s must be in (0, {MAX_TTL_S:g}] and finite, got {ttl_s}")


def detect_public_ip() -> str:
    """Auto-detect outbound IPv4 via `ip -4 route get 1.1.1.1`, falling back to 127.0.0.1."""
    try:
        proc = subprocess.run(
            ["ip", "-4", "route", "get", "1.1.1.1"],
            capture_output=True,
            text=True,
            timeout=2.0,
            check=False,
        )
        m = re.search(r"\bsrc\s+(\d+\.\d+\.\d+\.\d+)\b", proc.stdout or "")
        if m:
            return m.group(1)
    except Exception:
        pass
    return "127.0.0.1"


@dataclass
class _SlotEntry:
    slot: int
    port: int
    user: str
    passwd: str
    proxy_url: str
    cfg: str = ""
    bridge: HttpToSocksBridge | None = None
    alive: bool = False


@dataclass
class _Lease:
    lease_id: str
    client: str
    ttl_s: float
    expires_at: float
    deadline_mono: float
    slots: dict[int, _SlotEntry]
    released: bool = False


class GatewayServer:
    """HTTP Bearer-authenticated OpenVPN proxy lease gateway with TTL reaper."""

    COOLDOWN_S = 180.0
    MAX_BODY_BYTES = 65536
    REQUEST_TIMEOUT_S = 10.0
    LEASE_CONCURRENCY = 10
    MAX_LEASE_ATTEMPTS_PER_SLOT = 8
    MAX_ROTATE_ATTEMPTS = 8

    def __init__(
        self,
        ovpn_dir: str,
        host: str = "0.0.0.0",
        port: int = 8080,
        token: str = "",
        base_proxy_port: int = 20001,
        max_slots: int = 45,
        public_ip: str = "",
        ttl_s: float = 180.0,
        slot_manager: Any | None = None,
        reap_interval_s: float = 15.0,
    ) -> None:
        validate_gateway_config(port, base_proxy_port, max_slots, ttl_s)
        self.ovpn_dir = ovpn_dir
        self._configs, self._auth_file = discover_ovpn_configs(ovpn_dir)
        if not self._configs:
            raise ValueError(f"No .ovpn configs found in {ovpn_dir}")

        self.host = host
        self.port = port
        self.token = token or secrets.token_urlsafe(24)
        self._token_bytes = self.token.encode("utf-8")
        self.base_proxy_port = base_proxy_port
        self.max_slots = max_slots
        self.public_ip = public_ip or detect_public_ip()
        self.default_ttl_s = float(ttl_s)
        self.reap_interval_s = reap_interval_s

        if slot_manager is not None:
            self.slot_manager = slot_manager
            if getattr(self.slot_manager, "_on_unexpected_exit", None) is None and hasattr(
                self.slot_manager, "_on_unexpected_exit"
            ):
                self.slot_manager._on_unexpected_exit = self._handle_unexpected_exit
        else:
            self.slot_manager = OvpnSlotManager(
                ovpn_dir=ovpn_dir,
                auth_file=self._auth_file,
                on_unexpected_exit=self._handle_unexpected_exit,
            )

        self._lock = asyncio.Lock()
        self._slot_locks = {s: asyncio.Lock() for s in range(1, max_slots + 1)}
        self._leases: dict[str, _Lease] = {}
        self._pending_leases: dict[str, list[_SlotEntry]] = {}
        self._slot_owners: dict[int, str] = {}
        self._reserved_cfgs: dict[int, str] = {}
        self._cooldowns: dict[str, float] = {}
        self._server: asyncio.AbstractServer | None = None
        self._reaper_task: asyncio.Task[None] | None = None
        self._client_tasks: set[asyncio.Task[None]] = set()
        self._stopping = False

    async def start(self) -> None:
        if self._server is not None:
            return
        self._stopping = False
        await self.slot_manager.stop_all()
        self._server = await asyncio.start_server(self._on_client, self.host, self.port)
        self._reaper_task = asyncio.create_task(self._reaper_loop())

    async def stop(self) -> None:
        self._stopping = True
        if self._reaper_task is not None:
            self._reaper_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._reaper_task
            self._reaper_task = None
        srv, self._server = self._server, None
        await _stop_server(srv, self._client_tasks)

        async with self._lock:
            bridges = [
                e.bridge
                for lease in self._leases.values()
                for e in lease.slots.values()
                if e.bridge is not None
            ] + [
                e.bridge
                for entries in self._pending_leases.values()
                for e in entries
                if e.bridge is not None
            ]
            self._leases.clear()
            self._pending_leases.clear()
            self._slot_owners.clear()
            self._reserved_cfgs.clear()

        if bridges:
            await asyncio.gather(*(b.stop() for b in bridges), return_exceptions=True)
        await self.slot_manager.stop_all()

    def _on_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.create_task(self._handle_http(reader, writer))
        self._client_tasks.add(task)
        task.add_done_callback(self._client_tasks.discard)

    def _is_authorized(self, headers: dict[str, str]) -> bool:
        auth = headers.get("authorization", "")
        parts = auth.split(None, 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return False
        return hmac.compare_digest(parts[1].strip().encode("utf-8"), self._token_bytes)

    def _mark_cooldown(self, cfg: str) -> None:
        if cfg:
            self._cooldowns[cfg] = time.monotonic() + self.COOLDOWN_S

    def _pick_next_config(self, exclude: set[str], allow_cooldown_fallback: bool) -> str | None:
        """Select unused .ovpn (UDP-first, non-cooldown first). Caller holds self._lock."""
        now = time.monotonic()
        used = set(self._reserved_cfgs.values()) | exclude
        candidates = [c for c in self._configs if c not in used]
        if not candidates:
            return None
        fresh = [c for c in candidates if self._cooldowns.get(c, 0.0) <= now]
        if fresh:
            return fresh[0]
        if not allow_cooldown_fallback:
            return None
        return min(candidates, key=lambda c: self._cooldowns.get(c, 0.0))

    async def _handle_unexpected_exit(self, slot: int, cfg: str) -> None:
        lock = self._slot_locks.get(slot)
        if lock is None:
            return
        async with lock:
            bridge: HttpToSocksBridge | None = None
            async with self._lock:
                self._mark_cooldown(cfg)
                if cfg and self._reserved_cfgs.get(slot) == cfg:
                    self._reserved_cfgs.pop(slot, None)
                lease_id = self._slot_owners.get(slot)
                entry: _SlotEntry | None = None
                if lease_id:
                    lease = self._leases.get(lease_id)
                    if lease is not None:
                        entry = lease.slots.get(slot)
                    elif lease_id in self._pending_leases:
                        entry = next((e for e in self._pending_leases[lease_id] if e.slot == slot), None)
                if entry is not None and cfg and entry.cfg == cfg:
                    bridge = entry.bridge
                    entry.bridge = None
                    entry.cfg = ""
                    entry.alive = False
            if bridge is not None:
                await bridge.stop()

    async def _send_json(
        self,
        writer: asyncio.StreamWriter,
        status: int,
        reason: str,
        payload: dict[str, Any],
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        body = json.dumps(payload, separators=(",", ":"), allow_nan=False).encode("utf-8")
        lines = [
            f"HTTP/1.1 {status} {reason}",
            "Content-Type: application/json",
            f"Content-Length: {len(body)}",
            "Connection: close",
        ]
        if extra_headers:
            for k, v in extra_headers.items():
                lines.append(f"{k}: {v}")
        await _send_resp(writer, ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body)

    async def _read_json_body(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        headers: dict[str, str],
        trailing: bytes,
        deadline: float,
    ) -> dict[str, Any] | None:
        raw_cl = headers.get("content-length")
        body_bytes = b""
        if raw_cl is not None:
            if not (raw_cl.isascii() and raw_cl.isdigit()):
                await self._send_json(writer, 400, "Bad Request", {"ok": False, "error": "invalid Content-Length"})
                return None
            cl = int(raw_cl)
            if cl > self.MAX_BODY_BYTES:
                await self._send_json(writer, 413, "Payload Too Large", {"ok": False, "error": "body exceeds 64KB"})
                return None
            if cl > 0:
                if len(trailing) >= cl:
                    body_bytes = trailing[:cl]
                else:
                    rem = deadline - time.monotonic()
                    if rem <= 0:
                        await self._send_json(writer, 408, "Request Timeout", {"ok": False, "error": "body timeout"})
                        return None
                    try:
                        more = await asyncio.wait_for(reader.readexactly(cl - len(trailing)), timeout=rem)
                    except (asyncio.IncompleteReadError, asyncio.TimeoutError):
                        await self._send_json(writer, 400, "Bad Request", {"ok": False, "error": "incomplete body"})
                        return None
                    body_bytes = trailing + more
        if not body_bytes:
            return {}
        def _reject_json_constant(val: str) -> Any:
            raise ValueError(f"invalid JSON constant: {val}")

        try:
            parsed = json.loads(body_bytes.decode("utf-8"), parse_constant=_reject_json_constant)
        except Exception:
            await self._send_json(writer, 400, "Bad Request", {"ok": False, "error": "invalid JSON"})
            return None
        if not isinstance(parsed, dict):
            await self._send_json(writer, 400, "Bad Request", {"ok": False, "error": "JSON body must be an object"})
            return None
        return parsed

    async def _handle_http(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await _read_http_head(reader, writer, timeout_s=self.REQUEST_TIMEOUT_S)
            if head is None:
                return
            method, raw_path, _proto, headers, trailing, deadline = head
            method = method.upper()
            path = raw_path.split("?", 1)[0]

            if not self._is_authorized(headers):
                await self._send_json(
                    writer,
                    401,
                    "Unauthorized",
                    {"ok": False, "error": "unauthorized"},
                    {"WWW-Authenticate": 'Bearer realm="ufasproxy"'},
                )
                return

            if path == "/status":
                if method != "GET":
                    await self._send_json(writer, 405, "Method Not Allowed", {"ok": False, "error": "use GET"})
                    return
                status_code, payload = await self._api_status()
            elif path in ("/lease", "/rotate", "/heartbeat", "/release"):
                if method != "POST":
                    await self._send_json(writer, 405, "Method Not Allowed", {"ok": False, "error": "use POST"})
                    return
                body = await self._read_json_body(reader, writer, headers, trailing, deadline)
                if body is None:
                    return
                peer_closed = False
                if path == "/lease":
                    lease_task = asyncio.create_task(self._api_lease(body))
                    eof_task = asyncio.create_task(reader.read(1))
                    try:
                        done, _ = await asyncio.wait((lease_task, eof_task), return_when=asyncio.FIRST_COMPLETED)
                        if eof_task in done and lease_task not in done:
                            eof_val = b""
                            with contextlib.suppress(Exception):
                                eof_val = eof_task.result()
                            if not eof_val:
                                peer_closed = True
                                lease_task.cancel()
                                with contextlib.suppress(BaseException):
                                    await lease_task
                                return
                        if not lease_task.done():
                            status_code, payload = await lease_task
                        else:
                            status_code, payload = lease_task.result()
                        if eof_task.done():
                            eof_val = b""
                            with contextlib.suppress(Exception):
                                eof_val = eof_task.result()
                            if not eof_val:
                                peer_closed = True
                    finally:
                        if not eof_task.done():
                            eof_task.cancel()
                        with contextlib.suppress(BaseException):
                            await eof_task
                        if not lease_task.done():
                            lease_task.cancel()
                            with contextlib.suppress(BaseException):
                                await lease_task
                    if peer_closed:
                        if status_code == 200 and isinstance(payload, dict) and payload.get("lease_id"):
                            with contextlib.suppress(Exception):
                                await self._release_lease(str(payload["lease_id"]))
                        return
                elif path == "/rotate":
                    status_code, payload = await self._api_rotate(body)
                elif path == "/heartbeat":
                    status_code, payload = await self._api_heartbeat(body)
                else:
                    status_code, payload = await self._api_release(body)
            else:
                status_code, payload = 404, {"ok": False, "error": "not found"}

            reasons = {
                200: "OK",
                400: "Bad Request",
                404: "Not Found",
                405: "Method Not Allowed",
                409: "Conflict",
                503: "Service Unavailable",
            }
            created_lease_id = (
                str(payload["lease_id"])
                if path == "/lease" and status_code == 200 and isinstance(payload, dict) and payload.get("lease_id")
                else ""
            )
            try:
                if writer.is_closing():
                    raise ConnectionResetError("client closed connection before response")
                await self._send_json(writer, status_code, reasons.get(status_code, "Error"), payload)
            except BaseException:
                if created_lease_id:
                    with contextlib.suppress(Exception):
                        await self._release_lease(created_lease_id)
                raise
        except asyncio.TimeoutError:
            with contextlib.suppress(Exception):
                await self._send_json(writer, 408, "Request Timeout", {"ok": False, "error": "request timeout"})
        except Exception:
            pass
        finally:
            await _close_writer(writer)

    async def _api_status(self) -> tuple[int, dict[str, Any]]:
        now = time.monotonic()
        async with self._lock:
            leases = [
                {
                    "lease_id": ls.lease_id,
                    "client": ls.client,
                    "count": len(ls.slots),
                    "active_proxies": sum(1 for e in ls.slots.values() if e.alive),
                    "slots": sorted(ls.slots.keys()),
                    "ttl_s": ls.ttl_s,
                    "expires_at": ls.expires_at,
                }
                for ls in self._leases.values()
                if not ls.released
            ]
            cooldown_cnt = sum(1 for until in self._cooldowns.values() if until > now)
            return 200, {
                "ok": True,
                "active_slots": len(self._slot_owners),
                "max_slots": self.max_slots,
                "total_configs": len(self._configs),
                "cooldown_configs": cooldown_cnt,
                "leases": leases,
            }

    async def _rollback_reserved(self, entries: list[_SlotEntry], lease_id: str | None = None) -> None:
        slots = sorted(e.slot for e in entries)
        async with self._lock:
            if lease_id is not None:
                self._pending_leases.pop(lease_id, None)
        async with contextlib.AsyncExitStack() as stack:
            for s in slots:
                await stack.enter_async_context(self._slot_locks[s])
            bridges = [e.bridge for e in entries if e.bridge is not None]
            for e in entries:
                e.bridge = None
                e.alive = False
                e.cfg = ""
            if bridges:
                await asyncio.gather(*(b.stop() for b in bridges), return_exceptions=True)
            with contextlib.suppress(Exception):
                await self.slot_manager.stop_slots_batch(slots)
            async with self._lock:
                for s in slots:
                    self._slot_owners.pop(s, None)
                    self._reserved_cfgs.pop(s, None)

    async def _api_lease(self, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        count = body.get("count")
        if not isinstance(count, int) or isinstance(count, bool) or count < 1:
            return 400, {"ok": False, "error": "count must be a positive integer"}
        raw_ttl = body.get("ttl_s", self.default_ttl_s)
        if isinstance(raw_ttl, bool) or not isinstance(raw_ttl, (int, float)):
            return 400, {"ok": False, "error": "ttl_s must be > 0"}
        try:
            ttl_s = float(raw_ttl)
        except OverflowError:
            return 400, {"ok": False, "error": "ttl_s must be finite"}
        if not math.isfinite(ttl_s) or ttl_s <= 0 or ttl_s > MAX_TTL_S:
            return 400, {"ok": False, "error": f"ttl_s must be in (0, {MAX_TTL_S:g}]"}
        client = str(body.get("client", ""))[:64]

        lease_id = secrets.token_hex(12)
        async with self._lock:
            if self._stopping:
                return 503, {"ok": False, "error": "server shutting down"}
            free_slots = [s for s in range(1, self.max_slots + 1) if s not in self._slot_owners]
            if count > len(free_slots):
                return 409, {
                    "ok": False,
                    "error": f"insufficient capacity: requested {count}, available {len(free_slots)}",
                }
            pending_unreserved = sum(1 for s in self._slot_owners if s not in self._reserved_cfgs)
            avail_cfgs = max(0, len(set(self._configs) - set(self._reserved_cfgs.values())) - pending_unreserved)
            if count > avail_cfgs:
                return 409, {
                    "ok": False,
                    "error": f"insufficient unused configs: requested {count}, available {avail_cfgs}",
                }
            reserved = free_slots[:count]
            entries: list[_SlotEntry] = []
            for s in reserved:
                self._slot_owners[s] = lease_id
                port = self.base_proxy_port + s - 1
                user = f"u{s}_{secrets.token_hex(3)}"
                passwd = secrets.token_hex(12)
                entries.append(
                    _SlotEntry(
                        slot=s,
                        port=port,
                        user=user,
                        passwd=passwd,
                        proxy_url=f"http://{user}:{passwd}@{self.public_ip}:{port}",
                    )
                )
            self._pending_leases[lease_id] = entries

        sem = asyncio.Semaphore(self.LEASE_CONCURRENCY)
        attempted: set[str] = set()
        abort_event = asyncio.Event()

        async def _start_one(entry: _SlotEntry) -> bool:
            async with sem:
                async with self._slot_locks[entry.slot]:
                    for _attempt in range(self.MAX_LEASE_ATTEMPTS_PER_SLOT):
                        if abort_event.is_set() or self._stopping:
                            return False
                        async with self._lock:
                            cfg = self._pick_next_config(attempted, allow_cooldown_fallback=True)
                            if cfg is None:
                                abort_event.set()
                                return False
                            attempted.add(cfg)
                            self._reserved_cfgs[entry.slot] = cfg

                        ok = False
                        try:
                            ok = await self.slot_manager.start_slot(entry.slot, cfg)
                        except Exception as exc:
                            LOG.warning("slot %d start_slot error: %s", entry.slot, exc)
                            ok = False

                        if ok:
                            if abort_event.is_set() or self._stopping:
                                with contextlib.suppress(Exception):
                                    await self.slot_manager.stop_slot(entry.slot)
                                async with self._lock:
                                    if self._reserved_cfgs.get(entry.slot) == cfg:
                                        self._reserved_cfgs.pop(entry.slot, None)
                                return False
                            bridge = HttpToSocksBridge(host=self.host, idle_timeout_s=max(ttl_s, self.default_ttl_s))
                            try:
                                await bridge.start(
                                    entry.port,
                                    f"198.18.{entry.slot}.2",
                                    1080,
                                    make_basic_auth_fn(entry.user, entry.passwd),
                                )
                            except Exception as exc:
                                LOG.warning("slot %d bridge bind failed on %d: %s", entry.slot, entry.port, exc)
                                await bridge.stop()
                                with contextlib.suppress(Exception):
                                    await self.slot_manager.stop_slot(entry.slot)
                                async with self._lock:
                                    if self._reserved_cfgs.get(entry.slot) == cfg:
                                        self._reserved_cfgs.pop(entry.slot, None)
                                abort_event.set()
                                return False
                            async with self._lock:
                                if self._stopping or abort_event.is_set():
                                    abort_now = True
                                else:
                                    entry.cfg = cfg
                                    entry.bridge = bridge
                                    entry.alive = True
                                    abort_now = False
                            if abort_now:
                                await bridge.stop()
                                with contextlib.suppress(Exception):
                                    await self.slot_manager.stop_slot(entry.slot)
                                async with self._lock:
                                    if self._reserved_cfgs.get(entry.slot) == cfg:
                                        self._reserved_cfgs.pop(entry.slot, None)
                                return False
                            return True

                        async with self._lock:
                            if self._reserved_cfgs.get(entry.slot) == cfg:
                                self._reserved_cfgs.pop(entry.slot, None)
                            self._mark_cooldown(cfg)
                    abort_event.set()
                    return False

        tasks = [asyncio.create_task(_start_one(e)) for e in entries]
        try:
            results = await asyncio.gather(*tasks, return_exceptions=True)
        except BaseException:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await self._rollback_reserved(entries, lease_id=lease_id)
            raise

        if self._stopping or not all(r is True for r in results):
            await self._rollback_reserved(entries, lease_id=lease_id)
            return 503, {"ok": False, "error": "failed to start all requested OpenVPN slots"}

        now_wall = time.time()
        now_mono = time.monotonic()
        lease = _Lease(
            lease_id=lease_id,
            client=client,
            ttl_s=ttl_s,
            expires_at=now_wall + ttl_s,
            deadline_mono=now_mono + ttl_s,
            slots={e.slot: e for e in entries},
        )
        committed = False
        async with self._lock:
            self._pending_leases.pop(lease_id, None)
            if not self._stopping and all(
                e.alive and e.cfg and self._reserved_cfgs.get(e.slot) == e.cfg for e in entries
            ):
                self._leases[lease_id] = lease
                committed = True
        if not committed:
            await self._rollback_reserved(entries, lease_id=lease_id)
            return 503, {"ok": False, "error": "lease slot exited before commit"}
        return 200, {
            "lease_id": lease_id,
            "proxies": [e.proxy_url for e in entries],
            "expires_at": lease.expires_at,
        }

    @staticmethod
    def _match_lease_entry(lease: _Lease, proxy_url: str) -> _SlotEntry | None:
        exact = next((e for e in lease.slots.values() if e.proxy_url == proxy_url), None)
        if exact is not None:
            return exact
        try:
            parsed = urllib.parse.urlsplit(proxy_url)
            target = (parsed.port, parsed.username, parsed.password)
        except ValueError:
            return None
        if target[0] is None or target[1] is None or target[2] is None:
            return None
        return next(
            (e for e in lease.slots.values() if (e.port, e.user, e.passwd) == target),
            None,
        )

    async def _api_rotate(self, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        lease_id = body.get("lease_id")
        proxy_url = body.get("proxy")
        if not isinstance(lease_id, str) or not lease_id or not isinstance(proxy_url, str) or not proxy_url:
            return 400, {"ok": False, "error": "lease_id and proxy are required"}

        async with self._lock:
            lease = self._leases.get(lease_id)
            if lease is None or lease.released:
                return 404, {"ok": False, "error": "unknown lease"}
            entry = self._match_lease_entry(lease, proxy_url)
            if entry is None:
                return 404, {"ok": False, "error": "unknown proxy in lease"}

        async def _abort_if_closed(
            cfg_to_clear: str,
            bridge_to_stop: HttpToSocksBridge | None = None,
        ) -> tuple[int, dict[str, Any]] | None:
            async with self._lock:
                cur_lease = self._leases.get(lease_id)
                code = 503 if self._stopping else (404 if (cur_lease is None or cur_lease.released) else 0)
                if not code:
                    if bridge_to_stop is not None:
                        entry.cfg = cfg_to_clear
                        entry.bridge = bridge_to_stop
                        entry.alive = True
                    return None
                if self._reserved_cfgs.get(entry.slot) == cfg_to_clear:
                    self._reserved_cfgs.pop(entry.slot, None)
            if bridge_to_stop is not None:
                await bridge_to_stop.stop()
            with contextlib.suppress(Exception):
                await self.slot_manager.stop_slot(entry.slot)
            msg = "server shutting down" if code == 503 else "lease closed"
            return code, {"ok": False, "error": msg}

        async with self._slot_locks[entry.slot]:
            async with self._lock:
                if self._stopping:
                    return 503, {"ok": False, "error": "server shutting down"}
                lease = self._leases.get(lease_id)
                if lease is None or lease.released:
                    return 404, {"ok": False, "error": "lease closed"}
                old_bridge = entry.bridge
                old_cfg = entry.cfg
                entry.bridge = None
                entry.alive = False
                entry.cfg = ""
                attempted: set[str] = {old_cfg} if old_cfg else set()
                self._mark_cooldown(old_cfg)
                if not old_cfg or self._reserved_cfgs.get(entry.slot) == old_cfg:
                    self._reserved_cfgs.pop(entry.slot, None)

            if old_bridge is not None:
                await old_bridge.stop()

            for _attempt in range(self.MAX_ROTATE_ATTEMPTS):
                async with self._lock:
                    if self._stopping:
                        return 503, {"ok": False, "error": "server shutting down"}
                    lease = self._leases.get(lease_id)
                    if lease is None or lease.released:
                        return 404, {"ok": False, "error": "lease closed"}
                    new_cfg = self._pick_next_config(attempted, allow_cooldown_fallback=False)
                    if new_cfg is None:
                        return 503, {"ok": False, "error": "no unused off-cooldown .ovpn configs available"}
                    attempted.add(new_cfg)
                    self._reserved_cfgs[entry.slot] = new_cfg

                ok = False
                try:
                    ok = await self.slot_manager.rotate_slot(entry.slot, new_cfg)
                except Exception as exc:
                    LOG.warning("slot %d rotate_slot error: %s", entry.slot, exc)
                    ok = False

                if ok:
                    aborted = await _abort_if_closed(new_cfg)
                    if aborted is not None:
                        return aborted
                    new_bridge = HttpToSocksBridge(host=self.host, idle_timeout_s=max(lease.ttl_s, self.default_ttl_s))
                    try:
                        await new_bridge.start(
                            entry.port,
                            f"198.18.{entry.slot}.2",
                            1080,
                            make_basic_auth_fn(entry.user, entry.passwd),
                        )
                    except Exception as exc:
                        LOG.warning("slot %d bridge restart failed: %s", entry.slot, exc)
                        await new_bridge.stop()
                        with contextlib.suppress(Exception):
                            await self.slot_manager.stop_slot(entry.slot)
                        async with self._lock:
                            if self._reserved_cfgs.get(entry.slot) == new_cfg:
                                self._reserved_cfgs.pop(entry.slot, None)
                        return 503, {"ok": False, "error": "bridge restart failed"}
                    aborted = await _abort_if_closed(new_cfg, new_bridge)
                    if aborted is not None:
                        return aborted
                    return 200, {"ok": True, "proxy": entry.proxy_url}

                async with self._lock:
                    if self._reserved_cfgs.get(entry.slot) == new_cfg:
                        self._reserved_cfgs.pop(entry.slot, None)
                    self._mark_cooldown(new_cfg)

            if self._stopping:
                return 503, {"ok": False, "error": "server shutting down"}
            return 503, {"ok": False, "error": "rotate failed after maximum attempts"}

    async def _api_heartbeat(self, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        lease_id = body.get("lease_id")
        if not isinstance(lease_id, str) or not lease_id:
            return 400, {"ok": False, "error": "lease_id is required"}
        async with self._lock:
            lease = self._leases.get(lease_id)
            if lease is None or lease.released:
                return 404, {"ok": False, "error": "unknown lease"}
            lease.deadline_mono = time.monotonic() + lease.ttl_s
            lease.expires_at = time.time() + lease.ttl_s
            return 200, {"ok": True, "expires_at": lease.expires_at}

    async def _release_lease(self, lease_id: str) -> int | None:
        async with self._lock:
            lease = self._leases.get(lease_id)
            if lease is None or lease.released:
                return None
            lease.released = True
            slots = sorted(lease.slots.keys())
            entries = [lease.slots[s] for s in slots]

        async with contextlib.AsyncExitStack() as stack:
            for s in slots:
                await stack.enter_async_context(self._slot_locks[s])
            bridges = [e.bridge for e in entries if e.bridge is not None]
            for e in entries:
                e.bridge = None
                e.alive = False
            if bridges:
                await asyncio.gather(*(b.stop() for b in bridges), return_exceptions=True)
            with contextlib.suppress(Exception):
                await self.slot_manager.stop_slots_batch(slots)
            async with self._lock:
                self._leases.pop(lease_id, None)
                for s in slots:
                    self._slot_owners.pop(s, None)
                    self._reserved_cfgs.pop(s, None)
        return len(slots)

    async def _api_release(self, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        lease_id = body.get("lease_id")
        if not isinstance(lease_id, str) or not lease_id:
            return 400, {"ok": False, "error": "lease_id is required"}
        released = await self._release_lease(lease_id)
        if released is None:
            return 404, {"ok": False, "error": "unknown lease"}
        return 200, {"ok": True, "released": released}

    async def reap_expired(self) -> int:
        now = time.monotonic()
        async with self._lock:
            expired_ids = [
                lid for lid, ls in self._leases.items() if not ls.released and now >= ls.deadline_mono
            ]
        reaped = 0
        for lid in expired_ids:
            if await self._release_lease(lid) is not None:
                reaped += 1
        return reaped

    async def _reaper_loop(self) -> None:
        try:
            while not self._stopping:
                await asyncio.sleep(self.reap_interval_s)
                if not self._stopping:
                    await self.reap_expired()
        except asyncio.CancelledError:
            pass


async def _selftest_async() -> None:
    # 1. discover_ovpn_configs ordering (UDP before TCP, case-insensitive) + auth detection
    with tempfile.TemporaryDirectory() as tmp:
        for fname in ("b_tcp.ovpn", "z_UDP.OVPN", "a_udp.ovpn", "plain.OvPn", "notes.txt", "auth.txt"):
            with open(os.path.join(tmp, fname), "w", encoding="utf-8") as fh:
                fh.write("client\n")
        cfgs, auth = discover_ovpn_configs(tmp)
        names = [os.path.basename(p) for p in cfgs]
        assert names == ["a_udp.ovpn", "z_UDP.OVPN", "b_tcp.ovpn", "plain.OvPn"], f"bad order: {names}"
        assert os.path.basename(auth) == "auth.txt", f"bad auth: {auth}"

        os.remove(auth)
        with open(os.path.join(tmp, "surf.auth"), "w", encoding="utf-8") as fh:
            fh.write("u\np\n")
        _, auth2 = discover_ovpn_configs(tmp)
        assert os.path.basename(auth2) == "surf.auth", f"bad fallback auth: {auth2}"

        # 2. _build_ovpn_cmd --cd/abspath normalization, argument order, slot bounds & bare auth-user-pass rejection
        rel_cfg = os.path.join(tmp, ".", "a_udp.ovpn")
        abs_cfg = os.path.abspath(rel_cfg)
        abs_auth = os.path.abspath(auth2)
        mgr = OvpnSlotManager(state_dir=tmp)
        for bad_slot in (0, 201):
            try:
                mgr._build_ovpn_cmd(bad_slot, rel_cfg)
                raise AssertionError(f"slot {bad_slot} should have been rejected")
            except ValueError:
                pass
        cmd = mgr._build_ovpn_cmd(3, rel_cfg, auth2)
        idx_ign = cmd.index("--ignore-unknown-option")
        idx_cd = cmd.index("--cd")
        idx_cfg = cmd.index("--config")
        assert cmd[idx_ign + 1] == "block-outside-dns", cmd
        assert cmd[idx_cd + 1] == os.path.dirname(abs_cfg), cmd
        assert cmd[idx_cfg + 1] == abs_cfg, cmd
        assert idx_ign < idx_cd < idx_cfg, f"bad order before --config: {cmd}"
        assert "--log" not in cmd, f"unexpected --log in cmd: {cmd}"
        tail = cmd[idx_cfg + 2 :]
        for required in (
            ["--pull-filter", "ignore", "block-outside-dns"],
            ["--pull-filter", "ignore", "ping-restart"],
            ["--pull-filter", "ignore", "ifconfig-ipv6"],
            ["--pull-filter", "ignore", "route-ipv6"],
            ["--data-ciphers", "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-256-CBC"],
            ["--data-ciphers-fallback", "AES-256-CBC"],
            ["--script-security", "1"],
            ["--ping-exit", "60"],
            ["--connect-retry", "1", "2"],
            ["--resolv-retry", "2"],
            ["--mssfix", "1360", "--fast-io"],
            ["--auth-nocache"],
            ["--auth-user-pass", abs_auth],
        ):
            pos = next((i for i in range(len(tail) - len(required) + 1) if tail[i : i + len(required)] == required), -1)
            assert pos >= 0, f"missing {required} after --config in {cmd}"

        san_txt, san_tcp = _sanitize_ovpn_content(
            "client\nproto tcp6-client\nscript-security 2\nup /etc/openvpn/update-resolv-conf\ndown /etc/openvpn/update-resolv-conf\nblock-outside-dns\nncp-disable\nremote 1.2.3.4 443\n"
        )
        assert san_tcp is True and "update-resolv-conf" not in san_txt and "script-security" not in san_txt and "ncp-disable" not in san_txt
        cmd_tcp = mgr._build_ovpn_cmd(3, os.path.join(tmp, "b_tcp.ovpn"), auth2, is_tcp=True)
        assert "--fast-io" not in cmd_tcp and "--mssfix" not in cmd_tcp, cmd_tcp
        fb_cmds = mgr._fallback_host_drop_cmds(3)
        assert len(fb_cmds) == 2 and "--sport" in fb_cmds[0] and "1080" in fb_cmds[0] and "DROP" in fb_cmds[1], fb_cmds

        bare_cfg = os.path.join(tmp, "bare_auth.ovpn")
        with open(bare_cfg, "w", encoding="utf-8") as fh:
            fh.write("client\nauth-user-pass # proton comment\n")
        assert await mgr.start_slot(1, bare_cfg) is False, "expected fail-fast for bare auth-user-pass"

    # 3. _probe_mt_response_ok status rules
    for ok_code in (100, 200, 204, 301, 302, 401, 404, 418):
        assert _probe_mt_response_ok(ok_code) is True, f"expected True for {ok_code}"
    for bad_code in (0, 99, 400, 402, 403, 405, 407, 429, 500, 502, 503):
        assert _probe_mt_response_ok(bad_code) is False, f"expected False for {bad_code}"

    # 4. _parse_target IPv6 bracket validation & privileged port rejection (<= 1024 including 22)
    assert HttpToSocksBridge._parse_target("[::1]:443") == ("::1", 443)
    assert HttpToSocksBridge._parse_target("[2001:db8::1]:8443") == ("2001:db8::1", 8443)
    assert HttpToSocksBridge._parse_target("[not-ipv6]:443") is None
    assert HttpToSocksBridge._parse_target("[example.com]:443") is None
    assert HttpToSocksBridge._parse_target("127.0.0.1:\u00b2") is None

    bridge = HttpToSocksBridge(host="127.0.0.1")
    auth_fn = make_basic_auth_fn("u1", "p1")
    for bad_port in (0, 22, 80, 443, 1024):
        try:
            await bridge.start(bad_port, "127.0.0.1", 1080, auth_fn)
            raise AssertionError(f"port {bad_port} should have been rejected")
        except ValueError:
            pass

    # 5. Live loopback mock TCP echo + mock SOCKS5 + HttpToSocksBridge (407, CONNECT+trailing, 502, re-entry)
    async def handle_echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while data := await reader.read(4096):
                await _send_resp(writer, data.upper())
        finally:
            await _close_writer(writer)

    echo_srv = await asyncio.start_server(handle_echo, "127.0.0.1", 0)
    echo_port = echo_srv.sockets[0].getsockname()[1]

    socks_hits = 0
    socks_fail_mode = False

    async def handle_socks(c_reader: asyncio.StreamReader, c_writer: asyncio.StreamWriter) -> None:
        nonlocal socks_hits
        socks_hits += 1
        t_writer = None
        try:
            greeting = await c_reader.readexactly(2)
            assert greeting[0] == 5, greeting
            methods = await c_reader.readexactly(greeting[1])
            assert 0 in methods, methods
            await _send_resp(c_writer, b"\x05\x00")

            req = await c_reader.readexactly(4)
            assert req[:3] == b"\x05\x01\x00", req
            atyp = req[3]
            if atyp == 1:
                host = str(ipaddress.IPv4Address(await c_reader.readexactly(4)))
            elif atyp == 3:
                ln = (await c_reader.readexactly(1))[0]
                host = (await c_reader.readexactly(ln)).decode("ascii")
            elif atyp == 4:
                host = str(ipaddress.IPv6Address(await c_reader.readexactly(16)))
            else:
                raise AssertionError(f"unexpected atyp {atyp}")
            port = struct.unpack("!H", await c_reader.readexactly(2))[0]

            if socks_fail_mode:
                await _send_resp(c_writer, b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
                return

            t_reader, t_writer = await asyncio.open_connection(host, port)
            await _send_resp(c_writer, b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
            await asyncio.gather(
                _pipe(c_reader, t_writer, close_dst=True),
                _pipe(t_reader, c_writer, close_dst=True),
            )
        except Exception:
            pass
        finally:
            await asyncio.gather(_close_writer(c_writer), _close_writer(t_writer), return_exceptions=True)

    socks_srv = await asyncio.start_server(handle_socks, "127.0.0.1", 0)
    socks_port = socks_srv.sockets[0].getsockname()[1]

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe_sock:
        probe_sock.bind(("127.0.0.1", 0))
        bridge_port = probe_sock.getsockname()[1]

    await bridge.start(bridge_port, "127.0.0.1", socks_port, auth_fn)
    try:
        # 5a. Re-entry start() safety on already running bridge
        await bridge.start(bridge_port, "127.0.0.1", socks_port, auth_fn)

        # 5b. Unauthenticated CONNECT -> 407 before touching SOCKS5
        r, w = await asyncio.open_connection("127.0.0.1", bridge_port)
        await _send_resp(w, f"CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\nHost: 127.0.0.1:{echo_port}\r\n\r\n".encode())
        resp_407 = await r.read(4096)
        w.close()
        assert b"407 Proxy Authentication Required" in resp_407, resp_407
        assert b'Proxy-Authenticate: Basic realm="ufasproxy"' in resp_407, resp_407
        assert socks_hits == 0, f"unauthenticated request touched SOCKS5 {socks_hits} times"

        # 5c. Wrong BasicAuth -> 407 before touching SOCKS5
        bad_tok = base64.b64encode(b"u1:wrong").decode()
        r, w = await asyncio.open_connection("127.0.0.1", bridge_port)
        await _send_resp(
            w,
            f"CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\nProxy-Authorization: Basic {bad_tok}\r\n\r\n".encode(),
        )
        resp_bad = await r.read(4096)
        w.close()
        assert b"407 Proxy Authentication Required" in resp_bad, resp_bad
        assert socks_hits == 0, f"bad-auth request touched SOCKS5 {socks_hits} times"

        # 5d. Valid BasicAuth CONNECT + trailing payload right after \r\n\r\n + bidirectional stream
        good_tok = base64.b64encode(b"u1:p1").decode()
        r, w = await asyncio.open_connection("127.0.0.1", bridge_port)
        await _send_resp(
            w,
            f"CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{echo_port}\r\n"
            f"Proxy-Authorization: Basic {good_tok}\r\n\r\n"
            f"ping-trail\n".encode(),
        )
        hdr = await r.readuntil(b"\r\n\r\n")
        assert hdr.startswith(b"HTTP/1.1 200 Connection Established"), hdr
        echoed1 = await r.readline()
        assert echoed1 == b"PING-TRAIL\n", f"missing/corrupt trailing bytes: {echoed1!r}"
        await _send_resp(w, b"second-msg\n")
        echoed2 = await r.readline()
        assert echoed2 == b"SECOND-MSG\n", echoed2
        w.close()
        assert socks_hits == 1, socks_hits

        # 5e. Authenticated non-CONNECT -> 405, oversized header -> 431
        r, w = await asyncio.open_connection("127.0.0.1", bridge_port)
        await _send_resp(
            w,
            f"GET http://127.0.0.1:{echo_port}/ HTTP/1.1\r\nProxy-Authorization: Basic {good_tok}\r\n\r\n".encode(),
        )
        assert b"405 Method Not Allowed" in await r.read(4096)
        w.close()

        r, w = await asyncio.open_connection("127.0.0.1", bridge_port)
        await _send_resp(
            w,
            b"CONNECT 127.0.0.1:443 HTTP/1.1\r\nX-Pad: " + b"A" * (MAX_HEADER_BYTES + 64) + b"\r\n\r\n",
        )
        assert b"431 Request Header Fields Too Large" in await r.read(4096)
        w.close()

        # 5f. Upstream SOCKS5 failure -> 502 Bad Gateway + probe_socks_mt_api failure handling
        socks_fail_mode = True
        r, w = await asyncio.open_connection("127.0.0.1", bridge_port)
        await _send_resp(
            w,
            f"CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\nProxy-Authorization: Basic {good_tok}\r\n\r\n".encode(),
        )
        resp_502 = await r.read(4096)
        w.close()
        assert b"502 Bad Gateway" in resp_502, resp_502

        ok_probe, rtt_ms, detail = await probe_socks_mt_api("127.0.0.1", socks_port, timeout_s=2.0)
        assert ok_probe is False and rtt_ms >= 0 and detail, (ok_probe, rtt_ms, detail)

        # 5g. Non-blocking HttpToSocksBridge.stop() while an authenticated CONNECT tunnel stays open
        socks_fail_mode = False
        r_open, w_open = await asyncio.open_connection("127.0.0.1", bridge_port)
        try:
            await _send_resp(
                w_open,
                f"CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{echo_port}\r\n"
                f"Proxy-Authorization: Basic {good_tok}\r\n\r\n".encode(),
            )
            assert (await r_open.readuntil(b"\r\n\r\n")).startswith(b"HTTP/1.1 200 Connection Established")
            await _send_resp(w_open, b"keep-open\n")
            assert await r_open.readline() == b"KEEP-OPEN\n"
            t0 = time.monotonic()
            await bridge.stop()
            elapsed = time.monotonic() - t0
            assert elapsed < 2.0, f"bridge.stop() blocked with open CONNECT tunnel ({elapsed:.2f}s)"
            assert bridge._server is None
        finally:
            await _close_writer(w_open)
    finally:
        await bridge.stop()
        assert bridge._server is None
        socks_srv.close()
        echo_srv.close()
        await asyncio.gather(socks_srv.wait_closed(), echo_srv.wait_closed())


async def _http_req(
    host: str,
    port: int,
    method: str,
    path: str,
    token: str | None = None,
    body: object | None = None,
    raw_body: bytes | None = None,
    content_length_override: str | None = None,
) -> tuple[int, dict]:
    reader, writer = await asyncio.open_connection(host, port)
    try:
        payload = raw_body if raw_body is not None else (json.dumps(body).encode("utf-8") if body is not None else b"")
        hdrs = [f"{method} {path} HTTP/1.1", f"Host: {host}:{port}", "Connection: close"]
        if token is not None:
            hdrs.append(f"Authorization: Bearer {token}")
        if body is not None or raw_body is not None or content_length_override is not None:
            hdrs.append("Content-Type: application/json")
            hdrs.append(
                f"Content-Length: {content_length_override if content_length_override is not None else len(payload)}"
            )
        req = ("\r\n".join(hdrs) + "\r\n\r\n").encode("latin-1") + payload
        await _send_resp(writer, req)
        resp = await asyncio.wait_for(reader.read(), timeout=5.0)
        head, _, raw_resp = resp.partition(b"\r\n\r\n")
        status_line = head.split(b"\r\n", 1)[0].decode("latin-1")
        status = int(status_line.split()[1])
        data = json.loads(raw_resp.decode("utf-8")) if raw_resp else {}
        return status, data
    finally:
        await _close_writer(writer)


async def _selftest_gateway_async() -> None:
    # 6. Port validation & CLI rejection (<= 1024, overlap with proxy range, max_slots bounds)
    for bad_port, bad_base, bad_max in (
        (22, 20001, 45),
        (1024, 20001, 45),
        (8080, 22, 45),
        (8080, 1024, 45),
        (20001, 20001, 10),
        (20010, 20001, 10),
        (8080, 20001, 0),
        (8080, 20001, 201),
        (8080, 65530, 10),
    ):
        try:
            validate_gateway_config(bad_port, bad_base, bad_max)
            raise AssertionError(f"expected ValueError for {(bad_port, bad_base, bad_max)}")
        except ValueError:
            pass
    validate_gateway_config(20000, 20001, 10)
    validate_gateway_config(20011, 20001, 10)
    for bad_ttl in (0.0, -1.0, MAX_TTL_S + 1.0, float("nan"), float("inf"), float("-inf")):
        try:
            validate_gateway_config(8080, 20001, 10, bad_ttl)
            raise AssertionError(f"expected ValueError for ttl_s={bad_ttl}")
        except ValueError:
            pass

    # 7. OvpnSlotManager._on_unexpected_exit notification & clean cancellation
    with tempfile.TemporaryDirectory() as tmp_mgr:
        events: list[tuple[int, str]] = []

        async def _on_exit(slot: int, cfg: str) -> None:
            events.append((slot, cfg))

        mgr = OvpnSlotManager(state_dir=tmp_mgr, on_unexpected_exit=_on_exit)

        async def _fake_stop(slot: int) -> None:
            mgr._slots.pop(slot, None)

        mgr.stop_slot = _fake_stop  # type: ignore[method-assign]
        proc = await asyncio.create_subprocess_exec(sys.executable, "-c", "import sys; sys.exit(1)")
        mgr._slots[2] = ("x.ovpn", [proc])
        watcher = asyncio.create_task(mgr._watch_ovpn_exit(2, proc))
        mgr._watchers[2] = watcher
        await watcher
        assert events == [(2, "x.ovpn")], f"expected unexpected exit callback, got {events}"

        # microsocks exit must also trigger unexpected exit teardown
        events.clear()
        ovpn_alive = await asyncio.create_subprocess_exec(sys.executable, "-c", "import time; time.sleep(5)")
        ms_dead = await asyncio.create_subprocess_exec(sys.executable, "-c", "import sys; sys.exit(2)")
        mgr._slots[4] = ("z.ovpn", [ovpn_alive, ms_dead])
        watcher_ms = asyncio.create_task(mgr._watch_ovpn_exit(4, ovpn_alive, ms_dead))
        mgr._watchers[4] = watcher_ms
        await watcher_ms
        if ovpn_alive.returncode is None:
            ovpn_alive.terminate()
            await ovpn_alive.wait()
        assert events == [(4, "z.ovpn")], f"expected microsocks exit callback, got {events}"

        # Unexpected exit callback during clean stop must NOT fire
        events.clear()
        proc2 = await asyncio.create_subprocess_exec(sys.executable, "-c", "import time; time.sleep(2)")
        mgr._slots[3] = ("y.ovpn", [proc2])
        watcher2 = asyncio.create_task(mgr._watch_ovpn_exit(3, proc2))
        mgr._watchers[3] = watcher2
        w_popped = mgr._watchers.pop(3, None)
        if w_popped is not None:
            w_popped.cancel()
            await asyncio.gather(w_popped, return_exceptions=True)
        proc2.terminate()
        await proc2.wait()
        assert events == [], f"unexpected callback fired on clean cancel: {events}"

    # 8. GatewayServer full lifecycle with mocked OvpnSlotManager over real TCP HTTP
    class FakeSlotManager:
        MAX_SLOTS = 200

        def __init__(self, fail_cfgs: set[str] | None = None, delay_s: float = 0.0) -> None:
            self.fail_cfgs = set(fail_cfgs or set())
            self.delay_s = delay_s
            self.active: dict[int, str] = {}
            self.start_calls: list[tuple[int, str]] = []
            self.rotate_calls: list[tuple[int, str]] = []
            self.stopped_batches: list[list[int]] = []
            self.stop_all_calls = 0
            self._inflight = 0
            self.max_inflight = 0
            self._on_unexpected_exit = None

        async def start_slot(self, slot: int, cfg: str) -> bool:
            self._inflight += 1
            self.max_inflight = max(self.max_inflight, self._inflight)
            try:
                self.start_calls.append((slot, os.path.basename(cfg)))
                if self.delay_s:
                    await asyncio.sleep(self.delay_s)
                if os.path.basename(cfg) in self.fail_cfgs:
                    return False
                self.active[slot] = cfg
                return True
            finally:
                self._inflight -= 1

        async def rotate_slot(self, slot: int, cfg: str) -> bool:
            self.rotate_calls.append((slot, os.path.basename(cfg)))
            self.active.pop(slot, None)
            if self.delay_s:
                await asyncio.sleep(self.delay_s)
            if os.path.basename(cfg) in self.fail_cfgs:
                return False
            self.active[slot] = cfg
            return True

        async def stop_slots_batch(self, slots: list[int]) -> None:
            self.stopped_batches.append(list(slots))
            for s in slots:
                self.active.pop(s, None)

        async def stop_slot(self, slot: int) -> None:
            await self.stop_slots_batch([slot])

        async def stop_all(self) -> None:
            self.stop_all_calls += 1
            self.active.clear()

    with tempfile.TemporaryDirectory() as tmp:
        for name in ("a_udp.ovpn", "b_udp.ovpn", "c_udp.ovpn", "d_tcp.ovpn"):
            with open(os.path.join(tmp, name), "w", encoding="utf-8") as fh:
                fh.write("client\n")

        # CLI main() rejects --port <= 1024
        try:
            rc_cli = main(["--ovpn-dir", tmp, "--port", "22"])
            assert rc_cli != 0, "CLI should reject port 22"
        except SystemExit as exc:
            assert exc.code != 0

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_api, socket.socket(
            socket.AF_INET, socket.SOCK_STREAM
        ) as s_proxy:
            s_api.bind(("127.0.0.1", 0))
            s_proxy.bind(("127.0.0.1", 0))
            api_port = s_api.getsockname()[1]
            base_proxy_port = max(21000, (s_proxy.getsockname()[1] // 10) * 10)
            if base_proxy_port <= api_port <= base_proxy_port + 2:
                base_proxy_port += 100

        token = "test-secret-token"
        fake_mgr = FakeSlotManager(fail_cfgs={"a_udp.ovpn"}, delay_s=0.05)
        gw = GatewayServer(
            ovpn_dir=tmp,
            host="127.0.0.1",
            port=api_port,
            token=token,
            base_proxy_port=base_proxy_port,
            max_slots=3,
            public_ip="127.0.0.1",
            ttl_s=180.0,
            slot_manager=fake_mgr,
            reap_interval_s=0.05,
        )
        await gw.start()
        try:
            # 8a. Bearer auth enforcement (401 without/wrong token)
            st, _ = await _http_req("127.0.0.1", api_port, "GET", "/status")
            assert st == 401, f"expected 401 missing auth, got {st}"
            st, _ = await _http_req("127.0.0.1", api_port, "POST", "/lease", token="wrong", body={"count": 1})
            assert st == 401, f"expected 401 wrong token, got {st}"

            # 8a2. HTTP method/route/validation checks (405, 404, malformed Content-Length, NaN/Inf TTL -> 400)
            st, _ = await _http_req("127.0.0.1", api_port, "POST", "/status", token=token, body={})
            assert st == 405, f"expected 405 for POST /status, got {st}"
            st, _ = await _http_req("127.0.0.1", api_port, "GET", "/lease", token=token)
            assert st == 405, f"expected 405 for GET /lease, got {st}"
            st, _ = await _http_req("127.0.0.1", api_port, "GET", "/nonexistent", token=token)
            assert st == 404, f"expected 404 for unknown route, got {st}"
            for bad_cl in ("abc", "-1"):
                st, _ = await _http_req(
                    "127.0.0.1", api_port, "POST", "/lease", token=token, raw_body=b"{}", content_length_override=bad_cl
                )
                assert st == 400, f"expected 400 for Content-Length {bad_cl!r}, got {st}"
            for bad_json in (b'{"count":1,"ttl_s":NaN}', b'{"count":1,"ttl_s":Infinity}'):
                st, _ = await _http_req(
                    "127.0.0.1", api_port, "POST", "/lease", token=token, raw_body=bad_json
                )
                assert st == 400, f"expected 400 for {bad_json!r}, got {st}"
            st, _ = await gw._api_lease({"count": 1, "ttl_s": float("nan")})
            assert st == 400, f"expected 400 for float nan ttl_s, got {st}"
            st_big, _ = await gw._api_lease({"count": 1, "ttl_s": 1e308})
            assert st_big == 400, f"expected 400 for oversized ttl_s, got {st_big}"

            # 8b. POST /lease starts N=2 in parallel, retries on a_udp.ovpn failure, puts it on cooldown
            st, lease1 = await _http_req(
                "127.0.0.1", api_port, "POST", "/lease", token=token, body={"count": 2, "client": "w1"}
            )
            assert st == 200, (st, lease1)
            assert "lease_id" in lease1 and len(lease1["proxies"]) == 2 and lease1["expires_at"] > time.time(), lease1
            assert fake_mgr.max_inflight >= 2, f"expected parallel startup, max_inflight={fake_mgr.max_inflight}"
            assert all(p.startswith("http://") and "@127.0.0.1:" in p for p in lease1["proxies"]), lease1
            assert len(fake_mgr.active) == 2, fake_mgr.active

            # Verify bridge requires BasicAuth (407 when unauthenticated)
            p_port0 = int(lease1["proxies"][0].rsplit(":", 1)[1])
            br_r, br_w = await asyncio.open_connection("127.0.0.1", p_port0)
            await _send_resp(br_w, b"CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n")
            assert b"407 Proxy Authentication Required" in await br_r.read(4096)
            await _close_writer(br_w)

            # 8c. 409 Conflict when requesting more slots than remaining max_slots (3 - 2 = 1 left)
            st, _ = await _http_req(
                "127.0.0.1", api_port, "POST", "/lease", token=token, body={"count": 2}
            )
            assert st == 409, f"expected 409 conflict, got {st}"

            # 8d. GET /status returns active slots and lease metadata
            st, status_data = await _http_req("127.0.0.1", api_port, "GET", "/status", token=token)
            assert st == 200, (st, status_data)
            assert status_data["active_slots"] == 2 and status_data["max_slots"] == 3, status_data
            assert len(status_data["leases"]) == 1 and status_data["leases"][0]["lease_id"] == lease1["lease_id"]

            # 8e. POST /rotate skips cooldown a_udp.ovpn and active configs, picks next unused off-cooldown (d_tcp.ovpn)
            fake_mgr.fail_cfgs.discard("a_udp.ovpn")
            target_proxy = lease1["proxies"][0]
            rot_slot = next(
                s for s, e in gw._leases[lease1["lease_id"]].slots.items() if e.proxy_url == target_proxy
            )
            pre_rot_cfg = gw._leases[lease1["lease_id"]].slots[rot_slot].cfg
            st, rot = await _http_req(
                "127.0.0.1",
                api_port,
                "POST",
                "/rotate",
                token=token,
                body={"lease_id": lease1["lease_id"], "proxy": target_proxy},
            )
            assert st == 200 and rot.get("ok") is True and rot.get("proxy"), (st, rot)
            assert fake_mgr.rotate_calls and fake_mgr.rotate_calls[-1][1] == "d_tcp.ovpn", fake_mgr.rotate_calls

            # 8e2. Stale _handle_unexpected_exit(slot, old_cfg) after /rotate must NOT kill newly rotated slot
            await gw._handle_unexpected_exit(rot_slot, pre_rot_cfg)
            assert gw._cooldowns.get(pre_rot_cfg, 0.0) > time.monotonic(), "rotated-away config not on cooldown"
            rot_entry = gw._leases[lease1["lease_id"]].slots[rot_slot]
            assert rot_entry.alive is True and rot_entry.bridge is not None, rot_entry
            assert os.path.basename(rot_entry.cfg) == "d_tcp.ovpn", rot_entry.cfg
            assert gw._reserved_cfgs.get(rot_slot) == rot_entry.cfg, gw._reserved_cfgs
            chk_r, chk_w = await asyncio.open_connection("127.0.0.1", rot_entry.port)
            await _send_resp(chk_w, b"CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n")
            assert b"407 Proxy Authentication Required" in await chk_r.read(4096)
            await _close_writer(chk_w)

            # 8f. POST /heartbeat extends expires_at
            await asyncio.sleep(0.05)
            st, hb = await _http_req(
                "127.0.0.1", api_port, "POST", "/heartbeat", token=token, body={"lease_id": lease1["lease_id"]}
            )
            assert st == 200 and hb.get("ok") is True and hb["expires_at"] > lease1["expires_at"], (st, hb, lease1)

            # 8f2. Unexpected slot exit closes its bridge & moves config to cooldown cleanly
            dead_slot = next(iter(gw._leases[lease1["lease_id"]].slots.keys()))
            dead_port = gw._leases[lease1["lease_id"]].slots[dead_slot].port
            dead_cfg = gw._leases[lease1["lease_id"]].slots[dead_slot].cfg
            await gw._handle_unexpected_exit(dead_slot, dead_cfg)
            assert gw._cooldowns.get(dead_cfg, 0.0) > time.monotonic(), "unexpected exit config not on cooldown"
            try:
                _, w_dead = await asyncio.open_connection("127.0.0.1", dead_port)
                await _close_writer(w_dead)
                raise AssertionError(f"bridge port {dead_port} still open after unexpected exit")
            except OSError:
                pass

            # 8g. POST /release cleans up bridges and stops slots; second release -> 404
            st, rel = await _http_req(
                "127.0.0.1", api_port, "POST", "/release", token=token, body={"lease_id": lease1["lease_id"]}
            )
            assert st == 200 and rel == {"ok": True, "released": 2}, (st, rel)
            assert len(fake_mgr.active) == 0, fake_mgr.active
            st, _ = await _http_req(
                "127.0.0.1", api_port, "POST", "/release", token=token, body={"lease_id": lease1["lease_id"]}
            )
            assert st == 404, f"expected 404 for unknown lease, got {st}"

            try:
                _, w_closed = await asyncio.open_connection("127.0.0.1", p_port0)
                await _close_writer(w_closed)
                raise AssertionError(f"bridge port {p_port0} still open after release")
            except OSError:
                pass

            # 8h. Partial /lease failure rollback (503 + 0 leaked slots or bridges)
            fake_mgr2 = FakeSlotManager(fail_cfgs={"a_udp.ovpn", "b_udp.ovpn", "d_tcp.ovpn"})
            gw.slot_manager = fake_mgr2
            gw._cooldowns.clear()
            st, _ = await _http_req("127.0.0.1", api_port, "POST", "/lease", token=token, body={"count": 2})
            assert st == 503, f"expected 503 on partial lease failure, got {st}"
            assert len(fake_mgr2.active) == 0, f"leaked active slots on rollback: {fake_mgr2.active}"
            st, status_after_fail = await _http_req("127.0.0.1", api_port, "GET", "/status", token=token)
            assert status_after_fail["active_slots"] == 0 and status_after_fail["leases"] == [], status_after_fail
            for p_offset in range(3):
                try:
                    _, w_leak = await asyncio.open_connection("127.0.0.1", base_proxy_port + p_offset)
                    await _close_writer(w_leak)
                    raise AssertionError(f"leaked bridge on port {base_proxy_port + p_offset}")
                except OSError:
                    pass

            # 8i. TTL expiry triggers background reaper closing bridge + stopping slots
            fake_mgr2.fail_cfgs.clear()
            st, short_lease = await _http_req(
                "127.0.0.1", api_port, "POST", "/lease", token=token, body={"count": 1, "ttl_s": 0.12}
            )
            assert st == 200, (st, short_lease)
            short_port = int(short_lease["proxies"][0].rsplit(":", 1)[1])
            await asyncio.sleep(0.28)
            assert len(fake_mgr2.active) == 0, f"TTL reaper did not stop expired slot: {fake_mgr2.active}"
            st, status_after_ttl = await _http_req("127.0.0.1", api_port, "GET", "/status", token=token)
            assert status_after_ttl["active_slots"] == 0 and status_after_ttl["leases"] == [], status_after_ttl
            try:
                _, w_ttl = await asyncio.open_connection("127.0.0.1", short_port)
                await _close_writer(w_ttl)
                raise AssertionError(f"bridge port {short_port} still open after TTL reap")
            except OSError:
                pass

            # 8j. /rotate fallback proxy match + /rotate vs /release TOCTOU + pending /lease exit + retry budget cap
            gw._cooldowns.clear()
            st, rot_lease = await _http_req(
                "127.0.0.1", api_port, "POST", "/lease", token=token, body={"count": 1}
            )
            assert st == 200, (st, rot_lease)
            rot_lid = rot_lease["lease_id"]
            rot_e = next(iter(gw._leases[rot_lid].slots.values()))
            alt_proxy = f"http://{rot_e.user}:{rot_e.passwd}@localhost:{rot_e.port}/"
            st, rot2 = await _http_req(
                "127.0.0.1", api_port, "POST", "/rotate", token=token, body={"lease_id": rot_lid, "proxy": alt_proxy}
            )
            assert st == 200 and rot2.get("ok") is True, (st, rot2)

            rot_entered = asyncio.Event()
            rot_proceed = asyncio.Event()
            orig_rotate_slot = fake_mgr2.rotate_slot

            async def _paused_rotate(slot: int, cfg: str) -> bool:
                rot_entered.set()
                await rot_proceed.wait()
                return await orig_rotate_slot(slot, cfg)

            fake_mgr2.rotate_slot = _paused_rotate  # type: ignore[method-assign]
            rot_task = asyncio.create_task(
                _http_req(
                    "127.0.0.1",
                    api_port,
                    "POST",
                    "/rotate",
                    token=token,
                    body={"lease_id": rot_lid, "proxy": rot_e.proxy_url},
                )
            )
            await rot_entered.wait()
            rel_task = asyncio.create_task(
                _http_req("127.0.0.1", api_port, "POST", "/release", token=token, body={"lease_id": rot_lid})
            )
            await asyncio.sleep(0.02)
            rot_proceed.set()
            (rot_st, _), (rel_st, _) = await asyncio.gather(rot_task, rel_task)
            assert rel_st == 200 and rot_st == 404, (rel_st, rot_st)
            assert len(fake_mgr2.active) == 0 and gw._reserved_cfgs == {}, (fake_mgr2.active, gw._reserved_cfgs)

            # Pending /lease unexpected exit before sibling finishes -> 503 + clean rollback
            fake_mgr2.rotate_slot = orig_rotate_slot  # type: ignore[method-assign]
            orig_start_slot = fake_mgr2.start_slot
            slot2_release = asyncio.Event()
            started_slots: list[tuple[int, str]] = []

            async def _racy_start(slot: int, cfg: str) -> bool:
                ok = await orig_start_slot(slot, cfg)
                started_slots.append((slot, cfg))
                if len(started_slots) == 2:
                    await slot2_release.wait()
                return ok

            fake_mgr2.start_slot = _racy_start  # type: ignore[method-assign]
            lease_task = asyncio.create_task(
                _http_req("127.0.0.1", api_port, "POST", "/lease", token=token, body={"count": 2})
            )
            while len(started_slots) < 2:
                await asyncio.sleep(0.01)
            await gw._handle_unexpected_exit(*started_slots[0])
            slot2_release.set()
            racy_st, _ = await lease_task
            assert racy_st == 503, f"expected 503 when pending lease slot exited, got {racy_st}"
            assert len(fake_mgr2.active) == 0 and gw._pending_leases == {} and gw._slot_owners == {}, (
                fake_mgr2.active,
                gw._pending_leases,
                gw._slot_owners,
            )

            # Disconnected HTTP client during /lease must rollback committed lease without leaking slots
            fake_mgr2.fail_cfgs.clear()
            fake_mgr2.delay_s = 0.08
            r_drop, w_drop = await asyncio.open_connection("127.0.0.1", api_port)
            drop_body = json.dumps({"count": 1}).encode("utf-8")
            w_drop.write(
                f"POST /lease HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\n"
                f"Content-Type: application/json\r\nContent-Length: {len(drop_body)}\r\nConnection: close\r\n\r\n".encode("ascii")
                + drop_body
            )
            await w_drop.drain()
            await asyncio.sleep(0.02)
            w_drop.close()
            await asyncio.sleep(0.18)
            assert len(fake_mgr2.active) == 0 and gw._slot_owners == {}, (
                f"leaked lease after client disconnect: active={fake_mgr2.active}, owners={gw._slot_owners}"
            )
            fake_mgr2.delay_s = 0.0

            # Retry budget cap: > 8 failing configs stops at MAX_LEASE_ATTEMPTS_PER_SLOT (8)
            with tempfile.TemporaryDirectory() as tmp_cap:
                for i in range(12):
                    with open(os.path.join(tmp_cap, f"cfg_{i:02d}_udp.ovpn"), "w", encoding="utf-8") as fh:
                        fh.write("client\n")
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_cap:
                    s_cap.bind(("127.0.0.1", 0))
                    cap_proxy_port = s_cap.getsockname()[1]
                cap_mgr = FakeSlotManager(fail_cfgs={f"cfg_{i:02d}_udp.ovpn" for i in range(12)})
                gw_cap = GatewayServer(
                    ovpn_dir=tmp_cap,
                    host="127.0.0.1",
                    port=19998 if cap_proxy_port != 19998 else 19997,
                    token=token,
                    base_proxy_port=cap_proxy_port,
                    max_slots=1,
                    public_ip="127.0.0.1",
                    slot_manager=cap_mgr,
                )
                try:
                    cap_st, _ = await gw_cap._api_lease({"count": 1})
                    assert cap_st == 503 and len(cap_mgr.start_calls) == GatewayServer.MAX_LEASE_ATTEMPTS_PER_SLOT, (
                        cap_st,
                        len(cap_mgr.start_calls),
                    )
                    gw_cap._cooldowns.clear()
                    cap_mgr.fail_cfgs.discard("cfg_00_udp.ovpn")
                    cap_st2, cap_lease = await gw_cap._api_lease({"count": 1})
                    assert cap_st2 == 200, (cap_st2, cap_lease)
                    rot_cap_st, _ = await gw_cap._api_rotate(
                        {"lease_id": cap_lease["lease_id"], "proxy": cap_lease["proxies"][0]}
                    )
                    assert rot_cap_st == 503 and len(cap_mgr.rotate_calls) == GatewayServer.MAX_ROTATE_ATTEMPTS, (
                        rot_cap_st,
                        len(cap_mgr.rotate_calls),
                    )
                finally:
                    await gw_cap.stop()
        finally:
            await gw.stop()
            assert fake_mgr.stop_all_calls + (fake_mgr2.stop_all_calls if "fake_mgr2" in locals() else 0) >= 1


def _run_selftest() -> int:
    asyncio.run(_selftest_async())
    asyncio.run(_selftest_gateway_async())
    print("[OK] All self-tests passed!")
    return 0


async def _serve_forever(gw: GatewayServer) -> None:
    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig_name in ("SIGINT", "SIGTERM", "SIGHUP"):
        sig = getattr(signal, sig_name, None)
        if sig is not None:
            with contextlib.suppress(NotImplementedError, ValueError, RuntimeError):
                loop.add_signal_handler(sig, stop_event.set)
    await gw.start()
    try:
        await stop_event.wait()
    finally:
        await gw.stop()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ufasproxy OpenVPN proxy gateway")
    parser.add_argument("--ovpn-dir", default="", help="Directory containing *.ovpn configs and auth.txt")
    parser.add_argument("--host", default="0.0.0.0", help="API & proxy bind address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8080, help="HTTP API port (default: 8080, must be > 1024)")
    parser.add_argument("--token", default="", help="Bearer auth token (env: UFASPROXY_TOKEN; auto-generated if empty)")
    parser.add_argument("--base-proxy-port", type=int, default=20001, help="First slot proxy port (default: 20001)")
    parser.add_argument("--max-slots", type=int, default=45, help="Max concurrent VPN slots 1..200 (default: 45)")
    parser.add_argument("--public-ip", default="", help="Public IP returned in proxy URLs (auto-detected if omitted)")
    parser.add_argument("--ttl-s", type=float, default=180.0, help="Default lease TTL in seconds (default: 180)")
    parser.add_argument("--selftest", action="store_true", help="Run built-in self-tests and exit")
    args = parser.parse_args(argv)

    if args.selftest:
        return _run_selftest()

    if not args.ovpn_dir:
        parser.error("--ovpn-dir is required unless --selftest is specified")

    try:
        validate_gateway_config(args.port, args.base_proxy_port, args.max_slots, args.ttl_s)
    except ValueError as exc:
        parser.error(str(exc))

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    token = args.token.strip() or os.environ.get("UFASPROXY_TOKEN", "").strip()
    auto_token = False
    if not token:
        token = secrets.token_urlsafe(24)
        auto_token = True
    public_ip = args.public_ip.strip() or detect_public_ip()

    try:
        gw = GatewayServer(
            ovpn_dir=args.ovpn_dir,
            host=args.host,
            port=args.port,
            token=token,
            base_proxy_port=args.base_proxy_port,
            max_slots=args.max_slots,
            public_ip=public_ip,
            ttl_s=args.ttl_s,
        )
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    end_port = args.base_proxy_port + args.max_slots - 1
    print(f"[ufasproxy] API listening on http://{args.host}:{args.port} (public_ip={public_ip})")
    print(f"[ufasproxy] Proxy ports: {args.base_proxy_port}..{end_port} | configs: {len(gw._configs)} | ttl: {args.ttl_s:.0f}s")
    if auto_token:
        print(f"[ufasproxy] Generated Bearer token: {token}")
    else:
        print("[ufasproxy] Using configured Bearer token")

    try:
        asyncio.run(_serve_forever(gw))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
