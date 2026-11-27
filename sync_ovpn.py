#!/usr/bin/env python3
"""sync_ovpn.py: Generate missing Proton UDP .ovpn configs without manual downloads."""

from __future__ import annotations

import argparse
import glob
import ipaddress
import json
import os
import re
import sys
import tempfile
import urllib.request
from typing import Any

GLUETUN_PROTON_URL = "https://raw.githubusercontent.com/qdm12/gluetun-servers/main/pkg/servers/protonvpn.json"
PROTON_LOGICALS_URL = "https://account.protonvpn.com/api/vpn/v1/logicals"
PROTON_PORTS = (1194, 5060, 4569, 51820, 80)


def _is_ipv4(val: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(val.strip()), ipaddress.IPv4Address)
    except ValueError:
        return False


def extract_proton_cert_tail(sample_dirs: list[str], template_path: str = "") -> str:
    """Extract Proton <ca>...</ca> and <tls-crypt>...</tls-crypt> blocks from existing .ovpn."""
    candidates: list[str] = [template_path] if template_path else []
    for d in sample_dirs:
        if os.path.isdir(d):
            candidates.extend(sorted(glob.glob(os.path.join(d, "*.ovpn"))))
    for fp in candidates:
        if not fp or not os.path.isfile(fp):
            continue
        txt = open(fp, "r", encoding="utf-8", errors="replace").read()
        idx = txt.find("<ca>")
        if idx >= 0 and "<tls-crypt>" in txt[idx:]:
            return txt[idx:].rstrip() + "\n"
    raise FileNotFoundError("No Proton .ovpn template containing <ca> and <tls-crypt> found")


def scan_existing_proton(dirs: list[str]) -> tuple[set[str], set[tuple[str, str]]]:
    """Return existing (entry_ips, (entry_ip, b_label)) across all Proton .ovpn dirs."""
    ips: set[str] = set()
    pairs: set[tuple[str, str]] = set()
    for d in dirs:
        if not os.path.isdir(d):
            continue
        for fp in glob.glob(os.path.join(d, "*.ovpn")):
            txt = open(fp, "r", encoding="utf-8", errors="replace").read()
            m_b = re.search(r"\+(b:\d+)\b", txt)
            lbl = m_b.group(1) if m_b else ""
            for ip in re.findall(r"(?m)^remote\s+(\S+)", txt):
                if _is_ipv4(ip):
                    ips.add(ip)
                    pairs.add((ip, lbl))
    return ips, pairs


def build_proton_udp_ovpn(ip: str, cert_tail: str, b_label: str = "", server_name: str = "") -> str:
    """Build standard Proton UDP .ovpn config with optional +b:N exit-circuit comment."""
    lines: list[str] = []
    if b_label:
        lbl_tag = b_label if b_label.startswith("b:") else f"b:{b_label}"
        srv_lbl = server_name or ip
        lines.append(f'# Please use "proton+{lbl_tag}" in order to enforce exiting through {srv_lbl}.')
    lines.extend(["client", "dev tun", "proto udp"])
    for p in PROTON_PORTS:
        lines.append(f"remote {ip} {p}")
    lines.extend([
        "remote-random",
        "resolv-retry infinite",
        "nobind",
        "cipher AES-256-GCM",
        "setenv CLIENT_CERT 0",
        "tun-mtu 1500",
        "mssfix 0",
        "persist-key",
        "persist-tun",
        "reneg-sec 0",
        "remote-cert-tls server",
        "auth-user-pass",
        cert_tail.rstrip(),
    ])
    return "\n".join(lines) + "\n"


def _slug(val: str) -> str:
    return re.sub(r"[^a-z0-9-]+", "-", val.lower().replace("#", "-")).strip("-") or "node"


def sync_from_gluetun(
    data: dict[str, Any],
    out_dir: str,
    cert_tail: str,
    existing_ips: set[str],
    include_free: bool = True,
) -> int:
    """Generate missing Proton UDP IPv4 .ovpn configs from gluetun servers JSON."""
    os.makedirs(out_dir, exist_ok=True)
    added = 0
    seen = set(existing_ips)
    for srv in data.get("servers", []):
        if srv.get("vpn", "openvpn") != "openvpn" or not srv.get("udp"):
            continue
        if srv.get("tor") or srv.get("secure_core"):
            continue
        if not include_free and srv.get("free"):
            continue
        sname = str(srv.get("server_name") or srv.get("hostname") or "proton")
        slug = _slug(sname)
        for ip in srv.get("ips") or []:
            if not _is_ipv4(ip) or ip in seen:
                continue
            seen.add(ip)
            fname = f"{slug}-{ip.replace('.', '-')}.protonvpn.udp.ovpn"
            with open(os.path.join(out_dir, fname), "w", encoding="utf-8", newline="\n") as fh:
                fh.write(build_proton_udp_ovpn(ip, cert_tail, server_name=sname))
            added += 1
    return added


def sync_from_logicals(
    data: dict[str, Any],
    out_dir: str,
    cert_tail: str,
    existing_pairs: set[tuple[str, str]],
    max_tier: int = 2,
) -> int:
    """Generate missing Proton UDP IPv4 .ovpn configs from Proton LogicalServers JSON."""
    os.makedirs(out_dir, exist_ok=True)
    added = 0
    seen = set(existing_pairs)
    for ls in data.get("LogicalServers", []):
        if ls.get("Status") != 1:
            continue
        feat = int(ls.get("Features") or 0)
        if feat & 1 or feat & 2:  # Skip Secure Core (1) and Tor (2)
            continue
        if int(ls.get("Tier") or 0) > max_tier:
            continue
        sname = str(ls.get("Name") or "node")
        slug = _slug(sname)
        for ps in ls.get("Servers", []):
            if ps.get("Status") != 1:
                continue
            ip = str(ps.get("EntryIP") or "").strip()
            if not _is_ipv4(ip):
                continue
            raw_lbl = str(ps.get("Label") or "").strip()
            lbl = f"b:{raw_lbl}" if raw_lbl and not raw_lbl.startswith("b:") else raw_lbl
            key = (ip, lbl)
            if key in seen:
                continue
            seen.add(key)
            suffix = f"-{raw_lbl}" if raw_lbl else ""
            fname = f"{slug}{suffix}-{ip.replace('.', '-')}.protonvpn.udp.ovpn"
            with open(os.path.join(out_dir, fname), "w", encoding="utf-8", newline="\n") as fh:
                fh.write(build_proton_udp_ovpn(ip, cert_tail, b_label=lbl, server_name=sname))
            added += 1
    return added


def _fetch_json(url: str, headers: dict[str, str] | None = None) -> dict[str, Any]:
    hdrs = {"User-Agent": "curl/8.0"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs)
    with urllib.request.urlopen(req, timeout=25) as r:
        return json.loads(r.read().decode("utf-8"))


def _selftest() -> int:
    sample_tail = "<ca>\nCERT\n</ca>\n<tls-crypt>\nKEY\n</tls-crypt>\n"
    with tempfile.TemporaryDirectory() as td:
        ex_dir = os.path.join(td, "existing")
        out_dir = os.path.join(td, "out")
        os.makedirs(ex_dir)
        with open(os.path.join(ex_dir, "nl-01.protonvpn.udp.ovpn"), "w", encoding="utf-8") as fh:
            fh.write('# Please use "u+b:1"\nclient\nremote 1.1.1.1 1194\n' + sample_tail)
        tail = extract_proton_cert_tail([ex_dir])
        assert "<ca>" in tail and "<tls-crypt>" in tail
        ex_ips, ex_pairs = scan_existing_proton([ex_dir])
        assert ex_ips == {"1.1.1.1"} and ("1.1.1.1", "b:1") in ex_pairs

        gl_data = {
            "servers": [
                {"vpn": "openvpn", "udp": True, "server_name": "CA#1", "ips": ["1.1.1.1", "2.2.2.2", "2001:db8::1"]},
                {"vpn": "openvpn", "udp": True, "tor": True, "server_name": "US-TOR#1", "ips": ["3.3.3.3"]},
                {"vpn": "wireguard", "udp": True, "server_name": "WG#1", "ips": ["4.4.4.4"]},
            ]
        }
        added_g = sync_from_gluetun(gl_data, out_dir, tail, ex_ips)
        assert added_g == 1, added_g
        assert os.path.isfile(os.path.join(out_dir, "ca-1-2-2-2-2.protonvpn.udp.ovpn"))

        lg_data = {
            "LogicalServers": [
                {
                    "Name": "NL#99", "Status": 1, "Tier": 2, "Features": 0,
                    "Servers": [
                        {"Status": 1, "EntryIP": "1.1.1.1", "Label": "1"},  # duplicate (1.1.1.1, b:1)
                        {"Status": 1, "EntryIP": "1.1.1.1", "Label": "5"},  # new exit circuit on same EntryIP!
                    ],
                },
                {"Name": "TOR#1", "Status": 1, "Tier": 2, "Features": 2, "Servers": [{"Status": 1, "EntryIP": "8.8.8.8", "Label": "0"}]},
            ]
        }
        added_l = sync_from_logicals(lg_data, out_dir, tail, ex_pairs)
        assert added_l == 1, added_l
        gen_txt = open(os.path.join(out_dir, "nl-99-5-1-1-1-1.protonvpn.udp.ovpn"), encoding="utf-8").read()
        assert "+b:5" in gen_txt and "remote 1.1.1.1 1194" in gen_txt
    print("[OK] sync_ovpn self-tests passed!")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Auto-generate missing Proton UDP .ovpn configs")
    p.add_argument("--out-dir", default="/root/ufasvpn/vpns-proton", help="Target directory for new .ovpn files")
    p.add_argument("--existing-dir", action="append", default=[], help="Extra dir(s) to check for duplicate IPs/certs")
    p.add_argument("--template", default="", help="Optional .ovpn file to extract <ca>/<tls-crypt> from")
    p.add_argument("--logicals-json", default="", help="Optional path to Proton LogicalServers JSON file")
    p.add_argument("--proton-uid", default=os.environ.get("PROTON_UID", ""), help="Optional Proton x-pm-uid header")
    p.add_argument("--proton-cookie", default=os.environ.get("PROTON_COOKIE", ""), help="Optional Proton Cookie header")
    p.add_argument("--appversion", default="web-vpn-settings@5.0.0", help="x-pm-appversion header for Proton API")
    p.add_argument("--max-tier", type=int, default=2, help="Max Proton server tier for logicals (0=Free, 2=Plus)")
    p.add_argument("--selftest", action="store_true", help="Run built-in self-tests and exit")
    args = p.parse_args(argv)

    if args.selftest:
        return _selftest()

    all_dirs = [args.out_dir, *args.existing_dir]
    tail = extract_proton_cert_tail(all_dirs, args.template)
    ex_ips, ex_pairs = scan_existing_proton(all_dirs)

    if args.logicals_json:
        data = json.load(open(args.logicals_json, "r", encoding="utf-8"))
        added = sync_from_logicals(data, args.out_dir, tail, ex_pairs, max_tier=args.max_tier)
        src = args.logicals_json
    elif args.proton_uid and args.proton_cookie:
        data = _fetch_json(
            PROTON_LOGICALS_URL,
            headers={
                "x-pm-uid": args.proton_uid.strip(),
                "Cookie": args.proton_cookie.strip(),
                "x-pm-appversion": args.appversion,
                "Accept": "application/vnd.protonmail.v1+json",
            },
        )
        added = sync_from_logicals(data, args.out_dir, tail, ex_pairs, max_tier=args.max_tier)
        src = "Proton API logicals"
    else:
        data = _fetch_json(GLUETUN_PROTON_URL)
        added = sync_from_gluetun(data, args.out_dir, tail, ex_ips)
        src = "gluetun-servers protonvpn.json"

    print(f"[OK] Added {added} new Proton UDP .ovpn configs into {args.out_dir} (source: {src})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
