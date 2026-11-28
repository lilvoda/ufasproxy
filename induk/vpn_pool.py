"""Multi-folder OpenVPN pool scanner, cross-provider round-robin splitter, and bundle builder."""

from __future__ import annotations

import io
import os
import tarfile
from itertools import zip_longest

_AUTH_NAMES = ("auth.txt", ".auth", "pass.txt", "credentials.txt")


def _find_folder_auth(folder: str) -> str:
    for cand in _AUTH_NAMES:
        ap = os.path.join(folder, cand)
        if os.path.isfile(ap):
            return ap
    for fn in sorted(os.listdir(folder)):
        if fn.lower().endswith(".auth") and os.path.isfile(os.path.join(folder, fn)):
            return os.path.join(folder, fn)
    return ""


def scan_vpn_folders(root_dir: str, folders: list[str] | None = None) -> dict[str, dict]:
    """Scan vpns-* (or requested child folders inside root_dir) and return .ovpn lists + auth path."""
    root = os.path.abspath(root_dir)
    if folders:
        cand_names = [f.strip() for f in folders if f and f.strip()]
    else:
        cand_names = sorted(
            d for d in os.listdir(root)
            if d.startswith("vpns-") and os.path.isdir(os.path.join(root, d))
        ) if os.path.isdir(root) else []

    pool: dict[str, dict] = {}
    for name in cand_names:
        if "/" in name or "\\" in name or name in (".", ".."):
            raise ValueError(f"Invalid folder name: {name!r}")
        folder = os.path.abspath(os.path.join(root, name))
        if os.path.commonpath([root, folder]) != root or folder == root:
            raise ValueError(f"Folder escapes repository root: {name!r}")
        if not os.path.isdir(folder):
            continue
        ovpns = sorted(
            os.path.join(folder, f) for f in os.listdir(folder)
            if f.lower().endswith(".ovpn") and os.path.isfile(os.path.join(folder, f))
        )
        if not ovpns:
            continue
        pool[name] = {"ovpns": ovpns, "auth": _find_folder_auth(folder)}
    return pool


def interleave_and_shard(
    pool: dict[str, dict], vps_ids: list[str]
) -> dict[str, list[tuple[str, str, str]]]:
    """Shard each provider round-robin across vps_ids, then interleave per-VPS entries across providers."""
    targets = [v for v in vps_ids if v]
    if not targets:
        return {}
    per_vps_prov: dict[str, dict[str, list[tuple[str, str, str]]]] = {v: {} for v in targets}
    cursor = 0
    for prov in sorted(pool.keys()):
        info = pool[prov]
        auth = info.get("auth", "")
        for ov in (info.get("ovpns") or []):
            vid = targets[cursor % len(targets)]
            per_vps_prov[vid].setdefault(prov, []).append((prov, ov, auth))
            cursor += 1

    shards: dict[str, list[tuple[str, str, str]]] = {}
    for vid in targets:
        groups = [per_vps_prov[vid][p] for p in sorted(per_vps_prov[vid].keys())]
        interleaved: list[tuple[str, str, str]] = []
        for row in zip_longest(*groups):
            for item in row:
                if item is not None:
                    interleaved.append(item)
        shards[vid] = interleaved
    return shards


def build_vpn_tarball(entries: list[tuple[str, str, str]]) -> bytes:
    """Create gzipped tar preserving safe <provider>/<file>.ovpn and <provider>/<auth>."""
    buf = io.BytesIO()
    added_auth: set[str] = set()
    with tarfile.open(fileobj=buf, mode="w:gz", compresslevel=1) as tf:
        for prov, ovpn_path, auth_path in entries:
            prov_dir = os.path.basename(os.path.normpath(prov))
            if not prov_dir or prov_dir in (".", ".."):
                continue
            arc_ovpn = f"{prov_dir}/{os.path.basename(ovpn_path)}"
            if os.path.isfile(ovpn_path):
                tf.add(ovpn_path, arcname=arc_ovpn)
            if auth_path and prov_dir not in added_auth and os.path.isfile(auth_path):
                tf.add(auth_path, arcname=f"{prov_dir}/{os.path.basename(auth_path)}")
                added_auth.add(prov_dir)
    return buf.getvalue()
