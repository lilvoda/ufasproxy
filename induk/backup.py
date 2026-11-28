"""WAL-safe online backup and restore for portable Induk migration."""

from __future__ import annotations

import io
import os
import shutil
import tarfile
import tempfile

from induk.db import IndukDB


def _safe_extract_tar(tar_bytes: bytes, dest_dir: str) -> None:
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tf:
        safe_members: list[tarfile.TarInfo] = []
        for member in tf.getmembers():
            norm = os.path.normpath(member.name)
            if norm.startswith("..") or os.path.isabs(norm) or norm == ".":
                raise ValueError(f"Unsafe archive path: {member.name}")
            if not (member.isreg() or member.isdir()):
                raise ValueError(f"Unsafe archive entry type: {member.name}")
            member.mode &= 0o777
            safe_members.append(member)
        tf.extractall(dest_dir, members=safe_members)


async def export_induk_bundle(db: IndukDB, data_dir: str) -> bytes:
    """Create .tar.gz bundle containing consistent SQLite backup + jobs + vpn_pool."""
    buf = io.BytesIO()
    with tempfile.TemporaryDirectory() as tmpd:
        snap_db = os.path.join(tmpd, "induk.db")
        await db.backup_to(snap_db)
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            tf.add(snap_db, arcname="induk.db")
            for sub in ("jobs", "vpn_pool"):
                sp = os.path.join(data_dir, sub)
                if os.path.isdir(sp):
                    tf.add(sp, arcname=sub)
    return buf.getvalue()


async def restore_induk_bundle(tar_bytes: bytes, data_dir: str, db: IndukDB) -> dict:
    """Safely validate and restore backup .tar.gz into data_dir atomically under db lock."""
    os.makedirs(data_dir, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmpd:
        _safe_extract_tar(tar_bytes, tmpd)
        restored_db = os.path.join(tmpd, "induk.db")
        if not os.path.isfile(restored_db):
            raise ValueError("Invalid backup bundle: missing induk.db")

        await db.replace_from_file(restored_db)

        for sub in ("jobs", "vpn_pool"):
            src = os.path.join(tmpd, sub)
            dst = os.path.join(data_dir, sub)
            if os.path.isdir(src):
                shutil.rmtree(dst, ignore_errors=True)
                shutil.copytree(src, dst)

    nodes, _ = await db.list_nodes()
    return {"ok": True, "restored_nodes": len(nodes)}
