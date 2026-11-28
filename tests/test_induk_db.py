import asyncio
import pytest
from induk.db import IndukDB


@pytest.mark.asyncio
async def test_wal_and_concurrent_writes(tmp_path):
    db = IndukDB(str(tmp_path / "induk.db"))
    await db.init()
    assert (await db.wal_mode()).lower() == "wal"
    await db.register_node("vps-1", "VPS 1", 4, "tok-1")
    await db.create_job("job-a", "split", {})
    await asyncio.gather(
        *[
            db.update_telemetry("vps-1", {"agent_state": "RUNNING", "progress": {"checked": i, "total": 100}})
            for i in range(25)
        ],
        *[
            db.insert_hits("job-a", "vps-1", "VALID", [f"u{i}:p{i}|tok|1|n|2026-11-25 00:00:00"])
            for i in range(25)
        ],
    )
    hits = await db.export_hits("job-a", "VALID", dedup="per_job")
    assert len(hits) == 25


@pytest.mark.asyncio
async def test_command_ack_and_per_job_dedup(tmp_path):
    db = IndukDB(str(tmp_path / "induk.db"))
    await db.init()
    await db.register_node("vps-1", "VPS 1", 4, "secret-token")
    assert await db.verify_agent_token("secret-token") == "vps-1"
    assert await db.verify_agent_token("wrong") is None
    cmd = await db.enqueue_command("vps-1", "START", {"workers": 4})
    assert [c["cmd_id"] for c in await db.get_unacked_commands("vps-1")] == [cmd["cmd_id"]]
    await db.mark_delivered([cmd["cmd_id"]])
    assert len(await db.get_unacked_commands("vps-1")) == 1
    assert await db.ack_command("vps-1", cmd["cmd_id"], ok=True, message="started")
    assert await db.get_unacked_commands("vps-1") == []

    await db.create_job("job-1", "split", {})
    await db.create_job("job-2", "split", {})
    ins1, _ = await db.insert_hits("job-1", "vps-1", "VALID", ["a@b.com:123|x", "a@b.com:123|x"])
    ins2, _ = await db.insert_hits("job-2", "vps-1", "VALID", ["a@b.com:123|x"])
    assert (ins1, ins2) == (1, 1)
    assert len(await db.export_hits(None, "VALID", dedup="global")) == 1
