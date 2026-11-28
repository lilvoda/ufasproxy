import io
import json
import subprocess
import sys
import tarfile
import time
import zipfile
from agent import MuseAgent, _is_pid_alive


def test_reattach_pid_idempotent_cmd_benchmark_and_set_induk(tmp_path):
    env_file = tmp_path / "agent.env"
    env_file.write_text("VPS_ID=vps-1\nINDUK_URL=http://1.1.1.1:8000\nAGENT_TOKEN=t\n")
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])
    try:
        ag = MuseAgent(
            vps_id="vps-1",
            induk_url="http://1.1.1.1:8000",
            token="t",
            work_dir=str(tmp_path),
            env_file=str(env_file),
            ufasproxy_url="http://168.144.36.170:8080",
        )
        ag.save_active_job(
            {
                "pid": proc.pid,
                "job_id": "job-1",
                "output_dir": str(tmp_path / "out"),
                "status_json": str(tmp_path / "st.json"),
                "offsets": {},
            }
        )
        reattached = ag.load_or_reattach_job()
        assert reattached is not None and reattached["pid"] == proc.pid
        assert ag.mark_cmd_seen("cmd-1") is True
        assert ag.mark_cmd_seen("cmd-1") is False

        bench = ag.run_benchmark(duration_s=0.05)
        assert bench["cpu_cores"] >= 1 and bench["recommended_workers"] >= 1

        cmd_gw = ag._build_checker_cmd("c.txt", "out", "st.json", "rot.trig", {"args": ["--workers=6"]})
        assert "--vpn-api-url" in cmd_gw and "http://168.144.36.170:8080" in cmd_gw
        assert "--induk-host" not in cmd_gw
        assert "--workers=6" in cmd_gw and "auto" not in cmd_gw

        # Explicit sync_vpn overrides ufasproxy_url cleanly to use vpns_assigned + --induk-host
        cmd_sync = ag._build_checker_cmd("c.txt", "out", "st.json", "rot.trig", {"sync_vpn": True, "args": []})
        assert "--vpn-ovpn-dir" in cmd_sync and "--induk-host" in cmd_sync and "--vpn-api-url" not in cmd_sync

        ag.apply_new_induk("https://2.2.2.2:8443")
        assert ag.induk_url == "https://2.2.2.2:8443"
        assert "INDUK_URL=https://2.2.2.2:8443" in env_file.read_text()
    finally:
        proc.terminate()
        proc.wait(timeout=5)


def test_tail_new_hits_offset_retry_safe(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    (out / "hit_valid.txt").write_text("u1:p1|t|1|n|2026-11-25 00:00:00\n", encoding="utf-8")
    ag = MuseAgent(vps_id="vps-1", induk_url="http://127.0.0.1:8000", token="t", work_dir=str(tmp_path))
    batch, next_off = ag.tail_new_hits(str(out), {})
    assert len(batch["VALID"]) == 1
    batch_again, _ = ag.tail_new_hits(str(out), {})
    assert len(batch_again["VALID"]) == 1
    batch_empty, _ = ag.tail_new_hits(str(out), next_off)
    assert batch_empty["VALID"] == []


def test_agent_dead_pid_tar_symlink_and_reap(tmp_path):
    ag = MuseAgent(vps_id="vps-1", induk_url="http://127.0.0.1:8000", token="t", work_dir=str(tmp_path))
    st = tmp_path / "status.json"
    st.write_text(json.dumps({"stats": {"status": "RUNNING", "workers_live": 4, "checked": 10, "total": 10}}))
    ag.active_job = {"pid": 9999999, "job_id": "j1", "status_json": str(st), "output_dir": str(tmp_path), "offsets": {}}
    tel = ag.build_telemetry()
    assert tel["agent_state"] == "IDLE" and tel["progress"]["workers_live"] == 0 and tel["progress"]["status"] == "STOPPED"

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        sym = tarfile.TarInfo("vpns-proton/evil")
        sym.type = tarfile.SYMTYPE
        sym.linkname = "/etc/passwd"
        tf.addfile(sym)
        ok = tarfile.TarInfo("vpns-proton/ok.ovpn")
        data = b"client\n"
        ok.size = len(data)
        tf.addfile(ok, io.BytesIO(data))

    ag._http_request = lambda *a, **kw: buf.getvalue()
    dest = ag._sync_vpn_bundle()
    assert (tmp_path / "vpns_assigned" / "vpns-proton" / "ok.ovpn").is_file()
    assert not (tmp_path / "vpns_assigned" / "vpns-proton" / "evil").exists()
    assert dest.endswith("vpns_assigned")

    ag2 = MuseAgent(vps_id="vps-2", induk_url="http://127.0.0.1:8000", token="t", work_dir=str(tmp_path))
    ag2.proc = subprocess.Popen([sys.executable, "-c", "pass"])
    for _ in range(40):
        if not _is_pid_alive(ag2.proc.pid):
            break
        time.sleep(0.05)
    ag2.active_job = {"pid": ag2.proc.pid, "job_id": "j2", "status_json": "", "output_dir": str(tmp_path), "offsets": {}}
    ag2.build_telemetry()
    assert ag2.proc.returncode is not None
    ok_rot, _ = ag2.execute_command({"type": "ROTATE_VPN", "payload": {}})
    assert ok_rot is False

    # Finished output packaging uploads non-empty files once
    out3 = tmp_path / "out_zip"
    out3.mkdir()
    (out3 / "hit_valid.txt").write_text("u:p|t|1|n|2026\n", encoding="utf-8")
    (out3 / "invalid.txt").write_text("x:y|2026\n", encoding="utf-8")
    (out3 / "hit_2fa.txt").write_text("", encoding="utf-8")
    uploaded = []
    ag2._http_request_raw = lambda m, p, data=None, content_type="", timeout=15.0: uploaded.append((p, data)) or b"{}"
    ag2.active_job = {"pid": ag2.proc.pid, "job_id": "job_zip_1", "status_json": "", "output_dir": str(out3), "offsets": {}}
    assert ag2.upload_finished_output_sync() is True
    assert ag2.upload_finished_output_sync() is False
    assert len(uploaded) == 1 and uploaded[0][0] == "/api/v1/agent/output/job_zip_1"
    with zipfile.ZipFile(io.BytesIO(uploaded[0][1]), "r") as zf:
        assert set(zf.namelist()) == {"hit_valid.txt", "invalid.txt"}

    # RESTART must NOT trigger finished output upload for the same job_id
    ag2.active_job = {"pid": ag2.proc.pid, "job_id": "job_restart_1", "status_json": "", "output_dir": str(out3), "offsets": {}, "payload": {"job_id": "job_restart_1"}}
    called_restart = []
    ag2._start_checker = lambda p, upload_prev=True: called_restart.append(upload_prev) or "ok"
    ok_rs, _ = ag2.execute_command({"type": "RESTART", "payload": {}})
    assert ok_rs is True and called_restart == [False]
