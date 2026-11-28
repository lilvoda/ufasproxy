from fastapi.testclient import TestClient
from induk.app import create_app


def test_backup_restore_preserves_tokens_hits_and_migrate_push(tmp_path):
    d1, d2 = tmp_path / "induk1", tmp_path / "induk2"
    app1 = create_app(db_path=str(d1 / "induk.db"), api_key="k", data_dir=str(d1), repo_dir=str(tmp_path))
    with TestClient(app1) as c1:
        hdr = {"X-API-Key": "k"}
        tok = c1.post("/api/v1/vps", json={"vps_id": "vps-1"}, headers=hdr).json()["agent_token"]
        disp = c1.post(
            "/api/v1/jobs/dispatch",
            json={"vps_ids": ["vps-1"], "mode": "split", "combo_text": "u1:p1"},
            headers=hdr,
        )
        job_id = disp.json()["job_id"]
        c1.post(
            "/api/v1/agent/hits",
            json={"job_id": job_id, "hit_type": "VALID", "lines": ["u1:p1|t|1|n|2026-11-25 00:00:00"]},
            headers={"Authorization": f"Bearer {tok}"},
        )

        with c1.websocket_connect("/ws/agent", headers={"Authorization": f"Bearer {tok}"}) as ws:
            _ = ws.receive_json()  # START
            mig = c1.post("/api/v1/system/migrate-induk", json={"new_induk_url": "http://new-induk:8000"}, headers=hdr)
            assert mig.status_code == 200
            cmd = ws.receive_json()
            assert cmd["command"]["type"] == "SET_INDUK"
            assert cmd["command"]["payload"]["new_induk_url"] == "http://new-induk:8000"

        bundle = c1.get("/api/v1/system/backup", headers=hdr).content

    app2 = create_app(db_path=str(d2 / "induk.db"), api_key="k", data_dir=str(d2), repo_dir=str(tmp_path))
    with TestClient(app2) as c2:
        hdr = {"X-API-Key": "k"}
        r = c2.post(
            "/api/v1/system/restore",
            files={"bundle": ("backup.tar.gz", bundle, "application/gzip")},
            headers=hdr,
        )
        assert r.status_code == 200
        with c2.websocket_connect("/ws/agent", headers={"Authorization": f"Bearer {tok}"}) as ws2:
            assert ws2 is not None
        assert "u1:p1|t" in c2.get(f"/api/v1/results/{job_id}?format=txt", headers=hdr).text
