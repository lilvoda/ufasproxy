from fastapi.testclient import TestClient
from induk.app import create_app


def test_static_ui_and_full_dispatch_hit_flow(tmp_path):
    (tmp_path / "vpns-proton").mkdir()
    (tmp_path / "vpns-proton" / "p1.ovpn").write_text("client\n")
    (tmp_path / "vpns-proton" / "auth.txt").write_text("u\np\n")

    app = create_app(db_path=str(tmp_path / "induk.db"), api_key="k", data_dir=str(tmp_path), repo_dir=str(tmp_path))
    with TestClient(app) as client:
        assert client.get("/").status_code == 200
        assert client.get("/static/app.js").status_code == 200
        assert client.get("/static/styles.css").status_code == 200
        hdr = {"X-API-Key": "k"}
        tok = client.post("/api/v1/vps", json={"vps_id": "vps-1"}, headers=hdr).json()["agent_token"]

        with client.websocket_connect("/ws/agent", headers={"Authorization": f"Bearer {tok}"}) as ws:
            disp = client.post(
                "/api/v1/jobs/dispatch",
                json={"vps_ids": ["vps-1"], "mode": "split", "combo_text": "u1:p1\nu2:p2", "args": []},
                headers=hdr,
            )
            assert disp.status_code == 200
            job_id = disp.json()["job_id"]
            assert ws.receive_json()["command"]["type"] == "START"
            assert "u1:p1" in client.get(f"/api/v1/agent/combo/{job_id}/vps-1", headers={"Authorization": f"Bearer {tok}"}).text
            assert (
                client.post(
                    "/api/v1/agent/hits",
                    json={"job_id": job_id, "hit_type": "VALID", "lines": ["u1:p1|tok|1|Hero|2026-11-25 00:00:00"]},
                    headers={"Authorization": f"Bearer {tok}"},
                ).json()["inserted"]
                == 1
            )

        assert "u1:p1|tok" in client.get(f"/api/v1/results/{job_id}?hit_type=VALID&format=txt", headers=hdr).text
