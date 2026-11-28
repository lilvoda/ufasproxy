from fastapi.testclient import TestClient
from induk.app import create_app


def test_auth_rate_limit(tmp_path):
    app = create_app(db_path=str(tmp_path / "rl.db"), api_key="admin-key", data_dir=str(tmp_path))
    with TestClient(app) as client:
        for _ in range(10):
            assert client.get("/api/v1/vps", headers={"X-API-Key": "bad"}).status_code == 401
        assert client.get("/api/v1/vps", headers={"X-API-Key": "bad"}).status_code == 429


def test_health_and_ws_reconnect_flush(tmp_path):
    app = create_app(db_path=str(tmp_path / "induk.db"), api_key="admin-key", data_dir=str(tmp_path))
    with TestClient(app) as client:
        r = client.get("/api/v1/health")
        assert r.status_code == 200 and r.json()["db"] == "wal"

        hdr = {"X-API-Key": "admin-key"}
        created = client.post("/api/v1/vps", json={"vps_id": "vps-1", "name": "VPS 1", "default_workers": 4}, headers=hdr)
        assert created.status_code == 201
        agent_tok = created.json()["agent_token"]

        blk = client.post(
            "/api/v1/commands/bulk",
            json={"vps_ids": ["vps-1"], "type": "START", "payload": {"workers": 4}},
            headers=hdr,
        )
        assert blk.status_code == 200
        cmd_id = blk.json()["queued"][0]["cmd_id"]

        with client.websocket_connect("/ws/agent", headers={"Authorization": f"Bearer {agent_tok}"}) as ws:
            msg = ws.receive_json()
            assert msg["type"] == "command" and msg["command"]["cmd_id"] == cmd_id
            ws.send_json({"type": "cmd_ack", "cmd_id": cmd_id, "ok": True, "message": "ok"})
            ws.send_json(
                {
                    "type": "telemetry",
                    "agent_state": "RUNNING",
                    "progress": {"checked": 5, "total": 10},
                    "log_tail": ["l"] * 80,
                }
            )
            ws.send_json({"type": "ping"})
            assert ws.receive_json()["type"] == "pong"

        assert (
            client.get("/api/v1/agent/pending-commands", headers={"Authorization": f"Bearer {agent_tok}"}).json()[
                "commands"
            ]
            == []
        )
        nodes = client.get("/api/v1/vps", headers=hdr).json()["nodes"]
        assert nodes[0]["telemetry"]["log_tail"] and len(nodes[0]["telemetry"]["log_tail"]) <= 50
