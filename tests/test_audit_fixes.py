from fastapi.testclient import TestClient
from induk.app import create_app


def test_dispatch_validates_args_ufasproxy_flags_and_ghost_provision(tmp_path):
    app = create_app(db_path=str(tmp_path / "induk.db"), api_key="k", data_dir=str(tmp_path))
    with TestClient(app) as client:
        hdr = {"X-API-Key": "k"}
        client.post("/api/v1/vps", json={"vps_id": "vps-1"}, headers=hdr)

        # Allowed gateway URL flag passes cleanly
        r_ok = client.post(
            "/api/v1/jobs/dispatch",
            json={
                "vps_ids": ["vps-1"],
                "mode": "split",
                "combo_text": "a:b",
                "args": ["--vpn-api-url", "http://168.144.36.170:8080"],
            },
            headers=hdr,
        )
        assert r_ok.status_code == 200

        # Invalid URL scheme or disallowed token/shell flags rejected
        for bad_args in (
            ["--vpn-cmd", "rm -rf /"],
            ["--vpn-api-token", "secret-should-stay-in-token-env"],
            ["--vpn-api-url", "ftp://bad"],
            ["--vpn-api-url"],
            ["--workers", "999"],
            ["positional-arg"],
        ):
            r_bad = client.post(
                "/api/v1/jobs/dispatch",
                json={"vps_ids": ["vps-1"], "mode": "split", "combo_text": "a:b", "args": bad_args},
                headers=hdr,
            )
            assert r_bad.status_code == 400, bad_args

        # Single-use UI WS ticket works without sending X-API-Key in query string
        tkt = client.post("/api/v1/ui/ws-ticket", headers=hdr).json()["ticket"]
        with client.websocket_connect(f"/ws/ui?ticket={tkt}") as ws_ui:
            assert ws_ui.receive_json()["type"] == "snapshot"
        try:
            with client.websocket_connect(f"/ws/ui?ticket={tkt}"):
                raise AssertionError("reused ticket must fail")
        except Exception:
            pass

        # Dot-segment traversal ids rejected everywhere
        for bad_vid in ("../evil", "..", "."):
            assert client.post("/api/v1/vps", json={"vps_id": bad_vid}, headers=hdr).status_code in (400, 422)
        assert client.delete("/api/v1/vps/bad..id", headers=hdr).status_code == 422

        r_empty_11 = client.post(
            "/api/v1/jobs/dispatch",
            json={"vps_ids": ["vps-1"], "mode": "per_vps", "per_vps_combos": {"vps-1": "   "}},
            headers=hdr,
        )
        assert r_empty_11.status_code == 400

        r_ghost = client.post(
            "/api/v1/vps/provision",
            json={"vps_id": "ghost-vps", "mode": "ssh", "host": ""},
            headers=hdr,
        )
        assert r_ghost.status_code == 400
        ids = [n["vps_id"] for n in client.get("/api/v1/vps", headers=hdr).json()["nodes"]]
        assert "ghost-vps" not in ids

        r_unk_vpn = client.post(
            "/api/v1/vpn/distribute",
            json={"vps_ids": ["unknown-vps"]},
            headers=hdr,
        )
        assert r_unk_vpn.status_code == 404

        r_trav = client.post("/api/v1/vps", json={"vps_id": "../evil"}, headers=hdr)
        assert r_trav.status_code in (400, 422)

        r_bad_cmd = client.post(
            "/api/v1/commands/bulk",
            json={"vps_ids": ["vps-1"], "type": "DROP_TABLE"},
            headers=hdr,
        )
        assert r_bad_cmd.status_code == 400

        r_unk_cmd = client.post(
            "/api/v1/commands/bulk",
            json={"vps_ids": ["no-such-vps"], "type": "STOP"},
            headers=hdr,
        )
        assert r_unk_cmd.status_code == 404
