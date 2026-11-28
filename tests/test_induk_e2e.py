import io
import zipfile
from fastapi.testclient import TestClient
import induk.app as app_mod
from induk.app import create_app


def test_static_ui_and_full_dispatch_hit_flow(tmp_path):
    (tmp_path / "vpns-proton").mkdir()
    (tmp_path / "vpns-proton" / "p1.ovpn").write_text("client\n")
    (tmp_path / "vpns-proton" / "auth.txt").write_text("u\np\n")

    app = create_app(db_path=str(tmp_path / "induk.db"), api_key="k", data_dir=str(tmp_path), repo_dir=str(tmp_path))
    with TestClient(app) as client:
        html = client.get("/").text
        assert "run-workers" in html and "run-two-tab" in html
        assert "download-zip-btn" in html and "send-tg-btn" in html
        assert "prov-induk-url" not in html and "prov-ptr-url" not in html
        assert "smart-panel" not in html and "Rotate VPN" not in html
        assert client.get("/static/app.js").status_code == 200
        assert client.get("/static/styles.css").status_code == 200
        hdr = {"X-API-Key": "k"}
        tok = client.post("/api/v1/vps", json={"vps_id": "vps-1"}, headers=hdr).json()["agent_token"]

        with client.websocket_connect("/ws/agent", headers={"Authorization": f"Bearer {tok}"}) as ws:
            disp = client.post(
                "/api/v1/jobs/dispatch",
                json={
                    "vps_ids": ["vps-1"],
                    "mode": "split",
                    "combo_text": "u1:p1\nu2:p2",
                    "workers": "auto",
                    "two_tab": False,
                    "filename": "arch1.txt",
                    "args": [],
                },
                headers=hdr,
            )
            assert disp.status_code == 200
            job_id = disp.json()["job_id"]
            start_cmd = ws.receive_json()["command"]
            assert start_cmd["type"] == "START"
            assert "--no-two-tab" in start_cmd["payload"]["args"]
            assert "--workers" in start_cmd["payload"]["args"] and "auto" in start_cmd["payload"]["args"]
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


def test_job_output_zip_and_telegram_auto_and_manual_send(tmp_path, monkeypatch):
    tg_calls = []

    def _fake_tg(tok, chat, fn, data, cap):
        tg_calls.append((tok, chat, fn, data, cap))
        return {"ok": True}

    monkeypatch.setattr(app_mod, "_send_telegram_zip_sync", _fake_tg)
    app = create_app(
        db_path=str(tmp_path / "z.db"),
        api_key="k",
        data_dir=str(tmp_path),
        repo_dir=str(tmp_path),
        tg_token="bot-tok",
        tg_chat_id="chat-1",
    )
    with TestClient(app) as client:
        hdr = {"X-API-Key": "k"}
        tok = client.post("/api/v1/vps", json={"vps_id": "vps-1"}, headers=hdr).json()["agent_token"]
        disp = client.post(
            "/api/v1/jobs/dispatch",
            json={
                "vps_ids": ["vps-1"],
                "combo_text": "u1:p1\nu2:p2",
                "workers": "6",
                "two_tab": True,
                "filename": "koi_batch.txt",
            },
            headers=hdr,
        )
        assert disp.status_code == 200
        job_id = disp.json()["job_id"]

        # Disallowed path inside output zip rejected
        bad_buf = io.BytesIO()
        with zipfile.ZipFile(bad_buf, "w") as zf:
            zf.writestr("../evil.txt", "x")
        assert (
            client.post(
                f"/api/v1/agent/output/{job_id}",
                content=bad_buf.getvalue(),
                headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/zip"},
            ).status_code
            == 400
        )

        # Valid output zip triggers auto Telegram sendDocument once all expected VPS upload
        ok_buf = io.BytesIO()
        with zipfile.ZipFile(ok_buf, "w") as zf:
            zf.writestr("hit_valid.txt", "u1:p1|tok|1|Hero|2026-11-28 00:00:00\n")
            zf.writestr("invalid.txt", "u2:p2|2026-11-28 00:00:00\n")
        up = client.post(
            f"/api/v1/agent/output/{job_id}",
            content=ok_buf.getvalue(),
            headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/zip"},
        )
        assert up.status_code == 200 and up.json()["tg_auto_sent"] is True
        assert len(tg_calls) == 1 and tg_calls[0][2] == f"koi_batch_{job_id}.zip"

        # Download zip returns merged results + summary.txt
        zres = client.get(f"/api/v1/results/{job_id}/zip", headers=hdr)
        assert zres.status_code == 200
        with zipfile.ZipFile(io.BytesIO(zres.content), "r") as zf:
            names = set(zf.namelist())
            assert {"summary.txt", "hit_valid.txt", "invalid.txt"}.issubset(names)
            assert "u1:p1|tok" in zf.read("hit_valid.txt").decode("utf-8")

        # Manual Telegram resend works & job list reflects tg_sent
        assert client.post(f"/api/v1/results/{job_id}/telegram", headers=hdr).status_code == 200
        assert len(tg_calls) == 2
        jobs = client.get("/api/v1/jobs", headers=hdr).json()["jobs"]
        assert jobs[0]["job_id"] == job_id and jobs[0]["tg_sent"] is True and jobs[0]["filename"] == "koi_batch"

        # Unassigned VPS rejected on agent output upload (403)
        tok2 = client.post("/api/v1/vps", json={"vps_id": "vps-2"}, headers=hdr).json()["agent_token"]
        assert (
            client.post(
                f"/api/v1/agent/output/{job_id}",
                content=ok_buf.getvalue(),
                headers={"Authorization": f"Bearer {tok2}", "Content-Type": "application/zip"},
            ).status_code
            == 403
        )

        # Oversized / newline heredoc breakout rejected cleanly with zero DB side effects
        bad_boot = client.post(
            "/api/v1/vps/provision",
            json={"vps_id": "vps-3", "mode": "bootstrap", "induk_url": "http://ok\nUFP_ENV\nid"},
            headers=hdr,
        )
        assert bad_boot.status_code == 400
        assert "vps-3" not in [n["vps_id"] for n in client.get("/api/v1/vps", headers=hdr).json()["nodes"]]

        # Manual job started locally on worker is registerable and auto-zips + sends to Telegram
        r_reg = client.post(
            "/api/v1/agent/register-job",
            json={"job_id": "manual_999_ab", "filename": "local_combo.txt"},
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert r_reg.status_code == 200
        man_buf = io.BytesIO()
        with zipfile.ZipFile(man_buf, "w") as zf:
            zf.writestr("hit_2fa.txt", "u3:p3|a@b.com|2026-11-28\n")
        man_up = client.post(
            "/api/v1/agent/output/manual_999_ab",
            content=man_buf.getvalue(),
            headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/zip"},
        )
        assert man_up.status_code == 200 and man_up.json()["tg_auto_sent"] is True
        assert tg_calls[-1][2] == "local_combo_manual_999_ab.zip"

        # Combined checked-VPS output merges both vps-1 & vps-2 into ONE zip + Telegram send
        client.post(
            "/api/v1/agent/register-job",
            json={"job_id": "manual_888_cd", "filename": "other.txt"},
            headers={"Authorization": f"Bearer {tok2}"},
        )
        buf2 = io.BytesIO()
        with zipfile.ZipFile(buf2, "w") as zf:
            zf.writestr("hit_valid.txt", "u9:p9|tok|9|Mage|2026-11-28\n")
            zf.writestr("err.txt", "u0:p0|Timeout|2026-11-28\n")
        assert (
            client.post(
                "/api/v1/agent/output/manual_888_cd",
                content=buf2.getvalue(),
                headers={"Authorization": f"Bearer {tok2}", "Content-Type": "application/zip"},
            ).status_code
            == 200
        )

        comb_res = client.post(
            "/api/v1/results/checked/zip",
            json={"vps_ids": ["vps-1", "vps-2"], "scope": "all"},
            headers=hdr,
        )
        assert comb_res.status_code == 200
        with zipfile.ZipFile(io.BytesIO(comb_res.content), "r") as zf:
            names = set(zf.namelist())
            assert {"summary.txt", "hit_valid.txt", "hit_2fa.txt", "invalid.txt", "err.txt"}.issubset(names)
            assert "u1:p1|tok" in zf.read("hit_valid.txt").decode("utf-8")
            assert "u9:p9|tok" in zf.read("hit_valid.txt").decode("utf-8")
            assert "u3:p3" in zf.read("hit_2fa.txt").decode("utf-8")

        tg_comb = client.post(
            "/api/v1/results/checked/telegram",
            json={"vps_ids": ["vps-1", "vps-2"], "scope": "latest"},
            headers=hdr,
        )
        assert tg_comb.status_code == 200 and "vps-1_vps-2" in tg_comb.json()["zip_name"]

        # Full info upas card format + collector buckets + partial snapshot vs final upload
        full_card = "\n".join([
            "STATUS       : [NOT BANNED]  (Normal)",
            "IDENTITAS",
            "  Account    : Badria02:Badria02",
            "  GUID       : 38189909",
            "  Nickname   : mhineq03",
            "BIND (NO SENSOR)",
            "  Collector  : Amateur Collector V (1,100)",
            "",
            "-" * 60,
            "",
        ])

        client.post(
            "/api/v1/agent/register-job",
            json={"job_id": "manual_full_1", "filename": "upas.txt"},
            headers={"Authorization": f"Bearer {tok}"},
        )
        pbuf = io.BytesIO()
        with zipfile.ZipFile(pbuf, "w") as zf:
            zf.writestr("full_info_upas_valid.txt", full_card)
            zf.writestr("full_info_by_collector/08_amateur_collector.txt", full_card)
        prev_tg = len(tg_calls)
        part_res = client.post(
            "/api/v1/agent/output/manual_full_1?partial=1",
            content=pbuf.getvalue(),
            headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/zip"},
        )
        assert part_res.status_code == 200 and part_res.json()["tg_auto_sent"] is False
        assert len(tg_calls) == prev_tg  # partial never triggers Telegram auto-send

        fin_res = client.post(
            "/api/v1/agent/output/manual_full_1",
            content=pbuf.getvalue(),
            headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/zip"},
        )
        assert fin_res.status_code == 200 and fin_res.json()["tg_auto_sent"] is True
        assert len(tg_calls) == prev_tg + 1

        dl_full = client.get("/api/v1/results/manual_full_1/zip", headers=hdr)
        with zipfile.ZipFile(io.BytesIO(dl_full.content), "r") as zf:
            names = set(zf.namelist())
            assert {"summary.txt", "full_info_upas_valid.txt", "full_info_by_collector/08_amateur_collector.txt"}.issubset(names)
            assert "Full Info: 1" in zf.read("summary.txt").decode("utf-8")
