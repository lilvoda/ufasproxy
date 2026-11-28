import io
import tarfile
import pytest
from fastapi.testclient import TestClient

from induk.app import create_app
from induk.combo_split import assign_per_vps, clean_combos, split_combos
from induk.provisioner import (
    UnsupportedOSError,
    compute_recommended_workers,
    render_bootstrap_script,
    validate_supported_os_release,
)
from induk.vpn_pool import build_vpn_tarball, interleave_and_shard, scan_vpn_folders


def test_3folder_vpn_interleave_no_duplicates_and_tarball(tmp_path):
    for prov, cnt in (("vpns-proton", 5), ("vpns-proton-free", 3), ("vpns-surfshark", 4)):
        d = tmp_path / prov
        d.mkdir()
        (d / "auth.txt").write_text(f"u_{prov}\np_{prov}\n")
        for i in range(cnt):
            (d / f"{prov}_{i}.ovpn").write_text("client\n")

    pool = scan_vpn_folders(str(tmp_path))
    shards = interleave_and_shard(pool, ["vps-1", "vps-2", "vps-3"])
    all_ovpns = [ov for items in shards.values() for _, ov, _ in items]
    assert len(all_ovpns) == 12 and len(set(all_ovpns)) == 12
    for vid in ("vps-1", "vps-2", "vps-3"):
        assert {p for p, _, _ in shards[vid]} == {"vpns-proton", "vpns-proton-free", "vpns-surfshark"}

    raw = build_vpn_tarball(shards["vps-1"])
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tf:
        names = tf.getnames()
        assert any(n.endswith("vpns-proton/auth.txt") for n in names)
        assert any(n.endswith("vpns-surfshark/auth.txt") for n in names)


def test_distribute_vpn_blocks_running_vps(tmp_path):
    (tmp_path / "vpns-proton").mkdir()
    (tmp_path / "vpns-proton" / "a.ovpn").write_text("client\n")
    (tmp_path / "vpns-proton" / "auth.txt").write_text("u\np\n")
    app = create_app(db_path=str(tmp_path / "i.db"), api_key="k", data_dir=str(tmp_path), repo_dir=str(tmp_path))
    with TestClient(app) as client:
        hdr = {"X-API-Key": "k"}
        tok = client.post("/api/v1/vps", json={"vps_id": "vps-1"}, headers=hdr).json()["agent_token"]
        with client.websocket_connect("/ws/agent", headers={"Authorization": f"Bearer {tok}"}) as ws:
            ws.send_json({"type": "telemetry", "agent_state": "RUNNING", "progress": {"checked": 1, "total": 10}})
            ws.send_json({"type": "ping"})
            assert ws.receive_json()["type"] == "pong"
            res = client.post(
                "/api/v1/vpn/distribute",
                json={"vps_ids": ["vps-1"], "folders": ["vpns-proton"]},
                headers=hdr,
            )
            assert res.status_code == 409 and "vps-1" in res.json()["detail"]["busy_nodes"]


def test_combo_split_even_weighted_and_one_to_one():
    lines = clean_combos("a:1\nb:2\na:1\n\nc:3\nd:4\ne:5\nf:6\n")
    assert lines == ["a:1", "b:2", "c:3", "d:4", "e:5", "f:6"]
    weighted = split_combos(lines, {"vps-1": 2, "vps-2": 1})
    assert len(weighted["vps-1"]) == 4 and len(weighted["vps-2"]) == 2
    assert weighted["vps-1"] + weighted["vps-2"] == lines
    assert assign_per_vps({"vps-1": "x:1\ny:2", "vps-2": "z:3\nz:3"}) == {"vps-1": ["x:1", "y:2"], "vps-2": ["z:3"]}


def test_multidistro_os_validation_and_auto_benchmark():
    assert validate_supported_os_release('ID=ubuntu\nVERSION_ID="24.04"\n') == ("ubuntu-24.04", "apt-get")
    assert validate_supported_os_release('ID=debian\nVERSION_ID="12"\n') == ("debian-12", "apt-get")
    assert validate_supported_os_release('ID=arch\nBUILD_ID=rolling\n') == ("arch", "pacman")
    assert validate_supported_os_release('ID=fedora\nVERSION_ID="41"\n') == ("fedora-41", "dnf")
    assert validate_supported_os_release('ID=alpine\nVERSION_ID="3.20"\n') == ("alpine-3.20", "apk")
    for bad in ("", "VERSION_ID=1.0\n", "ID=unknownos\n"):
        with pytest.raises(UnsupportedOSError):
            validate_supported_os_release(bad)

    low = compute_recommended_workers(cpu_cores=2, ram_mb=1024, cpu_ops_per_ms=150.0)
    high = compute_recommended_workers(cpu_cores=8, ram_mb=16384, cpu_ops_per_ms=220.0)
    assert low["recommended_workers"] == 1
    assert high["recommended_workers"] >= 8

    script = render_bootstrap_script(
        "https://induk.test", "vps-4", "tok-4", "https://github.com/lilvoda/ufasproxy.git", "https://ptr.test/induk.json"
    )
    assert "vps-4" in script and "install.sh --client" in script and "INDUK_POINTER_URL=" in script
    assert "--agent-token" not in script and "chmod 600" in script

    for bad_dir in ("../outside", "/etc", "."):
        with pytest.raises(ValueError):
            scan_vpn_folders(str(__import__("pathlib").Path(".")), [bad_dir])
