import json
import sys
import types

# Allow running unit tests inside .venv_induk without full Playwright/CloakBrowser binaries
if "playwright" not in sys.modules:
    try:
        import playwright.async_api  # noqa: F401
    except ImportError:
        pw = types.ModuleType("playwright")
        pw_async = types.ModuleType("playwright.async_api")
        pw_async.async_playwright = None
        pw.async_api = pw_async
        sys.modules["playwright"] = pw
        sys.modules["playwright.async_api"] = pw_async

if "Crypto.Cipher" not in sys.modules:
    try:
        import Crypto.Cipher  # noqa: F401
    except ImportError:
        cr = types.ModuleType("Crypto")
        cc = types.ModuleType("Crypto.Cipher")
        cc.AES = object()
        cr.Cipher = cc
        sys.modules["Crypto"] = cr
        sys.modules["Crypto.Cipher"] = cc

if "zstandard" not in sys.modules:
    try:
        import zstandard  # noqa: F401
    except ImportError:
        sys.modules["zstandard"] = types.ModuleType("zstandard")

import info as _info
import old_browser_vpn as obv


def test_status_snapshot_gateway_and_induk_host_route(tmp_path):
    snap = obv._build_status_snapshot(
        obv.stats,
        obv._PERF,
        None,
        [],
        ["ok"],
        {"cause": "WAF", "at": 1.0},
        live_pool=[{"server": "http://168.144.36.170:20001"}],
        vpnpool_cfg={"api_url": "http://168.144.36.170:8080", "api_lease_id": "abc", "rotating": set()},
    )
    assert "stats" in snap and "smart" in snap and "vpn" in snap
    assert snap["vpn"]["mode"] == "ufasproxy" and snap["vpn"]["proxy_live"] == 1
    assert "target_workers" in snap["smart"] and "node_score" in snap["vpn"]

    p = tmp_path / "status.json"
    obv._write_json_atomic(str(p), snap)
    assert json.loads(p.read_text())["smart"]["last_heal"]["cause"] == "WAF"
    assert obv._resolve_host_ipv4("127.0.0.1") == "127.0.0.1"
    assert obv._build_induk_bypass_route_cmd("1.2.3.4", "eth0", "1.2.3.1") == [
        "route",
        "replace",
        "1.2.3.4/32",
        "via",
        "1.2.3.1",
        "dev",
        "eth0",
    ]


def test_vpncoordinator_recursive_provider_subfolders_and_per_dir_auth(tmp_path, monkeypatch):
    monkeypatch.setattr(obv, "_find_openvpn_bin", lambda: "openvpn")
    for prov in ("vpns-proton", "vpns-surfshark"):
        d = tmp_path / "vpns_assigned" / prov
        d.mkdir(parents=True)
        (d / "auth.txt").write_text(f"u_{prov}\np_{prov}\n")
        (d / f"{prov}_0.ovpn").write_text("client\n")
    vc = obv.VpnCoordinator(ovpn_dir=str(tmp_path / "vpns_assigned"), ip_check=False)
    assert len(vc.ovpn_files) == 2
    cmd0 = vc._build_ovpn_cmd(vc.ovpn_files[0], is_win=False)
    cmd1 = vc._build_ovpn_cmd(vc.ovpn_files[1], is_win=False)
    a0 = cmd0[cmd0.index("--auth-user-pass") + 1]
    a1 = cmd1[cmd1.index("--auth-user-pass") + 1]
    assert a0 != a1 and "vpns-proton" in a0 and "vpns-surfshark" in a1


def test_full_upas_info_formatter_and_collector_buckets():
    binds, reg_ts = _info.parse_binds([
        {0: "mt-and_1", 1: {"email": "a@b.com", "register_time": "1619606100"}},
        {0: "gg_123", 1: {"email": "g@gmail.com"}},
    ])
    assert reg_ts == 1619606100 and "a@b.com" in binds["Moonton"] and "g@gmail.com" in binds["Google"]
    lbl, bkt = _info.map_collector(49420)
    assert lbl == "Renowned Collector V (49,420)" and bkt == "04_renowned_collector.txt"
    banned, binfo = _info.inspect_ban({"ban_reason": "24", "endtime_day": 30})
    assert banned and binfo["reason_name"] == "Cheating in Ranked Match"
    card = _info.format_full_card({
        "upas": "u:p", "guid": 123, "no_role": False, "ban_seen": False, "ban_info": {},
        "nick": "Hero", "rid": 111, "zid": 222, "other_roles": [], "level": 45,
        "country": "ID", "alamat": "Indonesia", "squad": "-", "dibuat": "28 Apr 2021 17:35 WIB",
        "last_on": "-", "last_match": "-", "binds": binds, "v2l": False,
        "risk": "Low", "flags_pct": 0.0, "credits": 100, "followers": 10, "likes": 20,
        "bp": 1000, "diamonds": 5, "tickets": 2, "rank_now": "Epic II", "rank_max": "Mythic 10",
        "wr": "55.00%  (11/20)", "heroes": 19, "skins": 8,
        "sup": 0, "grd": 0, "exq": 0, "dlx": 1, "exc": 0, "com": 7, "collector": lbl,
    })
    assert "STATUS       : [NOT BANNED]  (Normal)" in card and "BIND (NO SENSOR)" in card and "WALLET" in card
    norole_card = _info.format_full_card({
        "upas": "x:y", "guid": 456, "no_role": True, "ban_seen": False, "ban_info": {},
        "binds": binds, "v2l": True, "country": "ID",
    })
    assert "Belum Buat Karakter" in norole_card and "2FA        : AKTIF" in norole_card
    assert obv._extract_ban_reason(None) is None
    assert obv._extract_ban_reason({"full_data": {"ban_seen": False}}) is None
    assert obv._extract_ban_reason({"full_data": {"ban_seen": True, "ban_info": {"reason_name": "Cheat"}}}) == "Cheat"
