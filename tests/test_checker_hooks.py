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
