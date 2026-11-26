# ufasproxy Implementation Plan & System Mapping (OpenVPN Edition)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `ufasproxy`, a single-file Python stdlib OpenVPN-to-Proxy HTTP API server (`server.py`) that uses existing `*.ovpn` + `auth.txt` folders to dynamically spin up, probe against Moonton API, rotate, and tear down authenticated HTTP proxies per client request (`count = workers + 50%` backup), plus thin client integration in `ufasvpn` (`old_browser_vpn.py`).

**Architecture:** Client machines (`ufasvpn` on Proxmox CT, DO VPS, or Windows) call `POST /lease` with `{"count": N}` on the gateway VPS. For each requested slot, the gateway creates an isolated network namespace `ovns<slot>` connected via RFC 2544 `/30` veth (`198.18.<slot>.1` <-> `198.18.<slot>.2`), starts `openvpn` **inside** `ovns<slot>` (so `tun0` default route stays confined to `ovns<slot>` and the host `main` routing table + SSH port `22` are NEVER touched), launches `microsocks` as uid `nobody` with an `iptables -m owner` kill-switch preventing any non-`tun0` WAN egress, and runs an end-to-end TLS probe (`HEAD https://accountmtapi.mobilelegends.com/`) over `198.18.<slot>.2:1080` before returning `http://user:pass@GATEWAY_IP:20000+slot` via a built-in `asyncio` HTTP CONNECT + Basic Auth bridge.

```mermaid
flowchart LR
    C1["Client: Proxmox CT / Windows (ufasvpn)"] -->|"POST /lease {count: 15}"| API["ufasproxy HTTP API (:8080, Bearer)"]
    API -->|"alloc slots + TTL reaper"| MGR["OvpnSlotManager (ovns1..ovnsN)"]
    MGR -->|"1: openvpn + microsocks (nobody kill-switch)"| NS["netns ovnsN (tun0 + veth 198.18.N.0/30)"]
    MGR -->|"2: probe HEAD accountmtapi.mobilelegends.com"| VPN["OpenVPN Server -> MT API"]
    API -->|"returns ONLY live MT-checked proxies"| C1
    C1 -->|"HTTP CONNECT + BasicAuth"| BRG["HttpToSocksBridge (:20001..20060)"]
    BRG -->|"SOCKS5 198.18.N.2:1080"| NS
```

**Tech Stack:** Python 3.10+ stdlib only (`asyncio`, `urllib`, `hmac`, `secrets`, `json`, `re`, `ssl`), Linux `iproute2`, `openvpn`, `microsocks`, `iptables`, `util-linux` (`setpriv`).

---

## Pemetaan Kebutuhan Sistem (Prerequisites & Components)

### 1. Sumber Config VPN (`vpns-surfshark/` atau `vpns-proton/`)
- Langsung memakai folder `*.ovpn` + `auth.txt` yang sudah ada (mis. `vpns-surfshark/` dengan 284 `.ovpn` — tidak perlu download `.conf` WireGuard manual).
- Server gateway wajib mem-prepend `--ignore-unknown-option block-outside-dns` sebelum `--config`, dan menempatkan `--pull-filter ignore block-outside-dns --pull-filter ignore ping-restart --script-security 1 --ping-exit 60 --connect-retry 1 2 --resolv-retry 2 --fast-io --auth-nocache` **sesudah** `--config`.

### 2. Server Side (`C:\Users\Dimz\Downloads\ufasproxy`)
| File | Tanggung Jawab | Dependensi Luar |
| :--- | :--- | :--- |
| `server.py` | Daemon tunggal: `OvpnSlotManager` (netns + OpenVPN + `nobody` kill-switch + `microsocks` + MT API pre-probe), `HttpToSocksBridge` (`HTTP CONNECT` + BasicAuth), REST API (`/lease`, `/rotate`, `/heartbeat`, `/release`, `/status`), TTL reaper, `--selftest` | `openvpn`, `microsocks`, `iproute2`, `iptables`, `util-linux` |
| `install.sh` | Installer server Ubuntu 24.04 (`apt-get install -y python3 openvpn microsocks iproute2 iptables procps util-linux`), cek `/dev/net/tun` & `ip netns`, opsional info firewall port | `apt-get` |
| `.gitignore` / `.gitattributes` | Mengabaikan `vpns*/`, `*.ovpn`, `auth.txt`, `*.auth`, `.ufasproxy_state.json*`; memaksa LF untuk `.sh` | Git |

### 3. Client Side (`C:\Users\Dimz\Downloads\muse-old-vpn\old_browser_vpn.py`)
- Tambah CLI `--vpn-api-url` & `--vpn-api-token` (+ opsi menu interaktif `API Proxy Server (ufasproxy)`).
- Setelah `_benchmark_vps_capacity` menentukan `spawn_w`, client memanggil `POST /lease` (`count = _calc_multi_vpn_slots(spawn_w)` = `workers + 50%` backup), memasukkan `http://u:p@GATEWAY_IP:PORT` langsung ke `live_pool` (`PROXY_ENABLED = True`), menjalankan background heartbeat per `60s`, mengarahkan `_maybe_rotate_vpnpool_slot` ke `POST /rotate`, dan memanggil `POST /release` saat exit / `Ctrl+C`.

---

## Global Constraints & Review Focus

**Global Constraints:**
- **VPS SSH 100% Untouched (Anti-Putus SSH):**
  - OpenVPN dijalankan **hanya di dalam `ip netns ovns<slot>`**, sehingga `tun0` & default route VPN terkurung di dalam netns. Tabel routing utama VPS (`ip route`), `eth0`, DNS host, dan port SSH `22` **tidak pernah diubah**.
  - Slot `veth` memakai subnet RFC 2544 `198.18.<slot>.0/30` (`198.18.<slot>.1` <-> `198.18.<slot>.2`), menghindari tabrakan dengan DO VPC (`10.x`), Docker (`172.17..31.x`), dan LAN (`192.168.x`).
  - Rule `iptables` memakai `-w 5` dengan scoping ketat hanya ke `198.18.0.0/16` (`-I FORWARD 1` & `POSTROUTING MASQUERADE` outbound WAN), tidak pernah flush global `iptables`/`ip route`, dan startup server menolak port `<= 1024` (termasuk port `22`).
- **Kill-Switch Anti Real-IP Leak per Slot:**
  - `microsocks` dijalankan di dalam `ovns<slot>` sebagai uid `nobody` via `setpriv` + rule `iptables -A OUTPUT -o ovw<slot> -m owner --uid-owner <nobody_uid> -m conntrack --ctstate NEW -j DROP` (fallback: tunda launch `microsocks` hingga `tun0` up).
- **Mandatory Moonton API Probe Before Returning Proxies (`POST /lease` & `POST /rotate`):**
  - Setiap slot yang baru dinyalakan atau di-rotate WAJIB lulus TLS HTTP probe (`HEAD https://accountmtapi.mobilelegends.com/` melalui SOCKS5 slot `198.18.<slot>.2:1080`, status `< 500` dan `not in (400, 402, 403, 405, 407, 429)`, RTT `<= 3500ms`) sebelum dikembalikan ke client. Node `.ovpn` yang gagal otomatis di-penalti cooldown sementara dan di-retry dengan `.ovpn` lain yang belum dipakai.
- **Zero new `pip` deps & Chromium-ready HTTP CONNECT Auth:**
  - `server.py` dan client integration pakai Python stdlib; proxy client-facing memakai `http://user:pass@GATEWAY_IP:PORT` (`Proxy-Authorization: Basic`), sementara REST API memakai `Authorization: Bearer <TOKEN>` (`hmac.compare_digest`).

**Review Focus:**
- **SSH routing & port invariant:** Startup verifies `ip -4 route show default` exists and never alters it across `start_slot`/`rotate_slot`/`stop_slot`; tests reject port `22` / `<= 1024` in `--selftest`.
- **Crashed client leak & orphan processes:** Client killed (`SIGKILL`) without `/release` -> background 15s reaper terminates leases past `ttl_s` (default 180s), batch-kills `ip netns pids`, and deletes `ovns*`/`ovh*` veth links.
- **Public port scanning / open-proxy probing:** Unauthenticated HTTP/CONNECT hits receive `401`/`407 Proxy-Authenticate: Basic` immediately before touching SOCKS5 upstream.
- **Slow OpenVPN handshake vs MT API pre-probe retry:** Parallel slot startup during `/lease` checks `"Initialization Sequence Completed"` + `tun0` + MT API probe (`HEAD`), replacing dead/WAF-blocked `.ovpn` slots cleanly (with oversubscription retry budget) before returning.
- **Proton vs Surfshark concurrency & duplicate `.ovpn` avoidance:** Global `asyncio.Lock` tracks active `slot -> conf_path` so concurrent clients never pick the same `.ovpn` or overload slots beyond `--max-slots` (`409` when saturated).

---

## Execution Tasks

### Task 1: OpenVPN Netns Slot Manager + MT API Probe + HTTP CONNECT Bridge (`server.py`)

**Files:**
- Create: `C:\Users\Dimz\Downloads\ufasproxy\server.py`

**Interfaces:**
- Produces:
  - `discover_ovpn_configs(ovpn_dir: str) -> tuple[list[str], str]` (UDP-first `.ovpn` list + resolved `auth.txt`/`.auth`)
  - `async def probe_socks_mt_api(socks_host: str, socks_port: int, timeout_s: float = 5.0) -> tuple[bool, int, str]`
  - `class OvpnSlotManager`: `async def start_slot(slot: int, cfg: str) -> bool`, `async def rotate_slot(slot: int, cfg: str) -> bool`, `async def stop_slot(slot: int)`, `async def stop_all()`
  - `class HttpToSocksBridge`: `async def start(port: int, socks_host: str, socks_port: int, auth_fn)`, `async def stop()`

- [ ] **Step 1: Write `server.py` skeleton with `--selftest` testing `HttpToSocksBridge` 407 auth rejection, BasicAuth forwarding over mock SOCKS5, `_probe_mt_response_ok` status rules, and OpenVPN cmd argument ordering**
- [ ] **Step 2: Run `--selftest` to confirm initial fail**

Run: `python server.py --selftest`
Expected: FAIL before implementation

- [ ] **Step 3: Implement `OvpnSlotManager` (netns `ovns<slot>`, `198.18.<slot>.0/30` veth + NAT/FORWARD `-w 5`, `setpriv nobody` kill-switch + `microsocks`, UDP-first OpenVPN launch, MT API `HEAD` probe, batched stop cleanup) & `HttpToSocksBridge`**
- [ ] **Step 4: Run verification**

Run: `python -m py_compile server.py && python server.py --selftest`
Expected: PASS

- [ ] **Step 5: Commit Task 1**

```bash
git add server.py && git commit -m "Add OpenVPN netns slot manager, MT API probe, and HTTP CONNECT bridge"
```

---

### Task 2: Lease REST API Server, TTL Reaper & Gateway Installer (`server.py`, `install.sh`)

**Files:**
- Modify: `C:\Users\Dimz\Downloads\ufasproxy\server.py`
- Create: `C:\Users\Dimz\Downloads\ufasproxy\install.sh`

**Interfaces:**
- Consumes: `OvpnSlotManager`, `HttpToSocksBridge`, `discover_ovpn_configs`
- Produces HTTP API (`--ovpn-dir vpns-surfshark --host 0.0.0.0 --port 8080 --token <SECRET> --base-proxy-port 20001 --max-slots 45 --public-ip <IP>`):
  - `POST /lease` `{"count": int, "ttl_s": int, "client": str}` -> `{"lease_id": str, "proxies": list[str], "expires_at": float}`
  - `POST /rotate` `{"lease_id": str, "proxy": str}` -> `{"ok": bool, "proxy": str}`
  - `POST /heartbeat` `{"lease_id": str}` -> `{"ok": bool, "expires_at": float}`
  - `POST /release` `{"lease_id": str}` -> `{"ok": bool, "released": int}`
  - `GET /status` -> `{"active_slots": int, "max_slots": int, "leases": list[dict]}`

- [ ] **Step 1: Extend `server.py --selftest` with API Bearer auth (`401`), port `<= 1024` safety rejection, `/lease` -> `/status` -> `/rotate` -> TTL reaper -> `/release` tests using mocked `OvpnSlotManager`**
- [ ] **Step 2: Run `--selftest` to confirm failing tests**
- [ ] **Step 3: Implement `GatewayServer` endpoints (parallel `/lease` slot startup + failed `.ovpn` cooldown/retry, single-slot `/rotate` retrying until MT API probe passes, 15s TTL reaper, graceful SIGINT/SIGTERM `stop_all()`) and `install.sh` (`apt-get install -y python3 openvpn microsocks iproute2 iptables procps util-linux`, `/dev/net/tun` + `ip netns` check)**
- [ ] **Step 4: Run verification**

Run: `python -m py_compile server.py && python server.py --selftest && bash -n install.sh`
Expected: PASS

- [ ] **Step 5: Commit Task 2**

```bash
git add server.py install.sh && git commit -m "Add lease REST API, MT-verified rotation, TTL reaper, and installer"
```

---

### Task 3: Checker Client Integration in `ufasvpn` (`old_browser_vpn.py`)

**Files:**
- Modify: `C:\Users\Dimz\Downloads\muse-old-vpn\old_browser_vpn.py`

**Interfaces:**
- Consumes: `POST /lease`, `POST /rotate`, `POST /heartbeat`, `POST /release` on `--vpn-api-url` with `--vpn-api-token`
- Produces:
  - CLI args `--vpn-api-url` and `--vpn-api-token` + interactive menu choice *"API Proxy Server (ufasproxy)"*.
  - Post-benchmark automatic lease of `_calc_multi_vpn_slots(spawn_w)` (`workers + 50% backup`), background 60s heartbeat task, `_maybe_rotate_vpnpool_slot` / gateway rotation via `POST /rotate`, and guaranteed `POST /release` in `finally:` + `_emergency_cleanup()`.

- [ ] **Step 1: Add `--selftest` check in `old_browser_vpn.py` for gateway lease payload & HTTP proxy URL matching**
- [ ] **Step 2: Run `old_browser_vpn.py --selftest` to confirm failing test**
- [ ] **Step 3: Implement gateway lease/heartbeat/rotate/release client helper cleanly in `old_browser_vpn.py`**
- [ ] **Step 4: Run `py_compile` & `--selftest` in `ufasvpn`**

Run: `python old_browser_vpn.py --selftest`
Expected: `[✓] All self-tests passed successfully!`

- [ ] **Step 5: Commit & Push `ufasvpn`**

```bash
git add old_browser_vpn.py && git commit -m "Add ufasproxy API lease client mode to old_browser_vpn.py" && git push origin main
```

---

### Task 4: Live End-to-End Smoke Test (DO VPS Gateway -> Checker Client)

- [ ] **Step 1:** On VPS (`<GATEWAY_IP>`), setup `ufasproxy`, run `sudo bash install.sh`, point `--ovpn-dir /path/to/vpns-surfshark`, start `sudo python3 server.py --ovpn-dir /path/to/vpns-surfshark --port 8080 --token <SECRET> --public-ip <GATEWAY_IP>` while keeping active SSH session open and verifying `ip -4 route show default` unchanged.
- [ ] **Step 2:** Verify `/lease` returns MT-verified `http://u:p@<GATEWAY_IP>:20001..`, verify unauthenticated proxy access returns `407`, verify `/rotate` swaps exit IP cleanly, and verify `/release` cleans up all `ovns*` namespaces.
- [ ] **Step 3:** Run `old_browser_vpn.py --vpn-api-url http://<GATEWAY_IP>:8080 --vpn-api-token <SECRET> -c input/combo.txt -w 10` from client and verify live run + cleanup on exit.
