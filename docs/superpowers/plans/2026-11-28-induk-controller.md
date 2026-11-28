# ufasproxy Induk Controller & Multi-VPS Agent Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Mengintegrasikan sistem kontrol 2-arah Induk–Agent dari `muse-old-vpn-induk` ke `ufasproxy` (`--induk` untuk control plane FastAPI/WS/SQLite UI dan pembaruan `--client` untuk mendaftarkan systemd worker `agent.py` + checker hooks, tetap kompatibel multi-distro dan gateway `server.py`).

**Architecture:**
- **Server VPN Gateway (`server.py`, default `:8080` + `:20001..20045`)** tetap terpisah perannya sebagai **data/proxy plane** OpenVPN netns; **Server Induk (`induk.app:app`, default `:8000`)** adalah **control plane** (Web UI, 2-way WebSocket `/ws/agent` & `/ws/ui`, SQLite WAL `induk_data/`, combo splitter, hit collector, SSH provisioner, backup/restore/migrate).
- Keduanya **berbeda proses, systemd unit, venv, dan port**, sehingga **bisa dipasang di VPS terpisah** (direkomendasikan untuk produksi saat slot penuh agar migrasi/restart Induk tidak memutus tunnel aktif) **maupun di VPS yang sama** (`bash install.sh --server --induk` -> `ufasproxy.service` + `ufasproxy-induk.service` berdampingan aman karena `server.py` mengisolasi `tun0` di `ip netns`).
- Worker `--client` mendukung dua mode jaringan: otomatis memakai gateway `ufasproxy` (`token.env` / `--vpn-api-url`) **atau** folder `.ovpn` lokal opsional (`vpns_assigned` dari `vpn_pool`), sambil mengirim snapshot status/log/hits real-time ke Induk.

**Tech Stack:** Python 3.10+ stdlib (`old_browser_vpn.py`, `server.py`), FastAPI + Uvicorn + WebSockets + AsyncSSH + SQLite WAL (`induk/`), `websockets` (`agent.py`), static HTML/CSS/JS, multi-distro `bash` installer (`install.sh` untuk `apt-get`, `pacman`, `dnf`, `yum`, `apk`, `zypper`).

---

## Global Constraints
- **Referensi Read-Only:** `C:\Users\Dimz\Downloads\lilvoda\muse-old-vpn\` tidak boleh diubah; `muse-old-vpn-induk` hanya menjadi sumber salin/adaptasi ke `ufasproxy`.
- **Koeksistensi Port & Routing:** Gateway (`8080`, `20001..20045`) dan Induk (`8000` atau `--induk-port`) wajib di port `> 1024` yang tidak bertabrakan; instalasi `--induk` tidak boleh mengubah `ufasproxy.service` atau memutus koneksi SSH.
- **Keamanan Secret & Repo Publik:** `lilvoda/ufasproxy` adalah repo publik — **jangan pernah** menaruh `INDUK_API_KEY`, `AGENT_TOKEN`, password SSH, atau Bearer token worker ke argumen DB `jobs.config_json`, Git, atau stdout log. `INDUK_API_KEY` hanya disimpan di `/etc/ufasproxy-induk/env` (`chmod 600`) dan `AGENT_TOKEN` di `/etc/ufasproxy-agent/env` (`chmod 600`). Worker mengambil `UFASPROXY_TOKEN` dari `token.env` lokal.
- **Multi-Distro Installer (`install.sh`):** Baik `--induk` maupun `--client` (termasuk setup `agent`) wajib menggunakan `pkg_install` lintas distro (`apt-get`, `pacman`, `dnf`, `yum`, `apk`, `zypper`) tanpa penguncian `Ubuntu 22.04/24.04` seperti di `muse-old-vpn-induk`, dan menjaga file `.sh` tetap pure `LF`.
- **Backward Compatibility:** Menjalankan `bash install.sh --client` atau `bash install.sh --server` tanpa flag `--induk` / `--induk-url` harus bekerja persis seperti sebelumnya tanpa wajib mengaktifkan systemd agent/induk.

## Review Focus
- **Tabrakan Port & Environment saat `--server --induk` di 1 VPS:** Memastikan `--induk-port` (`8000`) divalidasi tidak menabrak `8080` atau range `20001..20045`, dan `ufasproxy-induk.service` memakai `.venv_induk` + `/etc/ufasproxy-induk/env` terpisah dari `token.env`.
- **Token Gateway Bocor di Job/UI:** Pastikan `_ALLOWED_CHECKER_FLAGS` di `induk/app.py` hanya mengizinkan `--vpn-api-url` (bukan `--vpn-api-token` dalam `config_json` SQLite), sementara `old_browser_vpn.py` membaca `UFASPROXY_TOKEN` secara otomatis dari `token.env` lokal worker.
- **Hook Checker di Mode Proxy Gateway vs Mode `.ovpn` Lokal:** Memastikan `--status-json` mengisi ringkasan `vpn` dengan akurat baik saat `vpn_coord` aktif maupun saat memakai `live_pool` proxy `ufasproxy`, dan `--rotate-trigger` (`ROTATE_VPN` dari Induk) dapat merotasi slot proxy gateway ketika mode API aktif.
- **Installer `--client` Non-Systemd / Container / Multi-Distro:** Memastikan `--client` tanpa `--induk-url` tidak gagal jika systemd absen (mis. Docker/WSL tanpa PID 1), dan ketika `--induk-url` diberikan di host tanpa `/run/systemd/system`, beri pesan jelas alih-alih crash `set -e`.
- **Resiliensi Migrasi Induk & Offline Buffer:** `backup.py` WAL-safe `sqlite3.backup()`, `SET_INDUK` + `INDUK_POINTER_URL`, dan byte-offset tailer `hit_valid.txt` / `hit_2fa.txt` di `agent.py` tidak kehilangan hit saat Induk restart atau pindah VPS.

---

### Task 1: Port Package `induk/` & `.gitignore` ke `ufasproxy`

**Files:**
- Create: `ufasproxy/induk/__init__.py`
- Create: `ufasproxy/induk/requirements_induk.txt`
- Create: `ufasproxy/induk/db.py`
- Create: `ufasproxy/induk/backup.py`
- Create: `ufasproxy/induk/combo_split.py`
- Create: `ufasproxy/induk/vpn_pool.py`
- Create: `ufasproxy/induk/provisioner.py` (diadaptasi multi-distro + repo `lilvoda/ufasproxy`)
- Create: `ufasproxy/induk/app.py` (diadaptasi `_ALLOWED_CHECKER_FLAGS` + default `repo_url` `https://github.com/lilvoda/ufasproxy.git`)
- Create: `ufasproxy/induk/static/index.html`, `ufasproxy/induk/static/app.js`, `ufasproxy/induk/static/styles.css`
- Modify: `ufasproxy/.gitignore`
- Test: `ufasproxy/tests/test_induk_db.py`, `ufasproxy/tests/test_induk_api.py`, `ufasproxy/tests/test_splitters_provisioner.py`, `ufasproxy/tests/test_migration.py`, `ufasproxy/tests/test_audit_fixes.py`, `ufasproxy/tests/test_induk_e2e.py`

**Interfaces:**
- Consumes: `muse-old-vpn-induk/induk/*` dan `muse-old-vpn-induk/tests/*`
- Produces: Package `induk` di `ufasproxy` dengan `create_app(...) -> FastAPI`, `_ALLOWED_CHECKER_FLAGS` mendukung flag `ufasproxy` (`--vpn-api-url`, `--no-proxy`, `--ascii`, `--vpn-waf-threshold`, `--waf-cooldown`, `--vpn-rotate-every`, `--two-tab`, `--skip-ovpn-test`, `--retest-ovpn`, `--no-vpn-ip-check`, `--headless`, `--no-headless`, `--debug`, `--workers`), serta `provisioner.detect_pkg_mgr_and_os(os_release_text: str) -> str` & `render_bootstrap_script(...)` berbasis `ufasproxy`.

- [ ] **Step 1: Tambahkan pola state & runtime Induk/Agent ke `ufasproxy/.gitignore`**
  Tambahkan `induk_data/`, `.venv_induk/`, `.agent_state/`, `vpns_assigned*/`, `vpns_staging/`, `.pytest_cache/` ke `.gitignore`.
- [ ] **Step 2: Salin & adaptasi modul inti `induk/` (`__init__.py`, `db.py`, `backup.py`, `combo_split.py`, `vpn_pool.py`, `requirements_induk.txt`, `static/*`)**
- [ ] **Step 3: Adaptasi `induk/provisioner.py` untuk multi-distro Linux (`ubuntu`, `debian`, `arch`, `fedora`, `rocky`, `almalinux`, `alpine`, `opensuse`)**
  Ganti `validate_ubuntu_os_release` dengan validator distro-agnostic yang mendukung `apt-get`, `pacman`, `dnf`, `yum`, `apk`, `zypper`; perbarui `render_bootstrap_script` untuk meng-clone `https://github.com/lilvoda/ufasproxy.git` ke `/opt/ufasproxy` lalu menjalankan `bash install.sh --client --induk-url ... --agent-token ... --vps-id ...`.
- [ ] **Step 4: Adaptasi `induk/app.py`**
  Perbarui `ProvisionBody.repo_url` default ke `https://github.com/lilvoda/ufasproxy.git`, dan perluas `_ALLOWED_CHECKER_FLAGS` dengan `--vpn-api-url`, `--no-proxy`, `--ascii` (tetap tolak `--vpn-api-token` dari UI/DB demi keamanan, dan dukung optional `ufasproxy_url` jika disediakan).
- [ ] **Step 5: Port & jalankan suite test `tests/`**
  ```bash
  pytest tests/test_induk_db.py tests/test_induk_api.py tests/test_splitters_provisioner.py tests/test_migration.py tests/test_audit_fixes.py tests/test_induk_e2e.py -v
  ```
  Expected: semua test PASS termasuk test multi-distro provisioner & flag checker `ufasproxy`.
- [ ] **Step 6: Commit Task 1**
  ```bash
  git add .gitignore induk/ tests/ && git commit -m "feat(induk): port Induk controller, multi-distro provisioner, and dashboard UI"
  ```

---

### Task 2: Hook Checker `--status-json`, `--rotate-trigger`, `--induk-host`, & Mode API di `old_browser_vpn.py`

**Files:**
- Modify: `ufasproxy/old_browser_vpn.py`
- Test: `ufasproxy/tests/test_checker_hooks.py` + `ufasproxy/old_browser_vpn.py --selftest`

**Interfaces:**
- Consumes: `stats`, `_PERF`, `vpn_coord`, `live_pool`, `_TOP_HITS`, `_LIVE_LOGS`
- Produces:
  - CLI args `--status-json`, `--induk-host`, `--rotate-trigger` pada `old_browser_vpn.py`
  - `_build_status_snapshot(stats_dict, perf, vpn_coord=None, top_hits=None, live_logs=None, last_heal=None, live_pool=None, vpn_api_url='') -> dict`
  - `_write_json_atomic(path: str, data: dict) -> None`
  - Dukungan remote `ROTATE_VPN` (`--rotate-trigger` & `SIGUSR1`) baik untuk `vpn_coord` lokal maupun rotasi proxy gateway (`/rotate`) di mode `ufasproxy`.

- [ ] **Step 1: Tulis failing tests di `tests/test_checker_hooks.py` & `--selftest`**
  Uji `--status-json` snapshot untuk mode lokal `vpn_coord` maupun mode proxy gateway (`vpn_api_url` + `live_pool`), `_write_json_atomic`, dan `--help` menampilkan `--status-json`, `--induk-host`, `--rotate-trigger`.
- [ ] **Step 2: Jalankan test untuk konfirmasi fail awal**
  `pytest tests/test_checker_hooks.py -v` -> FAIL (`unrecognized arguments: --status-json`).
- [ ] **Step 3: Implementasikan `_resolve_host_ipv4`, `_build_status_snapshot`, `_write_json_atomic`, `induk_host` bypass route di `VpnCoordinator`, argumen CLI, dan integrasi `_tui_heartbeat()` di `old_browser_vpn.py`**
  Pastikan di mode `ufasproxy` (`vpn_api_url`), `_rotate_trigger` memicu rotasi proxy slot aktif via endpoint `/rotate` yang sudah ada.
- [ ] **Step 4: Verifikasi `--selftest` & `pytest`**
  ```bash
  python old_browser_vpn.py --selftest && pytest tests/test_checker_hooks.py -v
  ```
  Expected: `[✓] All self-tests passed successfully!` dan semua tests PASS.
- [ ] **Step 5: Commit Task 2**
  ```bash
  git add old_browser_vpn.py tests/test_checker_hooks.py && git commit -m "feat(checker): add Induk status-json, rotate-trigger, and induk-host hooks"
  ```

---

### Task 3: Port & Adaptasi Worker Agent `agent.py` untuk `ufasproxy`

**Files:**
- Create: `ufasproxy/agent.py`
- Create: `ufasproxy/tests/test_agent.py`

**Interfaces:**
- Consumes: `INDUK_URL`, `VPS_ID`, `AGENT_TOKEN`, `WORK_DIR`, `ENV_FILE`, `INDUK_POINTER_URL`, optional `UFASPROXY_URL` / `token.env`, dan endpoint Induk (`/ws/agent`, `/api/v1/agent/*`).
- Produces: `class MuseAgent` dengan resolusi Python `.venv` -> `.venv_old` -> `sys.executable`, `run_benchmark()`, `execute_command()` (`START`, `STOP`, `RESTART`, `ROTATE_VPN`, `SYNC_VPN`, `UPDATE_CODE`, `BENCHMARK`, `SET_INDUK`), tailer hit `hit_valid.txt`/`hit_2fa.txt`, dan auto-injection `--vpn-api-url` jika `UFASPROXY_URL` tersedia dan tidak pakai `vpns_assigned` / `--vpn-ovpn-dir`.

- [ ] **Step 1: Tulis `tests/test_agent.py`**
  Uji command idempotency (`mark_cmd_seen`), hit tailer byte-offset (`tail_new_hits`), deteksi interpreter `.venv/bin/python`, `SET_INDUK` atomic env update, dan pembentukan args `old_browser_vpn.py` untuk mode `ufasproxy` API vs mode `.ovpn` lokal.
- [ ] **Step 2: Implementasikan `ufasproxy/agent.py`**
  Adaptasi dari `muse-old-vpn-induk/agent.py`:
  - Prioritas venv: `.venv/bin/python` (default `ufasproxy`) -> `.venv_old/bin/python` -> `sys.executable`.
  - Jika `args` dari Induk belum punya `--vpn-api-url`, `--vpn-ovpn-dir`, atau `--no-proxy`: cek `vpns_assigned/` hanya jika `sync_vpn` dipakai atau folder ada; jika worker memiliki `UFASPROXY_URL` (env / `token.env`), biarkan `old_browser_vpn.py` membacanya otomatis dari `token.env` (atau teruskan `--vpn-api-url` jika di-set di env agent).
  - Jangan pakai `--induk-host` saat memakai gateway `ufasproxy` (karena host tidak menjalankan OpenVPN tun0), dan pakai saat mode OpenVPN lokal aktif.
- [ ] **Step 3: Verifikasi `tests/test_agent.py`**
  ```bash
  pytest tests/test_agent.py -v
  ```
  Expected: PASS.
- [ ] **Step 4: Commit Task 3**
  ```bash
  git add agent.py tests/test_agent.py && git commit -m "feat(agent): add 2-way WebSocket worker agent for ufasproxy clients"
  ```

---

### Task 4: Perbarui `install.sh` (`--induk`, `--client` Agent Setup, Multi-Distro) & `README.md`

**Files:**
- Modify: `ufasproxy/install.sh`
- Modify: `ufasproxy/README.md`

**Interfaces:**
- Consumes: `pkg_install`, `pkg_install_group`, `server.py`, `induk/app.py`, `agent.py`, `old_browser_vpn.py`
- Produces CLI options di `install.sh`:
  - Mode: `--client`, `--server`, `--induk`, `--all` (bisa dikombinasikan mis. `--server --induk` atau standalone `--induk`).
  - Opsi Induk server: `--induk-port PORT` (default `8000`), `--induk-api-key KEY`, `--restore BUNDLE.tar.gz`.
  - Opsi Client Agent: `--induk-url URL`, `--agent-token TOKEN`, `--vps-id ID`, `--induk-pointer-url URL`.

- [ ] **Step 1: Perbarui argument parser & menu interaktif di `install.sh`**
  - Ubah `--induk` menjadi toggle/mode (`DO_INDUK=1` atau `MODE="induk"`), sehingga user bisa memilih:
    1. `[1] Client Checker` (plus opsional sambungkan ke Induk jika isi `--induk-url` / prompt opsional)
    2. `[2] Server Gateway VPN` (`server.py` `:8080`)
    3. `[3] Server Induk Controller` (`induk.app:app` `:8000`)
    4. `[4] Server VPN + Server Induk`
    5. `[5] Semua (Server + Induk + Client)`
  - Validasi port `--induk-port` (`1025..65535`) tidak bertabrakan dengan `--port` (`8080`) maupun proxy port range bila dijalankan bersama `--server`.
- [ ] **Step 2: Implementasikan `install_induk()` di `install.sh`**
  - Gunakan `pkg_install_group python` + `git` + `curl` lintas distro (`apt-get`, `pacman`, `dnf`, `yum`, `apk`, `zypper`) bila belum tersedia.
  - Buat `.venv_induk` & install `-r induk/requirements_induk.txt`.
  - Buat `induk_data/` dan jalankan restore atomik bila `--restore <bundle>` diberikan.
  - Tulis `/etc/ufasproxy-induk/env` (`INDUK_API_KEY`, `INDUK_DATA_DIR`, `INDUK_REPO_DIR`) dengan `chmod 600` (pertahankan `INDUK_API_KEY` lama jika sudah ada dan tidak di-override).
  - Jika systemd aktif (`/run/systemd/system`), tulis `/etc/systemd/system/ufasproxy-induk.service` (`uvicorn induk.app:app --host 0.0.0.0 --port $INDUK_PORT`), `daemon-reload`, dan `enable --now`. Jika tanpa systemd (container/WSL), tampilkan perintah jalankan manual `.venv_induk/bin/uvicorn`.
- [ ] **Step 3: Perbarui `install_client()` di `install.sh` untuk mendukung Agent**
  - Pertahankan alur `.venv` + Chromium + `old_browser_vpn.py --selftest` + `token.env` yang sudah ada agar tetap 100% kompatibel.
  - Jika `--induk-url` dan `--agent-token` (atau env `INDUK_URL` & `AGENT_TOKEN`) tersedia — atau user memilih menyambungkan ke Induk di prompt interaktif — install `websockets>=13.0` di `.venv`, tulis `/etc/ufasproxy-agent/env` (`chmod 600`), set cap journald 100M, dan aktifkan `ufasproxy-agent.service` bila systemd berjalan (`[ -d /run/systemd/system ]`).
- [ ] **Step 4: Perbarui `README.md`**
  Dokumentasikan arsitektur singkat Server VPN vs Server Induk (bisa terpisah atau satu VPS), flag `install.sh --induk`, dan setup worker `--client` dengan `--induk-url`.
- [ ] **Step 5: Verifikasi akhir lintas komponen**
  ```bash
  bash -n install.sh
  python3 server.py --selftest
  python3 old_browser_vpn.py --selftest
  pytest tests/ -v
  ```
  Plus tes `bash install.sh --induk --induk-port 8000` (dan `--client`) di environment Linux (`wsl -d archlinux` / Ubuntu).
  Expected: `bash -n`, LF line ending, seluruh `--selftest`, dan `pytest tests/` 100% PASS.
- [ ] **Step 6: Commit & Push Task 4**
  ```bash
  git add install.sh README.md && git commit -m "feat(install): add --induk mode and optional Induk agent setup in --client" && git push origin main
  ```
