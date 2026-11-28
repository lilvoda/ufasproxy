# ufasproxy

On-demand OpenVPN-to-Proxy API Gateway (`http://user:pass@host:port`) untuk worker checker seperti `ufasvpn` — langsung memakai folder `.ovpn` (`vpns-surfshark` / `vpns-proton`) yang sudah ada tanpa download WireGuard key manual.

## Konsep Singkat
- Client mengirim request HTTP `POST /lease` dengan jumlah proxy yang dibutuhkan (`count = workers + 50%` backup).
- Gateway menyalakan `openvpn` + `microsocks` terisolasi di `ip netns` per slot (routing host & SSH `port 22` VPS 100% aman/tidak berubah), **menguji tiap slot ke API Moonton (`accountmtapi.mobilelegends.com`) sebelum dikirim**, lalu mengembalikan daftar `http://user:pass@GATEWAY_IP:PORT`.
- Flagged IP di-rotasi per slot lewat `POST /rotate`, lease mati otomatis dibersihkan TTL reaper, dan dilepas saat client memanggil `POST /release`.

## Quick Start
### 1. Gateway Server (Linux / VPS)
```bash
sudo bash install.sh --server --tg-token "<BOT_TOKEN>" --tg-chat-id "<CHAT_ID>"
# Buka firewall port 8080/tcp (API) dan 20001:20045/tcp (proxy slots)
sudo python3 server.py --ovpn-dir /path/to/vpns-surfshark --udp-only --port 8080
```
*(Kredensial `UFASPROXY_TOKEN`, `UFASPROXY_TG_TOKEN`, `UFASPROXY_TG_CHAT_ID`, dan `UFASPROXY_TG_INTERVAL` tersimpan di `token.env` `chmod 600` dan otomatis dibaca `server.py` / `systemd EnvironmentFile`.)*

### 2. Server Induk Controller (Multi-VPS Control Plane, Opsional)
Bisa dipasang di VPS terpisah **atau** di VPS yang sama dengan Gateway VPN (`--server --induk` memakai service & port berbeda: `:8000` vs `:8080`):
```bash
sudo bash install.sh --induk --induk-port 8000
# Buka Web UI Dashboard di http://<INDUK_IP>:8000 (login dengan username/password di /etc/ufasproxy-induk/env)
```

### 3. Client Checker (`old_browser_vpn.py` & Opsional Agent Induk di CT / Worker)
```bash
bash install.sh --client
# Atau sekalian daftarkan worker agent 2-arah ke Induk:
bash install.sh --client --induk-url http://<INDUK_IP>:8000 --agent-token "<TOKEN>" --vps-id vps-1

source .venv/bin/activate
python old_browser_vpn.py -c input/koi.txt -w auto --vpn-api-url http://<GATEWAY_IP>:8080 --vpn-api-token "<SECRET>" --no-prompt
```
*(Jalankan `bash install.sh` tanpa flag untuk memilih mode `[1] Client`, `[2] Server VPN`, `[3] Server Induk`, `[4] Server VPN + Induk`, atau `[5] Semua`. Simpan `UFASPROXY_URL` & `UFASPROXY_TOKEN` di env / `.env` / `token.env` untuk auto-connect.)*

## Mapping File & Plan
Lihat [docs/PLAN.md](docs/PLAN.md) untuk arsitektur gateway dan [docs/superpowers/plans/2026-11-28-induk-controller.md](docs/superpowers/plans/2026-11-28-induk-controller.md) untuk controller Induk multi-VPS.
