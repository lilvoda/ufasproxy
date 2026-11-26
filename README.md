# ufasproxy

On-demand OpenVPN-to-Proxy API Gateway (`http://user:pass@host:port`) untuk worker checker seperti `ufasvpn` — langsung memakai folder `.ovpn` (`vpns-surfshark` / `vpns-proton`) yang sudah ada tanpa download WireGuard key manual.

## Konsep Singkat
- Client mengirim request HTTP `POST /lease` dengan jumlah proxy yang dibutuhkan (`count = workers + 50%` backup).
- Gateway menyalakan `openvpn` + `microsocks` terisolasi di `ip netns` per slot (routing host & SSH `port 22` VPS 100% aman/tidak berubah), **menguji tiap slot ke API Moonton (`accountmtapi.mobilelegends.com`) sebelum dikirim**, lalu mengembalikan daftar `http://user:pass@GATEWAY_IP:PORT`.
- Flagged IP di-rotasi per slot lewat `POST /rotate`, lease mati otomatis dibersihkan TTL reaper, dan dilepas saat client memanggil `POST /release`.

## Quick Start
### 1. Gateway Server (Linux / VPS)
```bash
sudo bash install.sh
# Buka firewall port 8080/tcp (API) dan 20001:20045/tcp (proxy slots)
sudo python3 server.py --ovpn-dir /path/to/vpns-surfshark --port 8080 --token "<SECRET>"
```

### 2. Client Checker (`old_browser_vpn.py`)
```bash
pip install -r requirements.txt
python3 old_browser_vpn.py -c combo.txt -w auto --vpn-api-url http://<GATEWAY_IP>:8080 --vpn-api-token "<SECRET>" --no-prompt
```
Atau simpan `UFASPROXY_URL` dan `UFASPROXY_TOKEN` di env / `.env` / `token.env`, lalu jalankan `python3 old_browser_vpn.py`.

## Mapping File & Plan
Lihat [docs/PLAN.md](docs/PLAN.md) untuk pemetaan lengkap arsitektur, kontrak API, pengamanan SSH/kill-switch, dan tahapan implementasi.
