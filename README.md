# VPNaaS Enterprise Dev Console (UI)

Console web ringan berbasis **Go + templ + HTMX + Tailwind CSS** untuk pengujian dan operasional **VPNaaS Backend REST API** (IPsec/IKEv2 FIPS). Repository ini **hanya UI** — Backend VPNaaS harus sudah terpasang dan berjalan.

### Struktur Menu
- **Dashboard** (`/ringkasan`) — ringkasan jumlah & status S2S, C2S, Static Routing, dan Telemetri Gateway.
- **VPNaaS** (`/sites`) — tab terpadu untuk **Site-to-Site (S2S)**, **Client-to-Site (C2S)**, **Grup C2S**, **Static Routing**, **Firewall Rules**, dan **PKI** (mendukung sertifikat dengan masa berlaku hari maupun *No Expiration*).
- **Status & Diagnostik** (`/status`) — readiness `/api/ready`, metadata gateway, cek jalur konektivitas, dan log layanan.
- **Audit Log** (`/audit`) — riwayat aktivitas control-plane.

> **Integrasi Customer Portal:** UI ini berkomunikasi langsung ke Backend menggunakan native REST API (`/api/*` + `X-API-Key`). Customer Portal menggunakan endpoint, payload JSON, dan `X-API-Key` yang **sama persis**, cukup buka port `8000` di Security Group khusus untuk IP Customer Portal.

---

## 1. Instalasi Baru (Linux — Satu VM dengan Backend)

Pastikan Docker & Docker Compose sudah terpasang:
```bash
sudo apt-get update && sudo apt-get install -y curl ca-certificates git
curl -fsSL https://get.docker.com | sudo sh
sudo systemctl enable --now docker
```

Clone repo dan konfigurasi `.env`:
```bash
git clone https://github.com/xccvme/Development-VPNaaS-UI.git
cd Development-VPNaaS-UI
cp env.example .env
chmod 600 .env
nano .env
```

Isi `.env` (ganti `ADMIN_USERNAME` dan `ADMIN_PASSWORD`):
```dotenv
LISTEN_ADDR=0.0.0.0:8080
UPSTREAM_URL=http://127.0.0.1:8000
BACKEND_API_KEY_FILE=/etc/vpnaas/api.key
ADMIN_USERNAME=operator
ADMIN_PASSWORD=ganti-dengan-password-kuat
COOKIE_SECURE=0
```

Bangun dan jalankan container:
```bash
sudo docker compose up -d --build
sudo docker compose ps
sudo docker compose logs --tail=50 ui
```

Akses UI di **`http://<IP-SERVER>:8080`**.

---

## 2. Cara Update UI (Saat Ada Perubahan di GitHub)

Gunakan langkah ini agar file yang dihapus di repo ikut bersih (mencegah konflik build dari file lama):

```bash
cd ~/Development-VPNaaS-UI
git fetch origin
git reset --hard origin/main
sudo docker compose up -d --build
sudo docker compose ps
```

> File `.env` tidak akan terhapus oleh `git reset --hard` karena diabaikan oleh `.gitignore`.
> Jika hanya mengubah `.env` (mis. ganti `ADMIN_PASSWORD` atau `LISTEN_ADDR`), cukup jalankan:
> ```bash
> sudo docker compose up -d --force-recreate
> ```

---

## 3. Cara Install Ulang Bersih / Reset State UI (Clean Reinstall)

Menghapus container, volume session key (`ui-state`), serta clone ulang dari GitHub (data VPN di Backend **tidak ikut terhapus**):

```bash
cd ~/Development-VPNaaS-UI
sudo docker compose down -v

# Simpan .env bila ingin dipakai lagi, lalu clone ulang bersih
cp .env /tmp/vpnaas-ui.env.bak
cd ~
rm -rf Development-VPNaaS-UI
git clone https://github.com/xccvme/Development-VPNaaS-UI.git
cd Development-VPNaaS-UI
mv /tmp/vpnaas-ui.env.bak .env
chmod 600 .env

sudo docker compose up -d --build
sudo docker compose logs --tail=50 ui
```

---

## 4. Menjalankan dari Windows (Remote ke Server Backend)

1. Aktifkan **Settings → Resources → Network → Enable host networking** di Docker Desktop.
2. Salin API key backend dan buka SSH tunnel:
   ```powershell
   New-Item -ItemType Directory -Force secrets | Out-Null
   scp root@SERVER:/etc/vpnaas/api.key ./secrets/backend-api.key
   ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:18000:127.0.0.1:8000 root@SERVER
   ```
3. Set `.env` (`UPSTREAM_URL=http://127.0.0.1:18000`, `BACKEND_API_KEY_FILE=./secrets/backend-api.key`, `LISTEN_ADDR=127.0.0.1:8080`), lalu jalankan:
   ```powershell
   docker compose -f compose.windows.yaml up -d --build
   ```

---

## 5. Variabel Lingkungan `.env`

| Variabel | Default | Keterangan |
| :--- | :--- | :--- |
| `LISTEN_ADDR` | `0.0.0.0:8080` | Alamat & port UI (host networking). |
| `UPSTREAM_URL` | `http://127.0.0.1:8000` | URL Backend REST API VPNaaS. |
| `BACKEND_API_KEY_FILE` | `/etc/vpnaas/api.key` | Path file API key di host (di-mount read-only). |
| `ADMIN_USERNAME` | `admin` | Username login console. |
| `ADMIN_PASSWORD` | `admin` | Password login console (wajib diganti). |
| `COOKIE_SECURE` | `0` | Set `1` hanya jika diakses lewat HTTPS. |

## Pengembangan & Pengujian

Dockerfile multi-stage otomatis menjalankan `go test ./...`, `go vet ./...`, dan menghasilkan binary statis Go. Untuk verifikasi lokal:
```bash
templ generate
go vet ./...
go test -count=1 ./...
```
