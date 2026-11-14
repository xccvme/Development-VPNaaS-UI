# VPNaaS Console

UI Go + templ + HTMX + Tailwind untuk mengelola koneksi S2S, akun C2S, kebijakan, sesi, status gateway, audit, dan unduhan profil/Windows/CA. Backend VPNaaS harus sudah berjalan. Repository ini **hanya UI**, bukan installer backend; tidak ada `install.sh`.

## Pilih skenario

- **Linux, UI dan backend satu VM:** `compose.yaml` memakai host networking agar API `127.0.0.1:8000` tetap privat.
- **Windows, backend di server Linux:** Docker Desktop Linux containers dengan host networking aktif, SSH tunnel lokal, lalu `compose.windows.yaml`.

Login awal: username **admin**, password **admin**. Kredensial awal hanya didokumentasikan di README, tidak ditampilkan pada halaman login. Ganti `ADMIN_USERNAME` dan `ADMIN_PASSWORD` di `.env` sebelum penggunaan bersama atau akses publik.

## Windows — Docker Desktop sudah terpasang

Jalankan dari PowerShell. Gunakan Docker Desktop **4.34 atau lebih baru**, mode **Linux containers**, dan biarkan Desktop berjalan.

### 1. Git dan repository privat

```powershell
git --version
# Hanya bila Git belum terpasang:
winget install --id Git.Git -e --source winget
```

Setelah instalasi Git, buka ulang PowerShell. Git for Windows menyertakan Git Credential Manager. Saat clone HTTPS, selesaikan login GitHub di browser dengan akun yang diberi akses repository privat. Jangan memasukkan token ke URL, `.env`, command history, atau source.

```powershell
git clone https://github.com/xccvme/Development-VPNaaS-UI.git
cd Development-VPNaaS-UI
Copy-Item env.example .env
docker version
docker compose version
ssh -V
```

Jika `ssh`/`scp` belum tersedia, aktifkan fitur opsional Windows **OpenSSH Client**. Ganti `SERVER` pada contoh dengan alamat server backend. Akun SSH harus memiliki akses sah ke server dan file API key.

### 2. Aktifkan host networking

Buka Docker Desktop **Settings → Resources → Network → Enable host networking**, lalu **Apply & restart**. Fitur ini opt-in, membutuhkan versi 4.34+, hanya mendukung Linux containers, dan dapat tidak kompatibel dengan Enhanced Container Isolation. Jika kebijakan perangkat melarangnya, jalankan UI pada VM Linux seperti bagian berikut; jangan membuka API ke internet.

`compose.windows.yaml` adalah konfigurasi mandiri, bukan override: gunakan `-f` pada setiap perintah. Runtime memakai `network_mode: host`, tanpa port publishing. Dengan fitur Desktop tersebut aktif, container dapat mengakses layanan TCP loopback host. Tetap verifikasi koneksinya seperti di bawah: panduan ini **belum diuji pada Windows nyata**.

### 3. API key dan SSH tunnel

```powershell
New-Item -ItemType Directory -Force secrets | Out-Null
scp root@SERVER:/etc/vpnaas/api.key ./secrets/backend-api.key
```

Transfer memakai SSH. Jangan menampilkan isi key atau menempelkannya ke browser/chat. Batasi akses folder lokal melalui Windows Security/NTFS untuk akun yang menjalankan Docker Desktop; hindari folder bersama. `.env`, `*.key`, dan `secrets/` diabaikan Git dan build context. Key hanya dipasang read-only, bukan dimasukkan ke image.

Buka **PowerShell kedua** dan biarkan tunnel ini aktif selama UI dipakai:

```powershell
ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:18000:127.0.0.1:8000 root@SERVER
```

Tunnel bind hanya ke loopback Windows, bukan `0.0.0.0`. Sisi remote mengakses loopback server backend melalui SSH. Periksa fingerprint SSH saat koneksi pertama. Port SSH harus dapat dijangkau, tetapi **jangan membuka port API 8000**.

Di terminal pertama:

```powershell
Test-NetConnection 127.0.0.1 -Port 18000
curl.exe -i http://127.0.0.1:18000/api/overview
```

Respons 401/403 tanpa API key tetap menunjukkan API dapat dicapai, belum membuktikan autentikasi berhasil. Connection refused/timeout berarti tunnel atau backend belum siap.

### 4. Konfigurasi dan jalankan

Edit `notepad .env`, isi seperti berikut dan ganti password dengan nilai sendiri:

```dotenv
LISTEN_ADDR=127.0.0.1:8080
UPSTREAM_URL=http://127.0.0.1:18000
BACKEND_API_KEY_FILE=./secrets/backend-api.key
ADMIN_USERNAME=operator
ADMIN_PASSWORD=ganti-dengan-password-kuat
COOKIE_SECURE=0
```

```powershell
docker compose -f compose.windows.yaml config --quiet
docker compose -f compose.windows.yaml up -d --build
docker compose -f compose.windows.yaml ps
docker compose -f compose.windows.yaml logs --tail=100 ui
```

Buka **http://127.0.0.1:8080**, login memakai `.env`, lalu periksa Ringkasan dan Status Runtime. Data backend yang tampil tanpa error upstream membuktikan jalur container dan autentikasi bekerja; halaman login atau `/healthz` saja belum cukup. Bila host dapat mengakses tunnel tetapi UI gagal, cek host networking benar-benar aktif, Desktop sudah restart, file key benar, dan log upstream. Jangan mengatasi masalah dengan mempublikasikan API.

**Mengapa bukan `host.docker.internal`?** Loopback remote `127.0.0.1` bukan loopback Windows. Pada bridge Desktop, `host.docker.internal` menunjuk host, tetapi **tidak menjamin** layanan yang hanya bind ke loopback Windows dapat diakses secara default. Jangan mengganti upstream ke `http://host.docker.internal:18000` tanpa menguji dari container dan meninjau bind address/firewall. Pada Linux, `host-gateway` juga menunjuk IP gateway bridge, bukan loopback host. Solusi di sini sengaja menggunakan host networking + tunnel host-only; alternatifnya jalankan UI di VM backend.

## Linux baru — UI dan backend satu VM

Contoh Debian/Ubuntu dengan `sudo`. Tinjau dampak upgrade/reboot pada VM produksi. Jika login root dan `sudo` tidak tersedia, hilangkan awalan `sudo`.

```sh
sudo apt update
sudo apt upgrade -y
sudo apt install -y curl ca-certificates git
curl https://get.docker.com -o get-docker.sh
# Tinjau skrip sebelum menjalankannya dengan hak root.
sudo sh get-docker.sh
sudo systemctl enable --now docker
sudo docker version
sudo docker compose version
```

Skrip tersebut milik Docker, bukan installer project. Gunakan repository/paket resmi Docker sesuai kebijakan organisasi bila convenience script tidak diperbolehkan. Contoh tetap memakai `sudo docker`: akses grup docker setara hak root.

Clone dengan akun GitHub yang memiliki akses repository privat. Gunakan credential manager aman atau prompt HTTPS, **tanpa token di URL**. Password akun GitHub tidak berlaku untuk Git HTTPS. Jangan memakai credential helper plaintext `store` untuk token.

```sh
git clone https://github.com/xccvme/Development-VPNaaS-UI.git
cd Development-VPNaaS-UI
cp env.example .env
sudo test -f /etc/vpnaas/api.key
# Edit .env dengan editor pilihan Anda.
```

Untuk backend satu VM:

```dotenv
LISTEN_ADDR=0.0.0.0:8080
UPSTREAM_URL=http://127.0.0.1:8000
BACKEND_API_KEY_FILE=/etc/vpnaas/api.key
ADMIN_USERNAME=operator
ADMIN_PASSWORD=ganti-dengan-password-kuat
COOKIE_SECURE=0
```

```sh
chmod 600 .env
sudo docker compose config --quiet
sudo docker compose up -d --build
sudo docker compose ps
sudo docker compose logs --tail=100 ui
```

Buka **http://IP-VM:8080** dari jaringan yang diizinkan firewall. Backend harus mendengarkan pada loopback VM. `/etc/vpnaas/api.key` harus file benar, bukan direktori; mount read-only menolak pembuatan direktori otomatis bila file hilang. Jangan menyalin key ke source/image. Build Linux juga memakai jaringan host dan membutuhkan internet untuk image resmi, paket Debian, serta modul Go.

**Linux dengan backend remote:** buat tunnel SSH yang sama pada host Linux (`127.0.0.1:18000`), salin key dengan `scp` ke `./secrets/backend-api.key`, batasi mode file `chmod 600`, set `UPSTREAM_URL=http://127.0.0.1:18000` serta `BACKEND_API_KEY_FILE=./secrets/backend-api.key`. Tetap gunakan `compose.yaml` host networking dan pertahankan tunnel. Tidak perlu bridge gateway atau API publik.

## Port dan keamanan

| Variabel `.env` | Kegunaan |
|---|---|
| `LISTEN_ADDR` | Alamat/port UI host network. Linux default `0.0.0.0:8080`; Windows contoh `127.0.0.1:8080`. |
| `UPSTREAM_URL` | Satu VM `http://127.0.0.1:8000`; SSH tunnel `http://127.0.0.1:18000`. |
| `BACKEND_API_KEY_FILE` | File di **host**, dipasang read-only ke `/run/secrets/backend-api.key`. Windows gunakan path relatif `./secrets/backend-api.key`. |
| `ADMIN_USERNAME`, `ADMIN_PASSWORD` | Login UI, terpisah dari akun VPN/API key; kosong memakai login awal di atas. |
| `COOKIE_SECURE` | `0` untuk HTTP lokal, `1` hanya untuk akses browser melalui HTTPS. |

Untuk port 9090, ganti `LISTEN_ADDR=127.0.0.1:9090` (lokal) atau `0.0.0.0:9090` (jaringan dengan firewall), lalu jalankan `up -d` lagi dan buka alamat baru. Tidak ada `ports:` atau `UI_PORT`: host networking menggunakan `LISTEN_ADDR` langsung; port harus bebas. `EXPOSE 8080` pada Dockerfile hanya metadata.

Jangan membuka login awal ke internet. Batasi firewall dan gunakan reverse proxy HTTPS untuk akses jaringan. Pertahankan Host/skema yang sesuai validasi Origin aplikasi. API key hanya dibaca server-side. Hindari membagikan `docker compose config` tanpa `--quiet`, karena environment dapat berisi password. Lindungi akses Docker daemon serta backup key/state.

## Operasional, state, dan pembaruan

Linux (tambahkan `sudo` bila diperlukan):

```sh
docker compose ps
docker compose logs -f --tail=100 ui
docker compose restart ui
git pull --ff-only
docker compose up -d --build
docker compose down
```

Windows PowerShell:

```powershell
docker compose -f compose.windows.yaml ps
docker compose -f compose.windows.yaml logs -f --tail=100 ui
docker compose -f compose.windows.yaml restart ui
git pull --ff-only
docker compose -f compose.windows.yaml up -d --build
docker compose -f compose.windows.yaml down
```

`restart` tidak membaca ulang `.env`; setelah perubahan konfigurasi pakai `up -d` untuk recreate. Sesudah update source pakai `up -d --build`. Setelah reboot Windows, Docker Desktop dan tunnel harus aktif kembali; `restart: always` tidak menyalakan Desktop atau SSH tunnel secara otomatis.

Kunci sesi dibuat otomatis mode 0600 dalam volume `ui-state`. Restart/recreate mempertahankan kunci dan cookie yang belum kedaluwarsa. `down` mempertahankan volume; **jangan gunakan `down -v`** kecuali ingin membuang kunci dan memutus semua sesi. Logout revocation bersifat in-memory. Data VPN tetap disimpan backend, bukan volume UI. Backup state/config/key secara aman, terpisah dari Git.

## Source dan verifikasi

Dockerfile multi-stage menjalankan Go test/vet dan menghasilkan binary statis. `.templ`, hasil `*_templ.go`, CSS terkompilasi, HTMX, dan logo lokal sudah disertakan. Build produksi tidak membutuhkan Node, templ, atau Tailwind di host; tidak memakai CDN.

Lihat [pengembangan](dokumentasi/PENGEMBANGAN.md), [fitur/keamanan](dokumentasi/FITUR.md), serta [pengujian](dokumentasi/PENGUJIAN.md). Deployment diverifikasi pada Linux; Docker Desktop belum diuji pada Windows nyata. Keberhasilan HTTP/Linux tidak membuktikan cmdlet VPN Windows atau networking Desktop pada perangkat Anda sudah berjalan.
