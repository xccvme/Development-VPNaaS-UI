# VPNaaS Console

Konsol Go + templ + HTMX + Tailwind untuk mengelola koneksi S2S, akun C2S, kebijakan, status, dan audit. Logo/favicon, menu aksi ⋮, modal sesi, pilihan Split/Full, serta unduhan profil, Windows dan sertifikat CA disertakan.

## Menjalankan

Pasang [Docker Engine dan plugin Compose untuk Debian](https://docs.docker.com/engine/install/debian/), lalu jalankan pada host Linux yang sama dengan backend:

```sh
cp env.example .env
# Sesuaikan .env; backend harus sudah menyediakan file API key.
docker compose up -d --build
docker compose logs -f ui
```

Buka `http://IP-HOST:8080`. Login awal **admin:admin**; ganti `ADMIN_USERNAME` dan `ADMIN_PASSWORD` di `.env` sebelum membuka akses publik. Jangan commit `.env` atau API key. Gunakan firewall atau reverse proxy HTTPS untuk akses administratif.

Compose memakai jaringan host Linux agar backend `127.0.0.1:8000` tetap privat. Tidak perlu membuka port backend. File host `/etc/vpnaas/api.key` dipasang read-only; ubah `BACKEND_API_KEY_FILE` bila lokasinya berbeda. API key dibaca server-side, tidak disimpan dalam image. Build membutuhkan internet untuk image resmi, paket Debian dan modul Go; build juga memakai jaringan host.

## Konfigurasi

| Variabel `.env` | Default |
|---|---|
| `LISTEN_ADDR` | `0.0.0.0:8080` |
| `UPSTREAM_URL` | `http://127.0.0.1:8000` |
| `BACKEND_API_KEY_FILE` | `/etc/vpnaas/api.key` pada host |
| `ADMIN_USERNAME`, `ADMIN_PASSWORD` | `admin`, `admin` |
| `COOKIE_SECURE` | `0`; gunakan `1` untuk akses HTTPS |

Kunci sesi dibuat otomatis (0600) dalam volume `ui-state`, bukan dalam source/image. Restart atau recreate tidak mengubah kunci. `docker compose down` mempertahankan volume; **jangan gunakan `down -v`** bila sesi perlu dipertahankan. Menghapus volume mengganti kunci dan mengakhiri sesi aktif. Logout revocation bersifat in-memory.

```sh
docker compose up -d --build   # pembaruan source
docker compose restart ui
docker compose logs --tail=100 ui
docker compose down           # hentikan tanpa menghapus state
```

Source `.templ`, hasil `*_templ.go`, CSS terkompilasi dan aset lokal sudah disertakan; build produksi tidak membutuhkan Node, templ, atau Tailwind. Dockerfile multi-stage menjalankan test/vet dan menghasilkan binary Go statis. Untuk pengembangan lihat [panduan source](dokumentasi/PENGEMBANGAN.md), [fitur dan keamanan](dokumentasi/FITUR.md), serta [panduan verifikasi](dokumentasi/PENGUJIAN.md).
