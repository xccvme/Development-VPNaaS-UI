# Pengujian

```sh
go test ./...
go vet ./...
python3 -m unittest discover -s tests -v
docker compose up -d --build
python3 scripts/compose_smoke.py http://127.0.0.1:8080
# Di host deployment, periksa persistensi restart juga:
SMOKE_RESTART=1 python3 scripts/compose_smoke.py
```

Smoke memakai login awal yang tercantum di [README](../README.md); skrip ini untuk deployment uji yang belum mengganti kredensial. Pemeriksaan mencakup anonymous denial, cookie, enam halaman, no-store, CSRF/Origin, respons backend asli, CA/Windows, popup sesi dan aset. Bila belum ada akun, smoke membuat satu akun disabled dengan password acak lalu menghapusnya; tidak mengubah akun yang sudah ada. `SMOKE_RESTART=1` menjalankan docker compose restart, memeriksa kunci sesi tetap sama/mode 600, API key tidak berubah, dan cookie autentikasi masih berlaku. Tidak mencetak key/password.

Pengujian HTTP tidak menggantikan pengujian browser dropdown/modal atau eksekusi PowerShell pada Windows. Screenshot `images/login.png` diambil dari deployment Linux setelah pembaruan logo/tombol dan penghapusan hint. Docker Desktop dan cmdlet Windows belum diuji pada perangkat Windows. Untuk jaringan host dan SSH tunnel, ikuti skenario di [README](../README.md).
