# Fitur dan keamanan

- Ringkasan, koneksi S2S CRUD/initiate/terminate, akun C2S CRUD/reset, kebijakan CRUD, status runtime, audit dan pencarian HTMX.
- Status administratif terpisah dari runtime; kegagalan telemetri ditampilkan Unknown, bukan tunnel sehat.
- Akun memiliki mode Split/Full. Menu ⋮ mendukung klik, hover dan keyboard; sesi tampil dalam modal read-only. Hapus tetap meminta konfirmasi.
- Logo dan favicon menggunakan aset PNG lokal yang sama. [Logo](images/vpn-logo.png), [contoh login](images/login.png).
- Unduhan profil JSON, Windows PowerShell dan CA wajib autentikasi dan `Cache-Control: no-store`. Profil JSON dapat berisi kredensial akun; simpan secara aman. Skrip Windows tidak menyertakan password akun.
- CA diparse sebagai satu PEM CERTIFICATE CA menggunakan crypto/x509; tidak mengandung private key. Unduhan CA cocok dengan CA dalam profil dan setup Windows.
- Mode Full menghapus rute khusus lama dan memakai `SplitTunneling $false`; Split memakai rute eksplisit. Setelah mengubah mode, unduh ulang setup, jalankan saat VPN terputus, lalu reconnect. Verifikasi HTTP Linux bukan bukti cmdlet Windows berjalan pada perangkat pengguna.
- Cookie HMAC HttpOnly/SameSite Strict dengan kunci persisten 0600, masa berlaku 8 jam. Origin harus sama persis dan mutasi terautentikasi wajib CSRF. Login memakai pemeriksaan Origin; logout mencabut sesi in-memory.
- API key hanya dibaca di server. Proxy fixed-upstream membatasi metode/path, tidak mengikuti redirect upstream atau env proxy. Tidak menerima URL proxy dari browser.
- Rendering templ melakukan escaping; CSP self-only, no-frame, nosniff dan no-store diterapkan. Aset lokal memakai versi hash konten.

Jangan membuka login default ke internet tanpa firewall/HTTPS dan mengganti kredensial. Header `COOKIE_SECURE=1` hanya untuk HTTPS; reverse proxy perlu mempertahankan Host dan skema yang sesuai validasi Origin aplikasi.
