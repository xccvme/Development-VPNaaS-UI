# Pengembangan

Gunakan Go 1.27.4. Source templ dan hasil generator keduanya disimpan; CSS/HTMX/logo lokal ikut build melalui Go embed.

```sh
go test ./...
go vet ./...
CGO_ENABLED=0 go build -trimpath -o bin/vpnaas-ui ./cmd/vpnaas-ui
python3 -m unittest discover -s tests -v
```

Untuk mengubah tampilan, pasang templ v0.3.1118 dan Tailwind CLI v4.3.5 dari rilis resmi. `make build` menjalankan generator templ, kompilasi CSS, vet, test, dan build. Commit ulang `.templ`, `*_templ.go`, dan `internal/web/static/app.css`. Produksi hanya memakai generated assets, tanpa download CDN.

Struktur: `cmd/vpnaas-ui` konfigurasi/server, `internal/auth` sesi/CSRF, `upstream` allowlist proxy, `forms` validasi, `model` status, `views` templ, `web` handler/assets, `winsetup` generator PowerShell/golden tests. Docker menjalankan service melalui entrypoint, bukan unit systemd atau installer shell.
