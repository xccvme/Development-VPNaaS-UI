// Command vpnaas-ui serves the GoTH (Go + templ + HTMX + Tailwind) VPNaaS console.
package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"vpnaas/ui-goth/internal/auth"
	"vpnaas/ui-goth/internal/upstream"
	"vpnaas/ui-goth/internal/web"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	listen := env("LISTEN_ADDR", "0.0.0.0:8080")
	keyFile := env("API_KEY_FILE", "/etc/vpnaas/api.key")
	sessionKeyFile := env("SESSION_KEY_FILE", "/etc/vpnaas/ui-session.key")
	upstreamURL := env("UPSTREAM_URL", "http://127.0.0.1:8000")
	key, err := auth.LoadOrCreateKey(sessionKeyFile)
	if err != nil {
		log.Fatalf("session key: %v", err)
	}
	h := web.New(web.Config{
		Upstream: upstream.New(upstreamURL, keyFile),
		Auth:     auth.New(key, os.Getenv("COOKIE_SECURE") == "1"),
	})
	srv := &http.Server{
		Addr: listen, Handler: h,
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 64 << 10,
	}
	log.Printf("vpnaas-ui listening on %s (upstream %s)", listen, upstreamURL)
	log.Fatal(srv.ListenAndServe())
}
