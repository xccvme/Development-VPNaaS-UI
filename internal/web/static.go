package web

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"mime"
	"net/http"
	"path"
	"strings"
	"time"

	"vpnaas/ui-goth/internal/views"
)

// staticAsset is an embedded file served with a strong ETag and, for text
// types, a pre-compressed gzip variant.
type staticAsset struct {
	body, gz   []byte
	ctype, tag string
}

var staticAssets = map[string]staticAsset{}

func init() {
	for _, f := range []string{"app.css", "htmx.min.js", "app.js", "vpn-logo.png"} {
		b, err := staticFS.ReadFile("static/" + f)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(b)
		a := staticAsset{body: b, ctype: mime.TypeByExtension(path.Ext(f)), tag: `"` + hex.EncodeToString(sum[:8]) + `"`}
		if a.ctype == "" {
			a.ctype = http.DetectContentType(b)
		}
		if !strings.HasPrefix(a.ctype, "image/") {
			var buf bytes.Buffer
			zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
			zw.Write(b)
			zw.Close()
			a.gz = buf.Bytes()
		}
		staticAssets[f] = a
	}
}

// serveStatic: versioned URLs (?v=<AssetVersion>) are immutable for a year;
// anything else revalidates via ETag so stale bundles never stick.
func serveStatic(w http.ResponseWriter, r *http.Request) {
	a, ok := staticAssets[strings.TrimPrefix(r.URL.Path, "/static/")]
	if !ok {
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	if r.URL.Query().Get("v") == views.AssetVersion {
		h.Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		h.Set("Cache-Control", "public, max-age=0, must-revalidate")
	}
	h.Set("Content-Type", a.ctype)
	body, tag := a.body, a.tag
	if a.gz != nil {
		h.Add("Vary", "Accept-Encoding")
		if acceptsGzip(r) {
			body, tag = a.gz, strings.TrimSuffix(a.tag, `"`)+`-gz"`
			h.Set("Content-Encoding", "gzip")
		}
	}
	h.Set("ETag", tag)
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(body))
}

func acceptsGzip(r *http.Request) bool {
	for _, p := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		enc, q, _ := strings.Cut(strings.TrimSpace(p), ";")
		if strings.EqualFold(strings.TrimSpace(enc), "gzip") && strings.ReplaceAll(q, " ", "") != "q=0" {
			return true
		}
	}
	return false
}
