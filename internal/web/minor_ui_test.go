package web

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
	"vpnaas/ui-goth/internal/auth"
	"vpnaas/ui-goth/internal/upstream"
)

func TestCertificateDownload(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	current := ca
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/users/3/profile" || r.Header.Get("X-API-Key") != apiKey {
			t.Error("wrong authenticated upstream request")
		}
		json.NewEncoder(w).Encode(map[string]any{"ca_certificate": current, "password": "DO-NOT-EXPORT"})
	}))
	defer api.Close()
	kp := filepath.Join(t.TempDir(), "key")
	os.WriteFile(kp, []byte(apiKey), 0600)
	manager := auth.New([]byte(strings.Repeat("s", 64)), false)
	h := New(Config{Upstream: upstream.New(api.URL, kp), Auth: manager})
	request := func(logged bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/unduh/akun/3/vpnaas-ca.crt", nil)
		if logged {
			w := httptest.NewRecorder()
			manager.Login(w)
			r.AddCookie(w.Result().Cookies()[0])
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := request(false); w.Code != 401 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("anonymous: %d", w.Code)
	}
	w := request(true)
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/x-x509-ca-cert" || w.Header().Get("Content-Disposition") != `attachment; filename="vpnaas-ca.crt"` || w.Header().Get("Cache-Control") != "no-store" || w.Body.String() != ca {
		t.Fatalf("cert response: %d %v", w.Code, w.Header())
	}
	if strings.Contains(w.Body.String(), "DO-NOT-EXPORT") || strings.Contains(w.Body.String(), apiKey) {
		t.Fatal("secret leaked")
	}
	for _, bad := range []string{"", "-----BEGIN CERTIFICATE-----\nY2VydA==\n-----END CERTIFICATE-----", ca + "password", ca + string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("secret")}))} {
		current = bad
		if w := request(true); w.Code != 502 {
			t.Errorf("invalid cert accepted: %d", w.Code)
		}
	}
}

func TestSessionModal(t *testing.T) {
	e := setup(t)
	res, _ := e.do("GET", "/akun/3/sesi", nil, map[string]string{"HX-Request": "true"})
	if res.StatusCode != 401 {
		t.Fatal("modal needs auth")
	}
	e.login()
	e.api.users[0]["sessions"].([]any)[0].(map[string]any)["remote_address"] = "<script>bad</script>"
	_, body := e.do("GET", "/akun/3/sesi", nil, map[string]string{"HX-Request": "true"})
	for _, want := range []string{`role="dialog"`, `aria-modal="true"`, "Detail Sesi", "poc-client", "IKE #13", "ESTABLISHED", "CHILD #7", "INSTALLED", "5 B", "6 B", "&lt;script&gt;bad&lt;/script&gt;"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s", want)
		}
	}
	if strings.Contains(body, "<script>bad") || strings.Contains(body, "hx-put=") {
		t.Fatal("unsafe/editable modal")
	}
	_, body = e.do("GET", "/akun/9/sesi", nil, nil)
	if !strings.Contains(body, "Tidak ada sesi aktif") {
		t.Error("no empty state")
	}
	e.api.failPaths["users"] = 503
	_, body = e.do("GET", "/akun/3/sesi", nil, nil)
	if !strings.Contains(body, "Sesi tidak tersedia") || strings.Contains(body, "ESTABLISHED") {
		t.Error("stale sessions shown")
	}
}

func TestAccountMinorUI(t *testing.T) {
	e := setup(t)
	e.login()
	_, body := e.do("GET", "/akun", nil, nil)
	for _, want := range []string{`hx-get="/akun/3/sesi"`, `hx-target="#modal"`, `/unduh/akun/3/vpnaas-ca.crt`, "Download Sertifikat (.crt)", `alt="Logo VPNaaS"`} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s", want)
		}
	}
	for _, bad := range []string{"<summary", "Admin = status administratif", "Profil JSON berisi kredensial"} {
		if strings.Contains(body, bad) {
			t.Errorf("still present %s", bad)
		}
	}
	if !regexp.MustCompile(`rel="icon"[^>]+href="/static/vpn-logo.png\?v=[0-9a-f]{12}`).MatchString(body) {
		t.Error("missing local versioned favicon")
	}
	res, _ := e.do("GET", "/static/vpn-logo.png", nil, nil)
	if res.StatusCode != 200 {
		t.Error("logo unavailable")
	}
}

func TestGatewayAvailabilityLabel(t *testing.T) {
	e := setup(t)
	e.login()
	_, body := e.do("GET", "/ringkasan", nil, nil)
	re := regexp.MustCompile(`(?s)Telemetri Gateway.*?</a>`)
	card := re.FindString(body)
	if !strings.Contains(card, ">Active<") || strings.Contains(card, "Tersedia") {
		t.Errorf("available gateway label: %s", card)
	}
	e.api.failPaths["status"] = 503
	_, body = e.do("GET", "/ringkasan", nil, nil)
	card = re.FindString(body)
	if !strings.Contains(card, "Unknown") || strings.Contains(card, ">Active<") {
		t.Errorf("unavailable gateway: %s", card)
	}
}
