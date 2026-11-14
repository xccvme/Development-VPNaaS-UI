package auth

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newManager() *Manager {
	return New([]byte(strings.Repeat("k", 64)), false)
}

func TestCredentials(t *testing.T) {
	if !CheckCredentials("admin", "admin") {
		t.Fatal("admin:admin rejected")
	}
	for _, c := range [][2]string{{"admin", "wrong"}, {"root", "admin"}, {"", ""}, {"é", "admin"}, {"admin ", "admin"}} {
		if CheckCredentials(c[0], c[1]) {
			t.Fatalf("%q accepted", c)
		}
	}
}

func TestSessionCookieRoundTripAndFlags(t *testing.T) {
	m := newManager()
	w := httptest.NewRecorder()
	csrf := m.Login(w)
	res := w.Result()
	cookies := res.Cookies()
	if len(cookies) != 1 {
		t.Fatal("expected one cookie")
	}
	c := cookies[0]
	if c.Name != CookieName || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.MaxAge <= 0 {
		t.Fatalf("bad cookie flags: %+v", c)
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(c)
	s, ok := m.Session(r)
	if !ok || s.CSRF != csrf || s.CSRF == "" {
		t.Fatal("session not recognised")
	}
	// Tampering with the payload or signature is rejected.
	for _, v := range []string{c.Value + "x", "x" + c.Value, strings.Replace(c.Value, ".", ".9", 1), "", "a.b.c"} {
		r := httptest.NewRequest("GET", "/", nil)
		r.AddCookie(&http.Cookie{Name: CookieName, Value: v})
		if _, ok := m.Session(r); ok {
			t.Fatalf("tampered cookie %q accepted", v)
		}
	}
	// Another key does not validate it.
	other := New([]byte(strings.Repeat("z", 64)), false)
	if _, ok := other.Session(r); ok {
		t.Fatal("foreign key accepted")
	}
}

func TestSecureFlag(t *testing.T) {
	m := New([]byte(strings.Repeat("k", 64)), true)
	w := httptest.NewRecorder()
	m.Login(w)
	if !w.Result().Cookies()[0].Secure {
		t.Fatal("secure flag missing")
	}
}

func TestExpiryAndLogout(t *testing.T) {
	m := newManager()
	now := time.Now()
	m.now = func() time.Time { return now }
	w := httptest.NewRecorder()
	m.Login(w)
	c := w.Result().Cookies()[0]
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(c)
	s, ok := m.Session(r)
	if !ok {
		t.Fatal("no session")
	}
	m.now = func() time.Time { return now.Add(TTL + time.Second) }
	if _, ok := m.Session(r); ok {
		t.Fatal("expired session accepted")
	}
	m.now = func() time.Time { return now }
	lw := httptest.NewRecorder()
	m.Logout(lw, s)
	if _, ok := m.Session(r); ok {
		t.Fatal("revoked session accepted")
	}
	if lc := lw.Result().Cookies(); len(lc) != 1 || lc[0].MaxAge >= 0 {
		t.Fatal("logout did not clear cookie")
	}
}

func TestCSRF(t *testing.T) {
	m := newManager()
	w := httptest.NewRecorder()
	token := m.Login(w)
	c := w.Result().Cookies()[0]
	mk := func(h, form string) *http.Request {
		r := httptest.NewRequest("POST", "/x", strings.NewReader(form))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if h != "" {
			r.Header.Set("X-CSRF-Token", h)
		}
		r.AddCookie(c)
		return r
	}
	r := mk(token, "")
	s, _ := m.Session(r)
	if !m.CheckCSRF(r, s) {
		t.Fatal("header token rejected")
	}
	r = mk("", "csrf_token="+token)
	if !m.CheckCSRF(r, s) {
		t.Fatal("form token rejected")
	}
	for _, bad := range []string{"", "nope", token + "x"} {
		r = mk(bad, "")
		if m.CheckCSRF(r, s) {
			t.Fatalf("bad token %q accepted", bad)
		}
	}
	// Token of another session is not valid for this one.
	w2 := httptest.NewRecorder()
	other := m.Login(w2)
	if other == token || m.CheckCSRF(mk(other, ""), s) {
		t.Fatal("cross-session token accepted")
	}
}

func TestSameOrigin(t *testing.T) {
	m := newManager()
	r := httptest.NewRequest("POST", "http://dash.local:8080/x", nil)
	r.Host = "dash.local:8080"
	if m.SameOrigin(r) {
		t.Fatal("missing origin accepted")
	}
	r.Header.Set("Origin", "http://evil.test")
	if m.SameOrigin(r) {
		t.Fatal("evil origin accepted")
	}
	r.Header.Set("Origin", "https://dash.local:8080")
	if m.SameOrigin(r) {
		t.Fatal("scheme mismatch accepted")
	}
	r.Header.Set("Origin", "http://dash.local:8080")
	if !m.SameOrigin(r) {
		t.Fatal("same origin rejected")
	}
	r.Header.Set("Origin", "null")
	if m.SameOrigin(r) {
		t.Fatal("null origin accepted")
	}
}

func TestLoadOrCreateKey(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "session.key")
	k1, err := LoadOrCreateKey(p)
	if err != nil || len(k1) < 32 {
		t.Fatalf("create: %v", err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
	k2, err := LoadOrCreateKey(p)
	if err != nil || string(k1) != string(k2) {
		t.Fatal("key not stable")
	}
	os.Chmod(p, 0o644)
	if _, err := LoadOrCreateKey(p); err == nil {
		t.Fatal("world-readable key accepted")
	}
	short := filepath.Join(dir, "short")
	os.WriteFile(short, []byte("abc"), 0o600)
	if _, err := LoadOrCreateKey(short); err == nil {
		t.Fatal("short key accepted")
	}
}
