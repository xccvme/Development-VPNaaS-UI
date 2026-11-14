// Package auth implements the PoC admin login, HMAC-signed session cookies,
// CSRF tokens and Origin validation.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	CookieName = "vpnaas_session"
	TTL        = 8 * time.Hour
	// PoC credentials only.
	adminUser = "admin"
	adminPass = "admin"
)

// CheckCredentials compares in constant time (both fields always evaluated).
func CheckCredentials(user, pass string) bool {
	wantUser, wantPass := os.Getenv("ADMIN_USERNAME"), os.Getenv("ADMIN_PASSWORD")
	if wantUser == "" {
		wantUser = adminUser
	}
	if wantPass == "" {
		wantPass = adminPass
	}
	u := hmac.Equal([]byte(user), []byte(wantUser))
	p := hmac.Equal([]byte(pass), []byte(wantPass))
	return u && p
}

type Session struct {
	ID      string
	CSRF    string
	Expires time.Time
}

type Manager struct {
	key     []byte
	secure  bool
	now     func() time.Time
	mu      sync.Mutex
	revoked map[string]time.Time
}

func New(key []byte, secure bool) *Manager {
	return &Manager{key: key, secure: secure, now: time.Now, revoked: map[string]time.Time{}}
}

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (m *Manager) sign(payload string) string {
	mac := hmac.New(sha256.New, m.key)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// csrfFor derives the CSRF token from the session id so it needs no storage.
func (m *Manager) csrfFor(id string) string {
	return m.sign("csrf|" + id)
}

// Login issues a new session cookie and returns its CSRF token.
func (m *Manager) Login(w http.ResponseWriter) string {
	id := randomToken(24)
	exp := m.now().Add(TTL).Unix()
	payload := id + "." + strconv.FormatInt(exp, 10)
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: payload + "." + m.sign("session|"+payload), Path: "/",
		MaxAge: int(TTL.Seconds()), HttpOnly: true, Secure: m.secure, SameSite: http.SameSiteStrictMode,
	})
	return m.csrfFor(id)
}

func (m *Manager) Session(r *http.Request) (Session, bool) {
	c, err := r.Cookie(CookieName)
	if err != nil {
		return Session{}, false
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) != 3 || parts[0] == "" {
		return Session{}, false
	}
	payload := parts[0] + "." + parts[1]
	if !hmac.Equal([]byte(parts[2]), []byte(m.sign("session|"+payload))) {
		return Session{}, false
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || m.now().Unix() >= exp {
		return Session{}, false
	}
	m.mu.Lock()
	_, gone := m.revoked[parts[0]]
	m.mu.Unlock()
	if gone {
		return Session{}, false
	}
	return Session{ID: parts[0], CSRF: m.csrfFor(parts[0]), Expires: time.Unix(exp, 0)}, true
}

// Logout revokes the session server-side and clears the cookie.
func (m *Manager) Logout(w http.ResponseWriter, s Session) {
	m.mu.Lock()
	now := m.now()
	for id, exp := range m.revoked {
		if now.After(exp) {
			delete(m.revoked, id)
		}
	}
	m.revoked[s.ID] = s.Expires
	m.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: m.secure, SameSite: http.SameSiteStrictMode})
}

// CheckCSRF accepts the token from X-CSRF-Token (HTMX) or csrf_token form field.
func (m *Manager) CheckCSRF(r *http.Request, s Session) bool {
	token := r.Header.Get("X-CSRF-Token")
	if token == "" {
		token = r.PostFormValue("csrf_token")
	}
	return token != "" && subtle.ConstantTimeCompare([]byte(token), []byte(s.CSRF)) == 1
}

// SameOrigin requires an Origin header equal to scheme://Host of this request.
func (m *Manager) SameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	want := scheme + "://" + r.Host
	return origin != "" && subtle.ConstantTimeCompare([]byte(origin), []byte(want)) == 1
}

// LoadOrCreateKey reads a hex session key (mode 0600) or creates one atomically.
func LoadOrCreateKey(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		k := make([]byte, 48)
		if _, err := rand.Read(k); err != nil {
			return nil, err
		}
		_, werr := f.WriteString(hex.EncodeToString(k) + "\n")
		cerr := f.Close()
		if werr != nil || cerr != nil {
			return nil, errors.Join(werr, cerr)
		}
	} else if !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("session key %s must not be group/world accessible (mode %o)", path, st.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	k := strings.TrimSpace(string(raw))
	if len(k) < 64 {
		return nil, fmt.Errorf("session key %s too short", path)
	}
	return []byte(k), nil
}
