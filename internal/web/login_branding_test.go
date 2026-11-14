package web

import (
	"regexp"
	"strings"
	"testing"
)

func TestLoginBranding(t *testing.T) {
	e := setup(t)
	res, body := e.do("GET", "/login", nil, nil)
	if res.StatusCode != 200 {
		t.Fatalf("login: %d", res.StatusCode)
	}
	if !regexp.MustCompile(`<img[^>]+src="/static/vpn-logo.png\?v=[0-9a-f]{12}"[^>]+alt="Logo VPNaaS"`).MatchString(body) {
		t.Error("login needs shared versioned logo")
	}
	if !regexp.MustCompile(`<button[^>]+type="submit"[^>]*>Login</button>`).MatchString(body) {
		t.Error("submit must say Login")
	}
	for _, hint := range []string{"Login PoC", "admin", ">V</span>"} {
		if strings.Contains(body, hint) {
			t.Errorf("unexpected login hint/placeholder: %s", hint)
		}
	}
}
