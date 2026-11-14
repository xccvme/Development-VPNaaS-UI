package upstream

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestAllowlistMatchesPythonProxy(t *testing.T) {
	allowed := [][2]string{
		{"GET", "health"}, {"GET", "overview"}, {"GET", "connections"}, {"GET", "users"}, {"GET", "policies"},
		{"GET", "status"}, {"GET", "audit"}, {"GET", "users/7/profile"},
		{"POST", "connections"}, {"POST", "users"}, {"POST", "policies"},
		{"POST", "connections/1/initiate"}, {"POST", "connections/1/terminate"},
		{"PUT", "users/1"}, {"DELETE", "users/1"}, {"PUT", "connections/2"}, {"DELETE", "policies/3"},
		{"GET", "connections/7/sites/a/config"}, {"GET", "connections/7/sites/b/config"},
		{"POST", "connections/7/sites/a/connect"}, {"POST", "connections/7/sites/b/disconnect"},
	}
	for _, a := range allowed {
		if !Allowed(a[0], a[1]) {
			t.Errorf("%v rejected", a)
		}
	}
	denied := [][2]string{
		{"PATCH", "users/1"}, {"POST", "users/1/profile"}, {"POST", "status"}, {"GET", "not-a-route"},
		{"GET", "users/1"}, {"DELETE", "users"}, {"GET", "users/../status"}, {"PUT", "users/.."},
		{"GET", "users/1/profile/x"}, {"GET", "users/a?b/profile"}, {"GET", "users/a#b/profile"},
		{"GET", `users/a\b/profile`}, {"POST", "connections/1/reload"}, {"GET", ""}, {"GET", "/users"},
		{"OPTIONS", "users"}, {"GET", "users//profile"},
		{"GET", "connections/7/sites/c/config"}, {"POST", "connections/7/sites/a/config"}, {"GET", "connections/7/sites/a/connect"},
		{"POST", "connections/7/sites/a/reload"}, {"GET", "connections/7/sites//config"}, {"DELETE", "connections/7/sites/a"},
	}
	for _, d := range denied {
		if Allowed(d[0], d[1]) {
			t.Errorf("%v allowed", d)
		}
	}
}

func keyFile(t *testing.T, v string) string {
	p := filepath.Join(t.TempDir(), "key")
	os.WriteFile(p, []byte(v), 0o600)
	return p
}

func TestDoSendsKeyAndBody(t *testing.T) {
	var gotKey, gotPath, gotBody, gotCT, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("X-API-Key")
		gotPath = r.URL.EscapedPath()
		gotQuery = r.URL.RawQuery
		gotCT = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		w.Write([]byte(`{"id":7}`))
	}))
	defer srv.Close()
	c := New(srv.URL, keyFile(t, "server-secret\n"))
	res, err := c.Do(context.Background(), "POST", "connections", "a=1", []byte(`{"name":"x"}`), "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != 201 || string(res.Body) != `{"id":7}` || gotKey != "server-secret" || gotPath != "/api/connections" || gotBody != `{"name":"x"}` || gotCT != "application/json" || gotQuery != "a=1" {
		t.Fatalf("unexpected: %+v %q %q %q %q", res, gotKey, gotPath, gotBody, gotCT)
	}
}

func TestErrors(t *testing.T) {
	c := New("http://127.0.0.1:1", filepath.Join(t.TempDir(), "missing"))
	if _, err := c.Do(context.Background(), "GET", "users", "", nil, ""); !errors.Is(err, ErrKey) {
		t.Fatalf("want ErrKey got %v", err)
	}
	c = New("http://127.0.0.1:1", keyFile(t, "  \n"))
	if _, err := c.Do(context.Background(), "GET", "users", "", nil, ""); !errors.Is(err, ErrKey) {
		t.Fatalf("empty key: want ErrKey got %v", err)
	}
	c = New("http://127.0.0.1:1", keyFile(t, "k"))
	if _, err := c.Do(context.Background(), "GET", "users", "", nil, ""); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want ErrUnavailable got %v", err)
	}
	if _, err := c.Do(context.Background(), "GET", "../etc", "", nil, ""); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("want ErrNotAllowed got %v", err)
	}
}

func TestDetail(t *testing.T) {
	cases := map[string]string{
		`{"detail":"Name already exists"}`: "Name already exists",
		`{"detail":[{"msg":"x"}]}`:         `[{"msg":"x"}]`,
		`not json`:                         "Permintaan gagal (HTTP 409)",
		`{"error":"boom"}`:                 "boom",
	}
	for body, want := range cases {
		r := &Response{Status: 409, Body: []byte(body)}
		if got := r.Detail(); got != want {
			t.Errorf("%s => %q want %q", body, got, want)
		}
	}
}

func TestRedirectNotFollowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.com/", http.StatusFound)
	}))
	defer srv.Close()
	c := New(srv.URL, keyFile(t, "k"))
	res, err := c.Do(context.Background(), "GET", "users", "", nil, "")
	if err != nil || res.Status != 302 {
		t.Fatalf("redirect followed: %v %+v", err, res)
	}
}
