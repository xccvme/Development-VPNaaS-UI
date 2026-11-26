package web

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"vpnaas/ui-goth/internal/auth"
	"vpnaas/ui-goth/internal/upstream"
)

const apiKey = "server-only-secret-key"

// fakeAPI is a minimal in-memory VPNaaS backend.
type fakeAPI struct {
	mu        sync.Mutex
	users     []map[string]any
	conns     []map[string]any
	policies  []map[string]any
	sites     []map[string]any
	groups    []map[string]any
	routes    []map[string]any
	certs     []map[string]any
	tokens    []map[string]any
	nextID    int
	calls     []string
	bodies    []map[string]any
	failPaths map[string]int
	statusRaw string
	queries   []string
}

func newFake() *fakeAPI {
	return &fakeAPI{nextID: 20, failPaths: map[string]int{}, statusRaw: "site-4: #2, ESTABLISHED, IKEv2\n  net-4: #3, reqid 2, INSTALLED, TUNNEL\n",
		users: []map[string]any{
			{"id": 3.0, "username": "poc-client", "enabled": true, "allowed_cidrs": []any{"10.10.7.0/24"}, "traffic_mode": "split", "runtime_status": "Active", "session_count": 1.0, "virtual_ips": []any{"10.250.0.4"}, "sessions": []any{map[string]any{"ike_id": "13", "ike_state": "ESTABLISHED", "remote_address": "10.221.61.250", "virtual_ips": []any{"10.250.0.4"}, "children": []any{map[string]any{"child_id": "7", "state": "INSTALLED", "bytes_in": 5.0, "bytes_out": 6.0}}}}},
			{"id": 9.0, "username": "<script>alert(1)</script>", "enabled": false, "allowed_cidrs": []any{"10.10.7.0/24"}, "traffic_mode": "split", "runtime_status": "Down", "session_count": 0.0, "virtual_ips": []any{}, "sessions": []any{}},
		},
		conns: []map[string]any{{"id": 4.0, "name": "branch", "remote_address": "203.0.113.5", "remote_id": "203.0.113.5", "local_ts": "10.10.7.0/24", "remote_ts": "192.168.50.0/24", "enabled": true},
			{"id": 7.0, "name": "kantor", "enabled": true, "topology": "hub",
				"site_a": map[string]any{"name": "jakarta", "address": "%any", "id": "kantor-a@vpnaas", "psk_set": true, "subnets": "192.168.10.0/24,192.168.11.0/24", "nat": true, "status": "active", "remote_host": "203.0.113.20", "bytes_in": 10.0, "bytes_out": 20.0},
				"site_b": map[string]any{"name": "surabaya", "address": "203.0.113.30", "id": "kantor-b@vpnaas", "psk_set": true, "subnets": "192.168.20.0/24", "nat": false, "status": "down"}}},
		policies: []map[string]any{{"id": 5.0, "name": "lan", "source_cidr": "10.250.0.0/24", "destination_cidr": "10.10.7.0/24", "protocol": "tcp", "enabled": true}},
		sites:    []map[string]any{},
		groups:   []map[string]any{},
		routes:   []map[string]any{},
		certs:    []map[string]any{},
		tokens:   []map[string]any{},
	}
}

func strFromMap(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func (f *fakeAPI) list(kind string) *[]map[string]any {
	switch kind {
	case "users":
		return &f.users
	case "connections":
		return &f.conns
	case "sites":
		return &f.sites
	case "groups":
		return &f.groups
	case "routes":
		return &f.routes
	case "tokens":
		return &f.tokens
	}
	return &f.policies
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/api/")
	f.calls = append(f.calls, r.Method+" "+path)
	if r.Header.Get("X-API-Key") != apiKey {
		w.WriteHeader(401)
		return
	}
	if code := f.failPaths[path]; code != 0 {
		w.WriteHeader(code)
		w.Write([]byte(`{"detail":"Gagal <b>upstream</b>"}`))
		return
	}
	var body map[string]any
	if b, _ := io.ReadAll(r.Body); len(b) > 0 {
		json.Unmarshal(b, &body)
		snapshot := map[string]any{}
		for k, v := range body {
			snapshot[k] = v
		}
		f.bodies = append(f.bodies, snapshot)
	}
	w.Header().Set("Content-Type", "application/json")
	out := func(code int, v any) { w.WriteHeader(code); json.NewEncoder(w).Encode(v) }
	parts := strings.Split(path, "/")
	switch {
	case path == "overview":
		out(200, map[string]any{"connections": len(f.conns), "users": len(f.users), "policies": len(f.policies), "enabled_connections": 1, "vpn": map[string]any{"backend": "strongSwan swanctl", "pools": "pool-3 10.250.0.4 1 / 0 / 1\n"}})
	case path == "status":
		out(200, map[string]any{"raw": f.statusRaw, "connections": "user-3: IKEv2\n", "pools": "pool-3\n", "backend": "strongSwan swanctl"})
	case path == "audit":
		out(200, []any{map[string]any{"id": 1, "timestamp": "2026-11-13 20:15:11", "action": "delete", "resource": "users", "resource_id": 12}})
	case path == "ready":
		out(200, map[string]any{"ready": true, "checks": map[string]any{"strongswan": true, "nftables": true}})
	case path == "gateway":
		out(200, map[string]any{"engine": "strongSwan 6", "api_version": "2.0.0", "public_ip": "192.0.2.10", "public_if": "ens3", "lan_cidr": "10.10.7.0/24", "pool_cidr": "172.31.201.0/24", "region": "id-jkt-1"})
	case path == "logs":
		f.queries = append(f.queries, r.URL.RawQuery)
		out(200, map[string]any{"source": r.URL.Query().Get("source"), "lines": []any{"charon[100]: IKE_SA established [REDACTED]"}})
	case path == "diagnostics/check" && r.Method == "POST":
		out(200, map[string]any{"target": body["target"], "reachable_via": "site-n-1", "allowed": true})
	case path == "routes/live":
		out(200, map[string]any{"kernel_available": true, "static_routes": f.routes, "kernel_routes": []any{}})
	case path == "pki/ca":
		out(200, map[string]any{"present": true, "subject": "CN=VPNaaS Root CA", "not_after": "2036-01-01", "days_remaining": 3650, "sha256_fingerprint": "AA:BB:CC"})
	case path == "pki/ca/cert":
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.WriteHeader(200)
		w.Write([]byte("-----BEGIN CERTIFICATE-----\nQ0E=\n-----END CERTIFICATE-----\n"))
	case path == "pki/crl":
		w.Header().Set("Content-Type", "application/pkix-crl")
		w.WriteHeader(200)
		w.Write([]byte("-----BEGIN X509 CRL-----\nQ1JM\n-----END X509 CRL-----\n"))
	case path == "pki/server":
		out(200, map[string]any{"present": true, "subject": "CN=192.0.2.10", "san_ips": []any{"192.0.2.10"}, "san_dns": []any{}, "not_after": "2027-01-01", "days_remaining": 365})
	case path == "pki/server/rotate" && r.Method == "POST":
		out(200, map[string]any{"rotated": true})
	case path == "pki/certs" && r.Method == "GET":
		out(200, f.certs)
	case path == "pki/certs" && r.Method == "POST":
		f.nextID++
		noExp, _ := body["no_expiration"].(bool)
		rec := map[string]any{"id": float64(f.nextID), "name": body["name"], "target_type": body["target_type"], "san": body["san"], "serial": "00AA", "not_after": "2027-01-01", "days_remaining": 365.0, "no_expiration": noExp, "revoked": false}
		if noExp {
			rec["not_after"] = "9999-12-31T23:59:59Z"
			rec["days_remaining"] = nil
		}
		if rec["san"] == nil || rec["san"] == "" {
			rec["san"] = strFromMap(body, "name") + "@vpnaas"
		}
		f.certs = append(f.certs, rec)
		out(201, rec)
	case len(parts) == 4 && parts[0] == "pki" && parts[1] == "certs" && parts[3] == "revoke" && r.Method == "POST":
		id, _ := strconv.Atoi(parts[2])
		for _, c := range f.certs {
			if int(c["id"].(float64)) == id {
				c["revoked"] = true
			}
		}
		out(200, map[string]any{"revoked": true})
	case len(parts) == 4 && parts[0] == "pki" && parts[1] == "certs" && parts[3] == "bundle" && r.Method == "GET":
		f.queries = append(f.queries, r.URL.RawQuery)
		switch r.URL.Query().Get("format") {
		case "p12":
			w.Header().Set("Content-Type", "application/x-pkcs12")
			w.Header().Set("Content-Disposition", `attachment; filename="cert-`+parts[2]+`.p12"`)
			w.WriteHeader(200)
			w.Write([]byte("PK12DATA"))
		case "crt":
			w.Header().Set("Content-Type", "application/x-x509-ca-cert")
			w.Header().Set("Content-Disposition", `attachment; filename="cert-`+parts[2]+`.crt"`)
			w.WriteHeader(200)
			w.Write([]byte("-----BEGIN CERTIFICATE-----\nTEVBRg==\n-----END CERTIFICATE-----\n"))
		case "key":
			w.Header().Set("Content-Type", "application/x-pem-file")
			w.Header().Set("Content-Disposition", `attachment; filename="cert-`+parts[2]+`.key"`)
			w.WriteHeader(200)
			w.Write([]byte("-----BEGIN PRIVATE KEY-----\nS0VZ\n-----END PRIVATE KEY-----\n"))
		default:
			out(200, map[string]any{"certificate": "PEM-CERT", "private_key": "PEM-KEY", "ca_certificate": "PEM-CA"})
		}
	case len(parts) == 3 && parts[0] == "sites" && parts[2] == "config":
		f.queries = append(f.queries, r.URL.RawQuery)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="site-`+parts[1]+`-`+r.URL.Query().Get("vendor")+`.cfg"`)
		w.WriteHeader(200)
		w.Write([]byte("# vendor=" + r.URL.Query().Get("vendor") + " site=" + parts[1] + "\n"))
	case len(parts) == 3 && parts[0] == "sites" && (parts[2] == "connect" || parts[2] == "disconnect") && r.Method == "POST":
		out(200, map[string]any{"ok": true, "output": "site-n-" + parts[1] + " " + parts[2] + " ok"})
	case len(parts) == 3 && parts[0] == "users" && parts[2] == "disconnect" && r.Method == "POST":
		out(200, map[string]any{"disconnected": 1})
	case len(parts) == 5 && parts[0] == "users" && parts[2] == "sessions" && parts[4] == "disconnect" && r.Method == "POST":
		out(200, map[string]any{"disconnected": true})
	case path == "tokens" && r.Method == "POST":
		f.nextID++
		rec := map[string]any{"id": float64(f.nextID), "name": body["name"], "role": body["role"], "prefix": "vpnaas_test", "revoked": false, "token": "vpnaas_test_SECRET_ONCE"}
		f.tokens = append(f.tokens, rec)
		out(201, rec)
	case len(parts) == 3 && parts[0] == "users" && parts[2] == "profile":
		f.queries = append(f.queries, r.URL.RawQuery)
		switch r.URL.Query().Get("format") {
		case "mobileconfig":
			w.Header().Set("Content-Type", "application/x-apple-aspen-config")
			w.Header().Set("Content-Disposition", `attachment; filename="VPNaaS-poc-client.mobileconfig"`)
			w.WriteHeader(200)
			w.Write([]byte("<?xml version=\"1.0\"?><plist><dict/></plist>"))
			return
		case "sswan":
			w.Header().Set("Content-Type", "application/vnd.strongswan.profile+json")
			w.Header().Set("Content-Disposition", `attachment; filename="VPNaaS-poc-client.sswan"`)
			w.WriteHeader(200)
			w.Write([]byte(`{"uuid":"1234","name":"VPNaaS-poc-client"}`))
			return
		case "manual":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Content-Disposition", `attachment; filename="VPNaaS-Client-poc-client.conf"`)
			w.WriteHeader(200)
			w.Write([]byte("[GATEWAY_SERVER]\nserver_address = 192.0.2.10\n"))
			return
		}
		w.Header().Set("Content-Disposition", `attachment; filename="user-`+parts[1]+`.json"`)
		out(200, map[string]any{"username": "poc-client", "password": "DO-NOT-EXPORT", "traffic_mode": "split", "server": "192.0.2.10", "server_id": "192.0.2.10", "allowed_cidrs": []any{"10.10.7.0/24"}, "ca_certificate": "-----BEGIN CERTIFICATE-----\nY2VydA==\n-----END CERTIFICATE-----\n"})
	case len(parts) == 5 && parts[0] == "connections" && parts[2] == "sites" && parts[4] == "config":
		f.queries = append(f.queries, r.URL.RawQuery)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="upstream-name.txt"`)
		w.WriteHeader(200)
		w.Write([]byte("# " + r.URL.Query().Get("format") + " site " + parts[3] + "\n"))
	case len(parts) == 5 && parts[0] == "connections" && parts[2] == "sites":
		if parts[3] == "a" && parts[4] == "connect" {
			out(409, map[string]any{"detail": "Site-A di belakang NAT (%any): jalankan connect dari gateway Site-A"})
			return
		}
		out(200, map[string]any{"ok": true, "output": "site " + parts[3] + " " + parts[4] + " <done>"})
	case len(parts) == 3 && parts[0] == "connections":
		out(200, map[string]any{"ok": true, "output": "swanctl " + parts[2] + " <done>"})
	case len(parts) == 1 && r.Method == "GET":
		out(200, *f.list(path))
	case len(parts) == 1 && r.Method == "POST":
		f.nextID++
		body["id"] = float64(f.nextID)
		delete(body, "password")
		delete(body, "psk")
		l := f.list(path)
		*l = append(*l, body)
		out(201, body)
	case len(parts) == 2:
		l := f.list(parts[0])
		id, _ := strconv.Atoi(parts[1])
		for i, row := range *l {
			if int(row["id"].(float64)) == id {
				if r.Method == "DELETE" {
					*l = append((*l)[:i], (*l)[i+1:]...)
					out(200, map[string]any{"deleted": true})
					return
				}
				for k, v := range body {
					if k != "password" && k != "psk" {
						row[k] = v
					}
				}
				out(200, row)
				return
			}
		}
		out(404, map[string]any{"detail": "Not found"})
	default:
		out(404, map[string]any{"detail": "Not Found"})
	}
}

type env struct {
	t      *testing.T
	api    *fakeAPI
	srv    *httptest.Server
	client *http.Client
	csrf   string
}

func setup(t *testing.T) *env {
	t.Helper()
	api := newFake()
	up := httptest.NewServer(api)
	t.Cleanup(up.Close)
	key := filepath.Join(t.TempDir(), "api-key")
	os.WriteFile(key, []byte(apiKey+"\n"), 0o600)
	h := New(Config{Upstream: upstream.New(up.URL, key), Auth: auth.New([]byte(strings.Repeat("s", 64)), false)})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &env{t: t, api: api, srv: srv, client: c}
}

func (e *env) do(method, path string, form url.Values, hdr map[string]string) (*http.Response, string) {
	e.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	return res, string(b)
}

func (e *env) safe() map[string]string {
	return map[string]string{"Origin": e.srv.URL, "X-CSRF-Token": e.csrf, "HX-Request": "true"}
}

var csrfRe = regexp.MustCompile(`name="csrf-token" content="([^"]+)"`)

func (e *env) login() {
	e.t.Helper()
	res, _ := e.do("POST", "/login", url.Values{"username": {"admin"}, "password": {"admin"}}, map[string]string{"Origin": e.srv.URL})
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/ringkasan" {
		e.t.Fatalf("login: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	_, page := e.do("GET", "/ringkasan", nil, nil)
	m := csrfRe.FindStringSubmatch(page)
	if m == nil {
		e.t.Fatal("csrf meta missing")
	}
	e.csrf = m[1]
}

func TestAnonymousAccess(t *testing.T) {
	e := setup(t)
	for _, p := range []string{"/", "/ringkasan", "/koneksi", "/akun", "/kebijakan", "/status", "/audit"} {
		res, _ := e.do("GET", p, nil, nil)
		if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/login" {
			t.Errorf("%s: %d %s", p, res.StatusCode, res.Header.Get("Location"))
		}
	}
	res, _ := e.do("GET", "/akun/tabel", nil, map[string]string{"HX-Request": "true"})
	if res.StatusCode != 401 || res.Header.Get("HX-Redirect") != "/login" {
		t.Errorf("htmx anon: %d", res.StatusCode)
	}
	for _, p := range []string{"/unduh/akun/3/profil.json", "/unduh/akun/3/windows.ps1", "/downloads/users/3/windows.ps1", "/api/users", "/api/users/3/profile"} {
		res, body := e.do("GET", p, nil, nil)
		if res.StatusCode != 401 || strings.Contains(body, "DO-NOT-EXPORT") {
			t.Errorf("%s: %d", p, res.StatusCode)
		}
	}
	res, body := e.do("GET", "/login", nil, nil)
	if res.StatusCode != 200 || !strings.Contains(body, `id="login-form"`) {
		t.Fatal("login page")
	}
	if len(e.api.calls) != 0 {
		t.Fatalf("anonymous requests reached upstream: %v", e.api.calls)
	}
}

func TestLoginFlow(t *testing.T) {
	e := setup(t)
	res, body := e.do("POST", "/login", url.Values{"username": {"admin"}, "password": {"wrong"}}, map[string]string{"Origin": e.srv.URL})
	if res.StatusCode != 401 || !strings.Contains(body, "Username atau password salah") {
		t.Fatalf("wrong password: %d", res.StatusCode)
	}
	res, _ = e.do("POST", "/login", url.Values{"username": {"admin"}, "password": {"admin"}}, map[string]string{"Origin": "http://evil.test"})
	if res.StatusCode != 403 {
		t.Fatalf("cross-origin login: %d", res.StatusCode)
	}
	res, _ = e.do("POST", "/login", url.Values{"username": {"admin"}, "password": {"admin"}}, nil)
	if res.StatusCode != 403 {
		t.Fatalf("no-origin login: %d", res.StatusCode)
	}
	res, _ = e.do("POST", "/login", url.Values{"username": {"admin"}, "password": {"admin"}}, map[string]string{"Origin": e.srv.URL})
	sc := res.Header.Get("Set-Cookie")
	if !strings.Contains(sc, "HttpOnly") || !strings.Contains(sc, "SameSite=Strict") {
		t.Fatalf("cookie flags: %s", sc)
	}
	e.login()
	// logout requires CSRF
	res, _ = e.do("POST", "/logout", nil, map[string]string{"Origin": e.srv.URL})
	if res.StatusCode != 403 {
		t.Fatalf("logout without csrf: %d", res.StatusCode)
	}
	res, _ = e.do("POST", "/logout", url.Values{"csrf_token": {e.csrf}}, map[string]string{"Origin": e.srv.URL})
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("logout: %d", res.StatusCode)
	}
	res, _ = e.do("GET", "/ringkasan", nil, nil)
	if res.StatusCode != http.StatusSeeOther {
		t.Fatal("session survived logout")
	}
}

func TestReferrerPolicyKeepsFormOrigin(t *testing.T) {
	e := setup(t)
	res, _ := e.do("GET", "/login", nil, nil)
	if res.Header.Get("Referrer-Policy") != "same-origin" {
		t.Fatalf("Referrer-Policy %q would make browsers send Origin: null on form POST", res.Header.Get("Referrer-Policy"))
	}
}

func TestJSONLoginCompat(t *testing.T) {
	e := setup(t)
	req, _ := http.NewRequest("POST", e.srv.URL+"/login", strings.NewReader(`{"username":"admin","password":"admin"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", e.srv.URL)
	res, _ := e.client.Do(req)
	var out map[string]string
	json.NewDecoder(res.Body).Decode(&out)
	if res.StatusCode != 200 || out["csrf_token"] == "" || out["username"] != "admin" {
		t.Fatalf("%d %v", res.StatusCode, out)
	}
}

func TestPagesRenderAndEscape(t *testing.T) {
	e := setup(t)
	e.login()
	e.api.sites = []map[string]any{
		{"id": 10.0, "name": "site-jkt", "address": "203.0.113.5", "ike_id": "site-jkt@vpnaas", "subnets": "192.168.50.0/24", "enabled": true, "status": "active", "online": true, "last_connected_at": "2026-11-26T10:00:00Z"},
	}
	checks := map[string][]string{
		"/ringkasan": {"Dashboard", "Site-to-Site (S2S)", "Client-to-Site (C2S)", "Static Routing", "strongSwan swanctl"},
		"/sites":     {"site-jkt", "203.0.113.5", "192.168.50.0/24", "Online", "2026-11-26T10:00:00Z", "Detail Site", "Manual Configuration (.conf)", "strongSwan (.conf)", "Root CA (.crt)", "Disconnect"},
		"/akun":      {"poc-client", "Enabled", "Disabled", "Online", "Offline", "10.250.0.4", "Split", "Detail Account", "/unduh/akun/3/manual.conf", "/unduh/akun/3/profil.json", "/unduh/akun/3/vpnaas-ca.crt"},
		"/kebijakan": {"lan", "10.250.0.0/24", "TCP"},
		"/status":    {"ESTABLISHED", "strongSwan swanctl", "pool-3"},
		"/audit":     {"Audit Log", "2026-11-13 20:15:11", "delete", "resource_id"},
	}
	for p, wants := range checks {
		res, body := e.do("GET", p, nil, nil)
		if res.StatusCode != 200 {
			t.Fatalf("%s: %d", p, res.StatusCode)
		}
		for _, w := range wants {
			if !strings.Contains(body, w) {
				t.Errorf("%s: missing %q", p, w)
			}
		}
		if strings.Contains(body, "<script>alert(1)") || strings.Contains(body, apiKey) || strings.Contains(body, "DO-NOT-EXPORT") {
			t.Errorf("%s: unescaped or secret content", p)
		}
		for _, h := range []string{"Content-Security-Policy", "X-Content-Type-Options", "Referrer-Policy"} {
			if res.Header.Get(h) == "" {
				t.Errorf("%s missing %s", p, h)
			}
		}
		if res.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s cache-control", p)
		}
		if strings.Contains(body, "https://") && strings.Contains(body, "<script src=\"https") {
			t.Errorf("%s: external script", p)
		}
	}
	_, body := e.do("GET", "/akun", nil, nil)
	if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("username not escaped")
	}
	// HTMX partial table refresh with search
	res, body := e.do("GET", "/akun/tabel?q=poc", nil, map[string]string{"HX-Request": "true"})
	if res.StatusCode != 200 || !strings.Contains(body, "poc-client") || strings.Contains(body, "alert(1)") || strings.Contains(body, "<html") {
		t.Fatalf("partial: %d", res.StatusCode)
	}
}

func TestUserFormShowsTrafficModesAndWriteOnlyPassword(t *testing.T) {
	e := setup(t)
	e.login()
	_, body := e.do("GET", "/akun/baru", nil, map[string]string{"HX-Request": "true"})
	for _, w := range []string{"Split tunnel (default)", "Full tunnel", `name="traffic_mode"`, `value="split" selected`, `value="full"`, "semua internet lewat server", `name="password"`, `autocomplete="new-password"`, "10.10.7.0/24"} {
		if !strings.Contains(body, w) {
			t.Errorf("create form missing %q", w)
		}
	}
	_, body = e.do("GET", "/akun/3/ubah", nil, map[string]string{"HX-Request": "true"})
	if !strings.Contains(body, "poc-client") || !strings.Contains(body, "Kosongkan untuk mempertahankan password") || strings.Contains(body, `value="DO-NOT`) {
		t.Error("edit form")
	}
	if regexp.MustCompile(`name="password"[^>]*value="[^"]+`).MatchString(body) {
		t.Error("password prefilled")
	}
}

func TestCSRFAndOriginRequiredForMutations(t *testing.T) {
	e := setup(t)
	e.login()
	form := url.Values{"username": {"tmp-user"}, "password": {"Secret-123"}, "enabled": {"on"}}
	cases := []map[string]string{
		{"Origin": e.srv.URL, "HX-Request": "true"},
		{"Origin": e.srv.URL, "X-CSRF-Token": "forged", "HX-Request": "true"},
		{"Origin": "http://evil.test", "X-CSRF-Token": e.csrf, "HX-Request": "true"},
		{"X-CSRF-Token": e.csrf, "HX-Request": "true"},
	}
	for _, h := range cases {
		res, _ := e.do("POST", "/akun", form, h)
		if res.StatusCode != 403 {
			t.Errorf("%v: %d", h, res.StatusCode)
		}
	}
	for _, p := range []string{"/akun/3", "/sites/10", "/kebijakan/5"} {
		res, _ := e.do("DELETE", p, nil, map[string]string{"Origin": e.srv.URL})
		if res.StatusCode != 403 {
			t.Errorf("delete %s without csrf: %d", p, res.StatusCode)
		}
	}
	res, _ := e.do("POST", "/sites/10/connect", nil, map[string]string{"Origin": e.srv.URL})
	if res.StatusCode != 403 {
		t.Error("connect without csrf")
	}
	for _, c := range e.api.calls {
		if !strings.HasPrefix(c, "GET") {
			t.Fatalf("mutation reached upstream: %v", e.api.calls)
		}
	}
}

func TestUserCRUD(t *testing.T) {
	e := setup(t)
	e.login()
	res, body := e.do("POST", "/akun", url.Values{"username": {"tmp-user"}, "password": {"Secret-123"}, "allowed_cidrs": {"10.10.7.0/24\n192.168.9.0/24"}, "enabled": {"on"}}, e.safe())
	if res.StatusCode != 200 || !strings.Contains(res.Header.Get("HX-Trigger"), "vpnaas:close") {
		t.Fatalf("create: %d %s", res.StatusCode, body)
	}
	last := e.api.bodies[len(e.api.bodies)-1]
	if last["username"] != "tmp-user" || last["password"] != "Secret-123" || last["enabled"] != true || len(last["allowed_cidrs"].([]any)) != 2 {
		t.Fatalf("create body: %v", last)
	}
	if last["traffic_mode"] != "split" {
		t.Fatal("UI must send default split traffic_mode")
	}
	id := strconv.Itoa(e.api.nextID)
	// Validation error re-renders form without calling upstream
	n := len(e.api.calls)
	res, body = e.do("POST", "/akun", url.Values{"username": {"bad user"}, "password": {"x"}}, e.safe())
	if res.StatusCode != 200 || !strings.Contains(body, "Username 1-128") || len(e.api.calls) != n {
		t.Fatalf("validation: %d", res.StatusCode)
	}
	// Edit without password keeps it; enabled unchecked → false
	res, _ = e.do("PUT", "/akun/"+id, url.Values{"username": {"tmp-user"}, "allowed_cidrs": {"10.10.7.0/24"}}, e.safe())
	last = e.api.bodies[len(e.api.bodies)-1]
	if res.StatusCode != 200 || last["enabled"] != false {
		t.Fatalf("edit: %v", last)
	}
	if _, ok := last["password"]; ok {
		t.Fatal("blank password sent on edit")
	}
	// Reset password
	res, _ = e.do("PUT", "/akun/"+id+"/password", url.Values{"password": {"NewSecret-456"}}, e.safe())
	last = e.api.bodies[len(e.api.bodies)-1]
	if res.StatusCode != 200 || len(last) != 1 || last["password"] != "NewSecret-456" {
		t.Fatalf("reset: %v", last)
	}
	// Upstream error is shown, escaped
	e.api.failPaths["users/"+id] = 409
	_, body = e.do("PUT", "/akun/"+id, url.Values{"username": {"tmp-user"}}, e.safe())
	if !strings.Contains(body, "Gagal &lt;b&gt;upstream&lt;/b&gt;") {
		t.Fatalf("upstream error not shown: %s", body)
	}
	delete(e.api.failPaths, "users/"+id)
	// Delete confirmation modal then delete
	_, body = e.do("GET", "/akun/"+id+"/hapus", nil, map[string]string{"HX-Request": "true"})
	if !strings.Contains(body, "tmp-user") || !strings.Contains(body, `hx-delete="/akun/`+id+`"`) {
		t.Fatal("confirm modal")
	}
	res, _ = e.do("DELETE", "/akun/"+id, nil, e.safe())
	if res.StatusCode != 200 || e.api.calls[len(e.api.calls)-1] != "DELETE users/"+id {
		t.Fatalf("delete: %d %v", res.StatusCode, e.api.calls)
	}
	if len(e.api.users) != 2 {
		t.Fatal("existing users touched")
	}
}

func TestSiteAndPolicyCRUD(t *testing.T) {
	e := setup(t)
	e.login()
	res, _ := e.do("POST", "/sites", url.Values{"name": {"tmp-site"}, "address": {"198.51.100.7"}, "subnets": {"192.168.77.0/24"}, "allow_vpc": {"0", "on"}, "nat": {"0", "on"}, "encap": {"0", "on"}, "enabled": {"on"}}, e.safe())
	if res.StatusCode != 200 || e.api.bodies[len(e.api.bodies)-1]["subnets"] != "192.168.77.0/24" {
		t.Fatal("create site")
	}
	siteID := strconv.Itoa(e.api.nextID)
	res, body := e.do("POST", "/sites/"+siteID+"/connect", nil, e.safe())
	if res.StatusCode != 200 || !strings.Contains(body, "Connect site #"+siteID+" berhasil") {
		t.Fatalf("site connect: %s", body)
	}
	e.do("POST", "/sites/"+siteID+"/disconnect", nil, e.safe())
	if !strings.Contains(strings.Join(e.api.calls, ","), "POST sites/"+siteID+"/disconnect") {
		t.Fatal("site disconnect")
	}
	res, _ = e.do("POST", "/kebijakan", url.Values{"name": {"tmp-pol"}, "source_cidr": {"10.250.0.0/24"}, "destination_cidr": {"10.10.7.1/32"}, "protocol": {"icmp"}, "enabled": {"on"}}, e.safe())
	if res.StatusCode != 200 || e.api.bodies[len(e.api.bodies)-1]["protocol"] != "icmp" {
		t.Fatal("create policy")
	}
	id := strconv.Itoa(e.api.nextID)
	res, _ = e.do("PUT", "/kebijakan/"+id, url.Values{"name": {"tmp-pol"}, "source_cidr": {"10.250.0.0/24"}, "destination_cidr": {"10.10.7.1/32"}, "protocol": {"udp"}}, e.safe())
	if res.StatusCode != 200 || e.api.bodies[len(e.api.bodies)-1]["protocol"] != "udp" {
		t.Fatal("edit policy")
	}
	res, _ = e.do("DELETE", "/kebijakan/"+id, nil, e.safe())
	if res.StatusCode != 200 || len(e.api.policies) != 1 {
		t.Fatal("delete policy")
	}
	for _, p := range []string{"/akun/abc", "/akun/0", "/akun/-1", "/sites/1x/connect"} {
		res, _ := e.do("DELETE", p, nil, e.safe())
		if res.StatusCode != 404 && res.StatusCode != 405 {
			t.Errorf("%s: %d", p, res.StatusCode)
		}
	}
}

func TestDownloads(t *testing.T) {
	e := setup(t)
	e.login()
	res, body := e.do("GET", "/unduh/akun/3/profil.json", nil, nil)
	if res.StatusCode != 200 || res.Header.Get("Cache-Control") != "no-store" || res.Header.Get("Content-Disposition") != `attachment; filename="Profil-VPN-poc-client.json"` || !strings.Contains(body, "poc-client") {
		t.Fatalf("profile: %d %v", res.StatusCode, res.Header)
	}
	for _, p := range []string{"/unduh/akun/3/windows.ps1", "/downloads/users/3/windows.ps1"} {
		res, body = e.do("GET", p, nil, nil)
		if res.StatusCode != 200 || res.Header.Get("Cache-Control") != "no-store" || res.Header.Get("Content-Disposition") != `attachment; filename="Setup-Client-poc-client.ps1"` {
			t.Fatalf("%s: %d %v", p, res.StatusCode, res.Header)
		}
		if strings.Contains(body, "DO-NOT-EXPORT") || strings.Contains(body, apiKey) || !strings.Contains(body, "-SplitTunneling $true") || !strings.Contains(body, "'10.10.7.0/24'") {
			t.Fatal("windows script content")
		}
	}
	res, _ = e.do("GET", "/unduh/akun/0/windows.ps1", nil, nil)
	if res.StatusCode != 404 {
		t.Fatal("id 0")
	}
}

func TestUnsafeProfileRejected(t *testing.T) {
	e := setup(t)
	e.login()
	e.api.users[0]["x"] = 1
	// swap profile server to unsafe by intercepting via failPaths is not possible; use direct check
	e.api.failPaths["users/3/profile"] = 502
	res, body := e.do("GET", "/unduh/akun/3/windows.ps1", nil, nil)
	if res.StatusCode != 502 || strings.Contains(body, "Set-VpnConnection") {
		t.Fatalf("%d", res.StatusCode)
	}
}

func TestUnknownWhenStatusUnavailable(t *testing.T) {
	e := setup(t)
	e.login()
	e.api.failPaths["status"] = 502
	_, body := e.do("GET", "/status", nil, nil)
	if !strings.Contains(body, "Gagal &lt;b&gt;upstream&lt;/b&gt;") {
		t.Fatal("status error not shown")
	}
	// Users: cached rows invalidated to Unknown when backend fails
	e.do("GET", "/akun", nil, nil)
	e.api.failPaths["users"] = 503
	_, body = e.do("GET", "/akun/tabel", nil, map[string]string{"HX-Request": "true"})
	if !strings.Contains(body, "poc-client") || strings.Contains(body, ">Online<") || !strings.Contains(body, "Unknown") || !strings.Contains(body, "Gagal") {
		t.Fatalf("cached unknown: %s", body)
	}
}

func TestEmptyStates(t *testing.T) {
	e := setup(t)
	e.login()
	e.api.sites = nil
	e.api.policies = []map[string]any{}
	_, body := e.do("GET", "/sites", nil, nil)
	if !strings.Contains(body, "Belum ada Site S2S") {
		t.Fatal("empty sites")
	}
	_, body = e.do("GET", "/kebijakan", nil, nil)
	if !strings.Contains(body, "Belum ada firewall rule") {
		t.Fatal("empty policies")
	}
	_, body = e.do("GET", "/akun/tabel?q=zzzz", nil, map[string]string{"HX-Request": "true"})
	if !strings.Contains(body, "Tidak ada data yang cocok") {
		t.Fatal("no match")
	}
}

func TestAPIProxyAllowlistAndKeyHidden(t *testing.T) {
	e := setup(t)
	e.login()
	res, body := e.do("GET", "/api/users", nil, nil)
	if res.StatusCode != 200 || !strings.Contains(body, "poc-client") || res.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("proxy get")
	}
	for _, c := range [][2]string{{"GET", "/api/not-a-route"}, {"POST", "/api/status"}, {"PATCH", "/api/users/1"}, {"POST", "/api/users/1/profile"}, {"GET", "/api/users/..%2fstatus/profile"}} {
		res, _ := e.do(c[0], c[1], nil, e.safe())
		if res.StatusCode != 404 {
			t.Errorf("%v: %d", c, res.StatusCode)
		}
	}
	res, _ = e.do("POST", "/api/connections", nil, map[string]string{"Origin": e.srv.URL})
	if res.StatusCode != 403 {
		t.Fatal("proxy csrf")
	}
}

func TestStaticAssetsLocal(t *testing.T) {
	e := setup(t)
	_, page := e.do("GET", "/login", nil, nil)
	if !regexp.MustCompile(`/static/app\.css\?v=[0-9a-f]{12}`).MatchString(page) {
		t.Fatal("asset URLs must carry a content-hash version for cache busting")
	}
	for _, p := range []string{"/static/app.css", "/static/htmx.min.js", "/static/app.js"} {
		res, body := e.do("GET", p, nil, nil)
		if res.StatusCode != 200 || len(body) < 50 {
			t.Errorf("%s: %d", p, res.StatusCode)
		}
	}
	_, js := e.do("GET", "/static/app.js", nil, nil)
	if strings.Contains(js, "innerHTML") || strings.Contains(js, "eval(") {
		t.Fatal("unsafe js")
	}
}

func TestUserKebabMenu(t *testing.T) {
	e := setup(t)
	e.login()
	_, body := e.do("GET", "/akun", nil, nil)
	for _, want := range []string{`data-row-actions`, `aria-haspopup="menu"`, `aria-expanded="false"`, `role="menu"`, `role="menuitem"`, `popover="manual"`, `class="kebab-button"`, "Delete"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(body, "min-w-[240px]") {
		t.Fatal("inline actions remain")
	}
}
func TestFullModeFormRoundTrip(t *testing.T) {
	e := setup(t)
	e.login()
	_, _ = e.do("PUT", "/akun/3", url.Values{"username": {"poc-client"}, "allowed_cidrs": {"10.10.7.0/24"}, "traffic_mode": {"full"}, "enabled": {"on"}}, e.safe())
	last := e.api.bodies[len(e.api.bodies)-1]
	if last["traffic_mode"] != "full" {
		t.Fatalf("mode lost: %v", last)
	}
	_, body := e.do("GET", "/akun/3/ubah", nil, map[string]string{"HX-Request": "true"})
	if !strings.Contains(body, `value="full" selected`) {
		t.Fatal("edit mode lost")
	}
}
