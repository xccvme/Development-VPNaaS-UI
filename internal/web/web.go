// Package web wires HTTP routes: login/session, templ pages and HTMX
// partials, the restricted JSON proxy and authenticated downloads.
package web

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/a-h/templ"

	"vpnaas/ui-goth/internal/auth"
	"vpnaas/ui-goth/internal/forms"
	"vpnaas/ui-goth/internal/model"
	"vpnaas/ui-goth/internal/upstream"
	"vpnaas/ui-goth/internal/views"
	"vpnaas/ui-goth/internal/winsetup"
)

//go:embed static/app.css static/htmx.min.js static/app.js static/vpn-logo.png
var staticFS embed.FS

type Config struct {
	Upstream *upstream.Client
	Auth     *auth.Manager
}

type Server struct {
	up   *upstream.Client
	auth *auth.Manager
	mux  *http.ServeMux

	mu        sync.Mutex
	lastUsers []model.User // last successful users list (runtime invalidated on failure)
}

const csp = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'"

func init() {
	h := sha256.New()
	for _, f := range []string{"static/app.css", "static/htmx.min.js", "static/app.js", "static/vpn-logo.png"} {
		b, _ := staticFS.ReadFile(f)
		h.Write(b)
	}
	views.AssetVersion = hex.EncodeToString(h.Sum(nil))[:12]
}

func New(c Config) http.Handler {
	s := &Server{up: c.Upstream, auth: c.Auth, mux: http.NewServeMux()}
	s.routes()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Security-Policy", csp)
	h.Set("X-Content-Type-Options", "nosniff")
	// "same-origin" (not "no-referrer"): with no-referrer Chromium sends
	// "Origin: null" on HTML form POSTs, which our Origin check must reject.
	h.Set("Referrer-Policy", "same-origin")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	if !strings.HasPrefix(r.URL.Path, "/static/") {
		h.Set("Cache-Control", "no-store")
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /static/", serveStatic)
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	s.mux.HandleFunc("GET /login", s.loginPage)
	s.mux.HandleFunc("POST /login", s.login)
	s.mux.HandleFunc("POST /logout", s.mutating(s.logout))
	s.mux.HandleFunc("GET /session", s.authed(s.session))
	s.mux.HandleFunc("GET /{$}", s.authed(func(w http.ResponseWriter, r *http.Request, _ auth.Session) {
		http.Redirect(w, r, "/ringkasan", http.StatusSeeOther)
	}))

	s.mux.HandleFunc("GET /ringkasan", s.authed(s.overview))
	s.mux.HandleFunc("GET /status", s.authed(s.status))
	s.mux.HandleFunc("GET /audit", s.authed(s.audit))
	s.mux.HandleFunc("GET /audit/tabel", s.authed(s.audit))

	// Redirect legacy /koneksi URL directly to Site-to-Site (S2S).
	s.mux.HandleFunc("GET /koneksi", s.authed(func(w http.ResponseWriter, r *http.Request, _ auth.Session) {
		http.Redirect(w, r, "/sites", http.StatusSeeOther)
	}))

	s.mux.HandleFunc("GET /akun", s.authed(s.users))
	s.mux.HandleFunc("GET /akun/tabel", s.authed(s.users))
	s.mux.HandleFunc("GET /akun/baru", s.authed(s.userForm))
	s.mux.HandleFunc("GET /akun/{id}/sesi", s.authed(s.userSessions))
	s.mux.HandleFunc("GET /akun/{id}/ubah", s.authed(s.userForm))
	s.mux.HandleFunc("GET /akun/{id}/password", s.authed(s.passwordForm))
	s.mux.HandleFunc("GET /akun/{id}/hapus", s.authed(s.confirm("users")))
	s.mux.HandleFunc("POST /akun", s.mutating(s.saveUser))
	s.mux.HandleFunc("PUT /akun/{id}", s.mutating(s.saveUser))
	s.mux.HandleFunc("PUT /akun/{id}/password", s.mutating(s.resetPassword))
	s.mux.HandleFunc("DELETE /akun/{id}", s.mutating(s.remove("users")))

	s.mux.HandleFunc("GET /kebijakan", s.authed(s.policies))
	s.mux.HandleFunc("GET /kebijakan/tabel", s.authed(s.policies))
	s.mux.HandleFunc("GET /kebijakan/baru", s.authed(s.policyForm))
	s.mux.HandleFunc("GET /kebijakan/{id}/ubah", s.authed(s.policyForm))
	s.mux.HandleFunc("GET /kebijakan/{id}/hapus", s.authed(s.confirm("policies")))
	s.mux.HandleFunc("POST /kebijakan", s.mutating(s.savePolicy))
	s.mux.HandleFunc("PUT /kebijakan/{id}", s.mutating(s.savePolicy))
	s.mux.HandleFunc("DELETE /kebijakan/{id}", s.mutating(s.remove("policies")))

	s.mux.HandleFunc("GET /unduh/akun/{id}/vpnaas-ca.crt", s.authed(s.downloadCertificate))
	s.mux.HandleFunc("GET /unduh/akun/{id}/profil.json", s.authed(s.downloadProfile))
	s.mux.HandleFunc("GET /unduh/akun/{id}/windows.ps1", s.authed(s.downloadWindows))
	s.mux.HandleFunc("GET /unduh/akun/{id}/apple.mobileconfig", s.authed(s.downloadUserFormat("mobileconfig", "application/x-apple-aspen-config", "VPNaaS-", ".mobileconfig")))
	s.mux.HandleFunc("GET /unduh/akun/{id}/android.sswan", s.authed(s.downloadUserFormat("sswan", "application/vnd.strongswan.profile+json", "VPNaaS-", ".sswan")))
	s.mux.HandleFunc("GET /downloads/users/{id}/windows.ps1", s.authed(s.downloadWindows)) // legacy URL

	s.routesV2()
	s.mux.HandleFunc("/api/{path...}", s.proxy)
}

// ---------- middleware ----------

func isHX(r *http.Request) bool { return r.Header.Get("HX-Request") == "true" }

// wantsHTML: browser page navigations get a redirect to /login; API,
// downloads and HTMX requests get 401.
func wantsHTML(r *http.Request) bool {
	p := r.URL.Path
	return r.Method == http.MethodGet && !isHX(r) && !strings.HasPrefix(p, "/api/") && !strings.HasPrefix(p, "/unduh/") && !strings.HasPrefix(p, "/downloads/") && p != "/session"
}

func jsonError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"detail": msg})
}

type handler func(http.ResponseWriter, *http.Request, auth.Session)

func (s *Server) authed(h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := s.auth.Session(r)
		if !ok {
			switch {
			case isHX(r):
				w.Header().Set("HX-Redirect", "/login")
				jsonError(w, http.StatusUnauthorized, "Silakan masuk terlebih dahulu")
			case wantsHTML(r):
				http.Redirect(w, r, "/login", http.StatusSeeOther)
			default:
				jsonError(w, http.StatusUnauthorized, "Silakan masuk terlebih dahulu")
			}
			return
		}
		h(w, r, sess)
	}
}

// mutating = authenticated + same Origin + valid CSRF token.
func (s *Server) mutating(h handler) http.HandlerFunc {
	return s.authed(func(w http.ResponseWriter, r *http.Request, sess auth.Session) {
		if !s.auth.SameOrigin(r) {
			jsonError(w, http.StatusForbidden, "Permintaan harus berasal dari origin yang sama")
			return
		}
		if !s.auth.CheckCSRF(r, sess) {
			jsonError(w, http.StatusForbidden, "Token CSRF tidak valid")
			return
		}
		h(w, r, sess)
	})
}

func render(w http.ResponseWriter, r *http.Request, c templ.Component) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := c.Render(r.Context(), w); err != nil {
		log.Printf("render %s: %v", r.URL.Path, err)
	}
}

func (s *Server) page(w http.ResponseWriter, r *http.Request, sess auth.Session, active, title string, body templ.Component) {
	render(w, r, views.Layout(views.Page{Active: active, Title: title, CSRF: sess.CSRF}, body))
}

func pathID(r *http.Request) (int, bool) {
	v := r.PathValue("id")
	id, err := strconv.Atoi(v)
	if err != nil || id < 1 || strconv.Itoa(id) != v {
		return 0, false
	}
	return id, true
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func (s *Server) ctx(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), 30*time.Second)
}

// ---------- auth ----------

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.auth.Session(r); ok {
		http.Redirect(w, r, "/ringkasan", http.StatusSeeOther)
		return
	}
	render(w, r, views.Login("", ""))
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	isJSON := strings.HasPrefix(r.Header.Get("Content-Type"), "application/json")
	if !s.auth.SameOrigin(r) {
		jsonError(w, http.StatusForbidden, "Permintaan harus berasal dari origin yang sama")
		return
	}
	var user, pass string
	if isJSON {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body == nil {
			jsonError(w, http.StatusBadRequest, "Kredensial JSON diperlukan")
			return
		}
		user, _ = body["username"].(string)
		pass, _ = body["password"].(string)
	} else {
		user, pass = r.PostFormValue("username"), r.PostFormValue("password")
	}
	if !auth.CheckCredentials(user, pass) {
		if isJSON {
			jsonError(w, http.StatusUnauthorized, "Username atau password salah")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		views.Login("Username atau password salah", user).Render(r.Context(), w)
		return
	}
	token := s.auth.Login(w)
	if isJSON {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"username": "admin", "csrf_token": token})
		return
	}
	http.Redirect(w, r, "/ringkasan", http.StatusSeeOther)
}

func (s *Server) session(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"username": "admin", "csrf_token": sess.CSRF})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	s.auth.Logout(w, sess)
	if isHX(r) {
		w.Header().Set("HX-Redirect", "/login")
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ---------- data loading ----------

func (s *Server) fetchUsers(r *http.Request) ([]model.User, string, bool) {
	ctx, cancel := s.ctx(r)
	defer cancel()
	var users []model.User
	_, err := s.up.JSON(ctx, "GET", "users", nil, &users)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		// keep showing the last rows, but runtime can no longer be trusted
		stale := make([]model.User, len(s.lastUsers))
		for i, u := range s.lastUsers {
			u.RuntimeStatus, u.Online, u.SessionCount, u.VirtualIPs, u.Sessions = "Unknown", nil, nil, nil, nil
			stale[i] = u
		}
		s.lastUsers = stale
		return stale, err.Error(), len(stale) > 0
	}
	if users == nil {
		users = []model.User{}
	}
	s.lastUsers = users
	return users, "", false
}

var kvLabels = map[string]string{
	"sites": "Site S2S", "enabled_sites": "Site aktif (admin)", "users": "Akun C2S", "routes": "Static routes", "policies": "Firewall rules",
	"backend": "Backend", "pools": "Pool alamat", "raw": "SA aktif (swanctl --list-sas)",
}

func kvs(m map[string]any) []views.KV {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := []views.KV{}
	for _, k := range keys {
		label := strings.ReplaceAll(k, "_", " ")
		if l, ok := kvLabels[k]; ok {
			label = l + " (" + k + ")"
		}
		switch v := m[k].(type) {
		case map[string]any:
			for _, kv := range kvs(v) {
				kv.Key = label + " · " + kv.Key
				out = append(out, kv)
			}
		case string:
			out = append(out, views.KV{Key: label, Value: v, Block: strings.Contains(v, "\n")})
		case []any:
			out = append(out, views.KV{Key: label, Value: model.Printable(v), Block: true})
		default:
			out = append(out, views.KV{Key: label, Value: model.Printable(v)})
		}
	}
	return out
}

// ---------- pages ----------

func (s *Server) overview(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	ctx, cancel := s.ctx(r)
	defer cancel()
	var ov, st map[string]any
	var routes []model.StaticRoute
	var sites []model.MultiSite
	var oerr, rerr, sterr, sierr error
	var users []model.User
	var uerr string
	var wg sync.WaitGroup
	wg.Add(5)
	go func() { defer wg.Done(); _, oerr = s.up.JSON(ctx, "GET", "overview", nil, &ov) }()
	go func() { defer wg.Done(); _, rerr = s.up.JSON(ctx, "GET", "routes", nil, &routes) }()
	go func() { defer wg.Done(); users, uerr, _ = s.fetchUsers(r) }()
	go func() { defer wg.Done(); _, sierr = s.up.JSON(ctx, "GET", "sites", nil, &sites) }()
	go func() { defer wg.Done(); _, sterr = s.up.JSON(ctx, "GET", "status", nil, &st) }()
	wg.Wait()
	o := views.Overview{Sites: sites, Users: users}
	count := func(n int, err string) string {
		if err != "" {
			return "—"
		}
		return strconv.Itoa(n)
	}
	uOn, uOff, uUnk := 0, 0, 0
	for _, u := range users {
		switch u.OnlineLabel() {
		case "Online":
			uOn++
		case "Offline":
			uOff++
		default:
			uUnk++
		}
	}
	userNote := "Data tidak tersedia"
	if uerr == "" {
		userNote = strconv.Itoa(uOn) + " Online · " + strconv.Itoa(uOff) + " Offline"
		if uUnk > 0 {
			userNote += " · " + strconv.Itoa(uUnk) + " Unknown"
		}
	}
	sOn, sOff, sUnk := 0, 0, 0
	for _, site := range sites {
		switch site.OnlineLabel() {
		case "Online":
			sOn++
		case "Offline":
			sOff++
		default:
			sUnk++
		}
	}
	siteNote := "Data tidak tersedia"
	if sierr == nil {
		siteNote = strconv.Itoa(sOn) + " Online · " + strconv.Itoa(sOff) + " Offline"
		if sUnk > 0 {
			siteNote += " · " + strconv.Itoa(sUnk) + " Unknown"
		}
	}
	serr := errText(sterr)
	if sterr == nil {
		if _, ok := st["raw"].(string); !ok {
			serr = "respons status tidak berisi data SA"
		}
	}
	gw := "Unknown"
	if serr == "" {
		gw = "Active"
	}
	o.Cards = []views.Card{
		{Label: "Site-to-Site (S2S)", Value: count(len(sites), errText(sierr)), Note: siteNote, Href: "/sites", Ok: sierr == nil && sUnk == 0},
		{Label: "Client-to-Site (C2S)", Value: count(len(users), uerr), Note: userNote, Href: "/akun", Ok: uerr == "" && uUnk == 0},
		{Label: "Static Routing", Value: count(len(routes), errText(rerr)), Note: "Static route & routing tunnel", Href: "/routing", Ok: rerr == nil},
		{Label: "Telemetri Gateway", Value: gw, Note: "FIPS IPsec/IKEv2 · status runtime", Href: "/status", Ok: serr == ""},
	}
	for _, e := range []struct{ name, err string }{{"Ringkasan", errText(oerr)}, {"Site S2S", errText(sierr)}, {"Akun C2S", uerr}, {"Static Routing", errText(rerr)}, {"Status", serr}} {
		if e.err != "" {
			o.Errors = append(o.Errors, e.name+": "+e.err)
		}
	}
	if ov != nil {
		if vpn, ok := ov["vpn"].(map[string]any); ok {
			delete(vpn, "raw")
			delete(vpn, "connections")
		}
		o.Info = kvs(ov)
	}
	s.page(w, r, sess, "ringkasan", "Dashboard", views.OverviewPage(o))
}

func (s *Server) status(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	ctx, cancel := s.ctx(r)
	defer cancel()
	var st, rdy, gw map[string]any
	var logsResp struct {
		Lines []string `json:"lines"`
	}
	var users []model.User
	var sites []model.MultiSite
	var err, rerr, lerr error
	var wg sync.WaitGroup
	wg.Add(6)
	go func() { defer wg.Done(); _, err = s.up.JSON(ctx, "GET", "status", nil, &st) }()
	go func() { defer wg.Done(); _, rerr = s.up.JSON(ctx, "GET", "ready", nil, &rdy) }()
	go func() { defer wg.Done(); _, _ = s.up.JSON(ctx, "GET", "gateway", nil, &gw) }()
	go func() { defer wg.Done(); _, lerr = s.up.JSON(ctx, "GET", "logs", nil, &logsResp) }()
	go func() { defer wg.Done(); _, _ = s.up.JSON(ctx, "GET", "users", nil, &users) }()
	go func() { defer wg.Done(); _, _ = s.up.JSON(ctx, "GET", "sites", nil, &sites) }()
	wg.Wait()
	d := views.StatusViewData{
		Ready:     rdy,
		Gateway:   gw,
		Items:     kvs(st),
		Err:       errText(err),
		ReadyErr:  errText(rerr),
		LogSource: "strongswan",
		LogLines:  logsResp.Lines,
		LogErr:    errText(lerr),
		Users:     users,
		Sites:     sites,
	}
	// If backend doesn't expose v2 /ready & /gateway (e.g. legacy mock), hide benign 404 on ReadyErr/LogErr
	if rdy == nil && gw == nil {
		d.ReadyErr = ""
		d.LogErr = ""
	}
	s.page(w, r, sess, "status", "Status Runtime", views.StatusV2Page(d))
}

func (s *Server) audit(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	ctx, cancel := s.ctx(r)
	defer cancel()
	var rows []map[string]any
	_, err := s.up.JSON(ctx, "GET", "audit", nil, &rows)
	q := r.URL.Query().Get("q")
	a := views.Audit{Columns: model.AuditColumns(rows), Total: len(rows), Query: q, Err: errText(err)}
	for _, row := range rows {
		var fields []string
		for _, c := range a.Columns {
			fields = append(fields, model.Printable(row[c]))
		}
		if model.Matches(q, fields...) {
			a.Rows = append(a.Rows, row)
		}
	}
	if strings.HasSuffix(r.URL.Path, "/tabel") {
		render(w, r, views.AuditTable(a))
		return
	}
	s.page(w, r, sess, "audit", "Audit Log", views.AuditPage(a))
}

func (s *Server) userTable(r *http.Request, flash *views.Flash) views.UserTable {
	users, err, stale := s.fetchUsers(r)
	siteNames, groupNames := s.lookupSiteGroupNames(r)
	q := r.URL.Query().Get("q")
	t := views.UserTable{Total: len(users), Query: q, Err: err, Stale: stale, Flash: flash, SiteNames: siteNames, GroupNames: groupNames}
	for _, u := range users {
		fields := append([]string{u.Username, u.AdminLabel(), u.RuntimeLabel(), u.OnlineLabel(), u.LastConnectedAt, strconv.Itoa(u.ID)}, u.DisplayCIDRs()...)
		if model.Matches(q, append(fields, u.VirtualIPs...)...) {
			t.Rows = append(t.Rows, u)
		}
	}
	return t
}

func (s *Server) users(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	t := s.userTable(r, nil)
	if strings.HasSuffix(r.URL.Path, "/tabel") {
		render(w, r, views.UsersTable(t))
		return
	}
	s.page(w, r, sess, "akun", "Client-to-Site (C2S)", views.UsersPage(t))
}

func (s *Server) userSessions(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	users, err, _ := s.fetchUsers(r)
	if err != "" {
		render(w, r, views.UserSessions(model.User{}, "Sesi tidak tersedia: "+err))
		return
	}
	for _, u := range users {
		if u.ID == id {
			if u.RuntimeLabel() == "Unknown" {
				u.Sessions = nil
				err = "Sesi tidak tersedia: runtime Unknown"
			}
			render(w, r, views.UserSessions(u, err))
			return
		}
	}
	render(w, r, views.UserSessions(model.User{}, "Sesi tidak tersedia: akun tidak ditemukan"))
}

func (s *Server) policyTable(r *http.Request, flash *views.Flash) views.PolicyTable {
	ctx, cancel := s.ctx(r)
	defer cancel()
	var ps []model.Policy
	_, err := s.up.JSON(ctx, "GET", "policies", nil, &ps)
	siteNames, userNames, groupNames := s.lookupAllEntityNames(r)
	q := r.URL.Query().Get("q")
	t := views.PolicyTable{Total: len(ps), Query: q, Err: errText(err), Flash: flash, SiteNames: siteNames, UserNames: userNames, GroupNames: groupNames}
	for _, p := range ps {
		if model.Matches(q, p.Name, p.SourceDisplay(siteNames, userNames, groupNames), p.DestDisplay(siteNames), p.Protocol, p.Ports, p.ActionLabel(), p.AdminLabel()) {
			t.Rows = append(t.Rows, p)
		}
	}
	return t
}

func (s *Server) policies(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	t := s.policyTable(r, nil)
	if strings.HasSuffix(r.URL.Path, "/tabel") {
		render(w, r, views.PoliciesTable(t))
		return
	}
	s.page(w, r, sess, "kebijakan", "Firewall Rules", views.PoliciesPage(t))
}

// ---------- forms ----------

// findRecord loads a single record via the list endpoint (backend has no GET /{id}).
func (s *Server) findRecord(r *http.Request, kind string, id int) (map[string]any, error) {
	ctx, cancel := s.ctx(r)
	defer cancel()
	var rows []map[string]any
	if _, err := s.up.JSON(ctx, "GET", kind, nil, &rows); err != nil {
		return nil, err
	}
	for _, row := range rows {
		if f, ok := row["id"].(float64); ok && int(f) == id {
			return row, nil
		}
	}
	return nil, errors.New("data tidak ditemukan (mungkin sudah dihapus)")
}

func strVal(row map[string]any, k string) string {
	switch v := row[k].(type) {
	case string:
		return v
	case []any:
		parts := []string{}
		for _, p := range v {
			if s, ok := p.(string); ok {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, "\n")
	case float64:
		if v == float64(int64(v)) {
			return strconv.FormatInt(int64(v), 10)
		}
	}
	return ""
}

func (s *Server) loadForm(w http.ResponseWriter, r *http.Request, kind string, keys []string, defaults map[string]string) (views.Form, bool) {
	f := views.Form{Values: map[string]string{}, Enabled: true}
	for k, v := range defaults {
		f.Values[k] = v
	}
	if r.PathValue("id") == "" {
		return f, true
	}
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return f, false
	}
	row, err := s.findRecord(r, kind, id)
	if err != nil {
		f.Err = err.Error()
		f.ID = id
		return f, true
	}
	f.ID = id
	for _, k := range keys {
		f.Values[k] = strVal(row, k)
	}
	f.Enabled, _ = row["enabled"].(bool)
	return f, true
}

func (s *Server) userForm(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	if f, ok := s.loadForm(w, r, "users", []string{"username", "allowed_cidrs", "traffic_mode", "max_sessions", "auth_method", "cert_id"}, map[string]string{"traffic_mode": "split", "max_sessions": strconv.Itoa(forms.DefaultMaxSessions), "auth_method": "eap-mschapv2"}); ok {
		s.populateUserFormOptions(r, &f)
		if f.ID == 0 {
			f.Values["allow_vpc"] = "on"
		} else if f.Values["allow_vpc"] == "" {
			vpc := f.VPCDisplay()
			for _, c := range forms.SplitList(f.Values["allowed_cidrs"]) {
				if c == vpc {
					f.Values["allow_vpc"] = "on"
					break
				}
			}
		}
		render(w, r, views.UserForm(f))
	}
}

func (s *Server) policyForm(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	if f, ok := s.loadForm(w, r, "policies", []string{"name", "source_cidr", "destination_cidr", "protocol", "action", "ports", "priority", "source_type", "source_ref", "destination_type", "destination_ref"}, map[string]string{"protocol": "all", "action": "allow", "priority": "100", "source_type": "cidr", "destination_type": "cidr"}); ok {
		s.populatePolicyFormOptions(r, &f)
		render(w, r, views.PolicyForm(f))
	}
}

func (s *Server) passwordForm(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	row, err := s.findRecord(r, "users", id)
	render(w, r, views.PasswordForm(id, strVal(row, "username"), errText(err), ""))
}

func formFromRequest(r *http.Request, id int) views.Form {
	f := views.Form{ID: id, Values: map[string]string{}}
	r.ParseForm()
	for k := range r.PostForm {
		if k != "password" && !strings.HasSuffix(k, "psk") && k != "csrf_token" {
			f.Values[k] = r.PostForm.Get(k)
		}
	}
	f.Enabled = r.PostForm.Get("enabled") == "on"
	for _, k := range forms.SiteKeys {
		if _, has := r.PostForm["site_"+k+"_nat"]; has {
			f.Values["site_"+k+"_nat"] = ternary(forms.Checkbox(r.PostForm, "site_"+k+"_nat", true), "on", "")
		}
	}
	return f
}

// saved closes the modal and asks tables to refresh.
func saved(w http.ResponseWriter, msg string) {
	// Ordered: the modal (event source) must be closed last or later events
	// would be dispatched on a detached element and never reach <body>.
	m, _ := json.Marshal(msg)
	w.Header().Set("HX-Trigger", `{"vpnaas:changed":true,"vpnaas:toast":`+string(m)+`,"vpnaas:close":true}`)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) saveUser(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	id := 0
	if r.PathValue("id") != "" {
		var ok bool
		if id, ok = pathID(r); !ok {
			http.NotFound(w, r)
			return
		}
	}
	f := formFromRequest(r, id)
	if vpc := strings.TrimSpace(r.PostForm.Get("vpc_cidr")); vpc != "" {
		f.VPCCIDR = vpc
	}
	if _, hasVPC := r.PostForm["allow_vpc_present"]; hasVPC {
		f.Values["allow_vpc"] = ternary(forms.Checkbox(r.PostForm, "allow_vpc", false), "on", "")
	}
	if _, hasAll := r.PostForm["allow_all_sites_present"]; hasAll {
		f.Values["allow_all_sites"] = ternary(forms.Checkbox(r.PostForm, "allow_all_sites", false), "on", "")
	}
	f.SelectedIDs = map[string]map[int]bool{
		"allowed_sites": formIntSet(r.PostForm["allowed_sites"]),
		"groups":        formIntSet(r.PostForm["groups"]),
	}
	body, errs := forms.User(r.PostForm, id == 0)
	if len(errs) > 0 {
		f.Errs = errs
		render(w, r, views.UserForm(f))
		return
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	method, path := "POST", "users"
	if id > 0 {
		method, path = "PUT", "users/"+strconv.Itoa(id)
	}
	if _, err := s.up.JSON(ctx, method, path, body, nil); err != nil {
		f.Err = err.Error()
		s.populateUserFormChoices(r, &f)
		render(w, r, views.UserForm(f))
		return
	}
	saved(w, "Akun berhasil disimpan")
}

func (s *Server) savePolicy(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	id := 0
	if r.PathValue("id") != "" {
		var ok bool
		if id, ok = pathID(r); !ok {
			http.NotFound(w, r)
			return
		}
	}
	f := formFromRequest(r, id)
	body, errs := forms.Policy(r.PostForm)
	if len(errs) > 0 {
		f.Errs = errs
		render(w, r, views.PolicyForm(f))
		return
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	method, path := "POST", "policies"
	if id > 0 {
		method, path = "PUT", "policies/"+strconv.Itoa(id)
	}
	if _, err := s.up.JSON(ctx, method, path, body, nil); err != nil {
		f.Err = err.Error()
		s.populatePolicyFormOptions(r, &f)
		render(w, r, views.PolicyForm(f))
		return
	}
	saved(w, "Firewall rule berhasil disimpan")
}

func (s *Server) resetPassword(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	r.ParseForm()
	name := r.PostForm.Get("username")
	body, errs := forms.Password(r.PostForm)
	if len(errs) > 0 {
		render(w, r, views.PasswordForm(id, name, "", errs["password"]))
		return
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	if _, err := s.up.JSON(ctx, "PUT", "users/"+strconv.Itoa(id), body, nil); err != nil {
		render(w, r, views.PasswordForm(id, name, err.Error(), ""))
		return
	}
	saved(w, "Password berhasil direset")
}

var kindLabel = map[string]struct{ label, base, field string }{
	"users":    {"akun C2S", "/akun", "username"},
	"policies": {"firewall rule", "/kebijakan", "name"},
	"sites":    {"site S2S", "/sites", "name"},
	"groups":   {"grup C2S", "/grup", "name"},
	"routes":   {"static route", "/routing", "name"},
}

func (s *Server) confirm(kind string) handler {
	k := kindLabel[kind]
	return func(w http.ResponseWriter, r *http.Request, _ auth.Session) {
		id, ok := pathID(r)
		if !ok {
			http.NotFound(w, r)
			return
		}
		row, err := s.findRecord(r, kind, id)
		name := strVal(row, k.field)
		if name == "" {
			name = "ID " + strconv.Itoa(id)
		}
		render(w, r, views.ConfirmModal(views.Confirm{
			Title: "Hapus " + k.label, Message: "Hapus permanen " + k.label + " berikut? Tindakan ini tidak dapat dibatalkan dan sesi aktif terkait akan diputus.",
			Name: name, URL: k.base + "/" + strconv.Itoa(id), Button: "Hapus", Err: errText(err),
		}))
	}
}

func (s *Server) remove(kind string) handler {
	return func(w http.ResponseWriter, r *http.Request, _ auth.Session) {
		id, ok := pathID(r)
		if !ok {
			http.NotFound(w, r)
			return
		}
		ctx, cancel := s.ctx(r)
		defer cancel()
		if _, err := s.up.JSON(ctx, "DELETE", kind+"/"+strconv.Itoa(id), nil, nil); err != nil {
			k := kindLabel[kind]
			render(w, r, views.ConfirmModal(views.Confirm{Title: "Hapus " + k.label, Message: "Gagal menghapus.", Name: "ID " + strconv.Itoa(id), URL: k.base + "/" + strconv.Itoa(id), Button: "Hapus", Err: err.Error()}))
			return
		}
		saved(w, "Data berhasil dihapus")
	}
}

// ---------- downloads ----------

func (s *Server) profile(w http.ResponseWriter, r *http.Request) (*upstream.Response, bool) {
	id, ok := pathID(r)
	if !ok {
		jsonError(w, http.StatusNotFound, "Akun tidak dikenal")
		return nil, false
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	res, err := s.up.Do(ctx, "GET", "users/"+strconv.Itoa(id)+"/profile", "", nil, "")
	if err != nil {
		jsonError(w, http.StatusBadGateway, err.Error())
		return nil, false
	}
	if !res.OK() {
		jsonError(w, res.Status, res.Detail())
		return nil, false
	}
	return res, true
}

func (s *Server) downloadProfile(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	res, ok := s.profile(w, r)
	if !ok {
		return
	}
	var check map[string]any
	if json.Unmarshal(res.Body, &check) != nil {
		jsonError(w, http.StatusBadGateway, "Profil VPN dari backend tidak valid")
		return
	}
	username, _ := check["username"].(string)
	name, err := winsetup.Filename(username)
	if err != nil {
		jsonError(w, 502, "Username profil tidak valid")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="Profil-VPN-`+name+`.json"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Write(res.Body)
}

// downloadCertificate emits only a parsed public CA, never the profile or its secrets.
func (s *Server) downloadCertificate(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	res, ok := s.profile(w, r)
	if !ok {
		return
	}
	var p map[string]any
	if json.Unmarshal(res.Body, &p) != nil {
		jsonError(w, 502, "Sertifikat CA tidak valid")
		return
	}
	ca, _ := p["ca_certificate"].(string)
	trimmed := strings.TrimSpace(ca)
	block, rest := pem.Decode([]byte(trimmed))
	if block == nil || !strings.HasPrefix(trimmed, "-----BEGIN CERTIFICATE-----") || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(strings.TrimSpace(string(rest))) != 0 {
		jsonError(w, 502, "Sertifikat CA tidak valid")
		return
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !cert.IsCA || !cert.BasicConstraintsValid {
		jsonError(w, 502, "Sertifikat CA tidak valid")
		return
	}
	username, _ := p["username"].(string)
	name, err := winsetup.Filename(username)
	if err != nil {
		jsonError(w, 502, "Username profil tidak valid")
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.crt"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

func (s *Server) downloadWindows(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	res, ok := s.profile(w, r)
	if !ok {
		return
	}
	var p map[string]any
	if json.Unmarshal(res.Body, &p) != nil || p == nil {
		jsonError(w, http.StatusBadGateway, "Profil VPN tidak dapat menghasilkan setup Windows yang aman")
		return
	}
	if authMethod, _ := p["auth_method"].(string); authMethod == "pubkey" || authMethod == "eap-tls" {
		id, _ := pathID(r)
		ctx, cancel := s.ctx(r)
		defer cancel()
		winRes, err := s.up.Do(ctx, "GET", "users/"+strconv.Itoa(id)+"/profile", "format=windows", nil, "")
		if err != nil {
			jsonError(w, http.StatusBadGateway, err.Error())
			return
		}
		if !winRes.OK() {
			jsonError(w, winRes.Status, winRes.Detail())
			return
		}
		if cd := winRes.Header.Get("Content-Disposition"); cd != "" {
			w.Header().Set("Content-Disposition", cd)
		} else {
			username, _ := p["username"].(string)
			name, err := winsetup.Filename(username)
			if err != nil {
				jsonError(w, 502, "Username profil tidak valid")
				return
			}
			w.Header().Set("Content-Disposition", `attachment; filename="Setup-Client-`+name+`.ps1"`)
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(winRes.Body)
		return
	}
	script, err := winsetup.Render(p)
	if err != nil {
		jsonError(w, http.StatusBadGateway, "Profil VPN tidak dapat menghasilkan setup Windows yang aman")
		return
	}
	username, _ := p["username"].(string)
	name, err := winsetup.Filename(username)
	if err != nil {
		jsonError(w, 502, "Username profil tidak valid")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="Setup-Client-`+name+`.ps1"`)
	w.Header().Set("Cache-Control", "no-store")
	io.WriteString(w, script)
}

// ---------- restricted JSON proxy (compat with old UI clients) ----------

func (s *Server) proxy(w http.ResponseWriter, r *http.Request) {
	s.authed(func(w http.ResponseWriter, r *http.Request, sess auth.Session) {
		path := r.PathValue("path")
		raw := strings.TrimPrefix(r.URL.EscapedPath(), "/api/")
		if raw != path || !upstream.Allowed(r.Method, path) {
			jsonError(w, http.StatusNotFound, "Rute API tidak dikenal")
			return
		}
		if r.Method != http.MethodGet {
			if !s.auth.SameOrigin(r) {
				jsonError(w, http.StatusForbidden, "Permintaan harus berasal dari origin yang sama")
				return
			}
			if !s.auth.CheckCSRF(r, sess) {
				jsonError(w, http.StatusForbidden, "Token CSRF tidak valid")
				return
			}
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			jsonError(w, http.StatusRequestEntityTooLarge, "Permintaan terlalu besar")
			return
		}
		ctx, cancel := s.ctx(r)
		defer cancel()
		res, err := s.up.Do(ctx, r.Method, path, r.URL.RawQuery, body, r.Header.Get("Content-Type"))
		if err != nil {
			code := http.StatusBadGateway
			if errors.Is(err, upstream.ErrKey) {
				code = http.StatusServiceUnavailable
			}
			jsonError(w, code, err.Error())
			return
		}
		for _, h := range []string{"Content-Type", "Content-Disposition"} {
			if v := res.Header.Get(h); v != "" {
				w.Header().Set(h, v)
			}
		}
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(res.Status)
		w.Write(res.Body)
	})(w, r)
}

func ternary(c bool, a, b string) string {
	if c {
		return a
	}
	return b
}
