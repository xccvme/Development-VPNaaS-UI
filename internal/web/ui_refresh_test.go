package web

import (
	"net/url"
	"regexp"
	"strings"
	"testing"
)

var toggleRe = regexp.MustCompile(`<button[^>]*data-actions-toggle[^>]*>`)

func TestRowActionMenusIdenticalOnAkunAndKoneksi(t *testing.T) {
	e := setup(t)
	e.login()
	toggles := map[string]string{}
	for _, p := range []string{"/akun", "/koneksi"} {
		_, body := e.do("GET", p, nil, nil)
		if !strings.Contains(body, "data-row-actions") {
			t.Fatalf("%s: no row action menu", p)
		}
		tg := toggleRe.FindString(body)
		for _, want := range []string{`class="kebab-button"`, `aria-haspopup="menu"`, `aria-expanded="false"`} {
			if !strings.Contains(tg, want) {
				t.Errorf("%s toggle missing %s: %s", p, want, tg)
			}
		}
		// options are hidden (manual popover) until the toggle is clicked
		for _, want := range []string{`role="menu"`, `popover="manual"`, `class="action-menu"`, `<circle cx="12" cy="5"`} {
			if !strings.Contains(body, want) {
				t.Errorf("%s missing %s", p, want)
			}
		}
		if strings.Contains(body, "min-w-[240px]") || strings.Contains(body, ">⋮<") {
			t.Errorf("%s: legacy inline/text actions remain", p)
		}
		// same markup aside from per-row id/label
		norm := regexp.MustCompile(`(aria-label|aria-controls)="[^"]*"`).ReplaceAllString(tg, `$1=""`)
		toggles[p] = norm
	}
	if toggles["/akun"] != toggles["/koneksi"] {
		t.Fatalf("toggle markup differs:\n%s\n%s", toggles["/akun"], toggles["/koneksi"])
	}
	_, body := e.do("GET", "/koneksi", nil, nil)
	for _, want := range []string{`role="menuitem" hx-get="/koneksi/4/ubah"`, `role="menuitem" hx-post="/koneksi/4/initiate" hx-target="#conn-table" hx-swap="outerHTML"`, `hx-get="/koneksi/4/terminate"`, `hx-get="/koneksi/4/hapus"`} {
		if !strings.Contains(body, want) {
			t.Errorf("koneksi action missing %s", want)
		}
	}
	_, body = e.do("GET", "/akun", nil, nil)
	for _, want := range []string{`hx-get="/akun/3/ubah"`, `hx-get="/akun/3/password"`, `/unduh/akun/3/profil.json`, `/unduh/akun/3/windows.ps1`, `/unduh/akun/3/vpnaas-ca.crt`, `hx-get="/akun/3/hapus"`} {
		if !strings.Contains(body, want) {
			t.Errorf("akun action missing %s", want)
		}
	}
}

func TestKebabCSSHasNoBox(t *testing.T) {
	e := setup(t)
	_, css := e.do("GET", "/static/app.css", nil, nil)
	m := regexp.MustCompile(`\.kebab-button\{[^}]*\}`).FindString(css)
	if m == "" || !strings.Contains(m, "border:0") || !strings.Contains(m, "background:0 0") && !strings.Contains(m, "background:transparent") && !strings.Contains(m, "background:none") {
		t.Fatalf("kebab button must be borderless/transparent: %q", m)
	}
}

func TestMenuJSClickOnly(t *testing.T) {
	e := setup(t)
	_, js := e.do("GET", "/static/app.js", nil, nil)
	if strings.Contains(js, "pointerover") {
		t.Fatal("menu must not open on hover")
	}
	for _, want := range []string{"data-row-actions", "Escape", "menuitem"} {
		if !strings.Contains(js, want) {
			t.Errorf("js missing %s", want)
		}
	}
}

var refreshRe = regexp.MustCompile(`(?s)<button[^>]*data-refresh[^>]*>.*?</button>`)

func TestRefreshButtonsHaveLoadingState(t *testing.T) {
	e := setup(t)
	e.login()
	for _, p := range []string{"/ringkasan", "/koneksi", "/akun", "/kebijakan", "/status", "/audit"} {
		_, body := e.do("GET", p, nil, nil)
		b := refreshRe.FindString(body)
		if b == "" {
			t.Errorf("%s: no HTMX refresh button", p)
			continue
		}
		for _, want := range []string{`hx-get=`, `hx-disabled-elt="this"`, `hx-indicator="this"`, "Muat ulang", "Memuat...", "animate-spin", `class="refresh-idle`, `class="refresh-loading`} {
			if !strings.Contains(b, want) {
				t.Errorf("%s: refresh missing %s", p, want)
			}
		}
	}
	_, css := e.do("GET", "/static/app.css", nil, nil)
	for _, want := range []string{".htmx-request .refresh-idle", ".htmx-request .refresh-loading"} {
		if !strings.Contains(strings.ReplaceAll(css, ".htmx-request.refresh-btn", ".htmx-request"), want) {
			t.Errorf("css missing %s", want)
		}
	}
}

func TestPageRefreshPartial(t *testing.T) {
	e := setup(t)
	e.login()
	_, body := e.do("GET", "/ringkasan", nil, nil)
	if !strings.Contains(body, `id="page-content"`) || !strings.Contains(body, `hx-select="#page-content"`) {
		t.Fatal("overview refresh must swap #page-content")
	}
}

func TestCreateUserFormCIDRAndMaxSessions(t *testing.T) {
	e := setup(t)
	e.login()
	_, body := e.do("GET", "/akun/baru", nil, map[string]string{"HX-Request": "true"})
	ta := regexp.MustCompile(`(?s)<textarea[^>]*name="allowed_cidrs"[^>]*>(.*?)</textarea>`).FindStringSubmatch(body)
	if ta == nil || strings.TrimSpace(ta[1]) != "" || !strings.Contains(ta[0], `placeholder="10.10.7.0/24"`) {
		t.Fatalf("allowed_cidrs must be empty with placeholder: %v", ta)
	}
	sel := regexp.MustCompile(`(?s)<select[^>]*name="max_sessions".*?</select>`).FindString(body)
	for _, want := range []string{`value="1"`, `value="2"`, `value="3" selected`} {
		if !strings.Contains(sel, want) {
			t.Errorf("select missing %s: %s", want, sel)
		}
	}
	if strings.Contains(sel, `value="0"`) || !strings.Contains(body, "Maks. koneksi bersamaan") || !strings.Contains(body, "perangkat") {
		t.Error("max sessions label/helper")
	}
	// empty CIDRs omitted, max_sessions integer
	res, _ := e.do("POST", "/akun", url.Values{"username": {"m-user"}, "password": {"Secret-123"}, "allowed_cidrs": {"  "}, "max_sessions": {"2"}, "enabled": {"on"}}, e.safe())
	last := e.api.bodies[len(e.api.bodies)-1]
	if res.StatusCode != 200 {
		t.Fatalf("create %d", res.StatusCode)
	}
	if _, ok := last["allowed_cidrs"]; ok {
		t.Errorf("empty allowed_cidrs must be omitted: %v", last)
	}
	if last["max_sessions"] != 2.0 {
		t.Errorf("max_sessions must be integer 2: %#v", last["max_sessions"])
	}
	// invalid values never reach backend
	n := len(e.api.calls)
	for _, bad := range []string{"0", "4", "x"} {
		_, body := e.do("POST", "/akun", url.Values{"username": {"m2"}, "password": {"Secret-123"}, "max_sessions": {bad}}, e.safe())
		if !strings.Contains(body, "Maks. koneksi bersamaan harus 1, 2, atau 3") {
			t.Errorf("%s accepted", bad)
		}
	}
	if len(e.api.calls) != n {
		t.Error("invalid max_sessions reached upstream")
	}
}

func TestEditUserMaxSessions(t *testing.T) {
	e := setup(t)
	e.login()
	e.api.users[0]["max_sessions"] = 1.0
	_, body := e.do("GET", "/akun/3/ubah", nil, map[string]string{"HX-Request": "true"})
	if !strings.Contains(body, `value="1" selected`) || strings.Contains(body, `value="3" selected`) {
		t.Fatal("edit must preselect stored max_sessions")
	}
	delete(e.api.users[0], "max_sessions")
	_, body = e.do("GET", "/akun/3/ubah", nil, map[string]string{"HX-Request": "true"})
	if !strings.Contains(body, `value="3" selected`) {
		t.Fatal("missing max_sessions must default to 3")
	}
	e.do("PUT", "/akun/3", url.Values{"username": {"poc-client"}, "max_sessions": {"3"}, "enabled": {"on"}}, e.safe())
	last := e.api.bodies[len(e.api.bodies)-1]
	if last["max_sessions"] != 3.0 {
		t.Fatalf("edit body %v", last)
	}
}

func TestSessionCountOverMax(t *testing.T) {
	e := setup(t)
	e.login()
	e.api.users[0]["max_sessions"] = 2.0
	_, body := e.do("GET", "/akun", nil, nil)
	if !strings.Contains(body, "<span>1/2</span>") || !strings.Contains(body, "<span>0/3</span>") {
		t.Fatalf("session column must show count/max")
	}
	_, body = e.do("GET", "/akun/3/sesi", nil, map[string]string{"HX-Request": "true"})
	if !strings.Contains(body, "Sesi 1/2") {
		t.Fatal("modal must show count/max")
	}
}
