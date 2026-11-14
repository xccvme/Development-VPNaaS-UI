package web

import (
	"net/url"
	"regexp"
	"strings"
	"testing"
)

var hx = map[string]string{"HX-Request": "true"}

func TestHubPageTitleSidebarAndDiagram(t *testing.T) {
	e := setup(t)
	e.login()
	res, body := e.do("GET", "/koneksi", nil, nil)
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode)
	}
	for _, want := range []string{
		"<title>VPN Hub", ">VPN Hub</h1>",
		"Hubungkan LAN antar site lewat server ini sebagai hub: Site-A ⇄ Hub ⇄ Site-B. Client di Site-A bisa ping/akses Site-B dan sebaliknya.",
		"Buat VPN Hub", `hx-get="/koneksi/baru"`, "data-hub-diagram",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(body, "Buat Koneksi") {
		t.Error("old create button remains")
	}
	nav := regexp.MustCompile(`(?s)<nav.*?</nav>`).FindString(body)
	if !strings.Contains(nav, "VPN Hub") || strings.Contains(nav, "Koneksi S2S") {
		t.Errorf("sidebar label: %s", nav)
	}
}

func TestHubTableRendersSitesAndLegacyRow(t *testing.T) {
	e := setup(t)
	e.login()
	_, body := e.do("GET", "/koneksi/tabel", nil, hx)
	hub := regexp.MustCompile(`(?s)<table[^>]*data-hub-table.*?</table>`).FindString(body)
	for _, want := range []string{">Nama</th>", ">Site-A</th>", ">Site-B</th>", ">Aksi</th>", "kantor", "jakarta", "surabaya",
		"192.168.10.0/24", "192.168.11.0/24", "192.168.20.0/24", "203.0.113.20", ">Active<", ">Down<"} {
		if !strings.Contains(hub, want) {
			t.Errorf("hub table missing %q", want)
		}
	}
	if strings.Contains(hub, "branch") {
		t.Error("legacy row must not be in hub table")
	}
	legacy := regexp.MustCompile(`(?s)<section[^>]*data-direct-legacy.*?</section>`).FindString(body)
	for _, want := range []string{"Direct (lama)", "branch", "203.0.113.5", "192.168.50.0/24", ">Subnet (lokal ↔ remote)</th>",
		`hx-get="/koneksi/4/ubah"`, `hx-post="/koneksi/4/initiate"`, `hx-get="/koneksi/4/terminate"`, `hx-get="/koneksi/4/hapus"`} {
		if !strings.Contains(legacy, want) {
			t.Errorf("legacy section missing %q", want)
		}
	}
	// still a single refreshable section, polling every 30s
	if !strings.Contains(body, `id="conn-table"`) || !strings.Contains(body, `hx-trigger="every 30s, vpnaas:changed from:body"`) {
		t.Error("refresh wiring")
	}
}

func TestHubMenuItems(t *testing.T) {
	e := setup(t)
	e.login()
	_, body := e.do("GET", "/koneksi/tabel", nil, hx)
	menu := regexp.MustCompile(`(?s)<div id="connection-menu-7"[^>]*role="menu".*?</div>`).FindString(body)
	order := []string{
		`hx-get="/koneksi/7/ubah"`, ">Ubah<",
		`hx-get="/koneksi/7/site/a/configure"`, ">Configure Site-A<",
		`href="/unduh/koneksi/7/site-a/setup.sh"`, ">Download script Site-A (.sh)<",
		`href="/unduh/koneksi/7/site-a/hub.conf"`, ">Download config Site-A (.conf)<",
		`hx-get="/koneksi/7/site/b/configure"`, ">Configure Site-B<",
		`href="/unduh/koneksi/7/site-b/setup.sh"`, ">Download script Site-B (.sh)<",
		`href="/unduh/koneksi/7/site-b/hub.conf"`, ">Download config Site-B (.conf)<",
		`hx-post="/koneksi/7/site/a/connect"`, ">Connect Site-A<",
		`hx-get="/koneksi/7/site/a/disconnect"`, ">Disconnect Site-A<",
		`hx-post="/koneksi/7/site/b/connect"`, ">Connect Site-B<",
		`hx-get="/koneksi/7/site/b/disconnect"`, ">Disconnect Site-B<",
		`hx-get="/koneksi/7/hapus"`, ">Hapus<",
	}
	pos := 0
	for _, want := range order {
		i := strings.Index(menu[pos:], want)
		if i < 0 {
			t.Fatalf("menu missing or out of order %q in %s", want, menu)
		}
		pos += i
	}
	if strings.Contains(menu, "/initiate") || strings.Contains(menu, "/terminate") {
		t.Error("hub rows must not use legacy initiate/terminate")
	}
}

func TestHubConfigureModal(t *testing.T) {
	e := setup(t)
	e.login()
	_, body := e.do("GET", "/koneksi/7/site/a/configure", nil, hx)
	for _, want := range []string{"Configure Site-A", "jakarta", "Setup-Hub-kantor-Site-A.sh", "sudo bash Setup-Hub-kantor-Site-A.sh",
		`href="/unduh/koneksi/7/site-a/setup.sh"`, `href="/unduh/koneksi/7/site-a/hub.conf"`, "Active", "forwarding", "NAT", "route"} {
		if !strings.Contains(body, want) {
			t.Errorf("configure modal missing %q", want)
		}
	}
	res, _ := e.do("GET", "/koneksi/7/site/c/configure", nil, hx)
	if res.StatusCode != 404 {
		t.Errorf("bad site: %d", res.StatusCode)
	}
}

func TestHubDownloadProxy(t *testing.T) {
	e := setup(t)
	cases := []struct{ path, query, file, body string }{
		{"/unduh/koneksi/7/site-a/setup.sh", "format=script", "Setup-Hub-kantor-Site-A.sh", "# script site a\n"},
		{"/unduh/koneksi/7/site-b/setup.sh", "format=script", "Setup-Hub-kantor-Site-B.sh", "# script site b\n"},
		{"/unduh/koneksi/7/site-a/hub.conf", "format=swanctl", "Hub-kantor-Site-A.conf", "# swanctl site a\n"},
		{"/unduh/koneksi/7/site-b/hub.conf", "format=swanctl", "Hub-kantor-Site-B.conf", "# swanctl site b\n"},
	}
	if res, _ := e.do("GET", cases[0].path, nil, nil); res.StatusCode != 401 {
		t.Fatalf("anonymous download: %d", res.StatusCode)
	}
	e.login()
	for _, c := range cases {
		res, body := e.do("GET", c.path, nil, nil)
		if res.StatusCode != 200 || body != c.body {
			t.Fatalf("%s: %d %q", c.path, res.StatusCode, body)
		}
		if got := res.Header.Get("Content-Disposition"); got != `attachment; filename="`+c.file+`"` {
			t.Errorf("%s filename: %s", c.path, got)
		}
		if res.Header.Get("Cache-Control") != "no-store" || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/") {
			t.Errorf("%s headers %v", c.path, res.Header)
		}
		if q := e.api.queries[len(e.api.queries)-1]; q != c.query {
			t.Errorf("%s upstream query %q", c.path, q)
		}
	}
	for _, p := range []string{"/unduh/koneksi/7/site-c/setup.sh", "/unduh/koneksi/x/site-a/setup.sh", "/unduh/koneksi/4/site-a/setup.sh"} {
		if res, _ := e.do("GET", p, nil, nil); res.StatusCode == 200 {
			t.Errorf("%s must fail (bad site/id or legacy row)", p)
		}
	}
	e.api.failPaths["connections/7/sites/a/config"] = 409
	res, body := e.do("GET", cases[0].path, nil, nil)
	if res.StatusCode != 409 || !strings.Contains(body, "Gagal") {
		t.Errorf("upstream error passthrough: %d %s", res.StatusCode, body)
	}
}

func TestHubSiteConnectShows409AndDisconnectConfirms(t *testing.T) {
	e := setup(t)
	e.login()
	res, body := e.do("POST", "/koneksi/7/site/a/connect", nil, e.safe())
	if res.StatusCode != 200 || !strings.Contains(body, "Connect Site-A gagal (kantor): Site-A di belakang NAT (%any): jalankan connect dari gateway Site-A") || !strings.Contains(body, `id="conn-table"`) {
		t.Fatalf("409 message not shown: %d %s", res.StatusCode, body)
	}
	_, body = e.do("POST", "/koneksi/7/site/b/connect", nil, e.safe())
	if !strings.Contains(body, "Connect Site-B kantor berhasil") || !strings.Contains(body, "site b connect &lt;done&gt;") {
		t.Errorf("connect ok flash: %s", body)
	}
	_, modal := e.do("GET", "/koneksi/7/site/b/disconnect", nil, hx)
	for _, want := range []string{"Disconnect Site-B", "kantor", `hx-post="/koneksi/7/site/b/disconnect"`, ">Disconnect</button>"} {
		if !strings.Contains(modal, want) {
			t.Errorf("disconnect confirm missing %q", want)
		}
	}
	_, body = e.do("POST", "/koneksi/7/site/b/disconnect", nil, e.safe())
	if !strings.Contains(body, "Disconnect Site-B kantor berhasil") {
		t.Errorf("disconnect flash: %s", body)
	}
	calls := strings.Join(e.api.calls, ",")
	for _, c := range []string{"POST connections/7/sites/a/connect", "POST connections/7/sites/b/connect", "POST connections/7/sites/b/disconnect"} {
		if !strings.Contains(calls, c) {
			t.Errorf("missing upstream call %s", c)
		}
	}
	// CSRF still enforced
	if res, _ := e.do("POST", "/koneksi/7/site/a/disconnect", nil, map[string]string{"Origin": e.srv.URL}); res.StatusCode != 403 {
		t.Error("site action without csrf")
	}
	if res, _ := e.do("POST", "/koneksi/7/site/z/connect", nil, e.safe()); res.StatusCode != 404 {
		t.Error("bad site letter")
	}
}

func TestHubFormCreateEditAndErrors(t *testing.T) {
	e := setup(t)
	e.login()
	_, form := e.do("GET", "/koneksi/baru", nil, hx)
	for _, want := range []string{"Buat VPN Hub", `name="topology" value="hub"`, "Site-A", "Site-B", `name="site_a_name"`, `name="site_b_subnets"`,
		"IP publik/hostname, kosongkan jika di belakang NAT", "kosongkan = generate otomatis", "LAN di belakang site ini yang boleh diakses site lawan",
		"Aktifkan jika router LAN tidak punya route balik ke site lawan", `name="site_a_nat" value="on" checked`, `name="enabled" checked`} {
		if !strings.Contains(form, want) {
			t.Errorf("create form missing %q", want)
		}
	}
	v := url.Values{"topology": {"hub"}, "name": {"qa-hub"}, "enabled": {"on"},
		"site_a_name": {"jkt"}, "site_a_address": {""}, "site_a_id": {""}, "site_a_psk": {""}, "site_a_subnets": {"192.168.10.0/24"}, "site_a_nat": {"0", "on"},
		"site_b_name": {"sby"}, "site_b_address": {"203.0.113.30"}, "site_b_id": {""}, "site_b_psk": {"Secret-psk-1"}, "site_b_subnets": {"192.168.20.0/24\n192.168.21.0/24"}, "site_b_nat": {"0"}}
	res, _ := e.do("POST", "/koneksi", v, e.safe())
	last := e.api.bodies[len(e.api.bodies)-1]
	a, _ := last["site_a"].(map[string]any)
	b, _ := last["site_b"].(map[string]any)
	if res.StatusCode != 200 || last["topology"] != "hub" || a["address"] != "%any" || a["nat"] != true || b["nat"] != false || b["subnets"] != "192.168.20.0/24,192.168.21.0/24" || b["psk"] != "Secret-psk-1" {
		t.Fatalf("hub create body: %d %v", res.StatusCode, last)
	}
	if _, ok := last["remote_address"]; ok {
		t.Error("hub body must not carry legacy fields")
	}
	// validation error per field, PSK never echoed, no upstream call
	n := len(e.api.calls)
	bad := url.Values{}
	for k, vv := range v {
		bad[k] = vv
	}
	bad.Set("site_b_subnets", "10.0.0.0/33")
	bad.Set("site_a_name", "")
	_, body := e.do("POST", "/koneksi", bad, e.safe())
	if len(e.api.calls) != n || !strings.Contains(body, "CIDR IPv4 tidak valid: 10.0.0.0/33") || !strings.Contains(body, "Nama site") || strings.Contains(body, "Secret-psk-1") {
		t.Fatalf("hub validation: %s", body)
	}
	if !strings.Contains(body, `name="site_a_nat" value="on" checked`) || strings.Contains(body, `name="site_b_nat" value="on" checked`) {
		t.Error("nat state must survive re-render")
	}
	// edit existing hub row: nested values prefilled, psk blank, keep hint
	_, edit := e.do("GET", "/koneksi/7/ubah", nil, hx)
	for _, want := range []string{"Ubah VPN Hub", `hx-put="/koneksi/7"`, `value="jakarta"`, `value="surabaya"`, `value="203.0.113.30"`, `value="kantor-a@vpnaas"`,
		"192.168.10.0/24\n192.168.11.0/24</textarea>", "kosongkan = tidak diubah", `name="site_a_nat" value="on" checked`} {
		if !strings.Contains(edit, want) {
			t.Errorf("edit form missing %q", want)
		}
	}
	if strings.Contains(edit, `value="%any"`) || strings.Contains(edit, `name="site_b_nat" value="on" checked`) {
		t.Error("%any must be shown as empty address; site B nat false")
	}
	if strings.Contains(edit, `name="remote_address"`) {
		t.Error("hub edit must not show legacy form")
	}
	ev := url.Values{}
	for k, vv := range v {
		ev[k] = vv
	}
	ev.Set("site_b_psk", "")
	e.do("PUT", "/koneksi/7", ev, e.safe())
	last = e.api.bodies[len(e.api.bodies)-1]
	if _, ok := last["site_b"].(map[string]any)["psk"]; ok {
		t.Error("blank psk on edit must be omitted")
	}
	// legacy row still edits via the old form
	_, old := e.do("GET", "/koneksi/4/ubah", nil, hx)
	if !strings.Contains(old, `name="remote_address"`) || !strings.Contains(old, "Ubah Koneksi") || !strings.Contains(old, "Direct (lama)") {
		t.Errorf("legacy edit form: %s", old)
	}
}

func TestOverviewCountsHubSites(t *testing.T) {
	e := setup(t)
	e.login()
	_, body := e.do("GET", "/ringkasan", nil, nil)
	card := regexp.MustCompile(`(?s)<a href="/koneksi" class="block rounded-xl.*?</a>`).FindString(body)
	// hub kantor: A active, B down; legacy branch: Active (via status raw)
	if !strings.Contains(card, "VPN Hub") || !strings.Contains(card, ">2<") || !strings.Contains(card, "2 Active · 1 Down") {
		t.Errorf("overview card: %s", card)
	}
}
