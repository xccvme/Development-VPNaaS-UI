package web

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"vpnaas/ui-goth/internal/views"
)

func TestFirewallRulesWording(t *testing.T) {
	e := setup(t)
	e.login()
	_, body := e.do("GET", "/kebijakan", nil, nil)
	for _, want := range []string{
		"<title>Firewall Rules · VPNaaS Console</title>",
		">Firewall Rules</h1>",
		"Allow rule tambahan untuk traffic yang diforward antar jaringan (S2S/LAN). Default: deny. Akses user C2S tetap diatur dari Allowed CIDRs akun.",
		">Nama</th>", ">Source</th>", ">Destination</th>", ">Protokol</th>", ">Status</th>",
		"Buat Rule",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/kebijakan missing %q", want)
		}
	}
	for _, bad := range []string{"Kebijakan Jaringan", "CIDR Sumber", "CIDR Tujuan", "Nama Kebijakan"} {
		if strings.Contains(body, bad) {
			t.Errorf("/kebijakan still has %q", bad)
		}
	}
	nav := regexp.MustCompile(`(?s)<nav.*?</nav>`).FindString(body)
	for _, want := range []string{"<span>Dashboard</span>", "<span>VPNaaS</span>", "<span>Status &amp; Diagnostik</span>", "<span>Audit Log</span>"} {
		if !strings.Contains(nav, want) {
			t.Errorf("sidebar missing %s: %s", want, nav)
		}
	}
	if strings.Contains(nav, "Token API") || strings.Contains(nav, "Kebijakan") {
		t.Errorf("sidebar must only have the 4 clean items: %s", nav)
	}
	if !strings.Contains(body, `role="tab"`) || !strings.Contains(body, ">Firewall Rules</a>") {
		t.Errorf("VPNaaS tabs missing Firewall Rules")
	}
	_, form := e.do("GET", "/kebijakan/baru", nil, map[string]string{"HX-Request": "true"})
	for _, want := range []string{"Buat Firewall Rule", "Source CIDR", "Destination CIDR", `name="source_cidr"`, `name="destination_cidr"`, "Jaringan asal traffic", "Jaringan tujuan traffic"} {
		if !strings.Contains(form, want) {
			t.Errorf("policy form missing %q", want)
		}
	}
}

func TestConnectDisconnectWording(t *testing.T) {
	e := setup(t)
	e.login()
	e.api.sites = []map[string]any{
		{"id": 10.0, "name": "site-jkt", "address": "203.0.113.5", "ike_id": "site-jkt@vpnaas", "subnets": "192.168.50.0/24", "enabled": true, "status": "active", "online": true, "last_connected_at": "2026-11-26T10:00:00Z"},
	}
	_, body := e.do("GET", "/sites", nil, nil)
	for _, want := range []string{
		`hx-get="/sites/10/configure"`, ">Detail Site</button>",
		">Manual Configuration (.conf)</a>", ">strongSwan (.conf)</a>", ">Root CA (.crt)</a>",
		`hx-get="/sites/10/disconnect"`, ">Disconnect</button>",
		">Online<", "2026-11-26T10:00:00Z",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/sites missing %q", want)
		}
	}
	for _, bad := range []string{">Initiate<", ">Terminate<", ">Connect</button>", "MikroTik", "FortiGate", "Cisco", "Script Linux"} {
		if strings.Contains(body, bad) {
			t.Errorf("/sites still contains removed item %q", bad)
		}
	}
	_, modal := e.do("GET", "/sites/10/disconnect", nil, map[string]string{"HX-Request": "true"})
	for _, want := range []string{"Disconnect Site S2S", `hx-post="/sites/10/disconnect"`, ">Disconnect</button>"} {
		if !strings.Contains(modal, want) {
			t.Errorf("disconnect modal missing %q", want)
		}
	}
	_, out := e.do("POST", "/sites/10/connect", nil, e.safe())
	if !strings.Contains(out, "Connect site #10 berhasil") {
		t.Errorf("connect flash: %s", out)
	}
	_, out = e.do("POST", "/sites/10/disconnect", nil, e.safe())
	if !strings.Contains(out, "Disconnect site #10 berhasil") {
		t.Errorf("disconnect flash: %s", out)
	}
	e.api.failPaths["sites/10/connect"] = 500
	_, out = e.do("POST", "/sites/10/connect", nil, e.safe())
	if !strings.Contains(out, "Connect gagal") {
		t.Errorf("connect error flash: %s", out)
	}
}

func TestS2SFormSubnets(t *testing.T) {
	e := setup(t)
	e.login()
	_, form := e.do("GET", "/sites/baru", nil, map[string]string{"HX-Request": "true"})
	for _, want := range []string{"Subnet LAN Site", "IKE ID (opsional)", "PSK", "FIPS"} {
		if !strings.Contains(form, want) {
			t.Errorf("S2S form missing %q", want)
		}
	}
	ta := regexp.MustCompile(`(?s)<textarea[^>]*name="subnets"[^>]*>(.*?)</textarea>`).FindStringSubmatch(form)
	if ta == nil || strings.TrimSpace(ta[1]) != "" || !strings.Contains(ta[0], "placeholder=") {
		t.Errorf("subnets must be an empty textarea with placeholder: %v", ta)
	}
	res, _ := e.do("POST", "/sites", url.Values{"name": {"tmp2"}, "address": {"198.51.100.8"}, "subnets": {"192.168.77.0/24\n192.168.78.0/24"}, "allow_vpc": {"0", "on"}, "nat": {"0", "on"}, "encap": {"0", "on"}, "enabled": {"on"}}, e.safe())
	last := e.api.bodies[len(e.api.bodies)-1]
	if res.StatusCode != 200 || last["subnets"] != "192.168.77.0/24,192.168.78.0/24" {
		t.Fatalf("multi CIDR body: %d %v", res.StatusCode, last)
	}
	// edit form splits the stored comma list back to one CIDR per line
	_, edit := e.do("GET", "/sites/21/ubah", nil, map[string]string{"HX-Request": "true"})
	if !strings.Contains(edit, "192.168.77.0/24\n192.168.78.0/24</textarea>") {
		t.Errorf("edit textarea must show one CIDR per line: %s", edit)
	}
}

func TestSitesRoutingInfoBox(t *testing.T) {
	e := setup(t)
	e.login()
	_, body := e.do("GET", "/sites", nil, nil)
	box := regexp.MustCompile(`(?s)<details[^>]*data-s2s-info.*?</details>`).FindString(body)
	for _, want := range []string{"<summary", "Site-A", "NAT", "allowed-address-pairs", "port security"} {
		if !strings.Contains(box, want) {
			t.Errorf("info box missing %q: %s", want, box)
		}
	}
	if strings.Contains(box, "<details open") {
		t.Error("info box must be collapsed by default")
	}
}

func TestStaticCachingAndGzip(t *testing.T) {
	e := setup(t)
	res, _ := e.do("GET", "/static/app.js?v="+views.AssetVersion, nil, nil)
	if cc := res.Header.Get("Cache-Control"); !strings.Contains(cc, "immutable") || !strings.Contains(cc, "max-age=31536000") {
		t.Errorf("versioned asset cache-control: %q", cc)
	}
	etag := res.Header.Get("ETag")
	if etag == "" {
		t.Fatal("missing ETag")
	}
	res, _ = e.do("GET", "/static/app.js", nil, map[string]string{"If-None-Match": etag})
	if res.StatusCode != http.StatusNotModified {
		t.Errorf("If-None-Match: %d", res.StatusCode)
	}
	if cc := res.Header.Get("Cache-Control"); strings.Contains(cc, "immutable") {
		t.Errorf("unversioned asset must not be immutable: %q", cc)
	}
	req, _ := http.NewRequest("GET", e.srv.URL+"/static/htmx.min.js?v="+views.AssetVersion, nil)
	req.Header.Set("Accept-Encoding", "gzip")
	raw, err := (&http.Transport{DisableCompression: true}).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Body.Close()
	if raw.Header.Get("Content-Encoding") != "gzip" || !strings.Contains(raw.Header.Get("Vary"), "Accept-Encoding") || !strings.HasPrefix(raw.Header.Get("Content-Type"), "text/javascript") {
		t.Fatalf("gzip headers: %v", raw.Header)
	}
	zr, err := gzip.NewReader(raw.Body)
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := io.ReadAll(zr)
	if !strings.HasPrefix(string(plain), "var htmx=") {
		t.Fatal("gzip body")
	}
	_, png := e.do("GET", "/static/vpn-logo.png", nil, nil)
	if len(png) < 100 {
		t.Fatal("png")
	}
}

func TestPollingPausesWhenHidden(t *testing.T) {
	e := setup(t)
	_, js := e.do("GET", "/static/app.js", nil, nil)
	for _, want := range []string{"visibilityState", "visibilitychange", "htmx:beforeRequest"} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js missing %s", want)
		}
	}
}
