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
	if !strings.Contains(nav, `href="/kebijakan"`) || !strings.Contains(nav, "<span>Firewall</span>") || strings.Contains(nav, "Kebijakan") {
		t.Errorf("sidebar label must be Firewall: %s", nav)
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
	_, body := e.do("GET", "/koneksi", nil, nil)
	for _, want := range []string{
		`hx-post="/koneksi/4/initiate"`, `title="Mulai tunnel ke peer sekarang"`, ">Connect</button>",
		`hx-get="/koneksi/4/terminate"`, `title="Putus tunnel; bisa connect ulang kapan saja"`, ">Disconnect</button>",
		">Active<",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/koneksi missing %q", want)
		}
	}
	if strings.Contains(body, ">Initiate<") || strings.Contains(body, ">Terminate<") {
		t.Error("old Initiate/Terminate labels remain")
	}
	_, modal := e.do("GET", "/koneksi/4/terminate", nil, map[string]string{"HX-Request": "true"})
	for _, want := range []string{"Disconnect koneksi", "bisa connect ulang kapan saja", `hx-post="/koneksi/4/terminate"`, ">Disconnect</button>"} {
		if !strings.Contains(modal, want) {
			t.Errorf("disconnect modal missing %q", want)
		}
	}
	_, out := e.do("POST", "/koneksi/4/initiate", nil, e.safe())
	if !strings.Contains(out, "Connect koneksi branch berhasil") {
		t.Errorf("connect flash: %s", out)
	}
	_, out = e.do("POST", "/koneksi/4/terminate", nil, e.safe())
	if !strings.Contains(out, "Disconnect koneksi branch berhasil") {
		t.Errorf("disconnect flash: %s", out)
	}
	e.api.failPaths["connections/4/initiate"] = 500
	_, out = e.do("POST", "/koneksi/4/initiate", nil, e.safe())
	if !strings.Contains(out, "Connect gagal") {
		t.Errorf("connect error flash: %s", out)
	}
}

func TestS2SFormSubnets(t *testing.T) {
	e := setup(t)
	e.login()
	_, form := e.do("GET", "/koneksi/baru", nil, map[string]string{"HX-Request": "true"})
	for _, want := range []string{"Subnet LAN lokal (server ini)", "Subnet LAN remote (site lawan)", "Isi subnet yang boleh saling akses lewat tunnel. Di site lawan isinya dibalik.", "Remote ID", "PSK"} {
		if !strings.Contains(form, want) {
			t.Errorf("S2S form missing %q", want)
		}
	}
	for _, name := range []string{"local_ts", "remote_ts"} {
		ta := regexp.MustCompile(`(?s)<textarea[^>]*name="` + name + `"[^>]*>(.*?)</textarea>`).FindStringSubmatch(form)
		if ta == nil || strings.TrimSpace(ta[1]) != "" || !strings.Contains(ta[0], "placeholder=") {
			t.Errorf("%s must be an empty textarea with placeholder: %v", name, ta)
		}
	}
	res, _ := e.do("POST", "/koneksi", url.Values{"name": {"tmp2"}, "remote_address": {"198.51.100.8"}, "local_ts": {"10.10.7.0/24"}, "remote_ts": {"192.168.77.0/24\n192.168.78.0/24"}, "psk": {"pre-shared-key"}, "enabled": {"on"}}, e.safe())
	last := e.api.bodies[len(e.api.bodies)-1]
	if res.StatusCode != 200 || last["remote_ts"] != "192.168.77.0/24,192.168.78.0/24" || last["local_ts"] != "10.10.7.0/24" {
		t.Fatalf("multi CIDR body: %d %v", res.StatusCode, last)
	}
	// edit form splits the stored comma list back to one CIDR per line
	_, edit := e.do("GET", "/koneksi/21/ubah", nil, map[string]string{"HX-Request": "true"})
	if !strings.Contains(edit, "192.168.77.0/24\n192.168.78.0/24</textarea>") {
		t.Errorf("edit textarea must show one CIDR per line: %s", edit)
	}
	_, table := e.do("GET", "/koneksi", nil, nil)
	cell := regexp.MustCompile(`(?s)<td[^>]*data-subnets[^>]*>.*?</td>`).FindAllString(table, -1)
	if len(cell) != 2 || !strings.Contains(cell[1], "192.168.77.0/24") || !strings.Contains(cell[1], "192.168.78.0/24") || !strings.Contains(cell[1], "↔") {
		t.Errorf("subnet cell: %v", cell)
	}
	if !strings.Contains(table, ">Subnet (lokal ↔ remote)</th>") {
		t.Error("subnet column header")
	}
}

func TestKoneksiRoutingInfoBox(t *testing.T) {
	e := setup(t)
	e.login()
	_, body := e.do("GET", "/koneksi", nil, nil)
	box := regexp.MustCompile(`(?s)<details[^>]*data-s2s-info.*?</details>`).FindString(body)
	for _, want := range []string{"<summary", "route", "LAN IP", "allowed-address-pairs", "port security"} {
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
