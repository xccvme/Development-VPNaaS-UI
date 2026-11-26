package web

import (
	"net/url"
	"strings"
	"testing"
)

func TestV2MultiSiteIncrementalPeeringAndVendorDownloads(t *testing.T) {
	e := setup(t)
	e.login()

	// Empty state
	res, body := e.do("GET", "/sites", nil, nil)
	if res.StatusCode != 200 || !strings.Contains(body, "Multi-Site S2S (Hub &amp; Spoke)") || !strings.Contains(body, "Belum ada Multi-Site S2S") {
		t.Fatalf("/sites empty: %d", res.StatusCode)
	}

	// Step 1: Create Site-A first
	res, body = e.do("POST", "/sites", url.Values{
		"name": {"site-a"}, "subnets": {"192.168.10.0/24"},
		"allow_vpc": {"0", "on"}, "nat": {"0", "on"}, "encap": {"0", "on"}, "enabled": {"on"},
	}, e.safe())
	if res.StatusCode != 200 || !strings.Contains(res.Header.Get("HX-Trigger"), "vpnaas:close") {
		t.Fatalf("create site-a: %d %s", res.StatusCode, body)
	}
	siteAID := int(e.api.sites[0]["id"].(float64))
	e.api.sites[0]["ike_id"] = "site-a@vpnaas"
	e.api.sites[0]["hub_local_ts"] = "10.10.7.0/24"
	e.api.sites[0]["status"] = "active"

	// Step 2: Open create form for Site-B — must show Site-A as peer checkbox!
	_, form := e.do("GET", "/sites/baru", nil, hx)
	if !strings.Contains(form, `name="peer_sites"`) || !strings.Contains(form, "site-a") || !strings.Contains(form, "192.168.10.0/24") {
		t.Fatalf("site-b create form missing site-a peer checkbox: %s", form)
	}

	// Create Site-B peered with Site-A
	res, _ = e.do("POST", "/sites", url.Values{
		"name": {"site-b"}, "subnets": {"192.168.20.0/24"},
		"allow_vpc": {"0", "on"}, "nat": {"0", "on"}, "encap": {"0", "on"},
		"peer_sites": {strings.TrimSpace(strFromMap(map[string]any{"id": ""}, "id") + "21")}, "enabled": {"on"},
	}, e.safe())
	if res.StatusCode != 200 {
		t.Fatalf("create site-b: %d", res.StatusCode)
	}
	last := e.api.bodies[len(e.api.bodies)-1]
	peers, _ := last["peer_sites"].([]any)
	if len(peers) != 1 || int(peers[0].(float64)) != siteAID {
		t.Fatalf("site-b peer_sites body: %#v", last)
	}

	// Table shows Site-A and peering pill
	e.api.sites[0]["peer_sites"] = []any{float64(siteAID + 1)}
	e.api.sites[1]["peer_sites"] = []any{float64(siteAID)}
	e.api.sites[1]["hub_local_ts"] = "10.10.7.0/24,192.168.10.0/24"
	_, table := e.do("GET", "/sites/tabel", nil, hx)
	for _, want := range []string{"site-a", "site-b", "⇄ site-a", "⇄ site-b", "Remote TS: 10.10.7.0/24,192.168.10.0/24"} {
		if !strings.Contains(table, want) {
			t.Errorf("/sites/tabel missing %q", want)
		}
	}

	// Configure modal & multi-vendor downloads
	_, cfgModal := e.do("GET", "/sites/21/configure", nil, hx)
	for _, want := range []string{"Configure Site: site-a", "/unduh/sites/21/script", "/unduh/sites/21/mikrotik", "/unduh/sites/21/fortigate", "/unduh/sites/21/cisco"} {
		if !strings.Contains(cfgModal, want) {
			t.Errorf("configure modal missing %q", want)
		}
	}
	for _, vendor := range []string{"script", "swanctl", "mikrotik", "fortigate", "cisco"} {
		res, body := e.do("GET", "/unduh/sites/21/"+vendor, nil, nil)
		if res.StatusCode != 200 || !strings.Contains(body, "vendor="+vendor) || res.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("download vendor %s: %d %q", vendor, res.StatusCode, body)
		}
	}

	// Connect / Disconnect actions
	res, body = e.do("POST", "/sites/21/connect", nil, e.safe())
	if res.StatusCode != 200 || !strings.Contains(body, "Connect site #21 berhasil") {
		t.Fatalf("site connect: %d %s", res.StatusCode, body)
	}
}

func TestV2C2SSelectiveSiteAccessProfilesAndDisconnect(t *testing.T) {
	e := setup(t)
	e.login()
	e.api.sites = []map[string]any{
		{"id": 10.0, "name": "site-jkt", "subnets": "192.168.10.0/24", "enabled": true},
		{"id": 11.0, "name": "site-sby", "subnets": "192.168.20.0/24", "enabled": true},
	}
	e.api.groups = []map[string]any{
		{"id": 30.0, "name": "ops-team", "allowed_cidrs": []any{"10.10.7.0/24"}, "allowed_sites": []any{10.0}, "enabled": true},
	}

	// Create user form shows VPC toggle, Multi-Site checkboxes and Group checkboxes
	_, form := e.do("GET", "/akun/baru", nil, hx)
	for _, want := range []string{"Tujuan Akses Client", `name="allow_vpc"`, "10.10.7.0/24", "Akses Multi-Site S2S", "site-jkt", "site-sby", `name="allowed_sites"`, "ops-team", `name="groups"`} {
		if !strings.Contains(form, want) {
			t.Errorf("user form missing %q", want)
		}
	}

	// Create C2S user with ONLY site-jkt (unchecking allow_vpc)
	res, _ := e.do("POST", "/akun", url.Values{
		"username": {"field-jkt"}, "password": {"Secret-123"},
		"allow_vpc_present": {"1"}, "vpc_cidr": {"10.10.7.0/24"}, "allow_vpc": {"0"},
		"allowed_cidrs": {""}, "allowed_sites_present": {"1"}, "allowed_sites": {"10"},
		"enabled": {"on"},
	}, e.safe())
	if res.StatusCode != 200 {
		t.Fatalf("create site-only user: %d", res.StatusCode)
	}
	last := e.api.bodies[len(e.api.bodies)-1]
	cidrs, ok := last["allowed_cidrs"].([]any)
	if !ok || len(cidrs) != 0 {
		t.Fatalf("expected explicit empty allowed_cidrs for site-only user, got %#v", last)
	}
	asites, _ := last["allowed_sites"].([]any)
	if len(asites) != 1 || int(asites[0].(float64)) != 10 {
		t.Fatalf("expected allowed_sites=[10], got %#v", last)
	}

	// Edit that site-only user -> enable VPC + switch to site-sby!
	uid := strFromMap(map[string]any{}, "")
	_ = uid
	_, editForm := e.do("GET", "/akun/21/ubah", nil, hx)
	if strings.Contains(editForm, `name="allow_vpc" value="on" checked`) {
		t.Errorf("site-only user edit form must NOT pre-check allow_vpc")
	}
	res, _ = e.do("PUT", "/akun/21", url.Values{
		"username": {"field-jkt"},
		"allow_vpc_present": {"1"}, "vpc_cidr": {"10.10.7.0/24"}, "allow_vpc": {"0", "on"},
		"allowed_cidrs": {""}, "allowed_sites_present": {"1"}, "allowed_sites": {"11"},
		"enabled": {"on"},
	}, e.safe())
	if res.StatusCode != 200 {
		t.Fatalf("edit user destinations: %d", res.StatusCode)
	}
	last = e.api.bodies[len(e.api.bodies)-1]
	cidrs, _ = last["allowed_cidrs"].([]any)
	asites, _ = last["allowed_sites"].([]any)
	if len(cidrs) != 1 || cidrs[0] != "10.10.7.0/24" || len(asites) != 1 || int(asites[0].(float64)) != 11 {
		t.Fatalf("edited destinations mismatch: %#v", last)
	}

	// Apple .mobileconfig and Android .sswan downloads
	res, body := e.do("GET", "/unduh/akun/3/apple.mobileconfig", nil, nil)
	if res.StatusCode != 200 || !strings.Contains(body, "<plist>") || res.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("mobileconfig: %d %q", res.StatusCode, body)
	}
	res, body = e.do("GET", "/unduh/akun/3/android.sswan", nil, nil)
	if res.StatusCode != 200 || !strings.Contains(body, `"uuid"`) {
		t.Fatalf("sswan: %d %q", res.StatusCode, body)
	}

	// Explicit session disconnect (all + single IKE SA)
	res, body = e.do("POST", "/akun/3/disconnect", nil, e.safe())
	if res.StatusCode != 200 || !strings.Contains(body, "Sesi aktif akun #3 diputus") {
		t.Fatalf("disconnect all: %d %s", res.StatusCode, body)
	}
	res, _ = e.do("POST", "/akun/3/sesi/13/disconnect", nil, e.safe())
	if res.StatusCode != 200 || !strings.Contains(strings.Join(e.api.calls, ","), "POST users/3/sessions/13/disconnect") {
		t.Fatalf("disconnect single: %d %v", res.StatusCode, e.api.calls)
	}
}

func TestV2GroupsRoutingPKITokensAndDiagnostics(t *testing.T) {
	e := setup(t)
	e.login()

	// Groups
	res, body := e.do("GET", "/grup", nil, nil)
	if res.StatusCode != 200 || !strings.Contains(body, "Grup Client-to-Site") {
		t.Fatalf("/grup: %d", res.StatusCode)
	}
	res, _ = e.do("POST", "/grup", url.Values{"name": {"devops"}, "allowed_cidrs": {"10.10.7.0/24"}, "enabled": {"on"}}, e.safe())
	if res.StatusCode != 200 || len(e.api.groups) != 1 {
		t.Fatalf("create group: %d %v", res.StatusCode, e.api.groups)
	}

	// Routing: Add -> Edit (gateway/metric/description -> site_id) -> Delete
	res, body = e.do("GET", "/routing", nil, nil)
	if res.StatusCode != 200 || !strings.Contains(body, "Static Routing") {
		t.Fatalf("/routing: %d", res.StatusCode)
	}
	res, _ = e.do("POST", "/routing", url.Values{"name": {"to-db"}, "destination_cidr": {"10.120.0.0/24"}, "gateway": {"10.10.7.1"}, "metric": {"100"}, "description": {"db lan"}, "enabled": {"on"}}, e.safe())
	if res.StatusCode != 200 || len(e.api.routes) != 1 {
		t.Fatalf("create route: %d %v", res.StatusCode, e.api.routes)
	}
	_, editRt := e.do("GET", "/routing/22/ubah", nil, hx)
	if !strings.Contains(editRt, `value="to-db"`) || !strings.Contains(editRt, `value="10.10.7.1"`) || !strings.Contains(editRt, `value="db lan"`) {
		t.Fatalf("route edit form not prefilled: %s", editRt)
	}
	res, _ = e.do("PUT", "/routing/22", url.Values{"name": {"to-db"}, "destination_cidr": {"10.120.0.0/24"}, "gateway": {""}, "interface": {"ens8"}, "metric": {"50"}, "description": {""}, "enabled": {"on"}}, e.safe())
	if res.StatusCode != 200 {
		t.Fatalf("edit route: %d", res.StatusCode)
	}
	lastRt := e.api.bodies[len(e.api.bodies)-1]
	if lastRt["gateway"] != nil || lastRt["interface"] != "ens8" || lastRt["metric"] != 50.0 || lastRt["description"] != "" {
		t.Fatalf("route edit body mismatch: %#v", lastRt)
	}
	_, delModal := e.do("GET", "/routing/22/hapus", nil, hx)
	if !strings.Contains(delModal, `hx-delete="/routing/22"`) || !strings.Contains(delModal, "to-db") {
		t.Fatalf("route delete confirm modal: %s", delModal)
	}
	res, _ = e.do("DELETE", "/routing/22", nil, e.safe())
	if res.StatusCode != 200 || len(e.api.routes) != 0 {
		t.Fatalf("delete route: %d %v", res.StatusCode, e.api.routes)
	}

	// PKI
	res, body = e.do("GET", "/pki", nil, nil)
	if res.StatusCode != 200 || !strings.Contains(body, "VPNaaS Root CA") || !strings.Contains(body, "Rotasi Sertifikat Server") {
		t.Fatalf("/pki: %d", res.StatusCode)
	}
	res, _ = e.do("POST", "/pki/certs", url.Values{"name": {"alice-cert"}, "target_type": {"user"}, "validity_days": {"365"}}, e.safe())
	if res.StatusCode != 200 || len(e.api.certs) != 1 {
		t.Fatalf("issue cert: %d", res.StatusCode)
	}
	res, body = e.do("GET", "/unduh/pki/ca.pem", nil, nil)
	if res.StatusCode != 200 || !strings.Contains(body, "BEGIN CERTIFICATE") {
		t.Fatalf("ca.pem: %d", res.StatusCode)
	}
	res, body = e.do("GET", "/unduh/pki/certs/23/bundle.p12", nil, nil)
	if res.StatusCode != 200 || body != "PK12DATA" {
		t.Fatalf("bundle.p12: %d %q", res.StatusCode, body)
	}
	res, body = e.do("POST", "/pki/server/rotate", nil, e.safe())
	if res.StatusCode != 200 || !strings.Contains(body, "berhasil dirotasi") {
		t.Fatalf("rotate: %d", res.StatusCode)
	}

	// Tokens
	res, body = e.do("GET", "/tokens", nil, nil)
	if res.StatusCode != 200 || !strings.Contains(body, "Token API") {
		t.Fatalf("/tokens: %d", res.StatusCode)
	}
	res, body = e.do("POST", "/tokens", url.Values{"name": {"portal-prod"}, "role": {"operator"}, "expires_days": {"90"}}, e.safe())
	if res.StatusCode != 200 || !strings.Contains(body, "vpnaas_test_SECRET_ONCE") {
		t.Fatalf("create token: %d %s", res.StatusCode, body)
	}

	// Enhanced Status + Diagnostics + Logs
	res, body = e.do("GET", "/status", nil, nil)
	if res.StatusCode != 200 || !strings.Contains(body, "READY") || !strings.Contains(body, "id-jkt-1") || !strings.Contains(body, "[REDACTED]") {
		t.Fatalf("/status v2: %d", res.StatusCode)
	}
	res, body = e.do("POST", "/status/diagnostics", url.Values{"target": {"192.168.10.50"}, "source_user_id": {"3"}}, e.safe())
	if res.StatusCode != 200 || !strings.Contains(body, "site-n-1") {
		t.Fatalf("diagnostics: %d %s", res.StatusCode, body)
	}
	res, body = e.do("GET", "/status/logs?source=api", nil, hx)
	if res.StatusCode != 200 || !strings.Contains(body, "[REDACTED]") {
		t.Fatalf("logs: %d %s", res.StatusCode, body)
	}

	// Hub multi-vendor download works on legacy VPN Hub too
	res, body = e.do("GET", "/unduh/koneksi/7/site-a/mikrotik.rsc", nil, nil)
	if res.StatusCode != 200 || !strings.Contains(body, "mikrotik") || res.Header.Get("Content-Disposition") != `attachment; filename="Hub-kantor-Site-A.rsc"` {
		t.Fatalf("hub mikrotik: %d %q %v", res.StatusCode, body, res.Header)
	}
}
