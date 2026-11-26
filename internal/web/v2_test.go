package web

import (
	"net/url"
	"strings"
	"testing"
)

var hx = map[string]string{"HX-Request": "true"}

func TestV2MultiSiteIncrementalPeeringAndVendorDownloads(t *testing.T) {
	e := setup(t)
	e.login()

	// Legacy /koneksi redirects cleanly to /sites
	res, _ := e.do("GET", "/koneksi", nil, nil)
	if res.StatusCode != 303 || res.Header.Get("Location") != "/sites" {
		t.Fatalf("/koneksi redirect: %d %s", res.StatusCode, res.Header.Get("Location"))
	}

	// Empty state
	res, body := e.do("GET", "/sites", nil, nil)
	if res.StatusCode != 200 || !strings.Contains(body, "Site-to-Site (S2S)") || !strings.Contains(body, "Belum ada Site S2S") {
		t.Fatalf("/sites empty: %d", res.StatusCode)
	}
	if strings.Contains(body, "VPN Hub") || strings.Contains(body, "Direct (lama)") {
		t.Fatalf("legacy UI wording leaked into /sites")
	}

	// Step 1: First site form shows Site-A onboarding note (1 site first, no 2-site requirement)
	_, firstForm := e.do("GET", "/sites/baru", nil, hx)
	if !strings.Contains(firstForm, "Site pertama (Site-A)") {
		t.Fatalf("first site form missing onboarding note: %s", firstForm)
	}

	// Create Site-A first
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
	e.api.sites[0]["online"] = true
	e.api.sites[0]["connection_state"] = "online"
	e.api.sites[0]["last_connected_at"] = "2026-11-26T12:00:00Z"

	// Step 2: Open create form for Site-B — must show Site-A + subnet + Online badge as peer checkbox!
	_, form := e.do("GET", "/sites/baru", nil, hx)
	if !strings.Contains(form, `name="peer_sites"`) || !strings.Contains(form, "site-a") || !strings.Contains(form, "192.168.10.0/24") || !strings.Contains(form, "Online") {
		t.Fatalf("site-b create form missing site-a peer checkbox/status: %s", form)
	}

	// Create Site-B peered with Site-A
	res, _ = e.do("POST", "/sites", url.Values{
		"name": {"site-b"}, "subnets": {"192.168.20.0/24"},
		"allow_vpc": {"0", "on"}, "nat": {"0", "on"}, "encap": {"0", "on"},
		"peer_sites": {"21"}, "enabled": {"on"},
	}, e.safe())
	if res.StatusCode != 200 {
		t.Fatalf("create site-b: %d", res.StatusCode)
	}
	last := e.api.bodies[len(e.api.bodies)-1]
	peers, _ := last["peer_sites"].([]any)
	if len(peers) != 1 || int(peers[0].(float64)) != siteAID {
		t.Fatalf("site-b peer_sites body: %#v", last)
	}

	// Table shows Site-A Online + last_connected_at, Site-B Offline + Belum pernah terkoneksi, and peering pills
	e.api.sites[0]["peer_sites"] = []any{float64(siteAID + 1)}
	e.api.sites[1]["peer_sites"] = []any{float64(siteAID)}
	e.api.sites[1]["hub_local_ts"] = "10.10.7.0/24,192.168.10.0/24"
	e.api.sites[1]["status"] = "down"
	e.api.sites[1]["online"] = false
	_, table := e.do("GET", "/sites/tabel", nil, hx)
	for _, want := range []string{"site-a", "site-b", "Online", "Offline", "2026-11-26T12:00:00Z", "Belum pernah terkoneksi", "⇄ site-a", "⇄ site-b", "Remote TS: 10.10.7.0/24,192.168.10.0/24"} {
		if !strings.Contains(table, want) {
			t.Errorf("/sites/tabel missing %q", want)
		}
	}

	// Detail Site modal & clean downloads (Manual Configuration .conf, strongSwan .conf, Root CA .crt, plus Edit & Peering)
	_, cfgModal := e.do("GET", "/sites/21/configure", nil, hx)
	for _, want := range []string{"Detail Site: site-a", "Edit &amp; Peering", `hx-get="/sites/21/ubah"`, "192.0.2.10", "2026-11-26T12:00:00Z", "/unduh/sites/21/generic", "Manual Configuration (.conf)", "/unduh/sites/21/swanctl", "strongSwan (.conf)", "/unduh/pki/ca.crt"} {
		if !strings.Contains(cfgModal, want) {
			t.Errorf("detail site modal missing %q", want)
		}
	}
	for _, removed := range []string{"MikroTik", "FortiGate", "Cisco", "Linux Auto-Setup"} {
		if strings.Contains(cfgModal, removed) {
			t.Errorf("detail site modal should not show %q", removed)
		}
	}
	for _, vendor := range []string{"generic", "swanctl"} {
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

	// Mode 0: When 0 S2S sites exist, C2S form shows clear VPC/NAT-only guidance!
	_, formNoSites := e.do("GET", "/akun/baru", nil, hx)
	if !strings.Contains(formNoSites, "Belum ada Site S2S terdaftar") || !strings.Contains(formNoSites, `name="allow_vpc"`) {
		t.Fatalf("0-site user form missing VPC guidance: %s", formNoSites)
	}

	e.api.sites = []map[string]any{
		{"id": 10.0, "name": "site-jkt", "subnets": "192.168.10.0/24", "enabled": true, "status": "active", "online": true},
		{"id": 11.0, "name": "site-sby", "subnets": "192.168.20.0/24", "enabled": true, "status": "down", "online": false},
	}
	e.api.groups = []map[string]any{
		{"id": 30.0, "name": "ops-team", "allowed_cidrs": []any{"10.10.7.0/24"}, "allowed_sites": []any{10.0}, "enabled": true},
	}

	// Create user form shows VPC toggle, All Sites toggle, Multi-Site checkboxes with status, and Group checkboxes
	_, form := e.do("GET", "/akun/baru", nil, hx)
	for _, want := range []string{"Tujuan Akses Client", `name="allow_vpc"`, `name="allow_all_sites"`, "10.10.7.0/24", "site-jkt", "site-sby", "Online", "Offline", `name="allowed_sites"`, "ops-team", `name="groups"`} {
		if !strings.Contains(form, want) {
			t.Errorf("user form missing %q", want)
		}
	}

	// Create C2S user with ONLY site-jkt (unchecking allow_vpc & allow_all_sites)
	res, _ := e.do("POST", "/akun", url.Values{
		"username": {"field-jkt"}, "password": {"Secret-123"},
		"allow_vpc_present": {"1"}, "vpc_cidr": {"10.10.7.0/24"}, "allow_vpc": {"0"},
		"allow_all_sites_present": {"1"}, "allow_all_sites": {"0"},
		"allowed_cidrs": {""}, "allowed_sites_present": {"1"}, "allowed_sites": {"10"},
		"enabled": {"on"},
	}, e.safe())
	if res.StatusCode != 200 {
		t.Fatalf("create site-only user: %d", res.StatusCode)
	}
	last := e.api.bodies[len(e.api.bodies)-1]
	if last["allow_vpc"] != false || last["allow_all_sites"] != false {
		t.Fatalf("expected allow_vpc=false & allow_all_sites=false, got %#v", last)
	}
	asites, _ := last["allowed_sites"].([]any)
	if len(asites) != 1 || int(asites[0].(float64)) != 10 {
		t.Fatalf("expected allowed_sites=[10], got %#v", last)
	}

	// Edit that site-only user -> enable VPC + ALL SITES ("semuanya site + VPC")!
	_, editForm := e.do("GET", "/akun/21/ubah", nil, hx)
	if strings.Contains(editForm, `name="allow_vpc" value="on" checked`) {
		t.Errorf("site-only user edit form must NOT pre-check allow_vpc")
	}
	res, _ = e.do("PUT", "/akun/21", url.Values{
		"username": {"field-jkt"},
		"allow_vpc_present": {"1"}, "vpc_cidr": {"10.10.7.0/24"}, "allow_vpc": {"0", "on"},
		"allow_all_sites_present": {"1"}, "allow_all_sites": {"0", "on"},
		"allowed_cidrs": {""}, "allowed_sites_present": {"1"},
		"enabled": {"on"},
	}, e.safe())
	if res.StatusCode != 200 {
		t.Fatalf("edit user destinations: %d", res.StatusCode)
	}
	last = e.api.bodies[len(e.api.bodies)-1]
	if last["allow_vpc"] != true || last["allow_all_sites"] != true {
		t.Fatalf("edited destinations mismatch: %#v", last)
	}

	// Detail Account modal (includes Edit Account + Reset Password + clean downloads)
	_, uCfg := e.do("GET", "/akun/3/configure", nil, hx)
	for _, want := range []string{"Detail Account: poc-client", "Edit Account", `hx-get="/akun/3/ubah"`, "Reset Password", `hx-get="/akun/3/password"`, "192.0.2.10", "/unduh/akun/3/manual.conf", "/unduh/akun/3/profil.json", "/unduh/akun/3/vpnaas-ca.crt"} {
		if !strings.Contains(uCfg, want) {
			t.Errorf("detail akun modal missing %q", want)
		}
	}
	res, body := e.do("GET", "/unduh/akun/3/manual.conf", nil, nil)
	if res.StatusCode != 200 || !strings.Contains(body, "[GATEWAY_SERVER]") || res.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("manual.conf: %d %q", res.StatusCode, body)
	}
	res, body = e.do("GET", "/unduh/akun/3/apple.mobileconfig", nil, nil)
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
	if res.StatusCode != 200 || !strings.Contains(body, "C2S Groups") {
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
	if res.StatusCode != 200 || !strings.Contains(body, "VPNaaS Root CA") || !strings.Contains(body, "Rotate Server Cert") {
		t.Fatalf("/pki: %d", res.StatusCode)
	}
	res, _ = e.do("POST", "/pki/certs", url.Values{"name": {"alice-cert"}, "target_type": {"user"}, "validity_days": {"365"}}, e.safe())
	if res.StatusCode != 200 || len(e.api.certs) != 1 {
		t.Fatalf("issue cert: %d", res.StatusCode)
	}
	// Issue No Expiration cert (validity_days ignored when no_expiration=on)
	res, _ = e.do("POST", "/pki/certs", url.Values{"name": {"perm-site"}, "target_type": {"site"}, "no_expiration": {"0", "on"}, "validity_days": {""}}, e.safe())
	if res.StatusCode != 200 || len(e.api.certs) != 2 {
		t.Fatalf("issue no-expiration cert: %d", res.StatusCode)
	}
	_, pkiTbl := e.do("GET", "/pki/tabel", nil, hx)
	if !strings.Contains(pkiTbl, "No Expiration") {
		t.Fatalf("pki table missing No Expiration label: %s", pkiTbl)
	}
	res, body = e.do("GET", "/unduh/pki/ca.crt", nil, nil)
	if res.StatusCode != 200 || !strings.Contains(body, "BEGIN CERTIFICATE") {
		t.Fatalf("ca.crt: %d", res.StatusCode)
	}
	res, body = e.do("GET", "/unduh/pki/ca.pem", nil, nil)
	if res.StatusCode != 200 || !strings.Contains(body, "BEGIN CERTIFICATE") {
		t.Fatalf("ca.pem: %d", res.StatusCode)
	}
	res, body = e.do("GET", "/unduh/pki/certs/23/cert.crt", nil, nil)
	if res.StatusCode != 200 || !strings.Contains(body, "BEGIN CERTIFICATE") {
		t.Fatalf("cert.crt: %d", res.StatusCode)
	}
	res, body = e.do("GET", "/unduh/pki/certs/23/key.key", nil, nil)
	if res.StatusCode != 200 || !strings.Contains(body, "BEGIN PRIVATE KEY") {
		t.Fatalf("key.key: %d", res.StatusCode)
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
}

func TestAuditRegressionCertFormErrorsAndValidation(t *testing.T) {
	e := setup(t)
	e.login()

	// 1. SiteForm shows cert_id error clearly when auth_method=pubkey and no site cert exists
	res, body := e.do("POST", "/sites", url.Values{
		"name": {"site-x509"}, "subnets": {"192.168.90.0/24"}, "auth_method": {"pubkey"}, "enabled": {"on"},
	}, e.safe())
	if res.StatusCode != 200 || !strings.Contains(body, "Sertifikat site wajib dipilih") {
		t.Fatalf("site pubkey validation error not rendered: %d %s", res.StatusCode, body)
	}

	// 2. When a user X.509 cert exists, UserForm password input must NOT have HTML5 required attribute so pubkey/eap-tls users can submit
	e.api.certs = []map[string]any{
		{"id": 50.0, "name": "alice-x509", "san": "alice@corp.id", "target_type": "user", "serial": "AA11", "revoked": false},
	}
	_, uForm := e.do("GET", "/akun/baru", nil, hx)
	if strings.Contains(uForm, `name="password" autocomplete="new-password" placeholder="Wajib untuk EAP-MSCHAPv2 (kosongkan jika pakai X.509/EAP-TLS)" required`) {
		t.Fatalf("password input must not force HTML5 required when user certs exist: %s", uForm)
	}
	if !strings.Contains(uForm, "alice-x509") {
		t.Fatalf("user cert option missing from create form")
	}

	// 3. PolicyForm renders source_ref / destination_ref validation errors visibly
	res, pBody := e.do("POST", "/kebijakan", url.Values{
		"name": {"bad-ref"}, "source_type": {"site"}, "source_ref": {""}, "destination_type": {"site"}, "destination_ref": {""}, "protocol": {"all"},
	}, e.safe())
	if res.StatusCode != 200 || !strings.Contains(pBody, "Pilih entitas source") || !strings.Contains(pBody, "Pilih site tujuan") {
		t.Fatalf("policy ref validation errors not rendered: %d %s", res.StatusCode, pBody)
	}
}
