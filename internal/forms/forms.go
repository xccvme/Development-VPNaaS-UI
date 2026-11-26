// Package forms converts HTML form submissions into backend API JSON bodies,
// applying the same validation rules as the backend (backend/store.py) so the
// user gets immediate field errors. The backend remains authoritative.
package forms

import (
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const DefaultLAN = "10.10.7.0/24"

// DefaultMaxSessions is the concurrent session limit used when none is chosen.
const DefaultMaxSessions = 3

var (
	safeRe       = regexp.MustCompile(`^[A-Za-z0-9_@.:-]{1,128}$`)
	credentialRe = regexp.MustCompile(`^[A-Za-z0-9_@.!+,:/=-]{8,128}$`)
	hubPSKRe     = regexp.MustCompile(`^[A-Za-z0-9_@.!+,:/=-]{16,128}$`)
	ifnameRe     = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)
	Protocols    = []string{"all", "tcp", "udp", "icmp"}
)

type Errors map[string]string

// SplitList splits on newlines/commas, trims, drops empties and duplicates.
func SplitList(s string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, part := range regexp.MustCompile(`[\r\n,]+`).Split(s, -1) {
		p := strings.TrimSpace(part)
		if p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

func parseIntList(vals []string) ([]int, bool) {
	out := []int{}
	seen := map[int]bool{}
	for _, raw := range vals {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 {
			return nil, false
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out, true
}

func ipv4CIDR(s string) bool {
	p, err := netip.ParsePrefix(s)
	if err == nil {
		return p.Addr().Is4()
	}
	a, err := netip.ParseAddr(s)
	return err == nil && a.Is4()
}

func get(v url.Values, k string) string { return strings.TrimSpace(v.Get(k)) }

func enabled(v url.Values) bool {
	switch v.Get("enabled") {
	case "on", "true", "1":
		return true
	}
	return false
}

// User builds a users POST/PUT body. Password is write-only: blank on edit is
// omitted so the backend keeps the existing secret.
func User(v url.Values, create bool) (map[string]any, Errors) {
	errs := Errors{}
	body := map[string]any{"enabled": enabled(v)}
	name := get(v, "username")
	if !safeRe.MatchString(name) {
		errs["username"] = "Username 1-128 karakter: huruf, angka, _ @ . : -"
	}
	body["username"] = name

	authMethod := get(v, "auth_method")
	if authMethod != "" {
		if authMethod != "eap-mschapv2" && authMethod != "pubkey" && authMethod != "eap-tls" {
			errs["auth_method"] = "Metode auth harus eap-mschapv2, pubkey, atau eap-tls"
		}
		body["auth_method"] = authMethod
	}
	isCertAuth := authMethod == "pubkey" || authMethod == "eap-tls"
	if isCertAuth {
		cid, err := strconv.Atoi(get(v, "cert_id"))
		if err != nil || cid < 1 {
			errs["cert_id"] = "Sertifikat X.509 wajib dipilih untuk autentikasi sertifikat"
		} else {
			body["cert_id"] = cid
		}
	}

	pw := v.Get("password")
	if pw != "" {
		if !credentialRe.MatchString(pw) {
			errs["password"] = "Password 8-128 karakter: huruf, angka, _ @ . ! + , : / = -"
		}
		body["password"] = pw
	} else if create && !isCertAuth {
		errs["password"] = "Password wajib diisi saat membuat akun"
	}

	mode := v.Get("traffic_mode")
	if mode == "" {
		mode = "split"
	}
	if mode != "split" && mode != "full" {
		errs["traffic_mode"] = "Mode trafik harus split atau full"
	}
	body["traffic_mode"] = mode

	if raw, present := v["max_sessions"]; present || create {
		ms := ""
		if present {
			ms = strings.TrimSpace(raw[0])
		}
		switch ms {
		case "":
			body["max_sessions"] = DefaultMaxSessions
		case "1", "2", "3":
			body["max_sessions"] = int(ms[0] - '0')
		default:
			errs["max_sessions"] = "Maks. koneksi bersamaan harus 1, 2, atau 3"
		}
	}

	hasSitesField := false
	var allowedSites []int
	if _, ok := v["allowed_sites_present"]; ok || len(v["allowed_sites"]) > 0 {
		hasSitesField = true
		var okIDs bool
		allowedSites, okIDs = parseIntList(v["allowed_sites"])
		if !okIDs {
			errs["allowed_sites"] = "ID site tidak valid"
		} else {
			body["allowed_sites"] = allowedSites
		}
	}

	hasGroupsField := false
	var groupIDs []int
	if _, ok := v["groups_present"]; ok || len(v["groups"]) > 0 {
		hasGroupsField = true
		var okIDs bool
		groupIDs, okIDs = parseIntList(v["groups"])
		if !okIDs {
			errs["groups"] = "ID grup tidak valid"
		} else {
			body["groups"] = groupIDs
		}
	}

	// Empty allowed CIDRs:
	// - When allow_vpc_present is submitted by the UI form, toggle the server's vpc_cidr cleanly in/out of allowed_cidrs.
	// - When user explicitly chose allowed_sites or groups with blank CIDRs, send [] so user gets ONLY selected sites/groups (no forced VPC).
	// - Otherwise omit so backend applies its LAN default (create) or keeps stored value (edit).
	cidrs := SplitList(v.Get("allowed_cidrs"))
	if _, hasVPCField := v["allow_vpc_present"]; hasVPCField {
		vpcCIDR := get(v, "vpc_cidr")
		if vpcCIDR == "" {
			vpcCIDR = DefaultLAN
		}
		wantVPC := Checkbox(v, "allow_vpc", false)
		if wantVPC && ipv4CIDR(vpcCIDR) {
			found := false
			for _, c := range cidrs {
				if c == vpcCIDR {
					found = true
					break
				}
			}
			if !found {
				cidrs = append([]string{vpcCIDR}, cidrs...)
			}
		} else if !wantVPC && vpcCIDR != "" {
			filtered := []string{}
			for _, c := range cidrs {
				if c != vpcCIDR {
					filtered = append(filtered, c)
				}
			}
			cidrs = filtered
		}
		if len(cidrs) == 0 && len(allowedSites) == 0 && len(groupIDs) == 0 {
			errs["allowed_cidrs"] = "Pilih minimal satu tujuan akses: VPC server, Allowed CIDRs, Multi-Site S2S, atau Grup C2S"
			return body, errs
		}
	} else if len(cidrs) == 0 {
		if (hasSitesField && len(allowedSites) > 0) || (hasGroupsField && len(groupIDs) > 0) {
			body["allowed_cidrs"] = []string{}
		}
		return body, errs
	}
	if len(cidrs) > 16 {
		errs["allowed_cidrs"] = "Maksimal 16 CIDR"
	}
	for _, c := range cidrs {
		if !ipv4CIDR(c) {
			errs["allowed_cidrs"] = "CIDR IPv4 tidak valid: " + c
			break
		}
		if p, err := netip.ParsePrefix(c); err == nil && p.Bits() == 0 {
			errs["allowed_cidrs"] = "Default route (/0) tidak didukung pada split tunnel"
			break
		}
	}
	body["allowed_cidrs"] = cidrs
	return body, errs
}

func Connection(v url.Values, create bool) (map[string]any, Errors) {
	errs := Errors{}
	body := map[string]any{"enabled": enabled(v)}
	name := get(v, "name")
	if !safeRe.MatchString(name) {
		errs["name"] = "Nama 1-128 karakter: huruf, angka, _ @ . : -"
	}
	body["name"] = name
	addr := get(v, "remote_address")
	if a, err := netip.ParseAddr(addr); err != nil || !a.Is4() {
		errs["remote_address"] = "Alamat remote harus IPv4"
	}
	body["remote_address"] = addr
	if rid := get(v, "remote_id"); rid != "" {
		if !safeRe.MatchString(rid) {
			errs["remote_id"] = "Remote ID hanya huruf, angka, _ @ . : -"
		}
		body["remote_id"] = rid
	}
	if local := SplitList(v.Get("local_ts")); len(local) > 0 {
		if msg := selectorError(local); msg != "" {
			errs["local_ts"] = msg
		}
		body["local_ts"] = strings.Join(local, ",")
	}
	remote := SplitList(v.Get("remote_ts"))
	if len(remote) == 0 {
		errs["remote_ts"] = "Subnet LAN remote wajib diisi"
	} else if msg := selectorError(remote); msg != "" {
		errs["remote_ts"] = msg
	}
	body["remote_ts"] = strings.Join(remote, ",")
	psk := v.Get("psk")
	if psk != "" {
		if !credentialRe.MatchString(psk) {
			errs["psk"] = "PSK 8-128 karakter: huruf, angka, _ @ . ! + , : / = -"
		}
		body["psk"] = psk
	} else if create {
		errs["psk"] = "PSK wajib diisi saat membuat koneksi"
	}
	return body, errs
}

// MaxSelectors is the per-side S2S subnet limit accepted by the backend.
const MaxSelectors = 8

// AnyAddress is the strongSwan wildcard for a spoke behind NAT / dynamic IP.
const AnyAddress = "%any"

var hostnameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*$`)

// SiteKeys are the two hub spokes; form fields are prefixed "site_a_"/"site_b_".
var SiteKeys = []string{"a", "b"}

// Checkbox reads a checkbox paired with a hidden "0" marker: absent entirely
// means default (true), present without "on" means unchecked.
func Checkbox(v url.Values, k string, def bool) bool {
	vals, ok := v[k]
	if !ok {
		return def
	}
	for _, x := range vals {
		switch x {
		case "on", "true", "1":
			return true
		}
	}
	return false
}

// validSpokeAddress: %any, an IPv4 address, or a DNS hostname (not an IPv6/other IP).
func validSpokeAddress(addr string) bool {
	if addr == AnyAddress {
		return true
	}
	if a, err := netip.ParseAddr(addr); err == nil {
		return a.Is4()
	}
	return len(addr) <= 253 && hostnameRe.MatchString(addr) && !numericRe.MatchString(addr)
}

var numericRe = regexp.MustCompile(`^[0-9.]+$`)

func overlaps(a, b []string) string {
	for _, x := range a {
		px, err := netip.ParsePrefix(x)
		if err != nil {
			continue
		}
		for _, y := range b {
			py, err := netip.ParsePrefix(y)
			if err == nil && px.Masked().Overlaps(py.Masked()) {
				return y
			}
		}
	}
	return ""
}

// Hub builds a VPN Hub (topology "hub") POST/PUT body from site_a_*/site_b_* fields.
func Hub(v url.Values, create bool) (map[string]any, Errors) {
	errs := Errors{}
	body := map[string]any{"enabled": enabled(v), "topology": "hub"}
	name := get(v, "name")
	if !safeRe.MatchString(name) {
		errs["name"] = "Nama 1-128 karakter: huruf, angka, _ @ . : -"
	}
	body["name"] = name
	subnets := map[string][]string{}
	for _, s := range SiteKeys {
		p := "site_" + s + "_"
		label := "Site-" + strings.ToUpper(s)
		site := map[string]any{}
		sn := get(v, p+"name")
		if !safeRe.MatchString(sn) {
			errs[p+"name"] = "Nama site " + label + " wajib, 1-128 karakter: huruf, angka, _ @ . : -"
		}
		site["name"] = sn
		addr := get(v, p+"address")
		if addr == "" {
			addr = AnyAddress
		}
		if !validSpokeAddress(addr) {
			errs[p+"address"] = "Alamat publik harus IPv4 atau hostname (kosongkan jika di belakang NAT)"
		}
		site["address"] = addr
		if id := get(v, p+"id"); id != "" {
			if !safeRe.MatchString(id) {
				errs[p+"id"] = "IKE ID hanya huruf, angka, _ @ . : - (maks. 128)"
			}
			site["id"] = id
		}
		if psk := v.Get(p + "psk"); psk != "" {
			if !credentialRe.MatchString(psk) {
				errs[p+"psk"] = "PSK 8-128 karakter: huruf, angka, _ @ . ! + , : / = -"
			}
			site["psk"] = psk
		}
		list := SplitList(v.Get(p + "subnets"))
		if len(list) == 0 {
			errs[p+"subnets"] = "Subnet LAN " + label + " wajib diisi"
		} else if msg := selectorError(list); msg != "" {
			errs[p+"subnets"] = msg
		}
		subnets[s] = list
		site["subnets"] = strings.Join(list, ",")
		site["nat"] = Checkbox(v, p+"nat", true)
		body["site_"+s] = site
	}
	if errs["site_a_subnets"] == "" && errs["site_b_subnets"] == "" {
		if c := overlaps(subnets["a"], subnets["b"]); c != "" {
			errs["site_b_subnets"] = "Subnet Site-B tumpang tindih dengan Site-A: " + c
		}
	}
	return body, errs
}

// MultiSite builds a v2.0 /api/sites POST/PUT body with peer_sites and allow_vpc.
func MultiSite(v url.Values, create bool) (map[string]any, Errors) {
	errs := Errors{}
	body := map[string]any{
		"enabled":   enabled(v),
		"nat":       Checkbox(v, "nat", true),
		"encap":     Checkbox(v, "encap", true),
		"allow_vpc": Checkbox(v, "allow_vpc", true),
	}
	name := get(v, "name")
	if !safeRe.MatchString(name) {
		errs["name"] = "Nama site 1-128 karakter: huruf, angka, _ @ . : -"
	}
	body["name"] = name

	addr := get(v, "address")
	if addr == "" {
		addr = AnyAddress
	}
	if !validSpokeAddress(addr) {
		errs["address"] = "Alamat harus IPv4, hostname, atau kosong (%any)"
	}
	body["address"] = addr

	if id := get(v, "ike_id"); id != "" {
		if !safeRe.MatchString(id) {
			errs["ike_id"] = "IKE ID hanya huruf, angka, _ @ . : -"
		}
		body["ike_id"] = id
	}

	authMethod := get(v, "auth_method")
	if authMethod == "" {
		authMethod = "psk"
	}
	if authMethod != "psk" && authMethod != "pubkey" {
		errs["auth_method"] = "Metode auth harus psk atau pubkey"
	}
	body["auth_method"] = authMethod
	if authMethod == "psk" {
		if psk := v.Get("psk"); psk != "" {
			if !hubPSKRe.MatchString(psk) {
				errs["psk"] = "PSK minimal 16 karakter aman (A-Z a-z 0-9 _ @ . ! + , : / = -)"
			}
			body["psk"] = psk
		}
	} else {
		cid, err := strconv.Atoi(get(v, "cert_id"))
		if err != nil || cid < 1 {
			errs["cert_id"] = "Sertifikat site wajib dipilih untuk auth X.509"
		} else {
			body["cert_id"] = cid
		}
	}

	subnets := SplitList(v.Get("subnets"))
	if len(subnets) == 0 {
		errs["subnets"] = "Subnet LAN site wajib diisi"
	} else if len(subnets) > 16 {
		errs["subnets"] = "Maksimal 16 subnet"
	} else {
		for _, c := range subnets {
			if !ipv4CIDR(c) {
				errs["subnets"] = "CIDR IPv4 tidak valid: " + c
				break
			}
			if p, err := netip.ParsePrefix(c); err == nil && p.Bits() == 0 {
				errs["subnets"] = "Default route (/0) tidak didukung: " + c
				break
			}
		}
	}
	body["subnets"] = strings.Join(subnets, ",")

	peers, okPeers := parseIntList(v["peer_sites"])
	if !okPeers {
		errs["peer_sites"] = "Peer site tidak valid"
	} else {
		body["peer_sites"] = peers
	}

	if dpdStr := get(v, "dpd_delay"); dpdStr != "" {
		dpd, err := strconv.Atoi(dpdStr)
		if err != nil || dpd < 10 || dpd > 300 {
			errs["dpd_delay"] = "DPD delay harus 10–300 detik"
		} else {
			body["dpd_delay"] = dpd
		}
	}
	if ikeP := get(v, "ike_proposals"); ikeP != "" {
		body["ike_proposals"] = ikeP
	}
	if espP := get(v, "esp_proposals"); espP != "" {
		body["esp_proposals"] = espP
	}
	if _, hasDesc := v["description"]; hasDesc {
		body["description"] = get(v, "description")
	}
	return body, errs
}

// Group builds a v2.0 /api/groups POST/PUT body.
func Group(v url.Values) (map[string]any, Errors) {
	errs := Errors{}
	body := map[string]any{"enabled": enabled(v)}
	name := get(v, "name")
	if !safeRe.MatchString(name) {
		errs["name"] = "Nama grup 1-128 karakter: huruf, angka, _ @ . : -"
	}
	body["name"] = name
	body["description"] = get(v, "description")

	cidrs := SplitList(v.Get("allowed_cidrs"))
	if len(cidrs) > 16 {
		errs["allowed_cidrs"] = "Maksimal 16 CIDR"
	}
	for _, c := range cidrs {
		if !ipv4CIDR(c) {
			errs["allowed_cidrs"] = "CIDR IPv4 tidak valid: " + c
			break
		}
		if p, err := netip.ParsePrefix(c); err == nil && p.Bits() == 0 {
			errs["allowed_cidrs"] = "Default route (/0) tidak didukung"
			break
		}
	}
	body["allowed_cidrs"] = cidrs

	sites, ok := parseIntList(v["allowed_sites"])
	if !ok {
		errs["allowed_sites"] = "Site tidak valid"
	} else {
		body["allowed_sites"] = sites
	}
	return body, errs
}

// Route builds a v2.0 /api/routes POST/PUT body.
func Route(v url.Values) (map[string]any, Errors) {
	errs := Errors{}
	body := map[string]any{"enabled": enabled(v)}
	name := get(v, "name")
	if !safeRe.MatchString(name) {
		errs["name"] = "Nama route 1-128 karakter: huruf, angka, _ @ . : -"
	}
	body["name"] = name

	dst := get(v, "destination_cidr")
	if !ipv4CIDR(dst) {
		errs["destination_cidr"] = "Destination CIDR IPv4 tidak valid"
	} else if p, err := netip.ParsePrefix(dst); err == nil && p.Bits() == 0 {
		errs["destination_cidr"] = "Default route (/0) tidak didukung"
	}
	body["destination_cidr"] = dst

	gw := get(v, "gateway")
	if gw != "" {
		a, err := netip.ParseAddr(gw)
		if err != nil || !a.Is4() || gw == "0.0.0.0" {
			errs["gateway"] = "Gateway harus IPv4 valid"
		} else {
			body["gateway"] = gw
		}
	} else {
		body["gateway"] = nil
	}

	iface := get(v, "interface")
	if iface != "" {
		if !ifnameRe.MatchString(iface) || iface == "lo" {
			errs["interface"] = "Nama interface tidak valid"
		} else {
			body["interface"] = iface
		}
	} else {
		body["interface"] = nil
	}

	siteStr := get(v, "site_id")
	if siteStr != "" {
		sid, err := strconv.Atoi(siteStr)
		if err != nil || sid < 1 {
			errs["site_id"] = "Site tidak valid"
		} else {
			body["site_id"] = sid
		}
	} else {
		body["site_id"] = nil
	}

	if gw == "" && iface == "" && siteStr == "" {
		errs["gateway"] = "Isi minimal salah satu: Gateway, Interface, atau Site tujuan"
	}

	metric := 100
	if mStr := get(v, "metric"); mStr != "" {
		m, err := strconv.Atoi(mStr)
		if err != nil || m < 1 || m > 65535 {
			errs["metric"] = "Metric harus 1–65535"
		} else {
			metric = m
		}
	}
	body["metric"] = metric
	if _, hasDesc := v["description"]; hasDesc {
		body["description"] = get(v, "description")
	}
	return body, errs
}

func selectorError(cidrs []string) string {
	if len(cidrs) > MaxSelectors {
		return "Maksimal 8 subnet"
	}
	for _, c := range cidrs {
		if !ipv4CIDR(c) {
			return "CIDR IPv4 tidak valid: " + c
		}
		if p, err := netip.ParsePrefix(c); err == nil && p.Bits() == 0 {
			return "Default route (/0) tidak didukung: " + c
		}
	}
	return ""
}

func Policy(v url.Values) (map[string]any, Errors) {
	errs := Errors{}
	body := map[string]any{"enabled": enabled(v)}
	name := get(v, "name")
	if !safeRe.MatchString(name) {
		errs["name"] = "Nama 1-128 karakter: huruf, angka, _ @ . : -"
	}
	body["name"] = name

	srcType := get(v, "source_type")
	if srcType != "" && srcType != "cidr" {
		if srcType != "site" && srcType != "user" && srcType != "group" {
			errs["source_type"] = "Tipe source tidak valid"
		}
		body["source_type"] = srcType
		ref, err := strconv.Atoi(get(v, "source_ref"))
		if err != nil || ref < 1 {
			errs["source_ref"] = "Pilih entitas source"
		} else {
			body["source_ref"] = ref
		}
	} else {
		if srcType == "cidr" {
			body["source_type"] = "cidr"
		}
		c := get(v, "source_cidr")
		if !ipv4CIDR(c) {
			errs["source_cidr"] = "CIDR IPv4 tidak valid"
		}
		body["source_cidr"] = c
	}

	dstType := get(v, "destination_type")
	if dstType != "" && dstType != "cidr" {
		if dstType != "site" && dstType != "vpc" {
			errs["destination_type"] = "Tipe destination tidak valid"
		}
		body["destination_type"] = dstType
		if dstType == "site" {
			ref, err := strconv.Atoi(get(v, "destination_ref"))
			if err != nil || ref < 1 {
				errs["destination_ref"] = "Pilih site tujuan"
			} else {
				body["destination_ref"] = ref
			}
		}
	} else {
		if dstType == "cidr" {
			body["destination_type"] = "cidr"
		}
		c := get(v, "destination_cidr")
		if !ipv4CIDR(c) {
			errs["destination_cidr"] = "CIDR IPv4 tidak valid"
		}
		body["destination_cidr"] = c
	}

	proto := get(v, "protocol")
	if proto == "" {
		proto = "all"
	}
	ok := false
	for _, p := range Protocols {
		ok = ok || p == proto
	}
	if !ok {
		errs["protocol"] = "Protokol harus all, tcp, udp, atau icmp"
	}
	body["protocol"] = proto

	if action := get(v, "action"); action != "" {
		if action != "allow" && action != "deny" {
			errs["action"] = "Action harus allow atau deny"
		}
		body["action"] = action
	}
	if ports := get(v, "ports"); ports != "" {
		if proto != "tcp" && proto != "udp" {
			errs["ports"] = "Ports hanya berlaku untuk protokol TCP atau UDP"
		}
		body["ports"] = ports
	} else if _, present := v["ports"]; present {
		body["ports"] = nil
	}
	if prioStr := get(v, "priority"); prioStr != "" {
		prio, err := strconv.Atoi(prioStr)
		if err != nil || prio < 1 || prio > 10000 {
			errs["priority"] = "Priority harus 1–10000"
		} else {
			body["priority"] = prio
		}
	}
	return body, errs
}

// Password validates a write-only password reset.
func Password(v url.Values) (map[string]any, Errors) {
	pw := v.Get("password")
	if !credentialRe.MatchString(pw) {
		return nil, Errors{"password": "Password 8-128 karakter: huruf, angka, _ @ . ! + , : / = -"}
	}
	return map[string]any{"password": pw}, Errors{}
}
