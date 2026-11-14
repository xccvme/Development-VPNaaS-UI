// Package forms converts HTML form submissions into backend API JSON bodies,
// applying the same validation rules as the backend (backend/store.py) so the
// user gets immediate field errors. The backend remains authoritative.
package forms

import (
	"net/netip"
	"net/url"
	"regexp"
	"strings"
)

const DefaultLAN = "10.10.7.0/24"

// DefaultMaxSessions is the concurrent session limit used when none is chosen.
const DefaultMaxSessions = 3

var (
	safeRe       = regexp.MustCompile(`^[A-Za-z0-9_@.:-]{1,128}$`)
	credentialRe = regexp.MustCompile(`^[A-Za-z0-9_@.!+,:/=-]{8,128}$`)
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
	pw := v.Get("password")
	if pw != "" {
		if !credentialRe.MatchString(pw) {
			errs["password"] = "Password 8-128 karakter: huruf, angka, _ @ . ! + , : / = -"
		}
		body["password"] = pw
	} else if create {
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
	// Empty allowed CIDRs are omitted so the backend applies its LAN default
	// (create) or keeps the stored value (edit).
	cidrs := SplitList(v.Get("allowed_cidrs"))
	if len(cidrs) == 0 {
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
	// Blank local subnets are omitted: the backend applies its LAN default
	// on create and keeps the stored value on edit.
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

// Hub builds a VPN Hub (topology "hub") POST/PUT body from site_a_*/site_b_*
// fields. Empty address -> %any; empty IKE ID omitted (backend default);
// PSK write-only: empty is omitted (generate on create, keep on edit).
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
	for _, k := range []string{"source_cidr", "destination_cidr"} {
		c := get(v, k)
		if !ipv4CIDR(c) {
			errs[k] = "CIDR IPv4 tidak valid"
		}
		body[k] = c
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
