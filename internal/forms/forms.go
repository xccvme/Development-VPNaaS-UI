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
	cidrs := SplitList(v.Get("allowed_cidrs"))
	if len(cidrs) == 0 {
		cidrs = []string{DefaultLAN}
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
	local := get(v, "local_ts")
	if local == "" {
		local = DefaultLAN
	}
	if !ipv4CIDR(local) {
		errs["local_ts"] = "CIDR IPv4 tidak valid"
	}
	body["local_ts"] = local
	remote := get(v, "remote_ts")
	if !ipv4CIDR(remote) {
		errs["remote_ts"] = "CIDR IPv4 tidak valid"
	}
	body["remote_ts"] = remote
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
