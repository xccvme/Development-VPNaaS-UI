// Package winsetup ports ui/windows_setup.py: it renders a password-free native
// Windows IKEv2 split-tunnel PowerShell installer from a VPN profile.
package winsetup

import (
	_ "embed"
	"encoding/base64"
	"errors"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

//go:embed template.ps1.tmpl
var template string

var (
	hostRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$`)
	// Python's str-mode \s within ASCII also includes \v and \x1c-\x1f.
	caRe = regexp.MustCompile(`^[\t\n\v\f\r \x1c-\x1f]*-----BEGIN CERTIFICATE-----[\t\n\v\f\r \x1c-\x1f]+[A-Za-z0-9+/=\t\n\v\f\r \x1c-\x1f]+-----END CERTIFICATE-----[\t\n\v\f\r \x1c-\x1f]*$`)
)

// ErrInvalid wraps all validation errors.
var ErrInvalid = errors.New("invalid profile")

func invalid(msg string) error { return errors.Join(ErrInvalid, errors.New(msg)) }

// truthy mirrors Python truthiness for JSON-decoded values.
func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case float64:
		return x != 0
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}

// normalizeNetwork mirrors ipaddress.ip_network(value, strict=True) for the
// accepted syntaxes (prefix length, IPv4 netmask, IPv4 hostmask). Zone IDs are
// deliberately rejected (stricter than Python).
func normalizeNetwork(value string) (string, error) {
	parts := strings.Split(value, "/")
	if len(parts) > 2 || parts[0] == "" {
		return "", invalid("invalid network")
	}
	addr, err := netip.ParseAddr(parts[0])
	if err != nil || addr.Zone() != "" {
		return "", invalid("invalid network")
	}
	bits := addr.BitLen()
	prefix := bits
	if len(parts) == 2 {
		p := parts[1]
		if p == "" {
			return "", invalid("invalid prefix")
		}
		if isDigits(p) {
			n, err := strconv.Atoi(p)
			if err != nil || n > bits {
				return "", invalid("invalid prefix")
			}
			prefix = n
		} else if addr.Is4() {
			mask, err := netip.ParseAddr(p)
			if err != nil || !mask.Is4() {
				return "", invalid("invalid netmask")
			}
			n, ok := maskBits(mask, false)
			if !ok {
				n, ok = maskBits(mask, true)
			}
			if !ok {
				return "", invalid("invalid netmask")
			}
			prefix = n
		} else {
			return "", invalid("invalid prefix")
		}
	}
	pfx := netip.PrefixFrom(addr, prefix)
	if pfx.Masked().Addr() != addr {
		return "", invalid("host bits set")
	}
	return pfx.String(), nil
}

func isDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

// maskBits returns the prefix length for a contiguous netmask (or hostmask).
func maskBits(mask netip.Addr, host bool) (int, bool) {
	b := mask.As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	if host {
		v = ^v
	}
	n := 0
	for n < 32 && v&(1<<(31-n)) != 0 {
		n++
	}
	if n < 32 && v<<n != 0 {
		return 0, false
	}
	return n, true
}

var usernameRe = regexp.MustCompile(`^[A-Za-z0-9_@.:-]{1,128}$`)

// Filename validates the backend username and makes a Windows-safe basename.
// Colons are legal account characters but illegal in Windows filenames.
func Filename(username string) (string, error) {
	if !usernameRe.MatchString(username) {
		return "", invalid("invalid username")
	}
	name := strings.TrimRight(strings.ReplaceAll(username, ":", "_"), ".")
	if name == "" {
		name = "_"
	}
	stem := strings.ToUpper(strings.SplitN(name, ".", 2)[0])
	switch stem {
	case "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
		name = "_" + name
	}
	return name, nil
}

// Render validates profile and returns the CRLF PowerShell script.
func Render(profile map[string]any) (string, error) {
	if profile == nil {
		return "", invalid("profile must be an object")
	}
	username, _ := profile["username"].(string)
	if _, err := Filename(username); err != nil {
		return "", err
	}
	full := false
	if mode, ok := profile["traffic_mode"]; ok {
		if s, isStr := mode.(string); !isStr || (s != "split" && s != "full") {
			return "", invalid("traffic_mode must be split or full")
		}
	}
	full = profile["traffic_mode"] == "full"
	server, _ := profile["server"].(string)
	if _, present := profile["server"]; present {
		if _, isStr := profile["server"].(string); !isStr {
			return "", invalid("invalid VPN server address or identity")
		}
	}
	var identity string
	if raw := profile["server_id"]; truthy(raw) {
		s, ok := raw.(string)
		if !ok {
			return "", invalid("invalid VPN server address or identity")
		}
		identity = s
	} else {
		identity = server
	}
	for _, v := range []string{server, identity} {
		if !hostRe.MatchString(v) {
			return "", invalid("invalid VPN server address or identity")
		}
	}
	list, ok := profile["allowed_cidrs"].([]any)
	if !ok || len(list) == 0 {
		return "", invalid("profile must contain allowed networks")
	}
	var routes []string
	seen := map[string]bool{}
	for _, item := range list {
		s, ok := item.(string)
		if !ok {
			return "", invalid("invalid allowed network")
		}
		n, err := normalizeNetwork(s)
		if err != nil {
			return "", err
		}
		if strings.HasSuffix(n, "/0") {
			return "", invalid("default routes are not supported")
		}
		if !seen[n] {
			seen[n] = true
			routes = append(routes, n)
		}
	}
	ca, ok := profile["ca_certificate"].(string)
	if _, present := profile["ca_certificate"]; !present {
		ca, ok = "", true
	}
	if !ok || !caRe.MatchString(ca) {
		return "", invalid("profile CA certificate is missing or malformed")
	}
	if full {
		routes = nil
	}
	quoted := make([]string, len(routes))
	for i, r := range routes {
		quoted[i] = "'" + r + "'"
	}
	// Replace in one pass: account names resembling tokens must stay literal.
	out := strings.NewReplacer("__USERNAME__", username, "__SERVER__", server,
		"__IDENTITY__", identity, "__ROUTES__", strings.Join(quoted, ", "),
		"__CA__", base64.StdEncoding.EncodeToString([]byte(ca))).Replace(template)
	if full {
		out = strings.ReplaceAll(out, "-SplitTunneling $true", "-SplitTunneling $false")
		out = strings.ReplaceAll(out, "Internet stays on the existing local connection.", "Full tunnel: all IPv4 internet traffic goes through the VPN gateway.")
		out = strings.ReplaceAll(out, "foreach ($prefix in $routes) {\n    Add-VpnConnectionRoute -ConnectionName $ConnectionName -DestinationPrefix $prefix | Out-Null\n}\n", "")
		out = strings.ReplaceAll(out, "Split tunneling enabled. Only the listed allowed networks use this VPN:", "Full tunnel enabled. All IPv4 internet traffic uses this VPN; private LAN access is restricted by the server.")
		out = strings.ReplaceAll(out, "# Replace any prior routes (including default routes) with only the allowed networks.", "# Remove prior per-CIDR routes; full tunnel uses the VPN default route.")
	}
	return strings.ReplaceAll(out, "\n", "\r\n"), nil
}
