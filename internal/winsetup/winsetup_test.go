package winsetup

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func load(t *testing.T, name string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

// Golden files were produced by the original Python ui/windows_setup.py.
func TestMatchesPythonGenerator(t *testing.T) {
	for _, name := range []string{"basic", "multi"} {
		want, err := os.ReadFile("testdata/" + name + ".ps1")
		if err != nil {
			t.Fatal(err)
		}
		got, err := Render(load(t, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got != string(want) {
			t.Fatalf("%s: output differs from Python generator\n--- got ---\n%s", name, got)
		}
	}
}

func TestSafetyProperties(t *testing.T) {
	got, err := Render(load(t, "basic"))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"-SplitTunneling $true", "Add-VpnConnectionRoute", "'10.10.7.0/24'", "'VPNaaS-PoC'", "Group14", "rasphone.exe", "\r\n"} {
		if !strings.Contains(got, s) {
			t.Errorf("missing %q", s)
		}
	}
	for _, s := range []string{"DO-NOT-EXPORT", "0.0.0.0/0"} {
		if strings.Contains(got, s) {
			t.Errorf("must not contain %q", s)
		}
	}
}

func base() map[string]any {
	return map[string]any{
		"server":         "vpn.example.com",
		"ca_certificate": "-----BEGIN CERTIFICATE-----\nY2VydA==\n-----END CERTIFICATE-----",
		"allowed_cidrs":  []any{"10.10.7.0/24"},
	}
}

func TestRejectsUnsafeOrUnsupported(t *testing.T) {
	cases := []struct {
		key   string
		value any
	}{
		{"server", "x'; Start-Process evil"},
		{"server", "x\ncmd"},
		{"server", ""},
		{"server", 12.0},
		{"server", "-leading"},
		{"server_id", "id'evil"},
		{"allowed_cidrs", []any{"0.0.0.0/0"}},
		{"allowed_cidrs", []any{"::/0"}},
		{"allowed_cidrs", []any{"10.0.0.0/8';evil"}},
		{"allowed_cidrs", []any{}},
		{"allowed_cidrs", []any{123.0}},
		{"allowed_cidrs", "10.0.0.0/8"},
		{"allowed_cidrs", []any{"10.10.7.5/24"}}, // host bits set (strict)
		{"allowed_cidrs", []any{"10.10.7.0/33"}},
		{"allowed_cidrs", []any{"010.10.7.0/24"}},
		{"allowed_cidrs", []any{"0.0.0.0/0.0.0.0"}},
		{"ca_certificate", "'@\nStart-Process evil"},
		{"ca_certificate", ""},
		{"ca_certificate", nil},
		{"traffic_mode", "bogus"},
		{"traffic_mode", nil},
	}
	for _, c := range cases {
		p := base()
		p[c.key] = c.value
		if _, err := Render(p); err == nil {
			t.Errorf("%s=%#v accepted", c.key, c.value)
		}
	}
	delete(base(), "server")
	p := base()
	delete(p, "server")
	if _, err := Render(p); err == nil {
		t.Error("missing server accepted")
	}
	if _, err := Render(nil); err == nil {
		t.Error("nil profile accepted")
	}
}

func TestNetworkParsingLikePython(t *testing.T) {
	ok := map[string]string{
		"10.0.0.0/08":            "10.0.0.0/8",
		"10.1.2.3":               "10.1.2.3/32",
		"10.0.0.0/255.255.255.0": "10.0.0.0/24",
		"10.0.0.0/0.0.0.255":     "10.0.0.0/24",
		"2001:DB8:0::/32":        "2001:db8::/32",
		"192.168.1.0/24":         "192.168.1.0/24",
	}
	for in, want := range ok {
		got, err := normalizeNetwork(in)
		if err != nil || got != want {
			t.Errorf("%s => %q %v, want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "/24", "10.0.0.0/", "10.0.0.0/24/1", "10.0.0.0/+8", "fe80::1%eth0/128", "2001:db8::/1.2.3.4", "10.0.0.0/255.0.255.0"} {
		if got, err := normalizeNetwork(in); err == nil {
			t.Errorf("%s accepted as %s", in, got)
		}
	}
}

func TestServerIDFallback(t *testing.T) {
	p := base()
	p["server_id"] = ""
	got, err := Render(p)
	if err != nil || !strings.Contains(got, "$serverIdentity = 'vpn.example.com'") {
		t.Fatalf("fallback failed: %v", err)
	}
}

func TestFullTunnel(t *testing.T) {
	p := base()
	p["traffic_mode"] = "full"
	got, err := Render(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"-SplitTunneling $false", "$routes = @()", "Remove-VpnConnectionRoute", "Full tunnel", "Group14"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q", want)
		}
	}
	for _, unwanted := range []string{"Add-VpnConnectionRoute", "'10.10.7.0/24'", "Internet stays", "Split tunneling enabled"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("unexpected %q", unwanted)
		}
	}
}
