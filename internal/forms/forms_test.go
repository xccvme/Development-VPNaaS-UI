package forms

import (
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func vals(kv ...string) url.Values {
	v := url.Values{}
	for i := 0; i < len(kv); i += 2 {
		v.Add(kv[i], kv[i+1])
	}
	return v
}

func TestUserCreate(t *testing.T) {
	body, errs := User(vals("username", " alice ", "password", "Secret-123", "allowed_cidrs", "10.10.7.0/24\n192.168.1.0/24, 10.10.7.0/24", "enabled", "on", "evil", "x"), true)
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	want := map[string]any{"username": "alice", "password": "Secret-123", "traffic_mode": "split", "allowed_cidrs": []string{"10.10.7.0/24", "192.168.1.0/24"}, "enabled": true, "max_sessions": 3}
	if !reflect.DeepEqual(body, want) {
		t.Fatalf("got %#v", body)
	}
}

func TestUserDefaultsAndPasswordWriteOnly(t *testing.T) {
	body, errs := User(vals("username", "bob"), false)
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	if _, ok := body["password"]; ok {
		t.Fatal("blank password must be omitted on edit (keep existing)")
	}
	if body["enabled"] != false {
		t.Fatal("unchecked enabled must be false")
	}
	if _, ok := body["allowed_cidrs"]; ok {
		t.Fatalf("blank CIDRs must be omitted so backend keeps/defaults: %#v", body["allowed_cidrs"])
	}
	if _, errs := User(vals("username", "bob"), true); errs["password"] == "" {
		t.Fatal("password required on create")
	}
}

func TestUserValidation(t *testing.T) {
	cases := []struct {
		v     url.Values
		field string
	}{
		{vals("username", "", "password", "Secret-123"), "username"},
		{vals("username", "bad user", "password", "Secret-123"), "username"},
		{vals("username", "a", "password", "short"), "password"},
		{vals("username", "a", "password", "has space x"), "password"},
		{vals("username", "a", "password", "Secret-123", "allowed_cidrs", "10.0.0.0/33"), "allowed_cidrs"},
		{vals("username", "a", "password", "Secret-123", "allowed_cidrs", "0.0.0.0/0"), "allowed_cidrs"},
		{vals("username", "a", "password", "Secret-123", "allowed_cidrs", "fd00::/8"), "allowed_cidrs"},
		{vals("username", "a", "password", "Secret-123", "traffic_mode", "bogus"), "traffic_mode"},
		{vals("username", "a", "password", "Secret-123", "allowed_cidrs", strings.Repeat("10.0.0.0/8\n", 1)+"10.1.0.0/16\n10.2.0.0/16\n10.3.0.0/16\n10.4.0.0/16\n10.5.0.0/16\n10.6.0.0/16\n10.7.0.0/16\n10.8.0.0/16\n10.9.0.0/16\n10.10.0.0/16\n10.11.0.0/16\n10.12.0.0/16\n10.13.0.0/16\n10.14.0.0/16\n10.15.0.0/16\n10.16.0.0/16"), "allowed_cidrs"},
	}
	for _, c := range cases {
		if _, errs := User(c.v, true); errs[c.field] == "" {
			t.Errorf("%v: expected error on %s, got %v", c.v, c.field, errs)
		}
	}
	if _, errs := User(vals("username", "a", "password", "Secret-123", "traffic_mode", "split"), true); len(errs) != 0 {
		t.Fatal(errs)
	}
}

func TestConnection(t *testing.T) {
	body, errs := Connection(vals("name", "branch", "remote_address", "203.0.113.5", "remote_id", "", "local_ts", "", "remote_ts", "192.168.50.0/24", "psk", "pre-shared-key", "enabled", "on"), true)
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	want := map[string]any{"name": "branch", "remote_address": "203.0.113.5", "remote_ts": "192.168.50.0/24", "psk": "pre-shared-key", "enabled": true}
	if !reflect.DeepEqual(body, want) {
		t.Fatalf("got %#v", body)
	}
	body, errs = Connection(vals("name", "branch", "remote_address", "203.0.113.5", "remote_id", "peer.example", "local_ts", "10.10.7.0/24", "remote_ts", "192.168.50.0/24"), false)
	if len(errs) != 0 || body["remote_id"] != "peer.example" {
		t.Fatal(errs, body)
	}
	if _, ok := body["psk"]; ok {
		t.Fatal("blank psk must be omitted on edit")
	}
	for _, bad := range []url.Values{
		vals("name", "b", "remote_address", "not-ip", "remote_ts", "1.2.3.0/24", "psk", "pre-shared-key"),
		vals("name", "b", "remote_address", "1.2.3.4", "remote_ts", "", "psk", "pre-shared-key"),
		vals("name", "b", "remote_address", "1.2.3.4", "remote_ts", "1.2.3.0/24", "psk", ""),
		vals("name", "b c", "remote_address", "1.2.3.4", "remote_ts", "1.2.3.0/24", "psk", "pre-shared-key"),
		vals("name", "b", "remote_address", "1.2.3.4", "remote_id", "x y", "remote_ts", "1.2.3.0/24", "psk", "pre-shared-key"),
	} {
		if _, errs := Connection(bad, true); len(errs) == 0 {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestPolicy(t *testing.T) {
	body, errs := Policy(vals("name", "lan", "source_cidr", "10.250.0.0/24", "destination_cidr", "10.10.7.0/24", "protocol", "tcp"))
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	want := map[string]any{"name": "lan", "source_cidr": "10.250.0.0/24", "destination_cidr": "10.10.7.0/24", "protocol": "tcp", "enabled": false}
	if !reflect.DeepEqual(body, want) {
		t.Fatalf("got %#v", body)
	}
	if _, errs := Policy(vals("name", "lan", "source_cidr", "10.250.0.0/24", "destination_cidr", "10.10.7.0/24", "protocol", "gre")); errs["protocol"] == "" {
		t.Fatal("bad protocol accepted")
	}
	body, _ = Policy(vals("name", "lan", "source_cidr", "10.250.0.0/24", "destination_cidr", "10.10.7.0/24"))
	if body["protocol"] != "all" {
		t.Fatal("default protocol")
	}
}

func TestSplitCIDRs(t *testing.T) {
	got := SplitList(" a ,b\r\n\nc,, a")
	if !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Fatal(got)
	}
}

func TestFullTrafficMode(t *testing.T) {
	body, errs := User(vals("username", "a", "password", "Secret-123", "traffic_mode", "full"), true)
	if len(errs) != 0 || body["traffic_mode"] != "full" {
		t.Fatalf("full rejected: %v %v", body, errs)
	}
	body, errs = User(vals("username", "a", "password", "Secret-123"), true)
	if len(errs) != 0 || body["traffic_mode"] != "split" {
		t.Fatalf("split default missing: %v %v", body, errs)
	}
}

func TestUserMaxSessionsAndOptionalCIDRs(t *testing.T) {
	body, errs := User(vals("username", "a", "password", "Secret-123"), true)
	if len(errs) != 0 || body["max_sessions"] != 3 {
		t.Fatalf("default 3: %v %v", body, errs)
	}
	if _, ok := body["allowed_cidrs"]; ok {
		t.Fatal("empty allowed_cidrs must be omitted")
	}
	for _, v := range []string{"1", "2", "3"} {
		body, errs := User(vals("username", "a", "max_sessions", v), false)
		if len(errs) != 0 || body["max_sessions"] != int(v[0]-'0') {
			t.Errorf("%s: %v", v, body["max_sessions"])
		}
	}
	for _, v := range []string{"0", "4", "-1", "1.5", "x"} {
		if _, errs := User(vals("username", "a", "max_sessions", v), false); errs["max_sessions"] == "" {
			t.Errorf("%s accepted", v)
		}
	}
}

func TestConnectionMultiCIDR(t *testing.T) {
	body, errs := Connection(vals("name", "b", "remote_address", "203.0.113.5", "local_ts", "10.10.7.0/24\r\n10.10.8.0/24, 10.10.7.0/24", "remote_ts", "192.168.50.0/24,192.168.51.0/24", "psk", "pre-shared-key"), true)
	if len(errs) != 0 || body["local_ts"] != "10.10.7.0/24,10.10.8.0/24" || body["remote_ts"] != "192.168.50.0/24,192.168.51.0/24" {
		t.Fatalf("join: %v %v", errs, body)
	}
	// blank local selector is omitted: backend applies its LAN default (create) or keeps the stored value (edit)
	body, errs = Connection(vals("name", "b", "remote_address", "203.0.113.5", "local_ts", "  ", "remote_ts", "192.168.50.0/24", "psk", "pre-shared-key"), true)
	if _, ok := body["local_ts"]; ok || len(errs) != 0 {
		t.Fatalf("blank local_ts must be omitted: %v %v", errs, body)
	}
	nine := ""
	for i := 0; i < 9; i++ {
		nine += "10.1." + string(rune('0'+i)) + ".0/24\n"
	}
	for field, v := range map[string]url.Values{
		"remote_ts": vals("name", "b", "remote_address", "1.2.3.4", "remote_ts", nine, "psk", "pre-shared-key"),
		"local_ts":  vals("name", "b", "remote_address", "1.2.3.4", "local_ts", "0.0.0.0/0", "remote_ts", "1.2.3.0/24", "psk", "pre-shared-key"),
	} {
		if _, errs := Connection(v, true); errs[field] == "" {
			t.Errorf("%s: expected error, got %v", field, errs)
		}
	}
	if _, errs := Connection(vals("name", "b", "remote_address", "1.2.3.4", "remote_ts", "1.2.3.0/24,bad", "psk", "pre-shared-key"), true); !strings.Contains(errs["remote_ts"], "bad") {
		t.Errorf("invalid item must be named: %v", errs)
	}
}

func hubVals(kv ...string) url.Values {
	v := vals("name", "branches", "topology", "hub", "enabled", "on",
		"site_a_name", "jkt", "site_a_address", "", "site_a_id", "", "site_a_psk", "", "site_a_subnets", "192.168.10.0/24\n192.168.11.0/24", "site_a_nat", "0", "site_a_nat", "on",
		"site_b_name", "sby", "site_b_address", "203.0.113.30", "site_b_id", "sby@example", "site_b_psk", "Secret-psk-1", "site_b_subnets", "192.168.20.0/24", "site_b_nat", "0")
	for i := 0; i < len(kv); i += 2 {
		v.Set(kv[i], kv[i+1])
	}
	return v
}

func TestHubCreateBody(t *testing.T) {
	body, errs := Hub(hubVals(), true)
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	want := map[string]any{"name": "branches", "enabled": true, "topology": "hub",
		"site_a": map[string]any{"name": "jkt", "address": "%any", "subnets": "192.168.10.0/24,192.168.11.0/24", "nat": true},
		"site_b": map[string]any{"name": "sby", "address": "203.0.113.30", "id": "sby@example", "psk": "Secret-psk-1", "subnets": "192.168.20.0/24", "nat": false},
	}
	if !reflect.DeepEqual(body, want) {
		t.Fatalf("got %#v", body)
	}
	// NAT absent entirely (no hidden marker) defaults to true
	v := hubVals()
	v.Del("site_b_nat")
	body, _ = Hub(v, true)
	if body["site_b"].(map[string]any)["nat"] != true {
		t.Error("nat default true")
	}
	// hostname and explicit %any accepted
	for _, addr := range []string{"gw.example.com", "%any", "198.51.100.4"} {
		if _, errs := Hub(hubVals("site_a_address", addr), true); errs["site_a_address"] != "" {
			t.Errorf("%s rejected: %v", addr, errs)
		}
	}
}

func TestHubValidationPerField(t *testing.T) {
	cases := []struct{ key, val, field, msg string }{
		{"name", "bad name", "name", "Nama"},
		{"site_a_name", "", "site_a_name", "Nama site"},
		{"site_b_address", "bad addr!", "site_b_address", "Alamat"},
		{"site_a_id", "bad id", "site_a_id", "IKE ID"},
		{"site_a_psk", "short", "site_a_psk", "PSK"},
		{"site_a_subnets", "", "site_a_subnets", "wajib"},
		{"site_b_subnets", "10.0.0.0/33", "site_b_subnets", "CIDR IPv4 tidak valid"},
		{"site_b_subnets", "0.0.0.0/0", "site_b_subnets", "/0"},
		{"site_b_subnets", "10.0.1.0/24,10.0.2.0/24,10.0.3.0/24,10.0.4.0/24,10.0.5.0/24,10.0.6.0/24,10.0.7.0/24,10.0.8.0/24,10.0.9.0/24", "site_b_subnets", "Maksimal 8"},
		{"site_b_subnets", "192.168.10.128/25", "site_b_subnets", "tumpang tindih"},
	}
	for _, c := range cases {
		_, errs := Hub(hubVals(c.key, c.val), true)
		if !strings.Contains(errs[c.field], c.msg) {
			t.Errorf("%s=%q: want %s error containing %q, got %v", c.key, c.val, c.field, c.msg, errs)
		}
	}
}

func TestHubEditKeepsPSK(t *testing.T) {
	body, errs := Hub(hubVals("site_b_psk", ""), false)
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	for _, s := range []string{"site_a", "site_b"} {
		if _, ok := body[s].(map[string]any)["psk"]; ok {
			t.Errorf("%s: blank psk must be omitted on edit", s)
		}
	}
}
