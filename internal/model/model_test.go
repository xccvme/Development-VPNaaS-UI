package model

import (
	"encoding/json"
	"testing"
)

func TestUserRuntimeLabels(t *testing.T) {
	var users []User
	raw := `[
	 {"id":3,"username":"a","enabled":true,"allowed_cidrs":["10.10.7.0/24"],"traffic_mode":"split","runtime_status":"Active","session_count":1,"virtual_ips":["10.250.0.4"],"sessions":[{"ike_id":"13","ike_state":"ESTABLISHED","remote_address":"1.2.3.4","virtual_ips":["10.250.0.4"],"children":[{"child_id":"7","state":"INSTALLED","bytes_in":10,"bytes_out":20}]}]},
	 {"id":9,"username":"b","enabled":false,"allowed_cidrs":["10.10.7.0/24"],"runtime_status":"Down","session_count":0,"virtual_ips":[],"sessions":[]},
	 {"id":10,"username":"c","enabled":true,"allowed_cidrs":[]},
	 {"id":11,"username":"d","enabled":true,"runtime_status":"Weird","session_count":null}
	]`
	if err := json.Unmarshal([]byte(raw), &users); err != nil {
		t.Fatal(err)
	}
	want := []struct{ admin, runtime, sessions, mode string }{
		{"Enabled", "Active", "1/3", "Split"},
		{"Disabled", "Down", "0/3", "Split"},
		{"Enabled", "Unknown", "Unknown", "Split"},
		{"Enabled", "Unknown", "Unknown", "Split"},
	}
	for i, u := range users {
		if u.AdminLabel() != want[i].admin || u.RuntimeLabel() != want[i].runtime || u.SessionLabel() != want[i].sessions || u.TrafficLabel() != want[i].mode {
			t.Errorf("%d: %s %s %s %s", i, u.AdminLabel(), u.RuntimeLabel(), u.SessionLabel(), u.TrafficLabel())
		}
	}
	if users[0].Sessions[0].Children[0].BytesIn == nil || *users[0].Sessions[0].Children[0].BytesIn != 10 {
		t.Fatal("bytes not decoded")
	}
	if u := (User{TrafficMode: "full"}); u.TrafficLabel() != "Full" {
		t.Fatal(u.TrafficLabel())
	}
}

func TestConnectionRuntimeFromSwanctl(t *testing.T) {
	raw := "site-4: #2, ESTABLISHED, IKEv2, abc\n  local '1.1.1.1'\n  net-4: #3, reqid 2, INSTALLED, TUNNEL\nsite-5: #9, CONNECTING, IKEv2\nsite-41: #1, ESTABLISHED, IKEv2\n  net-41: #1, reqid 1, INSTALLED\nsite-6: #7, ESTABLISHED, IKEv2\n  net-6: #8, reqid 3, REKEYING\n"
	cases := map[int]string{4: "Active", 5: "Down", 6: "Down", 7: "Down", 41: "Active"}
	for id, want := range cases {
		if got := ConnectionRuntime(raw, true, id); got != want {
			t.Errorf("site-%d: %s want %s", id, got, want)
		}
	}
	if ConnectionRuntime(raw, false, 4) != "Unknown" {
		t.Fatal("unavailable status must be Unknown")
	}
	// "site-4" must not match "site-41" only data
	if ConnectionRuntime("site-41: #1, ESTABLISHED\n  net-41: #1, INSTALLED\n", true, 4) != "Down" {
		t.Fatal("prefix collision")
	}
}

func TestAuditColumnsDropSecrets(t *testing.T) {
	rows := []map[string]any{{"id": 1, "timestamp": "t", "action": "create", "resource": "users", "resource_id": 3, "zeta": 1, "password": "x", "api_token": "y"}}
	cols := AuditColumns(rows)
	want := []string{"id", "timestamp", "action", "resource", "resource_id", "zeta"}
	if len(cols) != len(want) {
		t.Fatal(cols)
	}
	for i := range want {
		if cols[i] != want[i] {
			t.Fatal(cols)
		}
	}
	if Printable(nil) != "—" || Printable("a") != "a" || Printable(float64(3)) != "3" || Printable([]any{"a", "b"}) != "a, b" || Printable(true) != "true" {
		t.Fatal("printable")
	}
}

func TestMatches(t *testing.T) {
	u := User{Username: "boss-windows", AllowedCIDRs: []string{"10.10.7.0/24"}}
	if !Matches("", u.Username) || !Matches("BOSS", u.Username) || Matches("zzz", append([]string{u.Username}, u.AllowedCIDRs...)...) || !Matches("10.10", append([]string{u.Username}, u.AllowedCIDRs...)...) {
		t.Fatal("matches")
	}
}

func TestSessionLabelWithMax(t *testing.T) {
	one, two, zero := 1, 2, 0
	cases := []struct {
		u    User
		want string
	}{
		{User{RuntimeStatus: "Down", SessionCount: &zero}, "0/3"},
		{User{RuntimeStatus: "Active", SessionCount: &one, MaxSessions: &two}, "1/2"},
		{User{RuntimeStatus: "Active", SessionCount: &one, MaxSessions: &zero}, "1/3"},
		{User{RuntimeStatus: "Unknown", SessionCount: &one}, "Unknown"},
	}
	for _, c := range cases {
		if got := c.u.SessionLabel(); got != c.want {
			t.Errorf("got %s want %s", got, c.want)
		}
	}
	if (User{}).Limit() != 3 {
		t.Fatal("default limit")
	}
}

func TestConnectionSubnetLists(t *testing.T) {
	c := Connection{LocalTS: "10.10.7.0/24", RemoteTS: "192.168.1.0/24, 192.168.2.0/24,"}
	if l := c.LocalList(); len(l) != 1 || l[0] != "10.10.7.0/24" {
		t.Fatal(l)
	}
	if r := c.RemoteList(); len(r) != 2 || r[1] != "192.168.2.0/24" {
		t.Fatal(r)
	}
	if SplitCSV("") != nil {
		t.Fatal("empty")
	}
}
