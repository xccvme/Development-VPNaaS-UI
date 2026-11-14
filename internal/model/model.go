// Package model holds decoded backend records and display helpers.
package model

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type Child struct {
	ChildID  string `json:"child_id"`
	State    string `json:"state"`
	BytesIn  *int64 `json:"bytes_in"`
	BytesOut *int64 `json:"bytes_out"`
}

type Session struct {
	IKEID         string   `json:"ike_id"`
	IKEState      string   `json:"ike_state"`
	RemoteAddress string   `json:"remote_address"`
	VirtualIPs    []string `json:"virtual_ips"`
	Children      []Child  `json:"children"`
}

type User struct {
	ID            int       `json:"id"`
	Username      string    `json:"username"`
	Enabled       bool      `json:"enabled"`
	AllowedCIDRs  []string  `json:"allowed_cidrs"`
	TrafficMode   string    `json:"traffic_mode"`
	RuntimeStatus string    `json:"runtime_status"`
	SessionCount  *int      `json:"session_count"`
	MaxSessions   *int      `json:"max_sessions"`
	VirtualIPs    []string  `json:"virtual_ips"`
	Sessions      []Session `json:"sessions"`
}

func adminLabel(enabled bool) string {
	if enabled {
		return "Enabled"
	}
	return "Disabled"
}

func (u User) AdminLabel() string { return adminLabel(u.Enabled) }

// RuntimeLabel is independent of administrative state; anything other than
// the backend's Active/Down is reported as Unknown.
func (u User) RuntimeLabel() string {
	switch u.RuntimeStatus {
	case "Active", "Down":
		return u.RuntimeStatus
	}
	return "Unknown"
}

// DefaultMaxSessions applies when the backend omits max_sessions or returns
// a value outside the supported 1..3 range.
const DefaultMaxSessions = 3

// Limit is the per-user concurrent session limit (1..3, default 3).
func (u User) Limit() int {
	if u.MaxSessions == nil || *u.MaxSessions < 1 || *u.MaxSessions > 3 {
		return DefaultMaxSessions
	}
	return *u.MaxSessions
}

// SessionLabel renders "count/max", e.g. 0/3; Unknown when runtime is unknown.
func (u User) SessionLabel() string {
	if u.SessionCount == nil || u.RuntimeLabel() == "Unknown" {
		return "Unknown"
	}
	return strconv.Itoa(*u.SessionCount) + "/" + strconv.Itoa(u.Limit())
}

func (u User) TrafficLabel() string {
	if u.TrafficMode == "" || u.TrafficMode == "split" {
		return "Split"
	}
	if u.TrafficMode == "full" {
		return "Full"
	}
	return u.TrafficMode + " (tidak didukung)"
}

type Connection struct {
	ID            int    `json:"id"`
	Name          string `json:"name"`
	RemoteAddress string `json:"remote_address"`
	RemoteID      string `json:"remote_id"`
	LocalTS       string `json:"local_ts"`
	RemoteTS      string `json:"remote_ts"`
	Enabled       bool   `json:"enabled"`
	// Topology is "hub" for VPN Hub rows; missing/"direct" is a legacy S2S row.
	Topology string `json:"topology"`
	SiteA    *Site  `json:"site_a"`
	SiteB    *Site  `json:"site_b"`
}

func (c Connection) AdminLabel() string { return adminLabel(c.Enabled) }

// IsHub reports a hub-and-spoke row; anything else renders as legacy direct.
func (c Connection) IsHub() bool { return c.Topology == "hub" }

func (c Connection) TopologyLabel() string {
	if c.IsHub() {
		return "Hub"
	}
	return "Direct (lama)"
}

// A and B never return nil so templates can query legacy rows safely.
func (c Connection) A() Site {
	if c.SiteA == nil {
		return Site{}
	}
	return *c.SiteA
}

func (c Connection) B() Site {
	if c.SiteB == nil {
		return Site{}
	}
	return *c.SiteB
}

// HubRuntime is Active only when both spokes are active, Unknown if either
// spoke status is missing/unrecognised, otherwise Down.
func (c Connection) HubRuntime() string {
	a, b := c.A().StatusLabel(), c.B().StatusLabel()
	switch {
	case a == "Unknown" || b == "Unknown":
		return "Unknown"
	case a == "Active" && b == "Active":
		return "Active"
	}
	return "Down"
}

// CSV accepts a backend comma-joined string or a JSON string array.
type CSV string

func (s *CSV) UnmarshalJSON(b []byte) error {
	var str string
	if json.Unmarshal(b, &str) == nil {
		*s = CSV(str)
		return nil
	}
	var arr []string
	if err := json.Unmarshal(b, &arr); err != nil {
		return err
	}
	*s = CSV(strings.Join(arr, ","))
	return nil
}

// Site is one spoke of a VPN Hub. PSK is write-only: only psk_set is read.
type Site struct {
	Name       string `json:"name"`
	Address    string `json:"address"`
	ID         string `json:"id"`
	PSKSet     bool   `json:"psk_set"`
	Subnets    CSV    `json:"subnets"`
	NAT        *bool  `json:"nat"`
	Status     string `json:"status"`
	RemoteHost string `json:"remote_host"`
	BytesIn    *int64 `json:"bytes_in"`
	BytesOut   *int64 `json:"bytes_out"`
}

func (s Site) SubnetList() []string { return SplitCSV(string(s.Subnets)) }

// NATOn defaults to true (backend default) when the field is missing.
func (s Site) NATOn() bool { return s.NAT == nil || *s.NAT }

// BehindNAT: the spoke has no fixed public address (%any) and must dial in.
func (s Site) BehindNAT() bool { return s.Address == "" || s.Address == "%any" }

func (s Site) StatusLabel() string {
	switch strings.ToLower(s.Status) {
	case "active":
		return "Active"
	case "down":
		return "Down"
	}
	return "Unknown"
}

var fileUnsafe = regexp.MustCompile(`[^A-Za-z0-9_.-]+`)

// HubFile builds the download filename for a hub spoke, e.g.
// HubFile("kantor","a","sh") = "Setup-Hub-kantor-Site-A.sh" and
// HubFile("kantor","a","conf") = "Hub-kantor-Site-A.conf".
func HubFile(name, site, kind string) string {
	stem := strings.Trim(fileUnsafe.ReplaceAllString(name, "_"), ".")
	if stem == "" {
		stem = "_"
	}
	base := "Hub-" + stem + "-Site-" + strings.ToUpper(site)
	if kind == "sh" {
		return "Setup-" + base + ".sh"
	}
	return base + ".conf"
}

// SplitCSV splits a backend traffic-selector string ("a,b" or a legacy single
// CIDR) into trimmed, non-empty items; nil when empty.
func SplitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (c Connection) LocalList() []string  { return SplitCSV(c.LocalTS) }
func (c Connection) RemoteList() []string { return SplitCSV(c.RemoteTS) }

type Policy struct {
	ID              int    `json:"id"`
	Name            string `json:"name"`
	SourceCIDR      string `json:"source_cidr"`
	DestinationCIDR string `json:"destination_cidr"`
	Protocol        string `json:"protocol"`
	Enabled         bool   `json:"enabled"`
}

func (p Policy) AdminLabel() string { return adminLabel(p.Enabled) }

var saLine = regexp.MustCompile(`^\s*(site|net)-(\d+):\s*#\d+,\s*(?:reqid \d+,\s*)?([A-Z_]+)`)

// ConnectionRuntime derives an S2S tunnel's state from `swanctl --list-sas`
// text: Active needs ESTABLISHED site-N plus INSTALLED net-N.
func ConnectionRuntime(raw string, available bool, id int) string {
	if !available {
		return "Unknown"
	}
	ike, child := false, false
	want := strconv.Itoa(id)
	for _, line := range strings.Split(raw, "\n") {
		m := saLine.FindStringSubmatch(line)
		if m == nil || m[2] != want {
			continue
		}
		if m[1] == "site" && m[3] == "ESTABLISHED" {
			ike = true
		}
		if m[1] == "net" && m[3] == "INSTALLED" {
			child = true
		}
	}
	if ike && child {
		return "Active"
	}
	return "Down"
}

var secretKey = regexp.MustCompile(`(?i)password|psk|secret|token`)

// AuditColumns returns the union of keys with known metadata first.
func AuditColumns(rows []map[string]any) []string {
	known := []string{"id", "timestamp", "action", "resource", "resource_id"}
	seen := map[string]bool{}
	var extra []string
	for _, r := range rows {
		for k := range r {
			if !seen[k] {
				seen[k] = true
				isKnown := false
				for _, kk := range known {
					isKnown = isKnown || kk == k
				}
				if !isKnown && !secretKey.MatchString(k) {
					extra = append(extra, k)
				}
			}
		}
	}
	sort.Strings(extra)
	var cols []string
	for _, k := range known {
		if seen[k] {
			cols = append(cols, k)
		}
	}
	return append(cols, extra...)
}

// Printable renders a decoded JSON value as plain text (escaped later by templ).
func Printable(v any) string {
	switch x := v.(type) {
	case nil:
		return "—"
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case int:
		return strconv.Itoa(x)
	case bool:
		return strconv.FormatBool(x)
	case []any:
		parts := make([]string, len(x))
		for i, p := range x {
			parts[i] = Printable(p)
		}
		return strings.Join(parts, ", ")
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

// Matches is a case-insensitive substring search over fields.
func Matches(q string, fields ...string) bool {
	q = strings.ToLower(strings.TrimSpace(q))
	if q == "" {
		return true
	}
	for _, f := range fields {
		if strings.Contains(strings.ToLower(f), q) {
			return true
		}
	}
	return false
}

func Join(v []string) string {
	if len(v) == 0 {
		return "—"
	}
	return strings.Join(v, ", ")
}

func Bytes(v *int64) string {
	if v == nil {
		return "—"
	}
	return strconv.FormatInt(*v, 10) + " B"
}
