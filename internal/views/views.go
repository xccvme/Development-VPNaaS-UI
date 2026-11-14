package views

import (
	"strconv"
	"strings"

	"vpnaas/ui-goth/internal/forms"
	"vpnaas/ui-goth/internal/model"
)

// AssetVersion is a content hash appended to static URLs (cache busting).
var AssetVersion = "dev"

// Page is the common chrome information for full-page renders.
type Page struct {
	Active   string // ringkasan|koneksi|akun|kebijakan|status|audit
	Title    string
	Subtitle string
	CSRF     string
}

type NavItem struct{ Key, Label, Href, Icon string }

var Nav = []NavItem{
	{"ringkasan", "Ringkasan", "/ringkasan", "grid"},
	{"koneksi", "VPN Hub", "/koneksi", "link"},
	{"akun", "Akun C2S", "/akun", "user"},
	{"kebijakan", "Firewall", "/kebijakan", "shield"},
	{"status", "Status Runtime", "/status", "pulse"},
	{"audit", "Audit", "/audit", "clock"},
}

type Flash struct {
	Message string
	Output  string // e.g. swanctl output; plain text
	Error   bool
}

type ConnRow struct {
	model.Connection
	Runtime string
}

// HubRows / DirectRows split the table: hub rows get the new Site-A/Site-B
// layout, legacy direct rows keep their original columns and actions.
func (t ConnTable) HubRows() []ConnRow {
	out := []ConnRow{}
	for _, r := range t.Rows {
		if r.IsHub() {
			out = append(out, r)
		}
	}
	return out
}

func (t ConnTable) DirectRows() []ConnRow {
	out := []ConnRow{}
	for _, r := range t.Rows {
		if !r.IsHub() {
			out = append(out, r)
		}
	}
	return out
}

// HubSite is the data for the per-site Configure modal.
type HubSite struct {
	ID   int
	Name string // hub name
	Key  string // "a" | "b"
	Site model.Site
	Err  string
}

func (h HubSite) Label() string      { return "Site-" + strings.ToUpper(h.Key) }
func (h HubSite) Peer() string       { return ternary(h.Key == "a", "Site-B", "Site-A") }
func (h HubSite) ScriptFile() string { return model.HubFile(h.Name, h.Key, "sh") }
func (h HubSite) ConfFile() string   { return model.HubFile(h.Name, h.Key, "conf") }
func (h HubSite) ScriptURL() string  { return siteDownload(h.ID, h.Key, "setup.sh") }
func (h HubSite) ConfURL() string    { return siteDownload(h.ID, h.Key, "hub.conf") }
func siteDownload(id int, key, f string) string {
	return "/unduh/koneksi/" + strconv.Itoa(id) + "/site-" + key + "/" + f
}
func siteURL(id int, key, action string) string {
	return "/koneksi/" + strconv.Itoa(id) + "/site/" + key + "/" + action
}
func siteLabel(key string) string { return "Site-" + strings.ToUpper(key) }

// siteOf returns the spoke for key "a"/"b".
func siteOf(c model.Connection, key string) model.Site {
	if key == "b" {
		return c.B()
	}
	return c.A()
}

type ConnTable struct {
	Rows      []ConnRow
	Total     int
	Query     string
	Err       string
	StatusErr string
	Flash     *Flash
}

type UserTable struct {
	Rows  []model.User
	Total int
	Query string
	Err   string
	Stale bool
	Flash *Flash
}

type PolicyTable struct {
	Rows  []model.Policy
	Total int
	Query string
	Err   string
	Flash *Flash
}

type Card struct {
	Label, Value, Note, Href string
	Ok                       bool
}

type Overview struct {
	Cards       []Card
	Errors      []string
	Info        []KV
	Connections []ConnRow
	Users       []model.User
}

type KV struct {
	Key, Value string
	Block      bool
}

type Audit struct {
	Columns []string
	Rows    []map[string]any
	Total   int
	Query   string
	Err     string
}

// Form carries values for create/edit modals.
type Form struct {
	ID      int
	Values  map[string]string
	Enabled bool
	Errs    forms.Errors
	Err     string
}

func (f Form) V(k string) string { return f.Values[k] }
func (f Form) E(k string) string {
	if f.Errs == nil {
		return ""
	}
	return f.Errs[k]
}
func (f Form) Edit() bool { return f.ID > 0 }

// maxSessionsValue is the selected limit; missing/invalid values show 3.
func maxSessionsValue(f Form) string {
	switch v := f.V("max_sessions"); v {
	case "1", "2", "3":
		return v
	}
	return strconv.Itoa(forms.DefaultMaxSessions)
}

type Confirm struct {
	Title, Message, Name, URL, Button string
	Err                               string
}

func itoa(i int) string { return strconv.Itoa(i) }

func idURL(base string, id int, suffix string) string {
	return base + "/" + strconv.Itoa(id) + suffix
}

func badgeClass(label string) string {
	switch label {
	case "Active", "Enabled", "Tersedia", "ESTABLISHED", "INSTALLED":
		return "bg-[#E6F4EA] text-[#1E7B34]"
	case "Down", "Disabled":
		return "bg-[#F1F3F5] text-[#495057]"
	case "Unknown":
		return "bg-[#FFF4E5] text-[#9A5B00]"
	case "Direct (lama)":
		return "bg-[#EDE7F6] text-[#5E35B1]"
	case "Hub":
		return "bg-[#E8EEF9] text-[#2F6BC4]"
	}
	return "bg-[#FDECEA] text-[#B3261E]"
}

func dotClass(label string) string {
	switch label {
	case "Active", "Enabled", "Tersedia":
		return "bg-[#28A745]"
	case "Unknown":
		return "bg-[#F0A202]"
	}
	return "bg-[#ADB5BD]"
}

func cell(v any) string { return model.Printable(v) }

func ternary(c bool, a, b string) string {
	if c {
		return a
	}
	return b
}

func upper(s string) string { return strings.ToUpper(s) }
