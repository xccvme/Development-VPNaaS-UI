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
	Active   string
	Title    string
	Subtitle string
	CSRF     string
}

type NavItem struct{ Key, Label, Href, Icon string }

var Nav = []NavItem{
	{"ringkasan", "Ringkasan", "/ringkasan", "grid"},
	{"sites", "Multi-Site S2S", "/sites", "network"},
	{"koneksi", "VPN Hub", "/koneksi", "link"},
	{"akun", "Akun C2S", "/akun", "user"},
	{"grup", "Grup C2S", "/grup", "users"},
	{"routing", "Routing", "/routing", "route"},
	{"kebijakan", "Firewall", "/kebijakan", "shield"},
	{"pki", "PKI & Sertifikat", "/pki", "key"},
	{"tokens", "Token API", "/tokens", "lock"},
	{"status", "Status Runtime", "/status", "pulse"},
	{"audit", "Audit", "/audit", "clock"},
}

type Flash struct {
	Message string
	Output  string // e.g. swanctl output or one-time token; plain text
	Error   bool
}

type ConnRow struct {
	model.Connection
	Runtime string
}

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
func (h HubSite) VendorURL(f string) string {
	return siteDownload(h.ID, h.Key, f)
}
func siteDownload(id int, key, f string) string {
	return "/unduh/koneksi/" + strconv.Itoa(id) + "/site-" + key + "/" + f
}
func siteURL(id int, key, action string) string {
	return "/koneksi/" + strconv.Itoa(id) + "/site/" + key + "/" + action
}
func siteLabel(key string) string { return "Site-" + strings.ToUpper(key) }

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

type SiteTable struct {
	Rows      []model.MultiSite
	SiteNames map[int]string
	Total     int
	Query     string
	Err       string
	Flash     *Flash
}

type SiteConfigureData struct {
	Site      model.MultiSite
	PeerNames []string
	Err       string
}

type GroupTable struct {
	Rows      []model.Group
	SiteNames map[int]string
	Total     int
	Query     string
	Err       string
	Flash     *Flash
}

type RouteTable struct {
	Rows         []model.StaticRoute
	KernelRoutes []map[string]any
	SiteNames    map[int]string
	KernelOK     bool
	Total        int
	Query        string
	Err          string
	Flash        *Flash
}

type PKIPageData struct {
	CA     map[string]any
	Server map[string]any
	Certs  []model.CertRecord
	Err    string
	Flash  *Flash
}

type TokenTable struct {
	Rows  []model.APIToken
	Err   string
	Flash *Flash
}

type StatusViewData struct {
	Ready     map[string]any
	Gateway   map[string]any
	Tunnels   map[string]any
	Items     []KV
	Err       string
	ReadyErr  string
	LogSource string
	LogLines  []string
	LogErr    string
	DiagRes   map[string]any
	DiagErr   string
	Users     []model.User
	Sites     []model.MultiSite
}

type UserTable struct {
	Rows       []model.User
	SiteNames  map[int]string
	GroupNames map[int]string
	Total      int
	Query      string
	Err        string
	Stale      bool
	Flash      *Flash
}

type PolicyTable struct {
	Rows       []model.Policy
	SiteNames  map[int]string
	UserNames  map[int]string
	GroupNames map[int]string
	Total      int
	Query      string
	Err        string
	Flash      *Flash
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
	Sites       []model.MultiSite
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

// Form carries values and choice options for create/edit modals.
type Form struct {
	ID          int
	Values      map[string]string
	Enabled     bool
	Errs        forms.Errors
	Err         string
	VPCCIDR     string
	Sites       []model.MultiSite
	Groups      []model.Group
	Users       []model.User
	Certs       []model.CertRecord
	SelectedIDs map[string]map[int]bool
}

func (f Form) V(k string) string { return f.Values[k] }
func (f Form) E(k string) string {
	if f.Errs == nil {
		return ""
	}
	return f.Errs[k]
}
func (f Form) Edit() bool { return f.ID > 0 }
func (f Form) Checked(field string, id int) bool {
	if f.SelectedIDs == nil {
		return false
	}
	return f.SelectedIDs[field][id]
}
func (f Form) OtherSites() []model.MultiSite {
	out := []model.MultiSite{}
	for _, st := range f.Sites {
		if st.ID != f.ID {
			out = append(out, st)
		}
	}
	return out
}
func (f Form) VPCDisplay() string {
	if f.VPCCIDR != "" {
		return f.VPCCIDR
	}
	return forms.DefaultLAN
}

func maxSessionsValue(f Form) string {
	switch v := f.V("max_sessions"); v {
	case "1", "2", "3":
		return v
	}
	return strconv.Itoa(forms.DefaultMaxSessions)
}

type Confirm struct {
	Title, Message, Name, URL, Button string
	Target                            string
	Method                            string
	Err                               string
}

func itoa(i int) string { return strconv.Itoa(i) }

func idURL(base string, id int, suffix string) string {
	return base + "/" + strconv.Itoa(id) + suffix
}

func siteDownloadURL(id int, vendor string) string {
	return "/unduh/sites/" + strconv.Itoa(id) + "/" + vendor
}

func badgeClass(label string) string {
	switch label {
	case "Active", "Enabled", "Tersedia", "ESTABLISHED", "INSTALLED", "ALLOW", "READY", "applied":
		return "bg-[#E6F4EA] text-[#1E7B34]"
	case "Down", "Disabled", "disabled", "ipsec-managed":
		return "bg-[#F1F3F5] text-[#495057]"
	case "Unknown", "unknown", "missing", "DEGRADED":
		return "bg-[#FFF4E5] text-[#9A5B00]"
	case "Direct (lama)", "X.509", "EAP-TLS":
		return "bg-[#EDE7F6] text-[#5E35B1]"
	case "Hub", "VPC", "PSK", "admin", "operator":
		return "bg-[#E8EEF9] text-[#2F6BC4]"
	case "readonly":
		return "bg-[#F1F3F5] text-[#495057]"
	}
	return "bg-[#FDECEA] text-[#B3261E]"
}

func dotClass(label string) string {
	switch label {
	case "Active", "Enabled", "Tersedia", "READY":
		return "bg-[#28A745]"
	case "Unknown", "DEGRADED":
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

func namesFromIDs(ids []int, m map[int]string) []string {
	out := []string{}
	for _, id := range ids {
		if n, ok := m[id]; ok {
			out = append(out, n)
		} else {
			out = append(out, "#"+strconv.Itoa(id))
		}
	}
	return out
}

func mapStr(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	return model.Printable(m[key])
}

func mapBool(m map[string]any, key string) bool {
	if m == nil {
		return false
	}
	b, _ := m[key].(bool)
	return b
}

func formatKernelRoute(r map[string]any) string {
	parts := []string{mapStr(r, "dst")}
	if gw := mapStr(r, "gateway"); gw != "" {
		parts = append(parts, "via "+gw)
	}
	if dev := mapStr(r, "dev"); dev != "" {
		parts = append(parts, "dev "+dev)
	}
	if proto := mapStr(r, "protocol"); proto != "" {
		parts = append(parts, "proto "+proto)
	}
	if metric := mapStr(r, "metric"); metric != "" {
		parts = append(parts, "metric "+metric)
	}
	return strings.Join(parts, " ")
}
