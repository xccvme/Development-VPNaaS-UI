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
	{"koneksi", "Koneksi S2S", "/koneksi", "link"},
	{"akun", "Akun C2S", "/akun", "user"},
	{"kebijakan", "Kebijakan", "/kebijakan", "shield"},
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
