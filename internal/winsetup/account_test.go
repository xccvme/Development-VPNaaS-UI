package winsetup

import (
	"strings"
	"testing"
)

func TestAccountDefaultAndAdministratorGate(t *testing.T) {
	p := base()
	p["username"] = "alice@example:team"
	got, err := Render(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"[string]$ConnectionName = 'alice@example:team'", "WindowsPrincipal", "Run as Administrator", "IsInRole", "Import-Certificate", "Group14"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q", want)
		}
	}
	gate := strings.Index(got, "IsInRole")
	if gate < 0 || gate > strings.Index(got, "Read-Host") || gate > strings.Index(got, "Import-Certificate") {
		t.Error("administrator gate must precede prompts and changes")
	}
	if strings.Contains(got, "VPNaaS-PoC") {
		t.Error("generic profile name remains")
	}
}

func TestUsernameTemplateTokensStayLiteral(t *testing.T) {
	p := base()
	p["username"] = "__SERVER__"
	got, err := Render(p)
	if err != nil || !strings.Contains(got, "$ConnectionName = '__SERVER__'") {
		t.Fatal("username must remain literal, not a template token")
	}
}

func TestUsernameAndFilenameSafety(t *testing.T) {
	for _, bad := range []any{nil, "", "../escape", "x';evil", "x\r\nHeader", "x\\path", strings.Repeat("x", 129)} {
		p := base()
		p["username"] = bad
		if _, err := Render(p); err == nil {
			t.Errorf("unsafe username accepted: %q", bad)
		}
	}
	for _, tc := range [][2]string{{"alice", "alice"}, {"alice@example:team", "alice@example_team"}, {"CON", "_CON"}, {"..", "_"}, {"bob.", "bob"}} {
		got, err := Filename(tc[0])
		if err != nil || got != tc[1] {
			t.Errorf("filename %q = %q, %v", tc[0], got, err)
		}
	}
}
