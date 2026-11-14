package auth

import "testing"

func TestConfiguredAdminCredentials(t *testing.T) {
	t.Setenv("ADMIN_USERNAME", "operator")
	t.Setenv("ADMIN_PASSWORD", "test-only-override")
	if !CheckCredentials("operator", "test-only-override") {
		t.Fatal("configured admin credentials rejected")
	}
	if CheckCredentials("admin", "admin") {
		t.Fatal("default credentials still accepted after override")
	}
}
