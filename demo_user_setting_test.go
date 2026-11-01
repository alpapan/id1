package id1

import (
	"os"
	"testing"
)

// requireDemoUserSetting returns the ORCID iD named by ORCID_DEMO_USER and fails the test
// when it is unset. TestMain loads the monorepo .env.test, which carries the value.
func requireDemoUserSetting(t *testing.T) string {
	t.Helper()
	value := os.Getenv("ORCID_DEMO_USER")
	if value == "" {
		t.Fatal("ORCID_DEMO_USER is unset: add it to the .env.test at the monorepo root (TestMain loads that file)")
	}
	return value
}

// requireRealUserSetting returns the ORCID iD named by ORCID_SANDBOX_REAL_USER and fails
// the test when it is unset. That iD belongs to the real person who is the administrator.
func requireRealUserSetting(t *testing.T) string {
	t.Helper()
	value := os.Getenv("ORCID_SANDBOX_REAL_USER")
	if value == "" {
		t.Fatal("ORCID_SANDBOX_REAL_USER is unset: add it to the .env.test at the monorepo root (TestMain loads that file)")
	}
	return value
}
