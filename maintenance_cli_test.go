// apps/id1/maintenance_cli_test.go
//
// group: server
// tags: maintenance, cli, testing
// summary: Tests for the argument-driven maintenance invocation of the id1 binary.
//
//

package id1

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// storeWithLegacyEntry builds a temporary store root holding one legacy TTL
// bookkeeping file, one scheduled command and one ordinary value, and returns
// the root together with a getenv function pointing DBPATH at it.
func storeWithLegacyEntry(t *testing.T) (string, func(string) string) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "alice", "msg")
	if err := os.MkdirAll(dir, 0o770); err != nil {
		t.Fatalf("failed to create %s: %v", dir, err)
	}
	for _, name := range []string{".ttl.greeting", ".after.1750000000000", "greeting"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
			t.Fatalf("failed to create %s: %v", name, err)
		}
	}
	getenv := func(key string) string {
		if key == "DBPATH" {
			return root
		}
		return ""
	}
	return root, getenv
}

func TestRunMaintenanceCommandRejectsArgumentsItDoesNotUnderstand(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{name: "no arguments at all", args: []string{}},
		{name: "a group that is not maintenance", args: []string{"serve", "legacy-ttl"}},
		{name: "maintenance with no subcommand", args: []string{"maintenance"}},
		{name: "a maintenance subcommand that does not exist", args: []string{"maintenance", "purge-everything"}},
		{name: "an unknown flag after a valid subcommand", args: []string{"maintenance", "legacy-ttl", "--force"}},
	}
	if len(cases) != 5 {
		t.Fatalf("the refusal case list must hold 5 cases, got %d", len(cases))
	}
	names := map[string]bool{}
	for _, c := range cases {
		names[c.name] = true
	}
	for _, want := range []string{"no arguments at all", "a maintenance subcommand that does not exist", "an unknown flag after a valid subcommand"} {
		if !names[want] {
			t.Errorf("the refusal case list is missing the case %q", want)
		}
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, getenv := storeWithLegacyEntry(t)
			var stdout, stderr bytes.Buffer

			code := RunMaintenanceCommand(c.args, getenv, &stdout, &stderr)

			if code != 2 {
				t.Errorf("expected exit code 2 for %v, got %d", c.args, code)
			}
			if !strings.Contains(stderr.String(), "usage:") {
				t.Errorf("expected usage text on stderr for %v, got %q", c.args, stderr.String())
			}
			if stdout.Len() != 0 {
				t.Errorf("nothing should be written to stdout on a refusal, got %q", stdout.String())
			}
		})
	}
}

func TestRunMaintenanceCommandReportsWithoutRemovingByDefault(t *testing.T) {
	root, getenv := storeWithLegacyEntry(t)
	var stdout, stderr bytes.Buffer

	code := RunMaintenanceCommand([]string{"maintenance", "legacy-ttl"}, getenv, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "alice/msg/.ttl.greeting") {
		t.Errorf("expected the report to name the legacy file, got %q", stdout.String())
	}
	if _, err := os.Stat(filepath.Join(root, "alice", "msg", ".ttl.greeting")); err != nil {
		t.Errorf("the legacy file must survive an invocation without --apply: %v", err)
	}
}

func TestRunMaintenanceCommandRemovesOnlyLegacyBookkeepingWithApply(t *testing.T) {
	root, getenv := storeWithLegacyEntry(t)
	var stdout, stderr bytes.Buffer

	code := RunMaintenanceCommand([]string{"maintenance", "legacy-ttl", "--apply"}, getenv, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %q)", code, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(root, "alice", "msg", ".ttl.greeting")); err == nil {
		t.Errorf("the legacy file should have been removed")
	}
	for _, mustSurvive := range []string{".after.1750000000000", "greeting"} {
		if _, err := os.Stat(filepath.Join(root, "alice", "msg", mustSurvive)); err != nil {
			t.Errorf("%s must survive the sweep but is gone: %v", mustSurvive, err)
		}
	}
}

func TestRunMaintenanceCommandFailsWhenTheStoreCannotBeRead(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-store")
	getenv := func(key string) string {
		if key == "DBPATH" {
			return missing
		}
		return ""
	}
	var stdout, stderr bytes.Buffer

	code := RunMaintenanceCommand([]string{"maintenance", "legacy-ttl"}, getenv, &stdout, &stderr)

	if code != 1 {
		t.Errorf("expected exit code 1 for an unreadable store, got %d", code)
	}
	if stderr.Len() == 0 {
		t.Errorf("expected an explanation on stderr, got nothing")
	}
}
