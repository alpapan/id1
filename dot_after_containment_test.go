package id1

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeScheduledCommand puts a .after. file on disk directly, which is what a
// planted schedule looks like however it got there. It deliberately does not go
// through set(): the point is that the sweep must be safe against a file it did
// not write itself.
func writeScheduledCommand(t *testing.T, tmpDir, keyPath, body string) string {
	t.Helper()
	full := filepath.Join(tmpDir, filepath.FromSlash(keyPath))
	if err := os.MkdirAll(filepath.Dir(full), 0770); err != nil {
		t.Fatalf("preparing %s: %v", keyPath, err)
	}
	if err := os.WriteFile(full, []byte(body), 0644); err != nil {
		t.Fatalf("writing %s: %v", keyPath, err)
	}
	return full
}

// TestDotAfterContainmentRefusesCrossNamespaceCommand - the account-takeover
// payload. A scheduled command sitting in the attacker's namespace names the
// victim's key and claims the victim's identity; the sweep must refuse it
// because the file it came from does not live in the victim's namespace.
func TestDotAfterContainmentRefusesCrossNamespaceCommand(t *testing.T) {
	tmpDir := seedVictim(t)

	if _, err := CmdSet(mustK(t, "victim/pub/keys/default"), map[string]string{"x-id": "victim"}, []byte("VICTIM-KEY")).Exec(); err != nil {
		t.Fatalf("seed victim key: %v", err)
	}
	planted := writeScheduledCommand(t, tmpDir, "mallory/.after.1",
		"set:/victim/pub/keys/default?x-id=victim\nATTACKER-KEY")

	dotAfter(tmpDir)

	data, readErr := os.ReadFile(filepath.Join(tmpDir, "victim", "pub", "keys", "default"))
	if readErr != nil {
		t.Fatalf("victim key vanished: %v", readErr)
	}
	if string(data) != "VICTIM-KEY" {
		t.Errorf("SECURITY: a planted schedule overwrote the victim's key, got %q", string(data))
	}
	if _, statErr := os.Stat(planted); statErr == nil {
		t.Errorf("a refused schedule must still be removed from disk")
	}
}

// TestDotAfterContainmentRefusesEmptyKeyDelete - the whole-store-deletion
// payload. A body of "del:" parses to a command with no target at all, whose
// empty key resolves to the store root.
func TestDotAfterContainmentRefusesEmptyKeyDelete(t *testing.T) {
	tmpDir := seedVictim(t)

	writeScheduledCommand(t, tmpDir, "mallory/.after.1", "del:")

	dotAfter(tmpDir)

	if _, statErr := os.Stat(tmpDir); statErr != nil {
		t.Fatalf("SECURITY: a planted schedule deleted the whole store: %v", statErr)
	}
	data, readErr := os.ReadFile(filepath.Join(tmpDir, "victim", "priv", "salt"))
	if readErr != nil {
		t.Errorf("SECURITY: the victim's file was destroyed: %v", readErr)
	} else if string(data) != "VICTIM-SALT" {
		t.Errorf("the victim's file was altered: %q", string(data))
	}
}

// TestDotAfterContainmentRefusesStoreRootSchedule - a .after. file sitting
// directly in the store root belongs to no namespace, so no command it carries
// can be contained. It must be refused rather than treated as owned by whatever
// it claims.
func TestDotAfterContainmentRefusesStoreRootSchedule(t *testing.T) {
	tmpDir := seedVictim(t)

	planted := writeScheduledCommand(t, tmpDir, ".after.1", "del:/victim/priv/salt?x-id=victim\n")

	dotAfter(tmpDir)

	data, readErr := os.ReadFile(filepath.Join(tmpDir, "victim", "priv", "salt"))
	if readErr != nil {
		t.Errorf("SECURITY: a store-root schedule deleted the victim's file: %v", readErr)
	} else if string(data) != "VICTIM-SALT" {
		t.Errorf("the victim's file was altered: %q", string(data))
	}
	if _, statErr := os.Stat(planted); statErr == nil {
		t.Errorf("a refused schedule must still be removed from disk")
	}
}

// TestDotAfterContainmentStillRunsOwnNamespaceSchedule is the control, and it
// is the important half of this change: containment must not break the feature.
// A schedule acting inside its own namespace still runs.
func TestDotAfterContainmentStillRunsOwnNamespaceSchedule(t *testing.T) {
	tmpDir := seedVictim(t)

	if _, err := CmdSet(mustK(t, "mallory/doomed"), map[string]string{"x-id": "mallory"}, []byte("TEMPORARY")).Exec(); err != nil {
		t.Fatalf("seed mallory/doomed: %v", err)
	}
	writeScheduledCommand(t, tmpDir, "mallory/.after.1", "del:/mallory/doomed?x-id=mallory\n")

	dotAfter(tmpDir)

	if _, statErr := os.Stat(filepath.Join(tmpDir, "mallory", "doomed")); statErr == nil {
		t.Errorf("a schedule acting inside its own namespace must still run")
	}
}

// TestDotAfterContainmentSkipsSingleSegmentKeyTtl - a ttl set against a
// single-segment key (no parent) cannot be scheduled: the only directory
// dot_after.go's containment check would accept is one named after the
// command's target Id, and for a single-segment key that name is already
// occupied by the key's own value file (dbpath/<id> is a file, not a
// directory). createDotTtl refuses to schedule in this case rather than
// attempt a write that collides on disk or create an unowned schedule at
// the store root - either of which the earlier tests in this file already
// prove the sweep must refuse. The set itself is unaffected: the key is
// written and stays written, and the ttl argument is silently a no-op.
func TestDotAfterContainmentSkipsSingleSegmentKeyTtl(t *testing.T) {
	tmpDir := seedVictim(t)

	if _, err := CmdSet(mustK(t, "mallory"), map[string]string{"ttl": "1", "x-id": "mallory"}, []byte("TEMPORARY")).Exec(); err != nil {
		t.Fatalf("seed mallory with ttl: %v", err)
	}

	entries, readErr := os.ReadDir(tmpDir)
	if readErr != nil {
		t.Fatalf("reading store root: %v", readErr)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".after.") || strings.HasPrefix(entry.Name(), ".ttl.") {
			t.Errorf("SECURITY: a single-segment ttl set created an unowned store-root schedule file %q", entry.Name())
		}
	}

	time.Sleep(1100 * time.Millisecond)
	dotAfter(tmpDir)

	data, getErr := CmdGet(mustK(t, "mallory")).Exec()
	if getErr != nil {
		t.Fatalf("a single-segment key's ttl must be a no-op, but the key is gone: %v", getErr)
	}
	if string(data) != "TEMPORARY" {
		t.Errorf("key data changed: got %q", string(data))
	}
}
