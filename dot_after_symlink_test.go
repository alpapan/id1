package id1

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// TestDotAfterDoesNotReadThroughSymlinkedAfterFile is the proof for the
// content-escape attack: the ".after." entry itself is a symlink (not a
// symlinked directory) whose target sits outside the store. A directory-only
// no-follow guard (the one filepath.Walk already provides for subdirectories)
// does not stop this, because the symlink here is a leaf entry, not a
// directory: the walk still visits it and, before this change, still called
// os.ReadFile on it, following the link and reading the outside content as if
// it were a genuine schedule. The root-scoped rewrite must refuse to read
// through it at all.
func TestDotAfterDoesNotReadThroughSymlinkedAfterFile(t *testing.T) {
	store, outside := seedSymlinkStore(t)

	targetPath := filepath.Join(outside, "malicious-command")
	maliciousBody := "set:/victim/priv/backdoor?x-id=victim\nPWNED"
	if err := os.WriteFile(targetPath, []byte(maliciousBody), 0644); err != nil {
		t.Fatalf("planting outside command file: %v", err)
	}

	pastTimestamp := time.Now().Add(-time.Hour).UnixMilli()
	symlinkPath := filepath.Join(store, "mallory", ".after."+strconv.FormatInt(pastTimestamp, 10))
	if err := os.Symlink(targetPath, symlinkPath); err != nil {
		t.Fatalf("planting symlinked .after. file: %v", err)
	}

	dotAfter(store)

	if _, err := CmdGet(mustK(t, "victim/priv/backdoor")).Exec(); err == nil {
		t.Errorf("SECURITY: a symlinked .after. file was read through and its command executed, planting victim/priv/backdoor")
	}
	if _, lstatErr := os.Lstat(symlinkPath); lstatErr != nil {
		t.Errorf("a symlinked .after. file must never be touched (not even removed), got: %v", lstatErr)
	}
}

// TestDotAfterDoesNotDescendIntoSymlinkedDirectory is the companion control
// for the directory case: a .after. file physically outside the store, only
// reachable by descending into mallory/escape (a symlink to an outside
// directory). This case is already safe under filepath.Walk (it never
// follows a symlinked directory), and the root-scoped rewrite must keep it
// that way.
func TestDotAfterDoesNotDescendIntoSymlinkedDirectory(t *testing.T) {
	store, outside := seedSymlinkStore(t)

	plantedPath := filepath.Join(outside, ".after.1")
	plantedBody := "set:/victim/priv/backdoor2?x-id=victim\nPWNED"
	if err := os.WriteFile(plantedPath, []byte(plantedBody), 0644); err != nil {
		t.Fatalf("planting outside .after. file: %v", err)
	}

	dotAfter(store)

	if _, err := CmdGet(mustK(t, "victim/priv/backdoor2")).Exec(); err == nil {
		t.Errorf("SECURITY: a .after. file reached only by descending into a symlinked directory was executed")
	}
	if _, statErr := os.Stat(plantedPath); statErr != nil {
		t.Errorf("a .after. file outside the store, reached only through a symlinked directory, must never be touched: %v", statErr)
	}
}

// TestDotAfterStillRunsOwnNamespaceScheduleAfterRootConversion is the control:
// containment must not break the feature for a plain, non-symlink schedule.
func TestDotAfterStillRunsOwnNamespaceScheduleAfterRootConversion(t *testing.T) {
	store, _ := seedSymlinkStore(t)

	pastTimestamp := time.Now().Add(-time.Hour).UnixMilli()
	body := "del:/mallory/own?x-id=mallory\n"
	scheduledPath := filepath.Join(store, "mallory", ".after."+strconv.FormatInt(pastTimestamp, 10))
	if err := os.WriteFile(scheduledPath, []byte(body), 0644); err != nil {
		t.Fatalf("planting mallory's own schedule: %v", err)
	}

	dotAfter(store)

	if _, statErr := os.Stat(filepath.Join(store, "mallory", "own")); statErr == nil {
		t.Errorf("a legitimate same-namespace schedule must still run after the root conversion")
	}
	if _, statErr := os.Stat(scheduledPath); statErr == nil {
		t.Errorf("a processed .after. file must still be removed")
	}
}
