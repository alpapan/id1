// apps/id1/legacy_ttl_test.go
//
// group: server
// tags: storage, maintenance, ttl, testing
// summary: Tests for detection and removal of pre-relocation TTL bookkeeping files.
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

// scanCase is one file shape the scanner is shown, and whether the scanner must
// report it as legacy TTL bookkeeping.
type scanCase struct {
	name    string
	relPath string
	isDir   bool
	want    bool
}

// scanCases is the whole recognition contract in one place. It is asserted by
// TestScanCaseListIsPopulatedAndNamed below, so deleting a row fails a test
// rather than silently dropping the coverage that row carried.
var scanCases = []scanCase{
	{name: "legacy bookkeeping file", relPath: "alice/msg/.ttl.greeting", want: true},
	{name: "legacy bookkeeping at a deeper parent", relPath: "alice/msg/threads/.ttl.1", want: true},
	{name: "relocated bookkeeping under the reserved directory", relPath: "alice/msg/.ttl/greeting", want: false},
	{name: "scheduled command file", relPath: "alice/msg/.after.1750000000000", want: false},
	{name: "ordinary value file", relPath: "alice/msg/greeting", want: false},
	{name: "reserved directory itself", relPath: "alice/msg/.ttl", isDir: true, want: false},
	{name: "dot-op authorisation file", relPath: "alice/msg/.set", want: false},
	{name: "bare prefix with no key name after it", relPath: "alice/msg/.ttl.", want: false},
}

func TestScanCaseListIsPopulatedAndNamed(t *testing.T) {
	if len(scanCases) != 8 {
		t.Fatalf("scanCases must hold 8 cases, got %d - update this guard whenever a row is inserted or deleted", len(scanCases))
	}
	names := map[string]bool{}
	for _, c := range scanCases {
		names[c.name] = true
	}
	for _, want := range []string{
		"legacy bookkeeping file",
		"relocated bookkeeping under the reserved directory",
		"scheduled command file",
		"reserved directory itself",
	} {
		if !names[want] {
			t.Errorf("scanCases is missing the case %q", want)
		}
	}
}

// writeStoreEntry creates relPath under root, as a directory when isDir is set
// and as a small regular file otherwise.
func writeStoreEntry(t *testing.T, root, relPath string, isDir bool) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(relPath))
	if isDir {
		if err := os.MkdirAll(full, 0o770); err != nil {
			t.Fatalf("failed to create directory %s: %v", full, err)
		}
		return
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o770); err != nil {
		t.Fatalf("failed to create parent of %s: %v", full, err)
	}
	if err := os.WriteFile(full, []byte("x"), 0o644); err != nil {
		t.Fatalf("failed to create file %s: %v", full, err)
	}
}

func TestScanLegacyTTLEntriesRecognisesOnlyLegacyBookkeeping(t *testing.T) {
	for _, c := range scanCases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			writeStoreEntry(t, root, c.relPath, c.isDir)

			found, err := ScanLegacyTTLEntries(root)
			if err != nil {
				t.Fatalf("ScanLegacyTTLEntries returned an error: %v", err)
			}

			got := false
			for _, f := range found {
				if f == c.relPath {
					got = true
				}
			}
			if got != c.want {
				t.Errorf("for %s: reported as legacy bookkeeping = %v, want %v (scan returned %v)", c.relPath, got, c.want, found)
			}
		})
	}
}

func TestScanLegacyTTLEntriesReturnsSortedRelativePaths(t *testing.T) {
	root := t.TempDir()
	writeStoreEntry(t, root, "bob/msg/.ttl.b", false)
	writeStoreEntry(t, root, "alice/msg/.ttl.a", false)

	found, err := ScanLegacyTTLEntries(root)
	if err != nil {
		t.Fatalf("ScanLegacyTTLEntries returned an error: %v", err)
	}
	if len(found) != 2 {
		t.Fatalf("expected 2 entries, got %d: %v", len(found), found)
	}
	if found[0] != "alice/msg/.ttl.a" || found[1] != "bob/msg/.ttl.b" {
		t.Errorf("expected sorted relative paths [alice/msg/.ttl.a bob/msg/.ttl.b], got %v", found)
	}
}

func TestScanLegacyTTLEntriesErrorsOnMissingRoot(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-store")

	if _, err := ScanLegacyTTLEntries(missing); err == nil {
		t.Errorf("expected an error for a store root that does not exist, got nil")
	}
}

func TestSweepLegacyTTLEntriesLeavesFilesInPlaceWithoutApply(t *testing.T) {
	root := t.TempDir()
	writeStoreEntry(t, root, "alice/msg/.ttl.greeting", false)

	report, err := SweepLegacyTTLEntries(root, false)
	if err != nil {
		t.Fatalf("SweepLegacyTTLEntries returned an error: %v", err)
	}
	if len(report.Entries) != 1 {
		t.Fatalf("expected 1 reported entry, got %d", len(report.Entries))
	}
	if report.Entries[0].Removed {
		t.Errorf("entry reported as removed even though apply was false")
	}
	if report.Applied {
		t.Errorf("report.Applied is true even though apply was false")
	}
	if _, statErr := os.Stat(filepath.Join(root, "alice", "msg", ".ttl.greeting")); statErr != nil {
		t.Errorf("legacy file is missing although apply was false: %v", statErr)
	}
}

func TestSweepLegacyTTLEntriesRemovesOnlyLegacyFilesWithApply(t *testing.T) {
	root := t.TempDir()
	writeStoreEntry(t, root, "alice/msg/.ttl.greeting", false)
	writeStoreEntry(t, root, "alice/msg/.after.1750000000000", false)
	writeStoreEntry(t, root, "alice/msg/greeting", false)
	writeStoreEntry(t, root, "alice/msg/.ttl/greeting", false)

	report, err := SweepLegacyTTLEntries(root, true)
	if err != nil {
		t.Fatalf("SweepLegacyTTLEntries returned an error: %v", err)
	}
	if len(report.Entries) != 1 {
		t.Fatalf("expected 1 reported entry, got %d: %+v", len(report.Entries), report.Entries)
	}
	if !report.Entries[0].Removed {
		t.Errorf("entry was not reported as removed: %+v", report.Entries[0])
	}
	if report.Failures() != 0 {
		t.Errorf("expected 0 failures, got %d", report.Failures())
	}

	if _, statErr := os.Stat(filepath.Join(root, "alice", "msg", ".ttl.greeting")); statErr == nil {
		t.Errorf("legacy bookkeeping file still present after apply")
	}
	for _, mustSurvive := range []string{
		filepath.Join(root, "alice", "msg", ".after.1750000000000"),
		filepath.Join(root, "alice", "msg", "greeting"),
		filepath.Join(root, "alice", "msg", ".ttl", "greeting"),
	} {
		if _, statErr := os.Stat(mustSurvive); statErr != nil {
			t.Errorf("%s must survive the sweep but is gone: %v", mustSurvive, statErr)
		}
	}
}

func TestLegacyTTLReportWriteTextNamesEveryEntry(t *testing.T) {
	root := t.TempDir()
	writeStoreEntry(t, root, "alice/msg/.ttl.greeting", false)

	report, err := SweepLegacyTTLEntries(root, false)
	if err != nil {
		t.Fatalf("SweepLegacyTTLEntries returned an error: %v", err)
	}
	var buf bytes.Buffer
	report.WriteText(&buf)
	out := buf.String()

	if !strings.Contains(out, "alice/msg/.ttl.greeting") {
		t.Errorf("report text does not name the entry it found:\n%s", out)
	}
	if !strings.Contains(out, "--apply") {
		t.Errorf("a scan without --apply must tell the operator how to act on it:\n%s", out)
	}
}
