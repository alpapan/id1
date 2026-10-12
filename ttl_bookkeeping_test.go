// apps/id1/ttl_bookkeeping_test.go
//
// group: server
// tags: storage, ttl, scheduling, testing
// summary: Tests for TTL bookkeeping living in the reserved .ttl directory.
//
//

package id1

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTTLStore points the package at a fresh temporary store root and restores
// the previous one when the test ends.
func newTTLStore(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	original := dbpath
	dbpath = tmpDir
	t.Cleanup(func() { dbpath = original })
	return tmpDir
}

func TestTTLBookkeepingLivesInTheReservedDirectory(t *testing.T) {
	root := newTTLStore(t)

	key := mustK(t, "alice/msg/greeting")
	if _, err := CmdSet(key, map[string]string{"ttl": "60", "x-id": "alice"}, []byte("hello")).Exec(); err != nil {
		t.Fatalf("set with ttl failed: %v", err)
	}

	pointer := filepath.Join(root, "alice", "msg", ".ttl", "greeting")
	data, err := os.ReadFile(pointer)
	if err != nil {
		t.Fatalf("expected the bookkeeping pointer at %s: %v", pointer, err)
	}
	if !strings.HasPrefix(string(data), "alice/msg/.after.") {
		t.Errorf("pointer should name the scheduled command, got %q", string(data))
	}

	legacy := filepath.Join(root, "alice", "msg", ".ttl.greeting")
	if _, err := os.Stat(legacy); err == nil {
		t.Errorf("the flat bookkeeping name %s must not be written", legacy)
	}
}

func TestTTLBookkeepingCancelsThePreviousSchedule(t *testing.T) {
	root := newTTLStore(t)
	key := mustK(t, "alice/msg/greeting")

	if _, err := CmdSet(key, map[string]string{"ttl": "60", "x-id": "alice"}, []byte("first")).Exec(); err != nil {
		t.Fatalf("first set failed: %v", err)
	}
	firstPointer, err := os.ReadFile(filepath.Join(root, "alice", "msg", ".ttl", "greeting"))
	if err != nil {
		t.Fatalf("reading the first pointer: %v", err)
	}

	if _, err := CmdSet(key, map[string]string{"ttl": "600", "x-id": "alice"}, []byte("second")).Exec(); err != nil {
		t.Fatalf("second set failed: %v", err)
	}

	if _, statErr := os.Stat(filepath.Join(root, string(firstPointer))); statErr == nil {
		t.Errorf("re-setting the key must cancel the previous schedule %q, but it is still armed", string(firstPointer))
	}

	secondPointer, err := os.ReadFile(filepath.Join(root, "alice", "msg", ".ttl", "greeting"))
	if err != nil {
		t.Fatalf("reading the second pointer: %v", err)
	}
	if string(secondPointer) == string(firstPointer) {
		t.Errorf("the pointer should now name a new schedule, still names %q", string(secondPointer))
	}
}

func TestDeletingAKeyRemovesItsBookkeepingPointer(t *testing.T) {
	root := newTTLStore(t)
	key := mustK(t, "alice/msg/greeting")

	if _, err := CmdSet(key, map[string]string{"ttl": "60", "x-id": "alice"}, []byte("hello")).Exec(); err != nil {
		t.Fatalf("set with ttl failed: %v", err)
	}
	pointer := filepath.Join(root, "alice", "msg", ".ttl", "greeting")
	if _, err := os.Stat(pointer); err != nil {
		t.Fatalf("expected the bookkeeping pointer to exist before the delete, at %s: %v", pointer, err)
	}

	if _, err := CmdDel(key).Exec(); err != nil {
		t.Fatalf("delete failed: %v", err)
	}

	if _, statErr := os.Stat(pointer); statErr == nil {
		t.Errorf("deleting the key must remove its bookkeeping pointer at %s", pointer)
	}
}

func TestTTLStillExpiresTheKey(t *testing.T) {
	root := newTTLStore(t)
	key := mustK(t, "alice/msg/greeting")

	if _, err := CmdSet(key, map[string]string{"ttl": "60", "x-id": "alice"}, []byte("hello")).Exec(); err != nil {
		t.Fatalf("set with ttl failed: %v", err)
	}

	// Rather than sleeping out a real TTL, rename the schedule to a timestamp
	// already in the past. The sweeper reads the deadline from the file name.
	parent := filepath.Join(root, "alice", "msg")
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatalf("reading %s: %v", parent, err)
	}
	scheduled := ""
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".after.") {
			scheduled = entry.Name()
		}
	}
	if scheduled == "" {
		t.Fatalf("no scheduled command was written in %s", parent)
	}
	if err := os.Rename(filepath.Join(parent, scheduled), filepath.Join(parent, ".after.1")); err != nil {
		t.Fatalf("renaming the schedule into the past: %v", err)
	}

	dotAfter(root)

	if _, getErr := CmdGet(key).Exec(); getErr == nil {
		t.Errorf("the sweeper should have expired the key, but it is still readable")
	}
}
