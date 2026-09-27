package id1

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSetRefusesWriteThroughEscapingSymlink(t *testing.T) {
	_, outside := seedSymlinkStore(t)
	key := mustKK(t, "mallory", "escape", "pwned")

	_, err := NewCommand(Set, key, map[string]string{"x-id": "mallory"}, []byte("PWNED")).Exec()
	if err != ErrForbidden {
		t.Fatalf("expected ErrForbidden, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(outside, "pwned")); !os.IsNotExist(statErr) {
		t.Fatalf("set() wrote through an escaping symlink: %s exists", filepath.Join(outside, "pwned"))
	}
}

func TestSetRefusesWriteThroughInStoreRelativeSymlink(t *testing.T) {
	store, _ := seedSymlinkStore(t)
	key := mustKK(t, "mallory", "cross", "pwned")

	_, err := NewCommand(Set, key, map[string]string{"x-id": "mallory"}, []byte("PWNED")).Exec()
	if err != ErrForbidden {
		t.Fatalf("expected ErrForbidden, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(store, "victim", "pwned")); !os.IsNotExist(statErr) {
		t.Fatalf("set() wrote through an in-store relative symlink: %s exists", filepath.Join(store, "victim", "pwned"))
	}
}

func TestSetSucceedsAgainstFreshNonExistentDbpath(t *testing.T) {
	parent := t.TempDir()
	fresh := filepath.Join(parent, "not-yet-created")

	originalDbpath := dbpath
	dbpath = fresh
	t.Cleanup(func() { dbpath = originalDbpath })

	if _, err := os.Stat(fresh); !os.IsNotExist(err) {
		t.Fatalf("test setup invariant broken: %q must not exist yet, stat err=%v", fresh, err)
	}

	key := mustKK(t, "newid", "newkey")
	if _, err := NewCommand(Set, key, map[string]string{"x-id": "newid"}, []byte("HELLO")).Exec(); err != nil {
		t.Fatalf("expected set() to succeed against a fresh non-existent dbpath, got %v", err)
	}
	data, err := os.ReadFile(filepath.Join(fresh, "newid", "newkey"))
	if err != nil {
		t.Fatalf("expected file to exist after set on a fresh dbpath: %v", err)
	}
	if string(data) != "HELLO" {
		t.Fatalf("expected file content %q, got %q", "HELLO", string(data))
	}
}

func TestSetWritesOrdinaryKeyWithNewParentDirectory(t *testing.T) {
	store, _ := seedSymlinkStore(t)
	key := mustKK(t, "newid", "newdir", "newkey")

	if _, err := NewCommand(Set, key, map[string]string{"x-id": "newid"}, []byte("HELLO")).Exec(); err != nil {
		t.Fatalf("expected ordinary set to succeed, got %v", err)
	}
	data, err := os.ReadFile(filepath.Join(store, "newid", "newdir", "newkey"))
	if err != nil {
		t.Fatalf("expected file to exist after ordinary set: %v", err)
	}
	if string(data) != "HELLO" {
		t.Fatalf("expected file content %q, got %q", "HELLO", string(data))
	}
}
