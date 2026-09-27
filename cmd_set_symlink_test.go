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
