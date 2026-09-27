package id1

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAddRefusesWriteThroughEscapingSymlink(t *testing.T) {
	_, outside := seedSymlinkStore(t)
	key := mustKK(t, "mallory", "escape", "pwned")

	_, err := NewCommand(Add, key, map[string]string{"x-id": "mallory"}, []byte("PWNED")).Exec()
	if err != ErrForbidden {
		t.Fatalf("expected ErrForbidden, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(outside, "pwned")); !os.IsNotExist(statErr) {
		t.Fatalf("add() wrote through an escaping symlink: %s exists", filepath.Join(outside, "pwned"))
	}
}

func TestAddRefusesWriteThroughInStoreRelativeSymlink(t *testing.T) {
	store, _ := seedSymlinkStore(t)
	key := mustKK(t, "mallory", "cross", "pwned")

	_, err := NewCommand(Add, key, map[string]string{"x-id": "mallory"}, []byte("PWNED")).Exec()
	if err != ErrForbidden {
		t.Fatalf("expected ErrForbidden, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(store, "victim", "pwned")); !os.IsNotExist(statErr) {
		t.Fatalf("add() wrote through an in-store relative symlink: %s exists", filepath.Join(store, "victim", "pwned"))
	}
}

func TestAddAppendsOrdinaryKeyWithNewParentDirectory(t *testing.T) {
	store, _ := seedSymlinkStore(t)
	key := mustKK(t, "newid", "newdir", "newkey")

	if _, err := NewCommand(Add, key, map[string]string{"x-id": "newid"}, []byte("HELLO")).Exec(); err != nil {
		t.Fatalf("expected first ordinary add to succeed, got %v", err)
	}
	if _, err := NewCommand(Add, key, map[string]string{"x-id": "newid"}, []byte("HELLO")).Exec(); err != nil {
		t.Fatalf("expected second ordinary add to succeed, got %v", err)
	}
	data, err := os.ReadFile(filepath.Join(store, "newid", "newdir", "newkey"))
	if err != nil {
		t.Fatalf("expected file to exist after ordinary add: %v", err)
	}
	if string(data) != "HELLOHELLO" {
		t.Fatalf("expected appended file content %q, got %q", "HELLOHELLO", string(data))
	}
}
