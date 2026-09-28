package id1

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// seedSymlinkStoreWithFileLeak extends seedSymlinkStore with an in-store FILE
// symlink whose target never leaves the store - mallory/leak points at
// ../victim/priv/salt. os.Root only refuses a symlink that resolves outside
// the root; this one resolves to another namespace INSIDE it, so the only
// thing standing between mallory and the victim's salt is the per-entry
// fs.ModeSymlink skip in listDir and walkDir (cmd_list.go). Distinct from the
// directory symlinks seedSymlinkStore already carries (mallory/escape,
// mallory/cross), which the existing tests in this file exercise.
func seedSymlinkStoreWithFileLeak(t *testing.T) (store string) {
	t.Helper()
	store, _ = seedSymlinkStore(t)
	if err := os.Symlink("../victim/priv/salt", filepath.Join(store, "mallory", "leak")); err != nil {
		t.Fatalf("seed failed: %v", err)
	}
	return store
}

func TestListDoesNotEnumerateThroughSymlinkEscapingStore(t *testing.T) {
	seedSymlinkStore(t)

	data, err := NewCommand(List, mustK(t, "mallory/escape*"), map[string]string{"x-id": "mallory", "keys": "true"}, []byte{}).Exec()

	if !errors.Is(err, ErrForbidden) {
		t.Errorf("list() on a namespace path that is itself a symlink out of the store: got err=%v, want ErrForbidden", err)
	}
	if strings.Contains(string(data), "OUTSIDE-SECRET") || strings.Contains(string(data), "secret") {
		t.Errorf("SECURITY: list() disclosed outside-store content through a symlink: %q", string(data))
	}
}

func TestListDoesNotEnumerateThroughInStoreCrossNamespaceSymlink(t *testing.T) {
	seedSymlinkStore(t)

	data, err := NewCommand(List, mustK(t, "mallory/cross*"), map[string]string{"x-id": "mallory", "keys": "true"}, []byte{}).Exec()

	if !errors.Is(err, ErrForbidden) {
		t.Errorf("list() on a namespace path that is itself an in-store symlink to another identity: got err=%v, want ErrForbidden", err)
	}
	if strings.Contains(string(data), "VICTIM-SALT") || strings.Contains(string(data), "priv/salt") {
		t.Errorf("SECURITY: list() disclosed the victim's namespace through mallory's symlink: %q", string(data))
	}
}

func TestRecursiveListSkipsSymlinkedEntriesInsideOwnNamespace(t *testing.T) {
	seedSymlinkStore(t)

	data, err := NewCommand(List, mustK(t, "mallory*"), map[string]string{"x-id": "mallory", "recursive": "true", "keys": "true"}, []byte{}).Exec()
	if err != nil {
		t.Fatalf("recursive list of mallory's own namespace was refused: %v", err)
	}
	if !strings.Contains(string(data), "mallory/own") {
		t.Errorf("recursive list lost the legitimate entry: got %q", string(data))
	}
	if strings.Contains(string(data), "OUTSIDE-SECRET") || strings.Contains(string(data), "secret") {
		t.Errorf("SECURITY: recursive list followed mallory/escape to the outside store: %q", string(data))
	}
	if strings.Contains(string(data), "VICTIM-SALT") {
		t.Errorf("SECURITY: recursive list followed mallory/cross into the victim's namespace: %q", string(data))
	}
}

func TestListNonRecursiveSkipsFileSymlinkTargetInBase64Mode(t *testing.T) {
	seedSymlinkStoreWithFileLeak(t)

	data, err := NewCommand(List, mustK(t, "mallory*"), map[string]string{"x-id": "mallory"}, []byte{}).Exec()
	if err != nil {
		t.Fatalf("non-recursive list of mallory's own namespace was refused: %v", err)
	}
	leakedBase64 := base64.StdEncoding.EncodeToString([]byte("VICTIM-SALT"))
	if strings.Contains(string(data), "VICTIM-SALT") || strings.Contains(string(data), leakedBase64) {
		t.Errorf("SECURITY: non-recursive base64-mode list disclosed the victim's salt through mallory/leak: %q", string(data))
	}
	if strings.Contains(string(data), "leak") {
		t.Errorf("SECURITY: non-recursive base64-mode list disclosed the mallory/leak entry itself: %q", string(data))
	}
	if !strings.Contains(string(data), "mallory/own") {
		t.Errorf("non-recursive base64-mode list lost the legitimate entry: got %q", string(data))
	}
}

func TestListNonRecursiveSkipsFileSymlinkTargetInKeysMode(t *testing.T) {
	seedSymlinkStoreWithFileLeak(t)

	data, err := NewCommand(List, mustK(t, "mallory*"), map[string]string{"x-id": "mallory", "keys": "true"}, []byte{}).Exec()
	if err != nil {
		t.Fatalf("non-recursive keys-mode list of mallory's own namespace was refused: %v", err)
	}
	if strings.Contains(string(data), "VICTIM-SALT") || strings.Contains(string(data), "leak") {
		t.Errorf("SECURITY: non-recursive keys-mode list disclosed mallory/leak or its target: %q", string(data))
	}
	if !strings.Contains(string(data), "mallory/own") {
		t.Errorf("non-recursive keys-mode list lost the legitimate entry: got %q", string(data))
	}
}

func TestRecursiveListSkipsFileSymlinkTargetWithoutKeysMode(t *testing.T) {
	seedSymlinkStoreWithFileLeak(t)

	data, err := NewCommand(List, mustK(t, "mallory*"), map[string]string{"x-id": "mallory", "recursive": "true"}, []byte{}).Exec()
	if err != nil {
		t.Fatalf("recursive list of mallory's own namespace was refused: %v", err)
	}
	leakedBase64 := base64.StdEncoding.EncodeToString([]byte("VICTIM-SALT"))
	if strings.Contains(string(data), "VICTIM-SALT") || strings.Contains(string(data), leakedBase64) {
		t.Errorf("SECURITY: recursive list disclosed the victim's salt through mallory/leak: %q", string(data))
	}
	if strings.Contains(string(data), "leak") {
		t.Errorf("SECURITY: recursive list disclosed the mallory/leak entry itself: %q", string(data))
	}
	if !strings.Contains(string(data), "mallory/own") {
		t.Errorf("recursive list lost the legitimate entry: got %q", string(data))
	}
}

func TestListOrdinaryAndRecursiveListingStillWorkWithoutSymlinks(t *testing.T) {
	seedSymlinkStore(t)

	nonRecursive, err := NewCommand(List, mustK(t, "victim/priv*"), map[string]string{"x-id": "victim", "keys": "true"}, []byte{}).Exec()
	if err != nil {
		t.Fatalf("ordinary non-recursive list was refused: %v", err)
	}
	if !strings.Contains(string(nonRecursive), "victim/priv/salt") {
		t.Errorf("ordinary listing lost its entry: got %q", string(nonRecursive))
	}

	recursive, err := NewCommand(List, mustK(t, "victim*"), map[string]string{"x-id": "victim", "recursive": "true", "keys": "true"}, []byte{}).Exec()
	if err != nil {
		t.Fatalf("ordinary recursive list was refused: %v", err)
	}
	if !strings.Contains(string(recursive), "victim/priv/salt") {
		t.Errorf("recursive listing lost its entry: got %q", string(recursive))
	}
}
