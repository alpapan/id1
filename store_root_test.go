package id1

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// seedSymlinkStore builds a store containing a victim namespace, a symlink that
// escapes the store, and a relative symlink that stays inside it, and points
// dbpath at that store. The two symlinks are the two cases that matter: os.Root
// refuses the escaping one by itself, and follows the relative one, so only the
// second proves the no-symlink guard is doing anything.
func seedSymlinkStore(t *testing.T) (store string, outside string) {
	t.Helper()
	store = t.TempDir()
	outside = t.TempDir()

	originalDbpath := dbpath
	dbpath = store
	t.Cleanup(func() { dbpath = originalDbpath })

	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("OUTSIDE-SECRET"), 0644); err != nil {
		t.Fatalf("seed failed: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(store, "victim", "priv"), 0770); err != nil {
		t.Fatalf("seed failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(store, "victim", "priv", "salt"), []byte("VICTIM-SALT"), 0644); err != nil {
		t.Fatalf("seed failed: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(store, "mallory"), 0770); err != nil {
		t.Fatalf("seed failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(store, "mallory", "own"), []byte("MALLORY-OWN"), 0644); err != nil {
		t.Fatalf("seed failed: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(store, "mallory", "escape")); err != nil {
		t.Fatalf("seed failed: %v", err)
	}
	if err := os.Symlink("../victim", filepath.Join(store, "mallory", "cross")); err != nil {
		t.Fatalf("seed failed: %v", err)
	}
	return store, outside
}

func TestGetRefusesEscapingSymlink(t *testing.T) {
	seedSymlinkStore(t)
	k := mustK(t, "mallory/escape/secret")
	data, err := CmdGet(k).Exec()
	if !errors.Is(err, ErrForbidden) {
		t.Errorf("get through an escaping symlink: got err=%v, want ErrForbidden", err)
	}
	if string(data) == "OUTSIDE-SECRET" {
		t.Errorf("get through an escaping symlink leaked the outside file: %q", string(data))
	}
}

func TestGetRefusesInStoreRelativeSymlink(t *testing.T) {
	seedSymlinkStore(t)
	k := mustK(t, "mallory/cross/priv/salt")
	data, err := CmdGet(k).Exec()
	if !errors.Is(err, ErrForbidden) {
		t.Errorf("get through an in-store relative symlink: got err=%v, want ErrForbidden", err)
	}
	if string(data) == "VICTIM-SALT" {
		t.Errorf("get through an in-store relative symlink leaked another namespace: %q", string(data))
	}
}

func TestGetStillReadsLegitimateKey(t *testing.T) {
	seedSymlinkStore(t)
	k := mustK(t, "mallory/own")
	data, err := CmdGet(k).Exec()
	if err != nil {
		t.Fatalf("legitimate get failed: %v", err)
	}
	if string(data) != "MALLORY-OWN" {
		t.Errorf("legitimate get returned %q, want %q", string(data), "MALLORY-OWN")
	}
}

// TestOpenStoreRootCreatesMissingDbpath proves openStoreRoot succeeds against a
// dbpath that does not exist yet. A standalone binary (e.g. annot8r_id1)
// pointed at a not-yet-created DBPATH must still be able to Set, including the
// fallback that stores the signing key and every sovereign-key registration.
func TestOpenStoreRootCreatesMissingDbpath(t *testing.T) {
	parent := t.TempDir()
	fresh := filepath.Join(parent, "not-yet-created")

	originalDbpath := dbpath
	dbpath = fresh
	t.Cleanup(func() { dbpath = originalDbpath })

	if _, err := os.Stat(fresh); !os.IsNotExist(err) {
		t.Fatalf("test setup invariant broken: %q must not exist yet, stat err=%v", fresh, err)
	}

	root, err := openStoreRoot()
	if err != nil {
		t.Fatalf("openStoreRoot against a not-yet-created dbpath: %v", err)
	}
	defer root.Close()

	info, statErr := os.Stat(fresh)
	if statErr != nil {
		t.Fatalf("expected dbpath to be created, stat failed: %v", statErr)
	}
	if !info.IsDir() {
		t.Fatalf("expected dbpath to be a directory")
	}
}

func TestPathIsSymlinkFreeAllowsNewWriteTarget(t *testing.T) {
	store, _ := seedSymlinkStore(t)
	root, err := os.OpenRoot(store)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer root.Close()

	for _, rel := range []string{"mallory/own", "mallory/newfile", "mallory/deep/new/file", ""} {
		if !pathIsSymlinkFree(root, rel) {
			t.Errorf("pathIsSymlinkFree(%q) = false, want true", rel)
		}
	}
	for _, rel := range []string{"mallory/escape", "mallory/escape/secret", "mallory/cross/priv/salt"} {
		if pathIsSymlinkFree(root, rel) {
			t.Errorf("pathIsSymlinkFree(%q) = true, want false", rel)
		}
	}
}
