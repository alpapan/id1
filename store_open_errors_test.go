package id1

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// storeTestOrcid is an iD in the reserved test range (0000-0000-, body 9002).
const storeTestOrcid = "0000-0000-0009-0027"

// withWorkingStore points the store at a fresh temporary directory for one test.
func withWorkingStore(t *testing.T) {
	t.Helper()
	originalDbpath := dbpath
	dbpath = t.TempDir()
	t.Cleanup(func() { dbpath = originalDbpath })
}

// withUnopenableStore points the store at a plain file inside a temporary
// directory for one test, so openStoreRoot fails.
func withUnopenableStore(t *testing.T) {
	t.Helper()
	notADir := filepath.Join(t.TempDir(), "store-is-a-file")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatalf("write placeholder file: %v", err)
	}
	originalDbpath := dbpath
	dbpath = notADir
	t.Cleanup(func() { dbpath = originalDbpath })
}

// moveWithinOwnNamespace builds a move of {id}/pub/a to {id}/pub/b on behalf of id.
func moveWithinOwnNamespace(t *testing.T) Command {
	t.Helper()
	cmd := CmdMov(mustKK(t, storeTestOrcid, "pub", "a"), mustKK(t, storeTestOrcid, "pub", "b"))
	cmd.Args["x-id"] = storeTestOrcid
	return cmd
}

func wantNotFound(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("%s: want ErrNotFound, got %v", what, err)
	}
}

// wantStoreError: a store that cannot be opened must surface as an error;
// ErrNotFound would tell the caller the key is absent while it may be stored.
func wantStoreError(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("%s: want an error other than ErrNotFound, got %v", what, err)
	}
}

func TestCmdGet_MissingKeyIsNotFound(t *testing.T) {
	withWorkingStore(t)
	_, err := CmdGet(mustKK(t, storeTestOrcid, "pub", "keys", "cur-a")).execUnauthorised()
	wantNotFound(t, "get of a missing key", err)
}

func TestCmdGet_UnopenableStoreIsAnErrorNotNotFound(t *testing.T) {
	withUnopenableStore(t)
	_, err := CmdGet(mustKK(t, storeTestOrcid, "pub", "keys", "cur-a")).execUnauthorised()
	wantStoreError(t, "get on an unopenable store", err)
}

func TestCmdList_MissingDirectoryIsNotFound(t *testing.T) {
	withWorkingStore(t)
	_, err := CmdList(mustKK(t, storeTestOrcid, "pub"), ListOptions{}).execUnauthorised()
	wantNotFound(t, "list of a missing directory", err)
}

func TestCmdList_UnopenableStoreIsAnErrorNotNotFound(t *testing.T) {
	withUnopenableStore(t)
	_, err := CmdList(mustKK(t, storeTestOrcid, "pub"), ListOptions{}).execUnauthorised()
	wantStoreError(t, "list on an unopenable store", err)
}

func TestCmdMov_MissingSourceIsNotFound(t *testing.T) {
	withWorkingStore(t)
	_, err := moveWithinOwnNamespace(t).execUnauthorised()
	wantNotFound(t, "move of a missing source", err)
}

func TestCmdMov_UnopenableStoreIsAnErrorNotNotFound(t *testing.T) {
	withUnopenableStore(t)
	_, err := moveWithinOwnNamespace(t).execUnauthorised()
	wantStoreError(t, "move on an unopenable store", err)
}
