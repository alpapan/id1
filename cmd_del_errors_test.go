package id1

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// cmdDelTestOrcid is an iD in the reserved test range (0000-0000-, body 9002).
const cmdDelTestOrcid = "0000-0000-0009-0027"

// TestCmdDel_MissingKeyIsNotFound: deleting a key that was never stored, in a
// store that opens, is ErrNotFound - the answer callers treat as "already absent".
func TestCmdDel_MissingKeyIsNotFound(t *testing.T) {
	originalDbpath := dbpath
	dbpath = t.TempDir()
	t.Cleanup(func() { dbpath = originalDbpath })

	_, err := CmdDel(mustKK(t, cmdDelTestOrcid, "pub", "keys", "cur-a")).execUnauthorised()
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing key: want ErrNotFound, got %v", err)
	}
}

// TestCmdDel_UnopenableStoreIsAnErrorNotNotFound: when the store root cannot be
// opened, del() must return that failure; ErrNotFound would tell the caller the
// key is gone while it may still be stored.
func TestCmdDel_UnopenableStoreIsAnErrorNotNotFound(t *testing.T) {
	notADir := filepath.Join(t.TempDir(), "store-is-a-file")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatalf("write placeholder file: %v", err)
	}
	originalDbpath := dbpath
	dbpath = notADir
	t.Cleanup(func() { dbpath = originalDbpath })

	_, err := CmdDel(mustKK(t, cmdDelTestOrcid, "pub", "keys", "cur-a")).execUnauthorised()
	if err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("unopenable store: want an error other than ErrNotFound, got %v", err)
	}
}
