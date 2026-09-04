package id1

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mustK builds a key the test author asserts is valid. It fails the test
// rather than returning an error, so a test body reads as it did before K
// gained its error result.
//
// A test that deliberately exercises a REJECTED key must not use this: call
// K directly and assert on the error with errors.Is(err, ErrInvalidKey).
func mustK(t *testing.T, s string) Id1Key {
	t.Helper()
	k, err := K(s)
	if err != nil {
		t.Fatalf("K(%q): unexpected error: %v", s, err)
	}
	return k
}

// mustKK is mustK for the variadic constructor. The same caveat applies: a
// test exercising a rejected key calls KK directly and asserts on the error.
func mustKK(t *testing.T, segments ...any) Id1Key {
	t.Helper()
	k, err := KK(segments...)
	if err != nil {
		t.Fatalf("KK(%v): unexpected error: %v", segments, err)
	}
	return k
}

// hostileKey builds an Id1Key that K() would refuse, by assembling the struct
// directly. This is deliberate: it simulates a future constructor, a
// deserialiser, or a hand-assembled key inside the package, which is the only
// remaining way a traversal key can reach an operation now that K() rejects
// them at the boundary.
//
// Shared across containment test files (cmd_sink_containment_test.go and any
// sibling containment suite) - keep this the single definition rather than
// letting a second file redeclare it, which would break the build for every
// test file in the package.
func hostileKey(t *testing.T, segments ...string) Id1Key {
	t.Helper()
	if len(segments) == 0 {
		t.Fatalf("hostileKey: need at least one segment")
	}
	k := Id1Key{Segments: segments}
	k.Id = segments[0]
	k.Name = segments[len(segments)-1]
	if len(segments) > 1 {
		k.Parent = strings.Join(segments[:len(segments)-1], "/")
		k.Pub = segments[1] == "pub"
	}
	return k
}

// seedVictim writes a file the attacker must not be able to reach, and
// returns the temp root. Shared across containment test files - see the
// hostileKey comment above for why this lives here rather than in any one
// of them.
func seedVictim(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	originalDbpath := dbpath
	dbpath = tmpDir
	t.Cleanup(func() { dbpath = originalDbpath })

	victimDir := filepath.Join(tmpDir, "victim", "priv")
	if err := os.MkdirAll(victimDir, 0770); err != nil {
		t.Fatalf("seed failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(victimDir, "salt"), []byte("VICTIM-SALT"), 0644); err != nil {
		t.Fatalf("seed failed: %v", err)
	}
	return tmpDir
}
