package id1

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// hostileKey and seedVictim are shared containment-test helpers defined once
// in k_helpers_test.go, not here - see that file's comments for why they
// live there. The positive controls below use mustK (also in
// k_helpers_test.go) to build a legitimate key through K(), the real
// constructor, so each one exercises exactly the path a genuine caller
// takes - a failure there means K() refused a key this file asserts is
// valid, which is a defect in the test's own premise, not in the guard.

// TestSinkContainmentSetRefusesTraversal - set() must refuse a hostile key.
func TestSinkContainmentSetRefusesTraversal(t *testing.T) {
	tmpDir := seedVictim(t)
	key := hostileKey(t, "mallory", "..", "victim", "priv", "planted")

	_, err := NewCommand(Set, key, map[string]string{"x-id": "mallory"}, []byte("PLANTED")).Exec()
	if !errors.Is(err, ErrForbidden) {
		t.Errorf("set() with a traversal key: got err=%v, want ErrForbidden", err)
	}
	if _, statErr := os.Stat(filepath.Join(tmpDir, "victim", "priv", "planted")); statErr == nil {
		t.Errorf("set() planted a file in the victim namespace")
	}
}

// TestSinkContainmentSetAllowsLegitimateKey is set()'s positive control. Without
// it, replacing set()'s guard with an unconditional "return ErrForbidden" leaves
// every other case in this file passing, so the file would report green over a
// completely bricked operation.
func TestSinkContainmentSetAllowsLegitimateKey(t *testing.T) {
	tmpDir := seedVictim(t)
	key := mustK(t, "mallory/msg/hello")

	if _, err := NewCommand(Set, key, map[string]string{"x-id": "mallory"}, []byte("HELLO")).Exec(); err != nil {
		t.Fatalf("set() refused a legitimate own-namespace key: %v", err)
	}
	data, readErr := os.ReadFile(filepath.Join(tmpDir, "mallory", "msg", "hello"))
	if readErr != nil {
		t.Fatalf("set() did not write the file: %v", readErr)
	}
	if string(data) != "HELLO" {
		t.Errorf("set() wrote %q, want \"HELLO\"", string(data))
	}
}

// TestSinkContainmentAddRefusesTraversal - add() must refuse a hostile key.
func TestSinkContainmentAddRefusesTraversal(t *testing.T) {
	tmpDir := seedVictim(t)
	key := hostileKey(t, "mallory", "..", "victim", "priv", "salt")

	_, err := NewCommand(Add, key, map[string]string{"x-id": "mallory"}, []byte("APPENDED")).Exec()
	if !errors.Is(err, ErrForbidden) {
		t.Errorf("add() with a traversal key: got err=%v, want ErrForbidden", err)
	}
	data, readErr := os.ReadFile(filepath.Join(tmpDir, "victim", "priv", "salt"))
	if readErr != nil {
		t.Fatalf("victim file vanished: %v", readErr)
	}
	if string(data) != "VICTIM-SALT" {
		t.Errorf("add() corrupted the victim's file: got %q", string(data))
	}
}

// TestSinkContainmentAddAllowsLegitimateKey is add()'s positive control. The
// second append also pins that add() still appends rather than truncates.
func TestSinkContainmentAddAllowsLegitimateKey(t *testing.T) {
	tmpDir := seedVictim(t)
	key := mustK(t, "mallory/msg/log")

	if _, err := NewCommand(Add, key, map[string]string{"x-id": "mallory"}, []byte("FIRST")).Exec(); err != nil {
		t.Fatalf("add() refused a legitimate own-namespace key: %v", err)
	}
	if _, err := NewCommand(Add, key, map[string]string{"x-id": "mallory"}, []byte("-SECOND")).Exec(); err != nil {
		t.Fatalf("add() refused a legitimate own-namespace key on the second append: %v", err)
	}
	data, readErr := os.ReadFile(filepath.Join(tmpDir, "mallory", "msg", "log"))
	if readErr != nil {
		t.Fatalf("add() did not write the file: %v", readErr)
	}
	if string(data) != "FIRST-SECOND" {
		t.Errorf("add() wrote %q, want \"FIRST-SECOND\"", string(data))
	}
}

// TestSinkContainmentListRefusesTraversal - list() must refuse a hostile key.
// This is the read-side hole: list() returns file CONTENTS, so an unguarded
// list is a bulk read of another namespace.
func TestSinkContainmentListRefusesTraversal(t *testing.T) {
	seedVictim(t)
	key := hostileKey(t, "mallory", "..", "victim", "priv")

	data, err := NewCommand(List, key, map[string]string{"x-id": "mallory"}, []byte{}).Exec()
	if !errors.Is(err, ErrForbidden) {
		t.Errorf("list() with a traversal key: got err=%v, want ErrForbidden", err)
	}
	if len(data) != 0 {
		t.Errorf("list() returned victim bytes: %q", string(data))
	}
}

// TestSinkContainmentListAllowsLegitimateKey is list()'s positive control. It
// lists a directory in the caller's own namespace with no trailing star, so it
// stays true regardless of how the trailing-star strip is later reordered.
func TestSinkContainmentListAllowsLegitimateKey(t *testing.T) {
	seedVictim(t)

	if _, err := NewCommand(Set, mustK(t, "mallory/msg/hello"), map[string]string{"x-id": "mallory"}, []byte("HELLO")).Exec(); err != nil {
		t.Fatalf("seeding mallory/msg/hello failed: %v", err)
	}

	data, err := NewCommand(List, mustK(t, "mallory/msg"), map[string]string{"x-id": "mallory"}, []byte{}).Exec()
	if err != nil {
		t.Fatalf("list() refused a legitimate own-namespace key: %v", err)
	}
	if !strings.Contains(string(data), "mallory/msg/hello=") {
		t.Errorf("list() lost its own entry: %q", string(data))
	}
}

// TestSinkContainmentMoveRefusesTraversalSource - move() guards its
// destination today but not its source, so an attacker could name a victim
// file as the SOURCE and a legitimate own-namespace path as the destination,
// stealing the file and destroying the victim's copy in one call.
func TestSinkContainmentMoveRefusesTraversalSource(t *testing.T) {
	tmpDir := seedVictim(t)
	src := hostileKey(t, "mallory", "..", "victim", "priv", "salt")

	_, err := NewCommand(Mov, src, map[string]string{"x-id": "mallory"}, []byte("mallory/stolen")).Exec()
	if !errors.Is(err, ErrForbidden) {
		t.Errorf("move() with a traversal SOURCE: got err=%v, want ErrForbidden", err)
	}
	if _, statErr := os.Stat(filepath.Join(tmpDir, "mallory", "stolen")); statErr == nil {
		t.Errorf("move() stole the victim's file into the attacker namespace")
	}
	data, readErr := os.ReadFile(filepath.Join(tmpDir, "victim", "priv", "salt"))
	if readErr != nil {
		t.Errorf("move() destroyed the victim's file: %v", readErr)
	} else if string(data) != "VICTIM-SALT" {
		t.Errorf("victim's file altered: got %q", string(data))
	}
}

// TestSinkContainmentMoveAllowsLegitimateOwnNamespaceMove is move()'s positive
// control: a move whose source AND destination are both inside the caller's own
// namespace must still succeed, leaving the source gone and the destination
// holding the moved bytes.
func TestSinkContainmentMoveAllowsLegitimateOwnNamespaceMove(t *testing.T) {
	tmpDir := seedVictim(t)
	src := mustK(t, "mallory/msg/hello")

	if _, err := NewCommand(Set, src, map[string]string{"x-id": "mallory"}, []byte("MOVE-ME")).Exec(); err != nil {
		t.Fatalf("seeding mallory/msg/hello failed: %v", err)
	}

	if _, err := NewCommand(Mov, src, map[string]string{"x-id": "mallory"}, []byte("mallory/archive/hello")).Exec(); err != nil {
		t.Fatalf("move() refused a legitimate own-namespace move: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(tmpDir, "mallory", "msg", "hello")); statErr == nil {
		t.Errorf("move() left the source file in place")
	}
	data, readErr := os.ReadFile(filepath.Join(tmpDir, "mallory", "archive", "hello"))
	if readErr != nil {
		t.Fatalf("move() did not create the destination file: %v", readErr)
	}
	if string(data) != "MOVE-ME" {
		t.Errorf("move() destination holds %q, want \"MOVE-ME\"", string(data))
	}
}

// TestSinkContainmentGetDelStillGuarded pins the two operations that were
// already correct, so this change cannot silently remove their guard.
func TestSinkContainmentGetDelStillGuarded(t *testing.T) {
	seedVictim(t)
	key := hostileKey(t, "mallory", "..", "victim", "priv", "salt")

	if _, err := NewCommand(Get, key, map[string]string{"x-id": "mallory"}, []byte{}).Exec(); !errors.Is(err, ErrForbidden) {
		t.Errorf("get() must still refuse a traversal key: got err=%v", err)
	}
	if _, err := NewCommand(Del, key, map[string]string{"x-id": "mallory"}, []byte{}).Exec(); !errors.Is(err, ErrForbidden) {
		t.Errorf("del() must still refuse a traversal key: got err=%v", err)
	}
}
