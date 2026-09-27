package id1

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestMoveSymlinkRefusesSourceEntryItself - move() must refuse a SOURCE key
// naming a symlink entry directly, for the same reason del() does: id1 never
// plants a symlink as data, so treating "the key names a symlink" as unsafe
// uniformly across every sink costs no real functionality.
func TestMoveSymlinkRefusesSourceEntryItself(t *testing.T) {
	store, outside := seedSymlinkStore(t)
	src := mustK(t, "mallory/escape")

	_, err := NewCommand(Mov, src, map[string]string{"x-id": "mallory"}, []byte("mallory/dest")).Exec()
	if !errors.Is(err, ErrForbidden) {
		t.Errorf("move() with a symlink SOURCE entry: got err=%v, want ErrForbidden", err)
	}
	info, lstatErr := os.Lstat(filepath.Join(store, "mallory", "escape"))
	if lstatErr != nil {
		t.Fatalf("SECURITY: move() removed the symlink entry: %v", lstatErr)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Errorf("symlink entry is no longer a symlink after move(): mode=%v", info.Mode())
	}
	if _, statErr := os.Stat(filepath.Join(store, "mallory", "dest")); statErr == nil {
		t.Errorf("SECURITY: move() created a destination from a refused symlink source")
	}
	data, readErr := os.ReadFile(filepath.Join(outside, "secret"))
	if readErr != nil {
		t.Errorf("SECURITY: the outside file vanished: %v", readErr)
	} else if string(data) != "OUTSIDE-SECRET" {
		t.Errorf("SECURITY: the outside file was altered: %q", string(data))
	}
}

// TestMoveSymlinkRefusesThroughAbsoluteSymlinkSource - move() must refuse a
// SOURCE key that traverses through an absolute symlink to reach a file
// outside the store.
func TestMoveSymlinkRefusesThroughAbsoluteSymlinkSource(t *testing.T) {
	store, outside := seedSymlinkStore(t)
	src := mustK(t, "mallory/escape/secret")

	_, err := NewCommand(Mov, src, map[string]string{"x-id": "mallory"}, []byte("mallory/dest")).Exec()
	if !errors.Is(err, ErrForbidden) {
		t.Errorf("move() through an absolute symlink SOURCE: got err=%v, want ErrForbidden", err)
	}
	data, readErr := os.ReadFile(filepath.Join(outside, "secret"))
	if readErr != nil {
		t.Fatalf("SECURITY: the outside file vanished: %v", readErr)
	}
	if string(data) != "OUTSIDE-SECRET" {
		t.Errorf("SECURITY: the outside file was altered: %q", string(data))
	}
	if _, statErr := os.Stat(filepath.Join(store, "mallory", "dest")); statErr == nil {
		t.Errorf("SECURITY: move() created a destination from a refused symlink source")
	}
}

// TestMoveSymlinkRefusesThroughRelativeSymlinkSourceCrossNamespace - move()
// must refuse a SOURCE key that traverses through a relative symlink to
// steal a different namespace's file, still inside the store (the exact
// cross-namespace hole the owner's ruling names: os.Root FOLLOWS a relative
// in-store symlink unless explicitly guarded).
func TestMoveSymlinkRefusesThroughRelativeSymlinkSourceCrossNamespace(t *testing.T) {
	store, _ := seedSymlinkStore(t)
	src := mustK(t, "mallory/cross/priv/salt")

	_, err := NewCommand(Mov, src, map[string]string{"x-id": "mallory"}, []byte("mallory/stolen")).Exec()
	if !errors.Is(err, ErrForbidden) {
		t.Errorf("move() through a relative cross-namespace symlink SOURCE: got err=%v, want ErrForbidden", err)
	}
	data, readErr := os.ReadFile(filepath.Join(store, "victim", "priv", "salt"))
	if readErr != nil {
		t.Fatalf("SECURITY: the victim's file vanished: %v", readErr)
	}
	if string(data) != "VICTIM-SALT" {
		t.Errorf("SECURITY: the victim's file was altered: %q", string(data))
	}
	if _, statErr := os.Stat(filepath.Join(store, "mallory", "stolen")); statErr == nil {
		t.Errorf("SECURITY: move() stole the victim's file into the attacker namespace")
	}
}

// TestMoveSymlinkRefusesDestinationThroughSymlink - move() must refuse a
// legitimate SOURCE when the DESTINATION traverses through a symlink,
// because the same os.Root cross-namespace and escape holes apply to
// writing a destination as to reading a source.
func TestMoveSymlinkRefusesDestinationThroughSymlink(t *testing.T) {
	store, outside := seedSymlinkStore(t)
	src := mustK(t, "mallory/own")

	_, err := NewCommand(Mov, src, map[string]string{"x-id": "mallory"}, []byte("mallory/escape/planted")).Exec()
	if !errors.Is(err, ErrForbidden) {
		t.Errorf("move() with a DESTINATION through a symlink: got err=%v, want ErrForbidden", err)
	}
	if _, statErr := os.Stat(filepath.Join(store, "mallory", "own")); statErr != nil {
		t.Errorf("a refused move must leave the source in place: %v", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(outside, "planted")); statErr == nil {
		t.Errorf("SECURITY: move() planted a file outside the store through the destination symlink")
	}
}

// TestMoveSymlinkRefusesDestinationEntryItself - move() must refuse
// overwriting a symlink entry named directly as the destination.
func TestMoveSymlinkRefusesDestinationEntryItself(t *testing.T) {
	store, _ := seedSymlinkStore(t)
	src := mustK(t, "mallory/own")

	_, err := NewCommand(Mov, src, map[string]string{"x-id": "mallory"}, []byte("mallory/escape")).Exec()
	if !errors.Is(err, ErrForbidden) {
		t.Errorf("move() onto a symlink DESTINATION entry: got err=%v, want ErrForbidden", err)
	}
	if _, statErr := os.Stat(filepath.Join(store, "mallory", "own")); statErr != nil {
		t.Errorf("a refused move must leave the source in place: %v", statErr)
	}
	info, lstatErr := os.Lstat(filepath.Join(store, "mallory", "escape"))
	if lstatErr != nil {
		t.Fatalf("SECURITY: move() removed the symlink entry: %v", lstatErr)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Errorf("destination symlink entry is no longer a symlink after move(): mode=%v", info.Mode())
	}
}

// TestMoveSymlinkAllowsLegitimateSameNamespaceMove is move()'s positive
// control for this change. Without it, replacing the symlink guard with an
// unconditional "return ErrForbidden" leaves every refusal test above
// passing, so the file would report green over a completely bricked move().
func TestMoveSymlinkAllowsLegitimateSameNamespaceMove(t *testing.T) {
	store, _ := seedSymlinkStore(t)
	src := mustK(t, "mallory/own")

	if _, err := NewCommand(Mov, src, map[string]string{"x-id": "mallory"}, []byte("mallory/archive/own")).Exec(); err != nil {
		t.Fatalf("move() refused a legitimate own-namespace move: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(store, "mallory", "own")); statErr == nil {
		t.Errorf("move() left the source file in place")
	}
	data, readErr := os.ReadFile(filepath.Join(store, "mallory", "archive", "own"))
	if readErr != nil {
		t.Fatalf("move() did not create the destination file: %v", readErr)
	}
	if string(data) != "MALLORY-OWN" {
		t.Errorf("move() destination holds %q, want \"MALLORY-OWN\"", string(data))
	}
}
