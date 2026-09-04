package id1

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSinkHardeningAddRefusesScheduledCommandTarget - add() appends raw bytes and
// cannot pin the identity inside a scheduled command the way set() does, so it
// must refuse to write one at all.
func TestSinkHardeningAddRefusesScheduledCommandTarget(t *testing.T) {
	tmpDir := seedVictim(t)

	payload := []byte("set:/victim/pub/keys/default?x-id=victim\nATTACKER-KEY")
	_, err := NewCommand(Add, mustK(t, "mallory/.after.1"), map[string]string{"x-id": "mallory"}, payload).Exec()

	if !errors.Is(err, ErrForbidden) {
		t.Errorf("add() to a .after. name: got err=%v, want ErrForbidden", err)
	}
	if _, statErr := os.Stat(filepath.Join(tmpDir, "mallory", ".after.1")); statErr == nil {
		t.Errorf("SECURITY: add() planted a scheduled command file")
	}
}

// TestSinkHardeningMoveRefusesScheduledCommandDestination - move() renames an
// existing file the caller controls, so a .after. DESTINATION is the same plant
// by another route.
func TestSinkHardeningMoveRefusesScheduledCommandDestination(t *testing.T) {
	tmpDir := seedVictim(t)

	payload := []byte("set:/victim/pub/keys/default?x-id=victim\nATTACKER-KEY")
	if _, err := CmdSet(mustK(t, "mallory/payload"), map[string]string{"x-id": "mallory"}, payload).Exec(); err != nil {
		t.Fatalf("seed mallory/payload: %v", err)
	}

	_, err := NewCommand(Mov, mustK(t, "mallory/payload"), map[string]string{"x-id": "mallory"}, []byte("mallory/.after.1")).Exec()

	if !errors.Is(err, ErrForbidden) {
		t.Errorf("move() to a .after. destination: got err=%v, want ErrForbidden", err)
	}
	if _, statErr := os.Stat(filepath.Join(tmpDir, "mallory", ".after.1")); statErr == nil {
		t.Errorf("SECURITY: move() planted a scheduled command file")
	}
	if _, statErr := os.Stat(filepath.Join(tmpDir, "mallory", "payload")); statErr != nil {
		t.Errorf("a refused move must leave the source in place: %v", statErr)
	}
}

// TestSinkHardeningDelRefusesZeroSegmentKey - an empty key joins to dbpath
// itself, and del() on a directory is os.RemoveAll. This is the whole-store
// deletion primitive.
func TestSinkHardeningDelRefusesZeroSegmentKey(t *testing.T) {
	tmpDir := seedVictim(t)

	_, err := NewCommand(Del, mustK(t, ""), map[string]string{"x-id": ""}, []byte{}).Exec()

	if !errors.Is(err, ErrForbidden) {
		t.Errorf("del() with a zero-segment key: got err=%v, want ErrForbidden", err)
	}
	if _, statErr := os.Stat(tmpDir); statErr != nil {
		t.Fatalf("SECURITY: del() with an empty key removed the whole store: %v", statErr)
	}
	data, readErr := os.ReadFile(filepath.Join(tmpDir, "victim", "priv", "salt"))
	if readErr != nil {
		t.Errorf("SECURITY: the victim's file was destroyed: %v", readErr)
	} else if string(data) != "VICTIM-SALT" {
		t.Errorf("the victim's file was altered: %q", string(data))
	}
}

// TestSinkHardeningAddRefusesZeroSegmentKey - the same empty key at the append
// sink, which would otherwise target the store root itself.
func TestSinkHardeningAddRefusesZeroSegmentKey(t *testing.T) {
	seedVictim(t)

	_, err := NewCommand(Add, mustK(t, ""), map[string]string{"x-id": ""}, []byte("X")).Exec()

	if !errors.Is(err, ErrForbidden) {
		t.Errorf("add() with a zero-segment key: got err=%v, want ErrForbidden", err)
	}
}

// TestSinkHardeningMoveRefusesZeroSegmentSource - the same empty key as a move
// source.
func TestSinkHardeningMoveRefusesZeroSegmentSource(t *testing.T) {
	seedVictim(t)

	_, err := NewCommand(Mov, mustK(t, ""), map[string]string{"x-id": "mallory"}, []byte("mallory/stolen")).Exec()

	if !errors.Is(err, ErrForbidden) {
		t.Errorf("move() with a zero-segment source: got err=%v, want ErrForbidden", err)
	}
}

// TestSinkHardeningSetStillPinsScheduledCommand is the control. set() remains
// the ONE way to create a scheduled command, and it must still rewrite the
// stored command's identity to the caller's own. If this test ever fails, the
// pin has been lost and the refusals above are the only remaining defence.
func TestSinkHardeningSetStillPinsScheduledCommand(t *testing.T) {
	tmpDir := seedVictim(t)

	payload := []byte("del:/victim/priv/salt?x-id=victim\n")
	if _, err := CmdSet(mustK(t, "mallory/.after.1"), map[string]string{"x-id": "mallory"}, payload).Exec(); err != nil {
		t.Fatalf("set() to a .after. name must still be allowed: %v", err)
	}

	stored, readErr := os.ReadFile(filepath.Join(tmpDir, "mallory", ".after.1"))
	if readErr != nil {
		t.Fatalf("reading the stored scheduled command: %v", readErr)
	}
	if !strings.Contains(string(stored), "x-id=mallory") {
		t.Errorf("set() must pin the scheduled command's identity to the caller, stored=%q", string(stored))
	}
	if strings.Contains(string(stored), "x-id=victim") {
		t.Errorf("SECURITY: the stored scheduled command kept the forged identity, stored=%q", string(stored))
	}
}
