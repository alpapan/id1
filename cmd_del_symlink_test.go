package id1

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestDelSymlinkRefusesSymlinkEntryItself - del() must refuse a key naming a
// symlink entry directly, not only a key that traverses through one. See the
// comment in cmd_del.go's del() for why deleting the link itself is refused
// rather than treated as a safe unlink.
func TestDelSymlinkRefusesSymlinkEntryItself(t *testing.T) {
	store, outside := seedSymlinkStore(t)
	key := mustK(t, "mallory/escape")

	_, err := NewCommand(Del, key, map[string]string{"x-id": "mallory"}, []byte{}).Exec()
	if !errors.Is(err, ErrForbidden) {
		t.Errorf("del() on a symlink entry: got err=%v, want ErrForbidden", err)
	}
	info, lstatErr := os.Lstat(filepath.Join(store, "mallory", "escape"))
	if lstatErr != nil {
		t.Fatalf("SECURITY: del() removed the symlink entry: %v", lstatErr)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Errorf("symlink entry is no longer a symlink after del(): mode=%v", info.Mode())
	}
	data, readErr := os.ReadFile(filepath.Join(outside, "secret"))
	if readErr != nil {
		t.Errorf("SECURITY: the outside file vanished: %v", readErr)
	} else if string(data) != "OUTSIDE-SECRET" {
		t.Errorf("SECURITY: the outside file was altered: %q", string(data))
	}
}

// TestDelSymlinkRefusesThroughAbsoluteSymlink - del() must refuse a key that
// traverses through an absolute symlink to reach a file outside the store.
func TestDelSymlinkRefusesThroughAbsoluteSymlink(t *testing.T) {
	_, outside := seedSymlinkStore(t)
	key := mustK(t, "mallory/escape/secret")

	_, err := NewCommand(Del, key, map[string]string{"x-id": "mallory"}, []byte{}).Exec()
	if !errors.Is(err, ErrForbidden) {
		t.Errorf("del() through an absolute symlink: got err=%v, want ErrForbidden", err)
	}
	data, readErr := os.ReadFile(filepath.Join(outside, "secret"))
	if readErr != nil {
		t.Fatalf("SECURITY: the outside file vanished: %v", readErr)
	}
	if string(data) != "OUTSIDE-SECRET" {
		t.Errorf("SECURITY: the outside file was altered: %q", string(data))
	}
}

// TestDelSymlinkRefusesThroughRelativeSymlinkCrossNamespace - del() must
// refuse a key that traverses through a relative symlink to reach a
// different namespace still inside the store (the case a plain
// dbpath-prefix check would miss, per the measured os.Root behaviour that a
// relative in-store symlink is FOLLOWED unless explicitly guarded).
func TestDelSymlinkRefusesThroughRelativeSymlinkCrossNamespace(t *testing.T) {
	store, _ := seedSymlinkStore(t)
	key := mustK(t, "mallory/cross/priv/salt")

	_, err := NewCommand(Del, key, map[string]string{"x-id": "mallory"}, []byte{}).Exec()
	if !errors.Is(err, ErrForbidden) {
		t.Errorf("del() through a relative cross-namespace symlink: got err=%v, want ErrForbidden", err)
	}
	data, readErr := os.ReadFile(filepath.Join(store, "victim", "priv", "salt"))
	if readErr != nil {
		t.Fatalf("SECURITY: the victim's file vanished: %v", readErr)
	}
	if string(data) != "VICTIM-SALT" {
		t.Errorf("SECURITY: the victim's file was altered: %q", string(data))
	}
}

// TestDelSymlinkRefusesRelativeSymlinkEntryItself pins the same leaf-entry
// refusal for a RELATIVE symlink, not only the absolute one above.
func TestDelSymlinkRefusesRelativeSymlinkEntryItself(t *testing.T) {
	store, _ := seedSymlinkStore(t)
	key := mustK(t, "mallory/cross")

	_, err := NewCommand(Del, key, map[string]string{"x-id": "mallory"}, []byte{}).Exec()
	if !errors.Is(err, ErrForbidden) {
		t.Errorf("del() on a relative symlink entry: got err=%v, want ErrForbidden", err)
	}
	info, lstatErr := os.Lstat(filepath.Join(store, "mallory", "cross"))
	if lstatErr != nil {
		t.Fatalf("SECURITY: del() removed the symlink entry: %v", lstatErr)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Errorf("symlink entry is no longer a symlink after del(): mode=%v", info.Mode())
	}
}

// TestDelSymlinkAllowsLegitimateDelete is del()'s positive control for this
// change. Without it, replacing the symlink guard with an unconditional
// "return ErrForbidden" leaves every refusal test above passing, so the file
// would report green over a completely bricked del().
func TestDelSymlinkAllowsLegitimateDelete(t *testing.T) {
	store, _ := seedSymlinkStore(t)
	key := mustK(t, "mallory/own")

	if _, err := NewCommand(Del, key, map[string]string{"x-id": "mallory"}, []byte{}).Exec(); err != nil {
		t.Fatalf("del() refused a legitimate own-namespace key: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(store, "mallory", "own")); statErr == nil {
		t.Errorf("del() left the file in place")
	}
}

// TestDelSymlinkSkipsTtlBookkeepingRemovalWhenSymlink pins that del() applies
// the same no-symlink guard to the .ttl.<name> bookkeeping removal that it
// already applies to the main key. If a stray symlink sits at
// mallory/msg/.ttl.1, del() must not blindly unlink it - it must run
// pathIsSymlinkFree on that path too and skip the bookkeeping removal when it
// fails, while the main key delete still succeeds.
func TestDelSymlinkSkipsTtlBookkeepingRemovalWhenSymlink(t *testing.T) {
	store, outside := seedSymlinkStore(t)

	msgDir := filepath.Join(store, "mallory", "msg")
	if err := os.MkdirAll(msgDir, 0770); err != nil {
		t.Fatalf("seed msg dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(msgDir, "1"), []byte("scheduled"), 0644); err != nil {
		t.Fatalf("seed message file: %v", err)
	}
	ttlSymlink := filepath.Join(msgDir, ".ttl.1")
	if err := os.Symlink(outside, ttlSymlink); err != nil {
		t.Fatalf("seed ttl symlink: %v", err)
	}

	key := mustK(t, "mallory/msg/1")
	if _, err := NewCommand(Del, key, map[string]string{"x-id": "mallory"}, []byte{}).Exec(); err != nil {
		t.Fatalf("del() errored on a legitimate delete with a symlink at the ttl bookkeeping path: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(msgDir, "1")); statErr == nil {
		t.Errorf("del() left the message file in place")
	}
	info, lstatErr := os.Lstat(ttlSymlink)
	if lstatErr != nil {
		t.Fatalf("SECURITY: del() removed the symlink at the ttl bookkeeping path: %v", lstatErr)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Errorf("ttl bookkeeping entry is no longer a symlink after del(): mode=%v", info.Mode())
	}
}

// TestDelSymlinkStillRemovesTtlBookkeeping pins that the .ttl.<name>
// bookkeeping removal (built by raw string interpolation, not through K())
// still works once it is routed through the root handle instead of
// filepath.Join(dbpath, ...).
func TestDelSymlinkStillRemovesTtlBookkeeping(t *testing.T) {
	store, _ := seedSymlinkStore(t)

	msgDir := filepath.Join(store, "mallory", "msg")
	if err := os.MkdirAll(msgDir, 0770); err != nil {
		t.Fatalf("seed msg dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(msgDir, "1"), []byte("scheduled"), 0644); err != nil {
		t.Fatalf("seed message file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(msgDir, ".ttl.1"), []byte("del:/mallory/msg/1?x-id=mallory\n"), 0644); err != nil {
		t.Fatalf("seed ttl bookkeeping file: %v", err)
	}

	key := mustK(t, "mallory/msg/1")
	if _, err := NewCommand(Del, key, map[string]string{"x-id": "mallory"}, []byte{}).Exec(); err != nil {
		t.Fatalf("del() refused a legitimate delete with ttl bookkeeping present: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(msgDir, "1")); statErr == nil {
		t.Errorf("del() left the message file in place")
	}
	if _, statErr := os.Stat(filepath.Join(msgDir, ".ttl.1")); statErr == nil {
		t.Errorf("del() left the .ttl bookkeeping file in place")
	}
}
