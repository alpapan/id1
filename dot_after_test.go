package id1

import (
	"fmt"
	"testing"
	"time"
)

func TestDotAfter(t *testing.T) {
	// Isolate test with temporary directory to prevent interference from global dbpath state
	tmpDir := t.TempDir()
	originalDbpath := dbpath
	dbpath = tmpDir
	t.Cleanup(func() { dbpath = originalDbpath })

	ttlKey := K("testda/1sec/qqqqbbbb")
	_, err := NewCommand(Set, ttlKey, map[string]string{"ttl": "1", "x-id": "testda"}, []byte("...")).Exec()
	if err != nil {
		t.Fatalf("failed to set key with TTL: %v", err)
	}

	// Verify key was created
	data, err := CmdGet(ttlKey).Exec()
	if err != nil || string(data) != "..." {
		t.Fatalf("failed to verify key creation: got err=%v, data=%q", err, string(data))
	}

	// Wait for TTL to expire with extra margin (1100ms instead of 1000ms)
	// to account for system clock precision and test execution overhead
	time.Sleep(1100 * time.Millisecond)

	// Run dotAfter to process expired TTLs
	dotAfter(dbpath)

	// After TTL expiry and dotAfter cleanup, the key should be gone
	if _, err := CmdGet(ttlKey).Exec(); err == nil {
		t.Errorf("expected ttlKey to be deleted by dotAfter, but it still exists")
	}

	// The .ttl. metadata file should also be removed
	ttlMetaKey := K(fmt.Sprintf("%s/.ttl.%s", ttlKey.Parent, ttlKey.Name))
	if _, err := CmdGet(ttlMetaKey).Exec(); err == nil {
		t.Errorf("expected .ttl.%s metadata to be deleted by dotAfter, but it still exists", ttlKey.Name)
	}
}
