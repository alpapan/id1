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
	expectedData := "..."

	// Set key with TTL
	_, err := NewCommand(Set, ttlKey, map[string]string{"ttl": "1", "x-id": "testda"}, []byte(expectedData)).Exec()
	if err != nil {
		t.Fatalf("Failed to set key with TTL: %v", err)
	}

	// Verify key was created with correct data
	data, err := CmdGet(ttlKey).Exec()
	if err != nil {
		t.Fatalf("Failed to retrieve key after creation: %v", err)
	}
	actualData := string(data)
	if actualData != expectedData {
		t.Fatalf("Key data mismatch after creation: expected %q, got %q", expectedData, actualData)
	}

	// Wait for TTL to expire with extra margin (1100ms instead of 1000ms)
	// to account for system clock precision and test execution overhead
	time.Sleep(1100 * time.Millisecond)

	// Run dotAfter to process expired TTLs
	dotAfter(dbpath)

	// After TTL expiry and dotAfter cleanup, the key should be gone
	_, errAfterDelete := CmdGet(ttlKey).Exec()
	if errAfterDelete == nil {
		t.Errorf("Expected TTL key to be deleted by dotAfter, but Get succeeded (key still exists)")
	}

	// The .ttl. metadata file should also be removed
	ttlMetaKey := K(fmt.Sprintf("%s/.ttl.%s", ttlKey.Parent, ttlKey.Name))
	_, errMetaDelete := CmdGet(ttlMetaKey).Exec()
	if errMetaDelete == nil {
		t.Errorf("Expected TTL metadata file %q to be deleted by dotAfter, but Get succeeded (file still exists)", ttlMetaKey.String())
	}
}
