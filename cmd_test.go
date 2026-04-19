// apps/backend/containers/id1/cmd_test.go
//
// group: models
// tags: commands, operations, testing
// summary: Tests for command parsing and operation structures.
//
//

package id1

import (
	"fmt"
	"strings"
	"testing"
)

func TestCmdBytes(t *testing.T) {
	cmd := Command{
		Op:  Set,
		Key: KK("testid", "dir", "one"),
		Args: map[string]string{
			"ttl":  "5",
			"x-id": "admin",
		},
		Data: []byte("test data"),
	}
	expected := "set:/testid/dir/one?ttl=5&x-id=admin\ntest data"
	actual := string(cmd.Bytes())
	if actual != expected {
		t.Errorf("cmd.Bytes mismatch: expected %q, got %q", expected, actual)
	}
}

func TestParseCommand(t *testing.T) {
	cmdStr := "set:/max/msg/1731664334195180?ttl=600"
	cmdData := []byte("data...")
	cmd, err := ParseCommand(fmt.Appendf(nil, "%s\n%s", cmdStr, cmdData))

	if err != nil {
		t.Errorf("ParseCommand failed with error: %v", err)
	}
	if cmd.Op != Set {
		t.Errorf("Operation mismatch: expected %v, got %v", Set, cmd.Op)
	}
	expectedKey := "max/msg/1731664334195180"
	if cmd.Key.String() != expectedKey {
		t.Errorf("Key mismatch: expected %q, got %q", expectedKey, cmd.Key.String())
	}
	if cmd.Args["ttl"] != "600" {
		t.Errorf("TTL mismatch: expected %q, got %q", "600", cmd.Args["ttl"])
	}
	expectedData := "data..."
	if string(cmd.Data) != expectedData {
		t.Errorf("Data mismatch: expected %q, got %q", expectedData, string(cmd.Data))
	}
	if cmd.String() != cmdStr {
		t.Errorf("String representation mismatch: expected %q, got %q", cmdStr, cmd.String())
	}
}

func TestCommandSet(t *testing.T) {
	tmpDir := t.TempDir()
	originalDbpath := dbpath
	dbpath = tmpDir
	t.Cleanup(func() { dbpath = originalDbpath })
	testKey := KK("test", "set_single")
	NewCommand(Del, testKey, map[string]string{}, []byte{}).Exec()

	_, err := NewCommand(Set, testKey, map[string]string{}, []byte("1")).Exec()
	if err != nil {
		t.Errorf("Set command failed: %v", err)
	}
}

func TestCommandGet(t *testing.T) {
	tmpDir := t.TempDir()
	originalDbpath := dbpath
	dbpath = tmpDir
	t.Cleanup(func() { dbpath = originalDbpath })
	testKey := KK("test", "get_single")
	NewCommand(Del, testKey, map[string]string{}, []byte{}).Exec()

	// Setup: Set a value first
	_, err := NewCommand(Set, testKey, map[string]string{}, []byte("test_value")).Exec()
	if err != nil {
		t.Fatalf("Setup failed: Set command returned error: %v", err)
	}

	// Test Get retrieves the value
	data, err := NewCommand(Get, testKey, map[string]string{}, []byte{}).Exec()
	if err != nil {
		t.Errorf("Get command failed: %v", err)
		return
	}
	expected := "test_value"
	if string(data) != expected {
		t.Errorf("Get value mismatch: expected %q, got %q", expected, string(data))
	}
}

func TestCommandUpdate(t *testing.T) {
	tmpDir := t.TempDir()
	originalDbpath := dbpath
	dbpath = tmpDir
	t.Cleanup(func() { dbpath = originalDbpath })
	testKey := KK("test", "update_single")
	NewCommand(Del, testKey, map[string]string{}, []byte{}).Exec()

	// Setup: Set initial value
	_, err := NewCommand(Set, testKey, map[string]string{}, []byte("original")).Exec()
	if err != nil {
		t.Fatalf("Setup failed: initial Set returned error: %v", err)
	}

	// Test: Update with new value
	_, err = NewCommand(Set, testKey, map[string]string{}, []byte("updated")).Exec()
	if err != nil {
		t.Errorf("Update (Set) command failed: %v", err)
		return
	}

	// Verify: Get should return updated value
	data, err := NewCommand(Get, testKey, map[string]string{}, []byte{}).Exec()
	if err != nil {
		t.Errorf("Get after update failed: %v", err)
		return
	}
	expected := "updated"
	if string(data) != expected {
		t.Errorf("Updated value mismatch: expected %q, got %q", expected, string(data))
	}
}

func TestCommandDelete(t *testing.T) {
	tmpDir := t.TempDir()
	originalDbpath := dbpath
	dbpath = tmpDir
	t.Cleanup(func() { dbpath = originalDbpath })
	testKey := KK("test", "delete_single")
	NewCommand(Del, testKey, map[string]string{}, []byte{}).Exec()

	// Setup: Set a value
	_, err := NewCommand(Set, testKey, map[string]string{}, []byte("to_delete")).Exec()
	if err != nil {
		t.Fatalf("Setup failed: Set returned error: %v", err)
	}

	// Test: Delete the key
	_, err = NewCommand(Del, testKey, map[string]string{}, []byte{}).Exec()
	if err != nil {
		t.Errorf("Delete command failed: %v", err)
		return
	}

	// Verify: Get should fail after delete
	data, err := NewCommand(Get, testKey, map[string]string{}, []byte{}).Exec()
	if err == nil {
		t.Errorf("Expected Get to fail after Delete, but succeeded with data: %q", string(data))
	}
}

func TestCommandMove(t *testing.T) {
	tmpDir := t.TempDir()
	originalDbpath := dbpath
	dbpath = tmpDir
	t.Cleanup(func() { dbpath = originalDbpath })
	testKey := KK("test", "move_source")
	testKeyTgt := KK("test", "move_target")
	CmdDel(testKeyTgt).Exec()

	// Setup: Set value at source location
	_, err := NewCommand(Set, testKey, map[string]string{}, []byte("move_data")).Exec()
	if err != nil {
		t.Fatalf("Setup failed: Set at source returned error: %v", err)
	}

	// Test: Move the key to target location
	_, err = NewCommand(Mov, testKey, map[string]string{"x-id": "test"}, []byte(testKeyTgt.String())).Exec()
	if err != nil {
		t.Errorf("Move command failed: %v", err)
		return
	}

	// Verify: Source location should be empty (deleted)
	_, errSource := NewCommand(Get, testKey, map[string]string{}, []byte{}).Exec()
	if errSource == nil {
		t.Errorf("Expected source key to be deleted after Move, but Get succeeded")
	}

	// Verify: Target location should contain the data
	dataTarget, errTarget := NewCommand(Get, testKeyTgt, map[string]string{}, []byte{}).Exec()
	if errTarget != nil {
		t.Errorf("Get target after Move failed: %v", errTarget)
		return
	}
	expected := "move_data"
	if string(dataTarget) != expected {
		t.Errorf("Target data mismatch after Move: expected %q, got %q", expected, string(dataTarget))
	}
}

func TestCommandListNonRecursive(t *testing.T) {
	tmpDir := t.TempDir()
	originalDbpath := dbpath
	dbpath = tmpDir
	t.Cleanup(func() { dbpath = originalDbpath })

	// Setup
	id := "test_list_nr"
	idKey := K(id)
	NewCommand(Del, idKey, map[string]string{}, []byte{}).Exec()
	NewCommand(Set, KK(id, "one"), map[string]string{}, []byte("1")).Exec()
	NewCommand(Set, KK(id, "two"), map[string]string{}, []byte("22")).Exec()
	NewCommand(Set, KK(id, "three"), map[string]string{}, []byte("333")).Exec()
	NewCommand(Set, K("test_list_nr/sub/one"), map[string]string{}, []byte("sub/1")).Exec()

	// Test: List without recursive flag should return only direct children
	data, err := NewCommand(List, idKey, map[string]string{}, []byte{}).Exec()
	if err != nil {
		t.Errorf("List command failed: %v", err)
		return
	}

	lines := strings.Split(string(data), "\n")
	expectedCount := 3 // one, two, three (not sub/one)
	if len(lines) != expectedCount {
		t.Errorf("List item count mismatch: expected %d items, got %d. Data: %s", expectedCount, len(lines), string(data))
	}
}

func TestCommandListRecursive(t *testing.T) {
	tmpDir := t.TempDir()
	originalDbpath := dbpath
	dbpath = tmpDir
	t.Cleanup(func() { dbpath = originalDbpath })

	// Setup
	id := "test_list_rec"
	idKey := K(id)
	NewCommand(Del, idKey, map[string]string{}, []byte{}).Exec()
	NewCommand(Set, KK(id, "one"), map[string]string{}, []byte("1")).Exec()
	NewCommand(Set, KK(id, "two"), map[string]string{}, []byte("22")).Exec()
	NewCommand(Set, KK(id, "three"), map[string]string{}, []byte("333")).Exec()
	NewCommand(Set, K("test_list_rec/sub/one"), map[string]string{}, []byte("sub/1")).Exec()

	// Test: List with recursive flag should return all descendants
	data, err := NewCommand(List, idKey, map[string]string{"recursive": "true"}, []byte{}).Exec()
	if err != nil {
		t.Errorf("List recursive command failed: %v", err)
		return
	}

	lines := strings.Split(string(data), "\n")
	expectedCount := 4 // one, two, three, sub/one
	if len(lines) != expectedCount {
		t.Errorf("List recursive item count mismatch: expected %d items, got %d. Data: %s", expectedCount, len(lines), string(data))
	}
}

func TestCommandListWithLimit(t *testing.T) {
	tmpDir := t.TempDir()
	originalDbpath := dbpath
	dbpath = tmpDir
	t.Cleanup(func() { dbpath = originalDbpath })

	// Setup
	id := "test_list_lim"
	idKey := K(id)
	NewCommand(Del, idKey, map[string]string{}, []byte{}).Exec()
	NewCommand(Set, KK(id, "one"), map[string]string{}, []byte("1")).Exec()
	NewCommand(Set, KK(id, "two"), map[string]string{}, []byte("22")).Exec()
	NewCommand(Set, KK(id, "three"), map[string]string{}, []byte("333")).Exec()

	// Test: List with limit should return only specified number of items
	data, err := NewCommand(List, idKey, map[string]string{"limit": "2"}, []byte{}).Exec()
	if err != nil {
		t.Errorf("List with limit command failed: %v", err)
		return
	}

	lines := strings.Split(string(data), "\n")
	expectedCount := 2
	if len(lines) != expectedCount {
		t.Errorf("List limit item count mismatch: expected %d items, got %d. Data: %s", expectedCount, len(lines), string(data))
	}
}

func TestCommandListKeysOnly(t *testing.T) {
	tmpDir := t.TempDir()
	originalDbpath := dbpath
	dbpath = tmpDir
	t.Cleanup(func() { dbpath = originalDbpath })

	// Setup
	id := "test_list_keys"
	idKey := K(id)
	NewCommand(Del, idKey, map[string]string{}, []byte{}).Exec()
	NewCommand(Set, KK(id, "one"), map[string]string{}, []byte("1")).Exec()
	NewCommand(Set, KK(id, "two"), map[string]string{}, []byte("22")).Exec()
	NewCommand(Set, KK(id, "three"), map[string]string{}, []byte("333")).Exec()

	// Test: List with keys=true should return only key names, not data
	data, err := NewCommand(List, idKey, map[string]string{"keys": "true"}, []byte{}).Exec()
	if err != nil {
		t.Errorf("List keys-only command failed: %v", err)
		return
	}

	dataStr := string(data)
	if strings.Contains(dataStr, "22") {
		t.Errorf("List keys-only should not contain data values. Got: %s", dataStr)
	}
}

func TestCommandListWithSizeLimit(t *testing.T) {
	tmpDir := t.TempDir()
	originalDbpath := dbpath
	dbpath = tmpDir
	t.Cleanup(func() { dbpath = originalDbpath })

	// Setup
	id := "test_list_size"
	idKey := K(id)
	NewCommand(Del, idKey, map[string]string{}, []byte{}).Exec()
	NewCommand(Set, KK(id, "one"), map[string]string{}, []byte("1")).Exec()
	NewCommand(Set, KK(id, "two"), map[string]string{}, []byte("22")).Exec()
	NewCommand(Set, KK(id, "three"), map[string]string{}, []byte("333")).Exec()

	// Test: List with size-limit should exclude items exceeding size
	data, err := NewCommand(List, idKey, map[string]string{"size-limit": "1"}, []byte{}).Exec()
	if err != nil {
		t.Errorf("List with size-limit command failed: %v", err)
		return
	}

	dataStr := string(data)
	if strings.Contains(dataStr, "22") {
		t.Errorf("List with size-limit=1 should not contain data larger than 1 byte. Got: %s", dataStr)
	}
}

func TestMoveRejectsCrossUserDestination(t *testing.T) {
	tmpDir := t.TempDir()
	originalDbpath := dbpath
	dbpath = tmpDir
	t.Cleanup(func() { dbpath = originalDbpath })

	// Setup: user "alice" has a file (Set auto-creates parent dirs via MkdirAll)
	srcKey := KK("alice", "priv", "myfile")
	_, err := NewCommand(Set, srcKey, map[string]string{"x-id": "alice"}, []byte("secret")).Exec()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Attempt: move alice's file to bob's directory — must be rejected
	cmd := NewCommand(Mov, srcKey, map[string]string{"x-id": "alice"}, []byte("bob/priv/stolen"))
	_, err = cmd.Exec()
	if err == nil {
		t.Errorf("Move to another user's directory should be rejected, but succeeded")
	}
}

func TestMoveRejectsCrossUserViaRelativePath(t *testing.T) {
	// Regression test: "alice/../bob/file" normalizes to "bob/file" but
	// a naive ownership check on the unnormalized string sees "alice".
	tmpDir := t.TempDir()
	originalDbpath := dbpath
	dbpath = tmpDir
	t.Cleanup(func() { dbpath = originalDbpath })

	srcKey := KK("alice", "priv", "myfile")
	_, err := NewCommand(Set, srcKey, map[string]string{"x-id": "alice"}, []byte("data")).Exec()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Attempt: bypass ownership via relative path that normalizes to bob's dir
	cmd := NewCommand(Mov, srcKey, map[string]string{"x-id": "alice"}, []byte("alice/../bob/priv/stolen"))
	_, err = cmd.Exec()
	if err == nil {
		t.Errorf("Move via alice/../bob/... should be rejected after normalization, but succeeded")
	}
}

func TestMoveRejectsPathTraversal(t *testing.T) {
	tmpDir := t.TempDir()
	originalDbpath := dbpath
	dbpath = tmpDir
	t.Cleanup(func() { dbpath = originalDbpath })

	srcKey := KK("alice", "priv", "myfile")
	_, err := NewCommand(Set, srcKey, map[string]string{"x-id": "alice"}, []byte("data")).Exec()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Attempt: escape the KV store root via ..
	cmd := NewCommand(Mov, srcKey, map[string]string{"x-id": "alice"}, []byte("../../../etc/evil"))
	_, err = cmd.Exec()
	if err == nil {
		t.Errorf("Move with path traversal should be rejected, but succeeded")
	}
}

func TestMoveRejectsEmptyXId(t *testing.T) {
	// Defense-in-depth: even if the auth layer is bypassed, an empty x-id
	// must not allow unrestricted moves.
	tmpDir := t.TempDir()
	originalDbpath := dbpath
	dbpath = tmpDir
	t.Cleanup(func() { dbpath = originalDbpath })

	srcKey := KK("alice", "priv", "myfile")
	_, err := NewCommand(Set, srcKey, map[string]string{"x-id": ""}, []byte("data")).Exec()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	cmd := NewCommand(Mov, srcKey, map[string]string{"x-id": ""}, []byte("alice/priv/renamed"))
	_, err = cmd.Exec()
	if err == nil {
		t.Errorf("Move with empty x-id should be rejected for defense-in-depth, but succeeded")
	}
}

func TestMoveAllowsSameUserDestination(t *testing.T) {
	tmpDir := t.TempDir()
	originalDbpath := dbpath
	dbpath = tmpDir
	t.Cleanup(func() { dbpath = originalDbpath })

	// Setup: user "alice" has a file (Set auto-creates parent dirs via MkdirAll)
	srcKey := KK("alice", "priv", "myfile")
	_, err := NewCommand(Set, srcKey, map[string]string{"x-id": "alice"}, []byte("data")).Exec()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Move within alice's own directory should succeed
	cmd := NewCommand(Mov, srcKey, map[string]string{"x-id": "alice"}, []byte("alice/priv/renamed"))
	_, err = cmd.Exec()
	if err != nil {
		t.Errorf("Move within same user's directory should succeed, got: %v", err)
	}

	// Verify the data moved
	data, err := NewCommand(Get, KK("alice", "priv", "renamed"), map[string]string{}, []byte{}).Exec()
	if err != nil {
		t.Errorf("Get moved file failed: %v", err)
	} else if string(data) != "data" {
		t.Errorf("Moved data mismatch: expected %q, got %q", "data", string(data))
	}
}
