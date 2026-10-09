// apps/backend/containers/id1/cmd_set.go
//
// group: server
// tags: storage, filesystem, set-operation
// summary: Set operation handler for updating key/value entries.
// Writes and overwrites data to filesystem with timestamp tracking.
//
//

package id1

import (
	"fmt"
	"log"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func (t *Command) set() error {
	if !keyWithinRoot(t.Key) {
		return ErrForbidden
	}
	// TTL bookkeeping is the scheduler's alone. A caller that could write it
	// could point an existing key's expiry at a schedule of its choosing.
	if isReservedTTLKey(t.Key) {
		return ErrForbidden
	}
	if !preflightChecks(t) {
		return fmt.Errorf("failed preflight checks")
	}

	root, err := openStoreRoot()
	if err != nil {
		return err
	}
	defer root.Close()

	rel := t.Key.String()
	if !pathIsSymlinkFree(root, rel) {
		return ErrForbidden
	}

	dir := filepath.Dir(rel)
	if err := root.MkdirAll(dir, 0770); err != nil {
		return err
	}
	if err := root.WriteFile(rel, t.Data, 0644); err != nil {
		return err
	} else {
		pubsub.Publish(t)
		createDotTtl(t)
		return nil
	}
}

func preflightChecks(cmd *Command) bool {
	if strings.HasPrefix(cmd.Key.Name, ".after.") {
		if dotAfterCmd, err := ParseCommand(cmd.Data); err != nil {
			return false
		} else {
			dotAfterCmd.Args["x-id"] = cmd.Args["x-id"]
			cmd.Data = dotAfterCmd.Bytes()
		}
	}
	return true
}

// dotTTLDir is the reserved directory that holds TTL bookkeeping. A pointer for
// the key {parent}/{name} lives at {parent}/.ttl/{name} and holds the key of the
// .after. schedule that will expire it.
//
// Nothing may be written anywhere beneath a segment of this name through set,
// add or mov. The scheduler is excluded by that rule too, which is why the two
// helpers below reach the file directly rather than through a command: the
// refusal then needs no exemption for anyone to misuse.
const dotTTLDir = ".ttl"

// isReservedTTLKey reports whether key names TTL bookkeeping, in either of the
// two reserved shapes: any key with a .ttl segment, which is the scheduler's
// directory and everything inside it, and any key whose final segment carries
// the flat .ttl. prefix the scheduler used before that directory existed.
//
// No writing operation accepts either shape, and there is no exemption. The
// scheduler is excluded as well and does not need one: it writes its pointer
// with writeTTLBookkeeping below, which never goes through a command.
func isReservedTTLKey(key Id1Key) bool {
	for _, segment := range key.Segments {
		if segment == dotTTLDir {
			return true
		}
	}
	return strings.HasPrefix(key.Name, dotTTLDir+".")
}

// writeTTLBookkeeping stores a pointer file, creating the reserved directory if
// this is the parent's first scheduled key. It goes through the same
// directory-scoped store handle and no-symlink guard as set().
func writeTTLBookkeeping(key Id1Key, data []byte) error {
	root, err := openStoreRoot()
	if err != nil {
		return err
	}
	defer root.Close()

	rel := key.String()
	if !pathIsSymlinkFree(root, rel) {
		return ErrForbidden
	}
	if err := root.MkdirAll(filepath.Dir(rel), 0770); err != nil {
		return err
	}
	return root.WriteFile(rel, data, 0644)
}

// readTTLBookkeeping returns a pointer file's contents, or an error when the key
// has no schedule. It goes through the same directory-scoped store handle and
// no-symlink guard as get().
func readTTLBookkeeping(key Id1Key) ([]byte, error) {
	root, err := openStoreRoot()
	if err != nil {
		return nil, err
	}
	defer root.Close()

	rel := key.String()
	if !pathIsSymlinkFree(root, rel) {
		return nil, ErrForbidden
	}
	return root.ReadFile(rel)
}

// {parent}/.ttl/{name} holds the .after.{timestamp} key, which holds the
// del:/{key} command that expires the key.
func createDotTtl(cmd *Command) {
	ttlSec, _ := strconv.Atoi(cmd.Args["ttl"])
	if ttlSec == 0 {
		return
	}
	if cmd.Key.Parent == "" {
		// A single-segment key (Id == Name, no parent) stores its value at
		// a path with no directory of its own: dbpath/<id> is a file, not
		// a directory. dot_after.go's containment check only accepts a
		// schedule sitting inside a directory named after the command's
		// target Id - for every other key shape that directory
		// is the key's own parent, a sibling location that already exists.
		// For a single-segment key the only directory containment would
		// accept is one named identically to the key's own value file,
		// which cannot be created (a nested write fails with "not a
		// directory") and cannot be nested at the store root either (the
		// store root has no owning namespace, so the sweep refuses it -
		// see dot_after.go's own containment comment). There is no
		// location that is both safe and writable, so ttl is a no-op on a
		// single-segment key: the set still succeeds, it just never
		// expires.
		log.Printf("createDotTtl: ttl is a no-op on single-segment key %s (no parent directory to nest the schedule under)", cmd.Key.String())
		return
	}
	ttdMs := time.Now().UnixMilli() + (int64(ttlSec) * 1000) //time to die in Ms
	ttlKey, err := KK(cmd.Key.Parent, dotTTLDir, cmd.Key.Name)
	if err != nil {
		log.Printf("createDotTtl: skipping TTL bookkeeping for %s: %v", cmd.Key.String(), err)
		return
	}
	dotAfterKey, err := KK(cmd.Key.Parent, fmt.Sprintf(".after.%d", ttdMs))
	if err != nil {
		log.Printf("createDotTtl: skipping TTL bookkeeping for %s: %v", cmd.Key.String(), err)
		return
	}

	if oldDotAfter, err := readTTLBookkeeping(ttlKey); err == nil {
		if oldKey, err := K(string(oldDotAfter)); err != nil {
			log.Printf("createDotTtl: skipping stale .after cleanup for %s: %v", cmd.Key.String(), err)
		} else {
			CmdDel(oldKey).Exec()
		}
	}

	dotAfterCommand := CmdDel(cmd.Key)
	dotAfterCommand.Args["x-id"] = cmd.Args["x-id"]
	if err := writeTTLBookkeeping(ttlKey, []byte(dotAfterKey.String())); err != nil {
		log.Printf("createDotTtl: skipping TTL bookkeeping for %s: %v", cmd.Key.String(), err)
		return
	}
	CmdSet(dotAfterKey, map[string]string{"x-id": cmd.Args["x-id"]}, dotAfterCommand.Bytes()).Exec()
}
