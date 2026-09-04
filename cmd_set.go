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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func (t *Command) set() error {
	if !keyWithinRoot(t.Key) {
		return ErrForbidden
	}
	if !preflightChecks(t) {
		return fmt.Errorf("failed preflight checks")
	}
	keyPath := filepath.Join(dbpath, t.Key.String())
	dir := filepath.Dir(keyPath)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if mkdirErr := os.MkdirAll(dir, 0770); mkdirErr != nil {
			return mkdirErr
		}
	}
	if err := os.WriteFile(keyPath, t.Data, 0644); err != nil {
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

// .filename.ttl contains .after.timestamp filename, which contains del:/filename command
func createDotTtl(cmd *Command) {
	ttlSec, _ := strconv.Atoi(cmd.Args["ttl"])
	if ttlSec == 0 {
		return
	}
	if cmd.Key.Parent == "" {
		// A single-segment key (Id == Name, no parent) stores its value at
		// a path with no directory of its own: dbpath/<id> is a file, not
		// a directory. dot_after.go's containment check only accepts a
		// .after./.ttl. pair sitting inside a directory named after the
		// command's target Id - for every other key shape that directory
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
	ttlKey, err := KK(cmd.Key.Parent, fmt.Sprintf(".ttl.%s", cmd.Key.Name))
	if err != nil {
		log.Printf("createDotTtl: skipping TTL bookkeeping for %s: %v", cmd.Key.String(), err)
		return
	}
	dotAfterKey, err := KK(cmd.Key.Parent, fmt.Sprintf(".after.%d", ttdMs))
	if err != nil {
		log.Printf("createDotTtl: skipping TTL bookkeeping for %s: %v", cmd.Key.String(), err)
		return
	}

	if oldDotAfter, err := CmdGet(ttlKey).Exec(); err == nil {
		if oldKey, err := K(string(oldDotAfter)); err != nil {
			log.Printf("createDotTtl: skipping stale .after cleanup for %s: %v", cmd.Key.String(), err)
		} else {
			CmdDel(oldKey).Exec()
		}
	}

	dotAfterCommand := CmdDel(cmd.Key)
	dotAfterCommand.Args["x-id"] = cmd.Args["x-id"]
	CmdSet(ttlKey, map[string]string{"x-id": cmd.Args["x-id"]}, []byte(dotAfterKey.String())).Exec()
	CmdSet(dotAfterKey, map[string]string{"x-id": cmd.Args["x-id"]}, dotAfterCommand.Bytes()).Exec()
}
