// apps/backend/containers/id1/cmd_add.go
//
// group: server
// tags: storage, filesystem, add-operation
// summary: Add operation handler for creating new key/value entries.
// Writes data to filesystem with directory creation and collision prevention.
//
//

package id1

import (
	"os"
	"path/filepath"
	"strings"
)

func (t *Command) add() error {
	if !keyWithinRoot(t.Key) {
		return ErrForbidden
	}
	// A zero-segment key joins to dbpath itself - the store root, which belongs
	// to no identity.
	if len(t.Key.Segments) == 0 {
		return ErrForbidden
	}
	// A .after.<ms> file is a scheduled command the sweep later executes on an
	// owner's behalf. set() pins the stored command's identity to the caller
	// (preflightChecks in cmd_set.go); add() appends raw bytes and cannot pin
	// anything, because the bytes may be part of a command completed by a later
	// call. set() is the only writer of scheduled commands in this package, so
	// refusing here removes no behaviour.
	if strings.HasPrefix(t.Key.Name, ".after.") {
		return ErrForbidden
	}
	filePath := filepath.Join(dbpath, t.Key.String())
	dir := filepath.Dir(filePath)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if mkdirErr := os.MkdirAll(dir, 0770); mkdirErr != nil {
			return mkdirErr
		}
	}

	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.WriteString(string(t.Data)); err != nil {
		return err
	}
	return f.Close()
}
