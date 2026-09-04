// apps/backend/containers/id1/cmd_mov.go
//
// group: server
// tags: storage, filesystem, move-operation, rename
// summary: Move operation handler for renaming and relocating key/value entries.
// Moves data between key paths with directory management.
//
//

package id1

import (
	"log"
	"os"
	"path/filepath"
	"strings"
)

func (t *Command) move() error {
	// The destination is checked below, after normalisation. The SOURCE needs
	// its own containment check: it is used to build oldPath directly, and a
	// traversal source (a ".." segment) enables two distinct outcomes without
	// this guard - moving a file from outside the KV root entirely, AND
	// moving another namespace's file that stays inside the root, e.g.
	// "mallory/../victim/priv/salt" resolves to "<dbpath>/victim/priv/salt".
	// keyWithinRoot blocks both, because both require a ".." segment to reach
	// the victim's path from here.
	//
	// This is containment only, not ownership: keyWithinRoot has no concept
	// of which id owns a key, so a source key that is comfortably inside the
	// root but belongs to a DIFFERENT namespace with NO ".." in it (e.g.
	// "victim/priv/salt" named directly) still passes here - only the
	// destination is ownership-checked, below. Whether the source also needs
	// an ownership check is an open question for the security-advisor pass
	// over the complete change.
	if !keyWithinRoot(t.Key) {
		return ErrForbidden
	}
	// A zero-segment source names the store root rather than any file.
	if len(t.Key.Segments) == 0 {
		return ErrForbidden
	}
	oldKey := t.Key.String()
	newKey := string(t.Data)

	// Normalize the destination path FIRST - all checks operate on the
	// resolved path to prevent bypasses like "alice/../bob/file".
	dbpathClean := filepath.Clean(dbpath)
	newPath := filepath.Clean(filepath.Join(dbpathClean, newKey))

	// Path containment: destination must stay within the KV store root
	if !strings.HasPrefix(newPath, dbpathClean+string(filepath.Separator)) {
		return ErrForbidden
	}

	// Extract the destination owner from the NORMALIZED relative path.
	// This prevents "alice/../bob/file" from passing as "alice" - after
	// normalization it resolves to "bob/file", and destID = "bob".
	relPath, err := filepath.Rel(dbpathClean, newPath)
	if err != nil {
		return ErrForbidden
	}
	destID := strings.SplitN(relPath, string(filepath.Separator), 2)[0]

	// Renaming a file the caller controls INTO a .after.<ms> name plants a
	// scheduled command the sweep later executes, bypassing the identity pin
	// that set() applies (preflightChecks in cmd_set.go). set() is the only
	// writer of scheduled commands in this package, so refusing here removes no
	// behaviour.
	if strings.HasPrefix(filepath.Base(newPath), ".after.") {
		return ErrForbidden
	}

	// Destination must belong to the same user as the caller.
	// The auth layer in id1.go prevents unauthenticated (empty x-id)
	// PATCH requests from reaching here, but we enforce anyway for
	// defense-in-depth.
	callerID := t.Args["x-id"]
	if callerID == "" || destID != callerID {
		return ErrForbidden
	}

	oldPath := filepath.Join(dbpathClean, oldKey)
	newDir := filepath.Dir(newPath)

	if _, err := os.Stat(oldPath); err != nil {
		return ErrNotFound
	}

	if _, err := os.Stat(newPath); err == nil {
		return ErrExists
	}

	if _, err := os.Stat(newDir); os.IsNotExist(err) {
		if mkdirErr := os.MkdirAll(newDir, 0770); mkdirErr != nil {
			return mkdirErr
		}
	}

	if err := os.Rename(oldPath, newPath); err != nil {
		log.Printf("cmd: mov error, %s", err)
		return err
	}

	return nil
}
