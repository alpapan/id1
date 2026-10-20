// apps/id1/cmd_get.go
//
// group: server
// tags: storage, filesystem, get-operation
// summary: Get operation handler for retrieving key/value entries.
// Reads data from filesystem and handles directory listing.
//
//

package id1

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
)

// keyWithinRoot reports whether key resolves to a path inside dbpath with no ".."
// traversal segment. A command reaching get()/del() through Command.ExecAs has passed
// auth() first, but one run through Command.execUnauthorised() (an in-process caller
// that built the command itself) has NO auth() check, so any such caller that
// builds a key from untrusted input could otherwise read/delete files in another
// namespace ("a/../b" stays inside dbpath but escapes namespace a) or outside
// dbpath entirely. Rejecting ".." segments closes both. move() has an analogous
// guard (cmd_mov.go).
//
// This check remains load-bearing after the move to os.Root: os.Root refuses a
// path that leaves the store, but it PERMITS a lexical "a/../b" that stays
// inside it, which is exactly the cross-namespace case this rejects.
func keyWithinRoot(key Id1Key) bool {
	for _, seg := range key.Segments {
		if seg == ".." {
			return false
		}
	}
	dbpathClean := filepath.Clean(dbpath)
	resolved := filepath.Clean(filepath.Join(dbpathClean, key.String()))
	return resolved == dbpathClean || strings.HasPrefix(resolved, dbpathClean+string(filepath.Separator))
}

func (t *Command) get() ([]byte, error) {
	if !keyWithinRoot(t.Key) {
		return []byte{}, ErrForbidden
	}

	root, err := openStoreRoot()
	if err != nil {
		return []byte{}, err
	}
	defer root.Close()

	rel := t.Key.String()
	if !pathIsSymlinkFree(root, rel) {
		return []byte{}, ErrForbidden
	}

	if info, err := root.Stat(rel); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return []byte{}, ErrNotFound
		}
		return []byte{}, err
	} else if info.IsDir() {
		return []byte{}, ErrNotFound
	}

	if data, err := root.ReadFile(rel); err != nil {
		return []byte{}, err
	} else {
		return data, nil
	}
}
