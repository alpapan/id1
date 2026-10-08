// apps/backend/containers/id1/cmd_del.go
//
// group: server
// tags: storage, filesystem, delete-operation
// summary: Delete operation handler for removing key/value entries.
// Removes data files and cleans up empty directories.
//
//

package id1

import (
	"path/filepath"
)

func (t *Command) del() error {
	if !keyWithinRoot(t.Key) {
		return ErrForbidden
	}
	// A zero-segment key joins to dbpath itself, which is a directory, and the
	// directory branch below is root.RemoveAll - so an empty key would delete
	// every namespace in the store.
	if len(t.Key.Segments) == 0 {
		return ErrForbidden
	}

	root, err := openStoreRoot()
	if err != nil {
		return ErrNotFound
	}
	defer root.Close()

	rel := t.Key.String()
	// pathIsSymlinkFree checks every segment of rel, including the final one -
	// so a key naming a symlink ENTRY directly (deleting the link itself) is
	// refused exactly like a key that only traverses THROUGH a symlink on the
	// way to a real target. This is a deliberate choice, not an oversight: id1
	// never plants a symlink as data, so a legitimate caller never needs to
	// delete one, and carving out a leaf-only exception would make del() the
	// one sink in this package that treats "the key names a symlink" as safe
	// while get()/set()/list() all refuse it - an asymmetry with no test
	// coverage and no real use case. Refusing both acts uniformly costs no
	// functionality and keeps every sink's symlink behaviour identical.
	if !pathIsSymlinkFree(root, rel) {
		return ErrForbidden
	}

	stat, err := root.Stat(rel)
	if err != nil {
		return ErrNotFound
	}
	if stat.IsDir() {
		pubsub.Publish(t)
		return root.RemoveAll(rel)
	}

	pubsub.Publish(t)
	dotTtlRel := filepath.Join(t.Key.Parent, dotTTLDir, t.Key.Name)
	// The bookkeeping path is built by joining segments, not via the key's own
	// guarded rel above, so it needs the same no-symlink check on its own last
	// component. A stray symlink planted at this path must be left alone, not
	// blindly unlinked - and the main key delete below still proceeds either way.
	if pathIsSymlinkFree(root, dotTtlRel) {
		root.Remove(dotTtlRel)
	}
	return root.Remove(rel)
}
