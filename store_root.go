// apps/backend/containers/id1/store_root.go
//
// group: server
// tags: storage, filesystem, containment
// summary: Directory-scoped handle on the KV store root, and the no-symlink guard.
// Every filesystem operation on a key-derived path goes through these.
//
//

package id1

import (
	"os"
	"strings"
)

// openStoreRoot opens a directory-scoped handle on the KV store root.
//
// The handle is opened per operation rather than cached in a package variable.
// dbpath is a package global, and the test suite reassigns it per test, so a
// cached handle would keep resolving against a previous test's directory. The
// cost of opening is one openat(2); a stale handle would be a correctness bug
// that appears only under a directory change, which is the hardest kind to
// find.
//
// The caller must Close the returned handle.
//
// What the handle buys: every method on *os.Root refuses a path that leaves the
// root, INCLUDING via a symbolic link, and the refusal happens in the kernel's
// path resolution rather than in a string comparison this package would have to
// keep correct. It does NOT replace keyWithinRoot: os.Root permits a lexical
// "a/../b" that stays inside the root, which is a namespace escape even though
// it is not a store escape.
//
// os.OpenRoot fails with ENOENT when dbpath itself does not exist. Nothing
// else in this package creates dbpath - Handle only assigns the package
// variable, and a standalone binary's main only calls ResolveConfig then
// Handle - so this function creates it, with the same mode every other
// directory in the store is created with (0770).
func openStoreRoot() (*os.Root, error) {
	if err := os.MkdirAll(dbpath, 0770); err != nil {
		return nil, err
	}
	return os.OpenRoot(dbpath)
}

// pathIsSymlinkFree reports whether no existing component of rel, resolved
// inside root, is a symbolic link.
//
// os.Root closes every symlink that leaves the store, and every absolute
// symlink. What it still follows is a RELATIVE symlink whose target stays
// inside the store - and that is a cross-namespace read or write, which is the
// attack this package's containment guards exist to refuse. This function
// closes it.
//
// Refusing symlinks outright removes no behaviour: nothing in this package
// creates one. A link in the store can only have arrived from outside it.
//
// A component that does not exist yet is not a symlink, so a write to a new key
// is allowed; nothing can exist beneath a component that does not exist, so
// there is no path left to check past that point. Any other Lstat failure is
// treated as a refusal: a guard that cannot see what it is guarding must not
// grant.
func pathIsSymlinkFree(root *os.Root, rel string) bool {
	if rel == "" {
		return true
	}
	segments := strings.Split(rel, "/")
	for i := range segments {
		partial := strings.Join(segments[:i+1], "/")
		info, err := root.Lstat(partial)
		if err != nil {
			if os.IsNotExist(err) {
				return true
			}
			return false
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return false
		}
	}
	return true
}
