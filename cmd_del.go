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
	"fmt"
	"os"
	"path/filepath"
)

func (t *Command) del() error {
	path := filepath.Join(dbpath, t.Key.String())
	if stat, err := os.Stat(path); err != nil {
		return ErrNotFound
	} else if stat.IsDir() {
		pubsub.Publish(t)
		return os.RemoveAll(path)
	} else {
		pubsub.Publish(t)
		dotTtlPath := filepath.Join(dbpath, t.Key.Parent, fmt.Sprintf(".ttl.%s", t.Key.Name))
		os.Remove(dotTtlPath)
		return os.Remove(path)
	}
}
