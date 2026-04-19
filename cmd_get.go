// apps/backend/containers/id1/cmd_get.go
//
// group: server
// tags: storage, filesystem, get-operation
// summary: Get operation handler for retrieving key/value entries.
// Reads data from filesystem and handles directory listing.
//
//

package id1

import (
	"os"
	"path/filepath"
)

func (t *Command) get() ([]byte, error) {
	filePath := filepath.Join(dbpath, t.Key.String())

	if info, err := os.Stat(filePath); os.IsNotExist(err) {
		return []byte{}, ErrNotFound
	} else if info.IsDir() {
		return []byte{}, ErrNotFound
	}

	if data, err := os.ReadFile(filePath); err != nil {
		return []byte{}, err
	} else {
		return data, nil
	}
}
