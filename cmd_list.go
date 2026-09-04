// apps/backend/containers/id1/cmd_list.go
//
// group: server
// tags: storage, filesystem, list-operation, directory
// summary: List operation handler for enumerating keys in a namespace.
// Recursively traverses filesystem and returns directory contents with metadata.
//
//

package id1

import (
	"encoding/base64"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type ListOptions struct {
	Limit          int
	SizeLimit      int
	TotalSizeLimit int
	Keys           bool
	Recursive      bool
	Children       bool
}

func (t ListOptions) Map() map[string]string {
	args := map[string]string{}
	args["limit"] = fmt.Sprintf("%d", t.Limit)
	args["size-limit"] = fmt.Sprintf("%d", t.SizeLimit)
	args["total-size-limit"] = fmt.Sprintf("%d", t.TotalSizeLimit)
	args["keys"] = fmt.Sprintf("%t", t.Keys)
	args["recursive"] = fmt.Sprintf("%t", t.Recursive)
	args["children"] = fmt.Sprintf("%t", t.Children)
	return args
}

func (t *ListOptions) Parse(args map[string]string) {
	if i, err := strconv.ParseInt(args["limit"], 10, 64); err == nil {
		t.Limit = int(i)
	} else {
		t.Limit = 1000
	}
	if i, err := strconv.ParseInt(args["size-limit"], 10, 64); err == nil {
		t.SizeLimit = int(i)
	} else {
		t.SizeLimit = 100 * MB
	}
	if i, err := strconv.ParseInt(args["total-size-limit"], 10, 64); err == nil {
		t.TotalSizeLimit = int(i)
	} else {
		t.TotalSizeLimit = 100 * MB
	}
	t.Keys = args["keys"] == "true"
	t.Recursive = args["recursive"] == "true"
	t.Children = args["children"] == "true"
}

func (t *Command) list() ([]byte, error) {
	if !keyWithinRoot(t.Key) {
		return []byte{}, ErrForbidden
	}

	// A list key can still carry a trailing "*" here: the HTTP ingress strips it
	// before building the key, but an in-process caller and a command parsed out
	// of a WebSocket frame do not. Trimming the star can reveal a segment the
	// guard above never saw - "..*" becomes ".." - so the trimmed key is rebuilt
	// through K() and re-checked before it reaches the filesystem. A zero-segment
	// key is refused outright: it resolves to dbpath itself, which would list
	// every namespace in the store.
	listKey, keyErr := K(strings.TrimSuffix(t.Key.String(), "*"))
	if keyErr != nil {
		return []byte{}, ErrForbidden
	}
	if len(listKey.Segments) == 0 {
		return []byte{}, ErrForbidden
	}
	if !keyWithinRoot(listKey) {
		return []byte{}, ErrForbidden
	}

	opt := ListOptions{}
	opt.Parse(t.Args)
	if opt.Children && opt.Recursive {
		return []byte{}, fmt.Errorf("recursive can't be true if children is true")
	}

	dirPath := filepath.Join(dbpath, listKey.String())

	if stat, err := os.Stat(dirPath); err != nil || !stat.IsDir() {
		return []byte{}, ErrNotFound
	}

	var results map[string][]byte
	var err error = nil

	if opt.Recursive {
		results, err = walkDir(dirPath, opt)
	} else {
		results, err = listDir(dirPath, opt)
	}

	list := []string{}
	for k, v := range results {
		var line string
		if opt.Children || opt.Keys {
			line = k
		} else {
			line = fmt.Sprintf("%s=%s", k, base64.StdEncoding.EncodeToString(v))
		}
		list = append(list, line)
	}
	if opt.Children || opt.Keys {
		sort.Strings(list)
	}
	return []byte(strings.Join(list, "\n")), err
}

func listDir(path string, opt ListOptions) (map[string][]byte, error) {
	results := map[string][]byte{}
	totalSize := 0
	dbpathClean := filepath.Clean(dbpath)
	if entries, err := os.ReadDir(path); err != nil {
		log.Printf("error listing dir %s: %s", path, err)
	} else {
		for _, e := range entries {
			if len(results) >= opt.Limit {
				break
			}
			itemPath := filepath.Join(path, e.Name())
			if stat, err := os.Stat(itemPath); err != nil {
				log.Printf("cmd list error, %s", err)
			} else if !stat.IsDir() && stat.Size() > int64(opt.SizeLimit) {
				continue
			} else if opt.Children {
				results[e.Name()] = []byte{}
				continue
			} else if stat.IsDir() {
				continue
			}

			key := strings.TrimPrefix(itemPath, dbpathClean)
			key = strings.TrimPrefix(key, "/")

			if totalSize+len(key) > opt.TotalSizeLimit {
				return results, ErrLimitExceeded
			} else {
				totalSize += len(key)
			}

			if opt.Keys {
				results[key] = []byte{}
				continue
			}

			if data, err := os.ReadFile(itemPath); err != nil {
				log.Printf("cmd list error, %s", err)
			} else if totalSize+len(data) > opt.TotalSizeLimit {
				return results, ErrLimitExceeded
			} else {
				results[key] = data
				totalSize += len(data)
			}
		}
	}
	return results, nil
}

func walkDir(path string, opt ListOptions) (map[string][]byte, error) {
	results := map[string][]byte{}
	totalSize := 0
	dbpathClean := filepath.Clean(dbpath)
	err := filepath.WalkDir(path, func(itemPath string, d fs.DirEntry, err error) error {
		if len(results) >= opt.Limit {
			return nil
		}
		if stat, err := os.Stat(itemPath); err != nil {
			log.Printf("cmd list error, %s", err)
		} else if !stat.IsDir() && stat.Size() > int64(opt.SizeLimit) {
			return nil
		} else if opt.Children {
			results[stat.Name()] = []byte{}
			return nil
		} else if stat.IsDir() {
			return nil
		}

		key := strings.TrimPrefix(itemPath, dbpathClean)
		key = strings.TrimPrefix(key, "/")

		if totalSize+len(key) > opt.TotalSizeLimit {
			return ErrLimitExceeded
		}
		totalSize += len(key)

		if opt.Keys {
			results[key] = []byte{}
		} else if data, err := os.ReadFile(itemPath); err != nil {
			log.Printf("cmd list error: %s", err)
		} else if totalSize+len(data) > opt.TotalSizeLimit {
			return ErrLimitExceeded
		} else {
			results[key] = data
			totalSize += len(data)
		}
		return nil
	})
	return results, err
}
