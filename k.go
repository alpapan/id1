// apps/backend/containers/id1/k.go
//
// group: models
// tags: keys, hierarchy, segments
// summary: Key structure and path parsing for hierarchical key namespace.
// Parses and validates Id1Key paths with owner, name, and segment components.
//
//

package id1

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// ErrInvalidKey is returned by K and KK for any key that does not name a
// location inside its own first segment. Callers surface it as a refusal:
// the HTTP KV dispatcher answers 403, in-process callers propagate or log
// and skip.
var ErrInvalidKey = errors.New("invalid key")

type Id1Key struct {
	Id       string
	Name     string
	Parent   string
	Pub      bool
	Segments []string
}

func (t Id1Key) String() string {
	return strings.Join(t.Segments, "/")
}

func K(s string) (Id1Key, error) {
	k := Id1Key{}
	if len(s) == 0 {
		return k, nil
	}
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, " ", "")
	s = strings.Trim(s, "/")

	k.Segments = strings.Split(s, "/")

	// Containment. A key must name a location inside its own first segment.
	//
	// The per-segment check is the load-bearing one and filepath.IsLocal is
	// NOT a substitute for it: IsLocal("a/../b") returns TRUE, because it
	// guarantees containment within the base directory, not within the first
	// segment. "a/../b" resolves to "b" - still inside the store, but inside
	// somebody else's namespace, which is the whole attack. IsLocal is kept
	// only as a second net for rooted and volume-prefixed forms.
	for _, seg := range k.Segments {
		if seg == ".." || seg == "." || seg == "" {
			return Id1Key{}, ErrInvalidKey
		}
	}
	if !filepath.IsLocal(s) {
		return Id1Key{}, ErrInvalidKey
	}

	k.Id = k.Segments[0]
	k.Name = k.Segments[len(k.Segments)-1]

	if len(k.Segments) > 1 {
		k.Parent = strings.Join(k.Segments[:len(k.Segments)-1], "/")
	}
	if len(k.Segments) > 1 {
		k.Pub = k.Segments[1] == "pub"
	}

	return k, nil
}

func KK(segments ...any) (Id1Key, error) {
	strSegments := []string{}
	for _, seg := range segments {
		if s, ok := seg.(string); ok {
			strSegments = append(strSegments, s)
		}
		if i, ok := seg.(int); ok {
			strSegments = append(strSegments, fmt.Sprintf("%d", i))
		}
		if stringer, ok := seg.(fmt.Stringer); ok {
			strSegments = append(strSegments, stringer.String())
		}
	}
	return K(strings.Join(strSegments, "/"))
}
