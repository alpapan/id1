// apps/id1/k.go
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
		// A NUL byte can never appear in a real path: open(2) takes a
		// NUL-terminated string, so the kernel refuses the whole call. Left
		// unrejected here, such a key travels through the guards as though it
		// were ordinary and fails much later as an opaque I/O error, and any
		// component that logs or compares the key sees a value truncated at
		// the NUL rather than the value the guards checked. Refusing it at
		// construction keeps the key the guards inspect and the key the
		// filesystem receives the same string.
		if strings.ContainsRune(seg, 0) {
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

// oneSegment applies the clean-up K applies to a whole path - remove every
// newline, remove every space, trim leading and trailing slashes - and reports
// the result only when it is a single non-empty segment.
func oneSegment(s string) (string, bool) {
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, " ", "")
	s = strings.Trim(s, "/")
	if s == "" || strings.Contains(s, "/") {
		return "", false
	}
	return s, true
}

// KK builds a key from pieces. A piece of plain text (a string, an int, or any
// other fmt.Stringer) must be exactly one non-empty segment: a slash inside it
// would silently change the key's depth, and a piece that is only a slash would
// collapse the key to its parent. A piece whose type is Id1Key is the output of
// a successful K, so it may span many segments; a zero-segment Id1Key adds
// nothing. A piece of any other type, or a call that ends with no segments at
// all, is refused rather than skipped. Every refusal is ErrInvalidKey.
func KK(segments ...any) (Id1Key, error) {
	parts := []string{}
	for _, seg := range segments {
		switch v := seg.(type) {
		case Id1Key:
			if len(v.Segments) > 0 {
				parts = append(parts, v.String())
			}
		case string:
			part, ok := oneSegment(v)
			if !ok {
				return Id1Key{}, ErrInvalidKey
			}
			parts = append(parts, part)
		case int:
			parts = append(parts, fmt.Sprintf("%d", v))
		case fmt.Stringer:
			part, ok := oneSegment(v.String())
			if !ok {
				return Id1Key{}, ErrInvalidKey
			}
			parts = append(parts, part)
		default:
			return Id1Key{}, ErrInvalidKey
		}
	}
	if len(parts) == 0 {
		return Id1Key{}, ErrInvalidKey
	}
	return K(strings.Join(parts, "/"))
}
