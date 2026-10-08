// apps/id1/k_one_segment_test.go
//
// group: models
// tags: keys, segments, containment, testing
// summary: Tests that KK accepts only one-segment text and lets a parsed key span many.
//
//

package id1

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// kkRejectedCase is one argument list KK must refuse with ErrInvalidKey.
type kkRejectedCase struct {
	name string
	args []any
}

// kkRejectedCases is the whole rejection contract in one place. It is asserted
// by TestKKRejectedCaseListIsPopulatedAndNamed, so deleting a row fails a test
// rather than silently dropping the coverage it carried.
var kkRejectedCases = []kkRejectedCase{
	{name: "a lone slash as the second piece", args: []any{"_syncticket", "/"}},
	{name: "two slashes as the second piece", args: []any{"_syncticket", "//"}},
	{name: "a single space as the second piece", args: []any{"_syncticket", " "}},
	{name: "a single newline as the second piece", args: []any{"_syncticket", "\n"}},
	{name: "a slash between spaces as the second piece", args: []any{"_syncticket", " / "}},
	{name: "an empty string as the second piece", args: []any{"_syncticket", ""}},
	{name: "a multi-segment string as the first piece", args: []any{"victim/pub/key", "priv", "salt"}},
	{name: "a multi-segment string as a later piece", args: []any{"alice", "a/b"}},
	{name: "an int64 piece", args: []any{"alice", int64(7)}},
	{name: "a byte-slice piece", args: []any{"alice", []byte("x")}},
	{name: "an untyped nil piece", args: []any{"alice", nil}},
	{name: "no pieces at all", args: []any{}},
	{name: "one empty string and nothing else", args: []any{""}},
}

func TestKKRejectedCaseListIsPopulatedAndNamed(t *testing.T) {
	if len(kkRejectedCases) != 13 {
		t.Fatalf("kkRejectedCases must hold 13 cases, got %d - update this guard when adding or dropping a row", len(kkRejectedCases))
	}
	names := map[string]bool{}
	for _, c := range kkRejectedCases {
		names[c.name] = true
	}
	for _, want := range []string{
		"a lone slash as the second piece",
		"a multi-segment string as the first piece",
		"an int64 piece",
		"no pieces at all",
	} {
		if !names[want] {
			t.Errorf("kkRejectedCases is missing the case %q", want)
		}
	}
}

func TestKKRefusesPiecesThatAreNotExactlyOneSegment(t *testing.T) {
	for _, c := range kkRejectedCases {
		t.Run(c.name, func(t *testing.T) {
			k, err := KK(c.args...)
			if !errors.Is(err, ErrInvalidKey) {
				t.Errorf("KK(%v): got err=%v key=%q, want ErrInvalidKey", c.args, err, k.String())
			}
			if len(k.Segments) != 0 {
				t.Errorf("KK(%v): a refused key must be the zero Id1Key, got segments=%v", c.args, k.Segments)
			}
		})
	}
}

func TestKKLetsAParsedKeySpanManySegments(t *testing.T) {
	parent := mustK(t, "alice/sub")

	got := mustKK(t, parent, ".get")
	if got.String() != "alice/sub/.get" {
		t.Errorf("KK(parsed key, %q) = %q, want %q", ".get", got.String(), "alice/sub/.get")
	}

	got = mustKK(t, parent, ".roles", "max")
	if got.String() != "alice/sub/.roles/max" {
		t.Errorf("KK(parsed key, %q, %q) = %q, want %q", ".roles", "max", got.String(), "alice/sub/.roles/max")
	}

	got = mustKK(t, "alice", 7)
	if got.String() != "alice/7" {
		t.Errorf("KK(%q, 7) = %q, want %q", "alice", got.String(), "alice/7")
	}
}

func TestKKStillTrimsLeadingAndTrailingSlashesFromOnePiece(t *testing.T) {
	got := mustKK(t, "alice", "/note/")
	if got.String() != "alice/note" {
		t.Errorf("KK(%q, %q) = %q, want %q", "alice", "/note/", got.String(), "alice/note")
	}
}

func TestGenerateSecretRefusesAMultiSegmentSubject(t *testing.T) {
	root := newTTLStore(t)

	if _, err := generateSecret("victim/pub/key"); err == nil {
		t.Fatalf("generateSecret must refuse a subject that is not one segment")
	}

	written := []string{}
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path != root {
			written = append(written, path)
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walking the store root failed: %v", walkErr)
	}
	if len(written) != 0 {
		t.Errorf("a refused subject must write nothing under the store root, found %v", written)
	}
}

func TestTTLStillWorksWithAMultiSegmentParent(t *testing.T) {
	root := newTTLStore(t)

	key := mustK(t, "alice/sub/deep/greeting")
	if _, err := CmdSet(key, map[string]string{"ttl": "60", "x-id": "alice"}, []byte("hello")).Exec(); err != nil {
		t.Fatalf("set with ttl failed: %v", err)
	}

	pointer := filepath.Join(root, "alice", "sub", "deep", ".ttl", "greeting")
	if _, err := os.Stat(pointer); err != nil {
		t.Errorf("expected the bookkeeping pointer at %s: %v", pointer, err)
	}
	scheduled, err := filepath.Glob(filepath.Join(root, "alice", "sub", "deep", ".after.*"))
	if err != nil {
		t.Fatalf("glob failed: %v", err)
	}
	if len(scheduled) != 1 {
		t.Errorf("expected exactly one scheduled .after. file beside the key, got %v", scheduled)
	}
}
