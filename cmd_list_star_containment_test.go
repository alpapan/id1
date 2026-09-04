package id1

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestListStarHTTPRefusesUnauthenticatedTraversal is the regression test for the
// proven attack: an unauthenticated GET whose path ends in "..*" is treated as a
// public read, and the trailing star hides the ".." from every containment check
// until list() strips it and hands it to the filesystem.
func TestListStarHTTPRefusesUnauthenticatedTraversal(t *testing.T) {
	tmpDir := seedVictim(t)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	handler := Handle(tmpDir, ctx)

	req := httptest.NewRequest(http.MethodGet, "/victim/pub/..*?recursive=true", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code == http.StatusOK {
		t.Errorf("SECURITY: unauthenticated GET /victim/pub/..* returned 200, body=%q", rec.Body.String())
	}
	leaked := base64.StdEncoding.EncodeToString([]byte("VICTIM-SALT"))
	if strings.Contains(rec.Body.String(), leaked) {
		t.Errorf("SECURITY: response disclosed the victim's salt, body=%q", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "VICTIM-SALT") {
		t.Errorf("SECURITY: response disclosed the victim's salt in cleartext, body=%q", rec.Body.String())
	}
}

// TestListStarSinkRefusesTraversal covers the paths that never touch req.go: an
// in-process caller, or a command parsed from a WebSocket frame. K() accepts
// "victim/pub/..*" because "..*" is a legal file name; list() must refuse it once
// trimming the star reveals the "..".
func TestListStarSinkRefusesTraversal(t *testing.T) {
	seedVictim(t)

	key := mustK(t, "victim/pub/..*")
	data, err := NewCommand(List, key, map[string]string{"recursive": "true", "x-id": "mallory"}, []byte{}).Exec()

	if !errors.Is(err, ErrForbidden) {
		t.Errorf("list() with a star-hidden traversal key: got err=%v, want ErrForbidden", err)
	}
	if strings.Contains(string(data), "VICTIM-SALT") {
		t.Errorf("SECURITY: list() returned the victim's salt: %q", string(data))
	}
	if len(data) != 0 {
		t.Errorf("list() returned %d bytes for a refused key: %q", len(data), string(data))
	}
}

// TestListStarRefusesZeroSegmentKey covers the store-root case: a key of exactly
// "*" trims to the empty string, which resolves to dbpath itself and would list
// every namespace in the store at once.
func TestListStarRefusesZeroSegmentKey(t *testing.T) {
	seedVictim(t)

	key := mustK(t, "*")
	data, err := NewCommand(List, key, map[string]string{"recursive": "true", "x-id": "mallory"}, []byte{}).Exec()

	if !errors.Is(err, ErrForbidden) {
		t.Errorf("list() with a zero-segment key: got err=%v, want ErrForbidden", err)
	}
	if strings.Contains(string(data), "VICTIM-SALT") {
		t.Errorf("SECURITY: a store-root list returned the victim's salt: %q", string(data))
	}
}

// TestListStarLegitimateListStillWorks pins the behaviour the fix must not break:
// an ordinary trailing-star list inside the caller's own namespace still returns
// that namespace's entries.
func TestListStarLegitimateListStillWorks(t *testing.T) {
	seedVictim(t)

	if _, err := CmdSet(mustK(t, "alice/msg/one"), map[string]string{"x-id": "alice"}, []byte("hello")).Exec(); err != nil {
		t.Fatalf("seed alice: %v", err)
	}

	data, err := NewCommand(List, mustK(t, "alice/msg/*"), map[string]string{"x-id": "alice"}, []byte{}).Exec()
	if err != nil {
		t.Fatalf("legitimate list was refused: %v", err)
	}
	wantLine := "alice/msg/one=" + base64.StdEncoding.EncodeToString([]byte("hello"))
	if !strings.Contains(string(data), wantLine) {
		t.Errorf("legitimate list lost its entry or corrupted its value: got %q, want a line %q", string(data), wantLine)
	}
}

// TestNewRequestPropsStripsListStarBeforeKeyConstruction pins the ingress rule:
// the star is removed BEFORE K() builds the key, so the key the guards inspect is
// the key the filesystem will be handed.
func TestNewRequestPropsStripsListStarBeforeKeyConstruction(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/alice/msg/*", nil)
	props := NewRequestProps(r)

	if props.Cmd.Op != List {
		t.Errorf("a trailing-star GET must map to List, got %v", props.Cmd.Op)
	}
	if props.Cmd.Key.String() != "alice/msg" {
		t.Errorf("the star must be stripped before the key is built, got %q", props.Cmd.Key.String())
	}
	if props.Id != "alice" {
		t.Errorf("expected Id \"alice\", got %q", props.Id)
	}
}

// TestHandleRefusesMalformedKeyPath pins the ingress refusal: a path K() cannot
// turn into a key is answered 400 and never reaches an operation. Before this
// change the same request was logged and carried on with a zero-value key.
func TestHandleRefusesMalformedKeyPath(t *testing.T) {
	tmpDir := seedVictim(t)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	handler := Handle(tmpDir, ctx)

	req := httptest.NewRequest(http.MethodGet, "/victim/pub/..*?recursive=true", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("a malformed key path must be refused with 400, got %d (body=%q)", rec.Code, rec.Body.String())
	}
}

// TestWalkDirEnforcesTotalSizeLimitInKeysMode is the regression test for CF-2:
// walkDir accumulates totalSize += len(key) unconditionally, but the
// TotalSizeLimit check only runs inside the branch that reads file data,
// which opt.Keys=true skips entirely. A recursive keys-only listing can
// therefore accumulate an unbounded number of key names with no limit ever
// enforced, unlike listDir's equivalent (cmd_list.go:132-136), which checks
// before every increment regardless of opt.Keys.
func TestWalkDirEnforcesTotalSizeLimitInKeysMode(t *testing.T) {
	tmpDir := t.TempDir()
	originalDbpath := dbpath
	dbpath = tmpDir
	t.Cleanup(func() { dbpath = originalDbpath })

	dir := filepath.Join(tmpDir, "victim", "many")
	if err := os.MkdirAll(dir, 0770); err != nil {
		t.Fatalf("seed failed: %v", err)
	}
	names := []string{
		"file-with-a-long-name-00", "file-with-a-long-name-01",
		"file-with-a-long-name-02", "file-with-a-long-name-03",
		"file-with-a-long-name-04", "file-with-a-long-name-05",
	}
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), []byte{}, 0644); err != nil {
			t.Fatalf("seed failed: %v", err)
		}
	}

	opt := ListOptions{Limit: 1000, SizeLimit: 100 * MB, TotalSizeLimit: 50, Keys: true}
	_, err := walkDir(dir, opt)

	if !errors.Is(err, ErrLimitExceeded) {
		t.Errorf("walkDir keys-only recursive list over %d files whose key names alone exceed TotalSizeLimit=%d: got err=%v, want ErrLimitExceeded", len(names), opt.TotalSizeLimit, err)
	}
}

// dbpathCleaningCases is the table for TestListingFunctionsCleanDbpathBeforeTrimmingPrefix.
// listDir and walkDir share the exact same signature and the exact same bug
// (CF-3), differing only in which one is under test, so they collapse into
// one table-driven test rather than two near-identical functions - per
// curatorium-testing's "collapse a family before you report DONE" rule.
var dbpathCleaningCases = []struct {
	name   string
	listFn func(string, ListOptions) (map[string][]byte, error)
}{
	{name: "listDir", listFn: listDir},
	{name: "walkDir", listFn: walkDir},
}

// TestDbpathCleaningCaseListIsPopulated is the case-list guard curatorium-testing
// requires alongside any parameterised table: it asserts both length and
// membership, so deleting a row here fails a test instead of passing quietly.
func TestDbpathCleaningCaseListIsPopulated(t *testing.T) {
	if len(dbpathCleaningCases) < 2 {
		t.Fatalf("dbpathCleaningCases has %d cases, want at least 2", len(dbpathCleaningCases))
	}
	names := map[string]bool{}
	for _, c := range dbpathCleaningCases {
		names[c.name] = true
	}
	for _, want := range []string{"listDir", "walkDir"} {
		if !names[want] {
			t.Errorf("dbpathCleaningCases is missing case %q", want)
		}
	}
}

// TestListingFunctionsCleanDbpathBeforeTrimmingPrefix is the regression test
// for CF-3: listDir (cmd_list.go:129-130) and walkDir (cmd_list.go:174-175)
// each strip the itemPath's dbpath prefix using the raw, uncleaned dbpath
// value. filepath.Join always cleans (cmd_list.go:76, 117), so a dbpath
// value carrying a redundant separator - for example a DBPATH=/mnt/id1db//
// misconfiguration - never matches the itemPath's single separator, and
// TrimPrefix returns the untouched, absolute itemPath as the "key". That
// leaks the absolute host filesystem path into the response body.
// filepath.Clean(dbpath) is what keyWithinRoot already uses for the same
// comparison (cmd_get.go:31); both listing functions must match it.
func TestListingFunctionsCleanDbpathBeforeTrimmingPrefix(t *testing.T) {
	for _, c := range dbpathCleaningCases {
		t.Run(c.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			originalDbpath := dbpath
			dbpath = tmpDir + string(filepath.Separator) + string(filepath.Separator)
			t.Cleanup(func() { dbpath = originalDbpath })

			dir := filepath.Join(tmpDir, "victim", "msg")
			if err := os.MkdirAll(dir, 0770); err != nil {
				t.Fatalf("seed failed: %v", err)
			}
			if err := os.WriteFile(filepath.Join(dir, "one"), []byte("hi"), 0644); err != nil {
				t.Fatalf("seed failed: %v", err)
			}

			opt := ListOptions{Limit: 1000, SizeLimit: 100 * MB, TotalSizeLimit: 100 * MB, Keys: true}
			results, err := c.listFn(dir, opt)
			if err != nil {
				t.Fatalf("%s: unexpected error: %v", c.name, err)
			}

			if _, ok := results["victim/msg/one"]; !ok {
				t.Errorf("SECURITY: %s with a redundant-separator dbpath must return the relative key %q, got keys %v", c.name, "victim/msg/one", results)
			}
		})
	}
}
