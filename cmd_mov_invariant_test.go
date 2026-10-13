// apps/id1/cmd_mov_invariant_test.go
//
// group: server
// tags: storage, move-operation, authorization, testing
// summary: Tests that move() refuses a private-subtree source and that only known files name the Mov operation.
//
//

package id1

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// movePrivCase is one move of something under {id}/priv/ that must be refused.
type movePrivCase struct {
	name   string
	source string
	caller string
	dest   string
}

// movePrivCases is the whole refusal contract in one place. It is asserted by
// TestMoveRefusesAPrivSourceCaseListIsPopulatedAndNamed, so deleting a row
// fails a test rather than silently dropping the coverage it carried.
var movePrivCases = []movePrivCase{
	{name: "the owner moves the salt", source: "victim/priv/salt", caller: "victim", dest: "victim/copy"},
	{name: "a delegate moves the salt into their own namespace", source: "victim/priv/salt", caller: "mallory", dest: "mallory/stolen"},
	{name: "a delegate moves the whole private directory", source: "victim/priv", caller: "mallory", dest: "mallory/stolen"},
}

func TestMoveRefusesAPrivSourceCaseListIsPopulatedAndNamed(t *testing.T) {
	if len(movePrivCases) != 3 {
		t.Fatalf("movePrivCases must hold 3 cases, got %d - update this guard when adding or dropping a row", len(movePrivCases))
	}
	names := map[string]bool{}
	for _, c := range movePrivCases {
		names[c.name] = true
	}
	for _, want := range []string{
		"a delegate moves the salt into their own namespace",
		"a delegate moves the whole private directory",
	} {
		if !names[want] {
			t.Errorf("movePrivCases is missing the case %q", want)
		}
	}
}

func TestMoveRefusesAPrivSource(t *testing.T) {
	for _, c := range movePrivCases {
		t.Run(c.name, func(t *testing.T) {
			root := seedVictim(t)

			_, err := NewCommand(Mov, mustK(t, c.source), map[string]string{"x-id": c.caller}, []byte(c.dest)).execUnauthorised()

			if !errors.Is(err, ErrForbidden) {
				t.Errorf("mov %s -> %s as %s: got err=%v, want ErrForbidden", c.source, c.dest, c.caller, err)
			}
			salt, readErr := os.ReadFile(filepath.Join(root, "victim", "priv", "salt"))
			if readErr != nil {
				t.Errorf("the salt must still be at its own path: %v", readErr)
			} else if string(salt) != "VICTIM-SALT" {
				t.Errorf("the salt was altered: %q", string(salt))
			}
			if _, statErr := os.Stat(filepath.Join(root, filepath.FromSlash(c.dest))); statErr == nil {
				t.Errorf("the destination %s must not exist after a refused move", c.dest)
			}
		})
	}
}

func TestMoveStillAllowsASourceOutsideThePrivateSubtree(t *testing.T) {
	seedVictim(t)
	source := mustK(t, "victim/msg/a")
	if _, err := CmdSet(source, map[string]string{"x-id": "victim"}, []byte("payload")).execUnauthorised(); err != nil {
		t.Fatalf("seeding the move source failed: %v", err)
	}

	_, err := NewCommand(Mov, source, map[string]string{"x-id": "victim"}, []byte("victim/msg/b")).execUnauthorised()

	if err != nil {
		t.Errorf("a source outside the private subtree must still move: %v", err)
	}
}

// filesNamingTheMoveOperation parses the given Go source files and returns the
// base name of each one that mentions the Mov operation constant or the CmdMov
// constructor, sorted.
func filesNamingTheMoveOperation(t *testing.T, paths []string) []string {
	t.Helper()
	found := []string{}
	for _, path := range paths {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", path, err)
		}
		mentions := false
		ast.Inspect(file, func(n ast.Node) bool {
			if ident, ok := n.(*ast.Ident); ok && (ident.Name == "Mov" || ident.Name == "CmdMov") {
				mentions = true
			}
			return true
		})
		if mentions {
			found = append(found, filepath.Base(path))
		}
	}
	sort.Strings(found)
	return found
}

// TestMoveOperationDerivationWorks proves the parser reads files in both
// directions: it reports a file that mentions the operation and does not report
// one that does not. Without this, a derivation that returned nothing would
// satisfy the real guard below.
func TestMoveOperationDerivationWorks(t *testing.T) {
	dir := t.TempDir()
	with := filepath.Join(dir, "with.go")
	if err := os.WriteFile(with, []byte("package id1\n\nvar op = Mov\n"), 0644); err != nil {
		t.Fatalf("writing synthetic source: %v", err)
	}
	without := filepath.Join(dir, "without.go")
	if err := os.WriteFile(without, []byte("package id1\n\nvar op = Get\n"), 0644); err != nil {
		t.Fatalf("writing synthetic source: %v", err)
	}
	got := filesNamingTheMoveOperation(t, []string{with, without})
	if len(got) != 1 || got[0] != "with.go" {
		t.Errorf("derivation must report exactly with.go, got %v", got)
	}
}

// TestMoveOperationIsNamedOnlyByTheExpectedFiles pins why move() may check only
// containment on its source. Each file below names the Mov operation and
// reaches execution through ExecAs: cmd.go builds one (CmdMov) and runs every
// command through the switch in execUnauthorised, cmd_op.go holds the operation
// tables, and req.go turns an X-Move-To header into one. A new file that names
// the operation fails here, and whoever adds it must first confirm the command
// it builds reaches move() only through ExecAs, then add the file to the list.
func TestMoveOperationIsNamedOnlyByTheExpectedFiles(t *testing.T) {
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("listing source files: %v", err)
	}
	sources := []string{}
	for _, path := range paths {
		if !strings.HasSuffix(path, "_test.go") {
			sources = append(sources, path)
		}
	}
	if len(sources) < 20 {
		t.Fatalf("derived only %d non-test source files; the derivation is broken", len(sources))
	}

	got := filesNamingTheMoveOperation(t, sources)

	want := []string{"cmd.go", "cmd_op.go", "req.go"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("the files naming the Mov operation changed\n got: %v\nwant: %v", got, want)
	}
}
