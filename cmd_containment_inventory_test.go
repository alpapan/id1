package id1

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"testing"
)

// deriveOpNamesFromSource parses a Go source file and returns the string keys
// of its package-level `nameOp` map literal.
//
// The list is derived from production source rather than written out here on
// purpose: a hardcoded list cannot notice the operation that a future author
// forgets to make containment-safe, which is precisely the failure this file
// exists to catch.
func deriveOpNamesFromSource(t *testing.T, path string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	names := []string{}
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for i, ident := range vs.Names {
			if ident.Name != "nameOp" || i >= len(vs.Values) {
				continue
			}
			cl, ok := vs.Values[i].(*ast.CompositeLit)
			if !ok {
				continue
			}
			for _, elt := range cl.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				bl, ok := kv.Key.(*ast.BasicLit)
				if !ok || bl.Kind != token.STRING {
					continue
				}
				s, unqErr := strconv.Unquote(bl.Value)
				if unqErr != nil {
					t.Fatalf("unquoting %s in %s: %v", bl.Value, path, unqErr)
				}
				names = append(names, s)
			}
		}
		return true
	})
	sort.Strings(names)
	return names
}

// inventoryHostileKey assembles a traversal key as a struct literal. K() would
// refuse to build one, which is the point: this simulates a future second
// constructor or a hand-assembled key reaching an operation.
func inventoryHostileKey() Id1Key {
	return Id1Key{
		Id:       "mallory",
		Name:     "salt",
		Parent:   "mallory/../victim/priv",
		Pub:      false,
		Segments: []string{"mallory", "..", "victim", "priv", "salt"},
	}
}

// TestOpContainmentInventoryDerivationWorks proves the parser actually reads
// the file, in both directions: it finds an operation that is present, and it
// does not invent one that is absent. Without this, a derivation that returned
// an empty slice would satisfy every other assertion in this file.
func TestOpContainmentInventoryDerivationWorks(t *testing.T) {
	dir := t.TempDir()

	extra := filepath.Join(dir, "extra_op.go")
	if err := os.WriteFile(extra, []byte(`package id1

type Op int

const (
	Set Op = iota
	Wipe
)

var nameOp = map[string]Op{
	"set":  Set,
	"wipe": Wipe,
}
`), 0644); err != nil {
		t.Fatalf("writing synthetic source: %v", err)
	}
	got := deriveOpNamesFromSource(t, extra)
	if len(got) != 2 {
		t.Fatalf("synthetic source with 2 ops: derived %v", got)
	}
	foundWipe := false
	for _, n := range got {
		if n == "wipe" {
			foundWipe = true
		}
	}
	if !foundWipe {
		t.Errorf("derivation missed the synthetic %q operation: got %v", "wipe", got)
	}

	empty := filepath.Join(dir, "no_ops.go")
	if err := os.WriteFile(empty, []byte(`package id1

var somethingElse = map[string]int{"a": 1}
`), 0644); err != nil {
		t.Fatalf("writing synthetic source: %v", err)
	}
	if got := deriveOpNamesFromSource(t, empty); len(got) != 0 {
		t.Errorf("derivation invented operations from a file with no nameOp: %v", got)
	}
}

// TestOpContainmentInventory is the tripwire itself.
func TestOpContainmentInventory(t *testing.T) {
	names := deriveOpNamesFromSource(t, "cmd_op.go")

	if len(names) < 6 {
		t.Fatalf("derived only %d operations from cmd_op.go (%v); the derivation is broken or an operation was removed", len(names), names)
	}
	for _, want := range []string{"add", "del", "get", "list", "mov", "set"} {
		found := false
		for _, n := range names {
			if n == want {
				found = true
			}
		}
		if !found {
			t.Errorf("operation %q is missing from the derived inventory %v", want, names)
		}
	}

	for _, name := range names {
		opCode, known := nameOp[name]
		if !known {
			t.Errorf("derived operation %q has no entry in the runtime nameOp map", name)
			continue
		}
		t.Run(name, func(t *testing.T) {
			tmpDir := t.TempDir()
			originalDbpath := dbpath
			dbpath = tmpDir
			t.Cleanup(func() { dbpath = originalDbpath })

			victimDir := filepath.Join(tmpDir, "victim", "priv")
			if err := os.MkdirAll(victimDir, 0770); err != nil {
				t.Fatalf("seed: %v", err)
			}
			if err := os.WriteFile(filepath.Join(victimDir, "salt"), []byte("VICTIM-SALT"), 0644); err != nil {
				t.Fatalf("seed: %v", err)
			}

			cmd := NewCommand(opCode, inventoryHostileKey(),
				map[string]string{"x-id": "mallory"},
				[]byte("mallory/stolen"))

			_, err := cmd.Exec()
			if !errors.Is(err, ErrForbidden) {
				t.Errorf("operation %q must refuse a traversal key with ErrForbidden, got %v", name, err)
			}

			data, readErr := os.ReadFile(filepath.Join(victimDir, "salt"))
			if readErr != nil {
				t.Errorf("operation %q destroyed the victim's file: %v", name, readErr)
			} else if string(data) != "VICTIM-SALT" {
				t.Errorf("operation %q altered the victim's file: got %q", name, string(data))
			}
		})
	}
}
