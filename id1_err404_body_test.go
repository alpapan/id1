// apps/id1/id1_err404_body_test.go
//
// group: server
// tags: http, disclosure, testing
// summary: Tests that Handle never puts an error message in a 404 body.
//
//

package id1

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"testing"
)

// err404Messages parses one Go source file and returns, for every call to
// err404(w, message), the source text of the message argument, together with
// the number of such calls.
func err404Messages(t *testing.T, path string) ([]string, int) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	messages := []string{}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		fn, ok := call.Fun.(*ast.Ident)
		if !ok || fn.Name != "err404" || len(call.Args) != 2 {
			return true
		}
		messages = append(messages, types.ExprString(call.Args[1]))
		return true
	})
	return messages, len(messages)
}

// TestHandleErr404DerivationWorks proves the parser reads the file in both
// directions: it reports a call that carries a message and it reports an
// empty-string call as exactly that. Without this, a derivation that returned
// nothing would satisfy the real guard below.
func TestHandleErr404DerivationWorks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.go")
	if err := os.WriteFile(path, []byte(`package id1

func sample(w int, keyErr error) {
	err404(w, "")
	err404(w, keyErr.Error())
}
`), 0644); err != nil {
		t.Fatalf("writing synthetic source: %v", err)
	}
	got, count := err404Messages(t, path)
	if count != 2 {
		t.Fatalf("synthetic source holds 2 err404 calls, derived %d: %v", count, got)
	}
	if got[0] != `""` || got[1] != "keyErr.Error()" {
		t.Errorf("derived messages %v, want [\"\" keyErr.Error()]", got)
	}
}

func TestHandleErr404NeverCarriesAMessage(t *testing.T) {
	messages, count := err404Messages(t, "id1.go")
	if count < 4 {
		t.Fatalf("derived only %d err404 calls from id1.go; the derivation is broken or the calls were removed", count)
	}
	for _, message := range messages {
		if message != `""` {
			t.Errorf("err404 in id1.go must pass an empty message, found %s", message)
		}
	}
}
