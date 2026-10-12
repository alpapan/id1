// apps/id1/exec_entry_points_test.go
//
// group: auth
// tags: authorization, dispatch, testing
// summary: Tests that only in-process constructors, and ExecAs itself, run a command without authorising.
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
	"strings"
	"testing"
)

// unauthorisedExecName is the method that runs a command with no authorisation.
const unauthorisedExecName = "execUnauthorised"

// inProcessConstructors names the constructors whose direct call on the result
// is allowed without ExecAs. The guard checks call shape only: a call of the
// unauthorised method on a constructor result or on the receiver inside ExecAs
// passes, and every other call is flagged. A Command held in a variable, such
// as one parsed from a request, a socket frame or a file, must run through ExecAs.
var inProcessConstructors = map[string]bool{
	"CmdGet":  true,
	"CmdSet":  true,
	"CmdDel":  true,
	"CmdList": true,
}

// unauthorisedExecCalls parses one Go source file and returns a description of
// every call to the unauthorised method whose receiver is NOT an in-process
// constructor call (and is not the receiver inside ExecAs in cmd.go), together
// with the number of calls that are allowed.
func unauthorisedExecCalls(t *testing.T, path string) ([]string, int) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	base := filepath.Base(path)
	violations := []string{}
	allowed := 0
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 0 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != unauthorisedExecName {
			return true
		}
		if inner, isCall := sel.X.(*ast.CallExpr); isCall {
			if ctor, isIdent := inner.Fun.(*ast.Ident); isIdent && inProcessConstructors[ctor.Name] {
				allowed++
				return true
			}
		}
		if recv, isIdent := sel.X.(*ast.Ident); isIdent && recv.Name == "t" && base == "cmd.go" {
			allowed++
			return true
		}
		violations = append(violations, base+": "+types.ExprString(sel.X))
		return true
	})
	return violations, allowed
}

// TestExecutionEntryPointsDerivationWorks proves the parser reads the file in
// both directions: it flags a receiver that is a variable and it does not flag
// a constructor call. Without this, a derivation that returned nothing would
// satisfy the real guard below.
func TestExecutionEntryPointsDerivationWorks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.go")
	if err := os.WriteFile(path, []byte(`package id1

func sample(cmd Command, k Id1Key) {
	cmd.execUnauthorised()
	CmdGet(k).execUnauthorised()
}
`), 0644); err != nil {
		t.Fatalf("writing synthetic source: %v", err)
	}
	violations, allowed := unauthorisedExecCalls(t, path)
	if len(violations) != 1 || violations[0] != "sample.go: cmd" {
		t.Errorf("derivation must flag exactly the variable receiver, got %v", violations)
	}
	if allowed != 1 {
		t.Errorf("derivation must allow exactly the constructor call, allowed %d", allowed)
	}
}

func TestExecutionEntryPointsAreOnlyInProcessConstructorsAndExecAs(t *testing.T) {
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("listing source files: %v", err)
	}
	scanned := 0
	allowedTotal := 0
	violations := []string{}
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		scanned++
		found, allowed := unauthorisedExecCalls(t, path)
		violations = append(violations, found...)
		allowedTotal += allowed
	}
	if scanned < 20 {
		t.Fatalf("derived only %d non-test source files; the derivation is broken", scanned)
	}
	if allowedTotal < 25 {
		t.Fatalf("derived only %d allowed calls; the derivation is broken or the call sites were removed", allowedTotal)
	}
	if len(violations) != 0 {
		t.Errorf("a command from a request, a socket frame or a file must run through ExecAs, not the unauthorised method; found %v", violations)
	}
}
