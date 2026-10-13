// apps/id1/auth_single_evaluation_test.go
//
// group: auth
// tags: authorization, dispatch, testing
// summary: Tests that no function evaluates auth and then also runs ExecAs, which evaluates it again.
//
//

package id1

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"strings"
	"testing"
)

// TestNoFunctionAuthorisesThenExecAs - ExecAs runs auth itself, so a function
// that calls auth and then ExecAs evaluates the same authorisation twice per
// request. A dispatcher calls ExecAs and reacts to ErrUnauthorised instead.
func TestNoFunctionAuthorisesThenExecAs(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse package: %v", err)
	}
	pkg, ok := pkgs["id1"]
	if !ok {
		t.Fatalf("package id1 not found among %d parsed packages", len(pkgs))
	}

	execAsCallers := 0
	for fileName, file := range pkg.Files {
		for _, decl := range file.Decls {
			fn, isFunc := decl.(*ast.FuncDecl)
			if !isFunc || fn.Body == nil {
				continue
			}
			callsAuth, callsExecAs := false, false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, isCall := n.(*ast.CallExpr)
				if !isCall {
					return true
				}
				switch f := call.Fun.(type) {
				case *ast.Ident:
					if f.Name == "auth" {
						callsAuth = true
					}
				case *ast.SelectorExpr:
					if f.Sel.Name == "ExecAs" {
						callsExecAs = true
					}
				}
				return true
			})
			if callsExecAs {
				execAsCallers++
			}
			if callsAuth && callsExecAs {
				t.Errorf("%s: %s calls both auth and ExecAs, so it authorises twice", fileName, fn.Name.Name)
			}
		}
	}
	if execAsCallers < 3 {
		t.Errorf("found %d functions calling ExecAs, want at least the 3 dispatchers; the scan is not seeing them", execAsCallers)
	}
}
