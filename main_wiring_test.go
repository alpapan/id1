// apps/id1/main_wiring_test.go
//
// group: server
// tags: http, limits, main, testing
// summary: Tests that main.go_ serves a LimitBody-wrapped mux and that the raise table names registered routes.
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
	"reflect"
	"strconv"
	"testing"
)

// mainWiring is what a parse of a main file shows about how the server is started.
type mainWiring struct {
	limitBodyCalls int
	limitedName    string   // the identifier assigned the result of id1.LimitBody(...), "" if none
	servedHandlers []string // one entry per serving call, in source order: the handler that call serves (see readMainWiring)
	serverHandlers []string // one entry per http.Server literal: source text of its Handler, "" if unset
	handlePatterns []string // the pattern of each http.HandleFunc and http.Handle call
}

// isHTTPServerLiteral reports whether expr is `&http.Server{...}` or `http.Server{...}`.
func isHTTPServerLiteral(expr ast.Expr) (*ast.CompositeLit, bool) {
	if unary, ok := expr.(*ast.UnaryExpr); ok && unary.Op == token.AND {
		expr = unary.X
	}
	lit, ok := expr.(*ast.CompositeLit)
	if !ok || lit.Type == nil || types.ExprString(lit.Type) != "http.Server" {
		return nil, false
	}
	return lit, true
}

// serverLiteralHandler returns the source text of the Handler field of an http.Server literal, "" if unset.
func serverLiteralHandler(lit *ast.CompositeLit) string {
	handler := ""
	for _, element := range lit.Elts {
		if pair, ok := element.(*ast.KeyValueExpr); ok && types.ExprString(pair.Key) == "Handler" {
			handler = types.ExprString(pair.Value)
		}
	}
	return handler
}

// readMainWiring parses a main file. servedHandlers gets one entry for each call that
// starts serving: for http.ListenAndServe, http.Serve, http.ListenAndServeTLS and
// http.ServeTLS it is the source text of the handler argument; for a Serve, ServeTLS,
// ListenAndServe or ListenAndServeTLS method call on a variable assigned from an
// http.Server literal it is that literal's Handler; for the same method call on any
// other receiver it is "?" followed by the receiver text, so an unrecognised receiver
// can never pass the guard.
func readMainWiring(t *testing.T, path string) mainWiring {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	var wiring mainWiring
	serverVars := map[string]string{} // variable name -> Handler text of the http.Server literal assigned to it
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			if len(node.Lhs) == 1 && len(node.Rhs) == 1 {
				if call, ok := node.Rhs[0].(*ast.CallExpr); ok && types.ExprString(call.Fun) == "id1.LimitBody" {
					if ident, ok := node.Lhs[0].(*ast.Ident); ok {
						wiring.limitedName = ident.Name
					}
				}
				if lit, ok := isHTTPServerLiteral(node.Rhs[0]); ok {
					if ident, ok := node.Lhs[0].(*ast.Ident); ok {
						serverVars[ident.Name] = serverLiteralHandler(lit)
					}
				}
			}
		case *ast.CallExpr:
			name := types.ExprString(node.Fun)
			switch name {
			case "id1.LimitBody":
				wiring.limitBodyCalls++
			case "http.ListenAndServe", "http.Serve", "http.ListenAndServeTLS", "http.ServeTLS":
				handlerIndex := 1
				if name == "http.ListenAndServeTLS" {
					handlerIndex = 3
				}
				if len(node.Args) > handlerIndex {
					wiring.servedHandlers = append(wiring.servedHandlers, types.ExprString(node.Args[handlerIndex]))
				}
			case "http.HandleFunc", "http.Handle":
				if len(node.Args) == 2 {
					if lit, ok := node.Args[0].(*ast.BasicLit); ok {
						if pattern, unquoteErr := strconv.Unquote(lit.Value); unquoteErr == nil {
							wiring.handlePatterns = append(wiring.handlePatterns, pattern)
						}
					}
				}
			default:
				if selector, ok := node.Fun.(*ast.SelectorExpr); ok {
					switch selector.Sel.Name {
					case "Serve", "ServeTLS", "ListenAndServe", "ListenAndServeTLS":
						receiver := types.ExprString(selector.X)
						if handler, known := serverVars[receiver]; known {
							wiring.servedHandlers = append(wiring.servedHandlers, handler)
						} else {
							wiring.servedHandlers = append(wiring.servedHandlers, "?"+receiver)
						}
					}
				}
			}
		case *ast.CompositeLit:
			if lit, ok := isHTTPServerLiteral(node); ok {
				wiring.serverHandlers = append(wiring.serverHandlers, serverLiteralHandler(lit))
			}
		}
		return true
	})
	return wiring
}

// TestMainWiringDerivationWorks proves the parser reads a file in both
// directions: it reports a wrapped and an unwrapped server alike, through the
// package functions and through methods on an http.Server variable. Without it,
// a derivation that returned nothing would satisfy the real guards below.
func TestMainWiringDerivationWorks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "main.go_")
	source := `package main

func main() {
	http.HandleFunc("/a", h)
	http.Handle("/b", h)
	limited := id1.LimitBody(http.DefaultServeMux, id1.IngressBodyLimits())
	wrapped := &http.Server{Addr: "x", Handler: limited}
	bare := &http.Server{Addr: "y"}
	unwrapped := &http.Server{Addr: "w", Handler: http.DefaultServeMux}
	http.ListenAndServe("z", limited)
	http.ListenAndServe("z", nil)
	http.Serve(l, limited)
	http.ServeTLS(l, nil, "", "")
	http.ListenAndServeTLS("z", "c", "k", limited)
	wrapped.ServeTLS(l, "", "")
	wrapped.ListenAndServe()
	bare.Serve(l)
	unwrapped.Serve(l)
	stranger.Serve(l)
}
`
	if err := os.WriteFile(path, []byte(source), 0o644); err != nil {
		t.Fatalf("writing synthetic source: %v", err)
	}
	got := readMainWiring(t, path)
	want := mainWiring{
		limitBodyCalls: 1,
		limitedName:    "limited",
		servedHandlers: []string{"limited", "nil", "limited", "nil", "limited", "limited", "limited", "", "http.DefaultServeMux", "?stranger"},
		serverHandlers: []string{"limited", "", "http.DefaultServeMux"},
		handlePatterns: []string{"/a", "/b"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("derived %+v, want %+v", got, want)
	}
}

func TestMainWrapsTheServerHandlerWithLimitBody(t *testing.T) {
	wiring := readMainWiring(t, "main.go_")
	if wiring.limitBodyCalls != 1 {
		t.Errorf("main.go_ must call id1.LimitBody exactly once, found %d", wiring.limitBodyCalls)
	}
	if wiring.limitedName == "" {
		t.Error("main.go_ must assign the result of id1.LimitBody(...) to a variable that every serving call uses")
	}
	if len(wiring.servedHandlers) == 0 {
		t.Error("derived no serving call (Serve, ServeTLS, ListenAndServe or ListenAndServeTLS) from main.go_; the derivation is broken or the server is never started")
	}
	for _, handler := range wiring.servedHandlers {
		if wiring.limitedName == "" || handler != wiring.limitedName {
			t.Errorf("every serving call in main.go_ must serve the wrapped handler, got %q", handler)
		}
	}
	if len(wiring.serverHandlers) == 0 {
		t.Error("derived no http.Server literal from main.go_; the derivation is broken or the server is built another way")
	}
	for _, handler := range wiring.serverHandlers {
		if wiring.limitedName == "" || handler != wiring.limitedName {
			t.Errorf("every http.Server literal in main.go_ must set Handler to the wrapped mux, got %q", handler)
		}
	}
}

func TestIngressBodyLimitKeysAreRegisteredInMain(t *testing.T) {
	wiring := readMainWiring(t, "main.go_")
	if len(wiring.handlePatterns) < 5 {
		t.Fatalf("derived only %d registered patterns from main.go_; the derivation is broken", len(wiring.handlePatterns))
	}
	registered := map[string]bool{}
	for _, pattern := range wiring.handlePatterns {
		registered[pattern] = true
	}
	for pattern := range IngressBodyLimits() {
		if !registered[pattern] {
			t.Errorf("IngressBodyLimits names %q but main.go_ never registers it, so the entry raises nothing", pattern)
		}
	}
}
