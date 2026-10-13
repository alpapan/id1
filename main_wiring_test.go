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
	listenHandlers []string // source text of the second argument of each http.ListenAndServe call
	serverHandlers []string // one entry per http.Server literal: source text of its Handler, "" if unset
	handlePatterns []string // the pattern of each http.HandleFunc and http.Handle call
}

func readMainWiring(t *testing.T, path string) mainWiring {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	var wiring mainWiring
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			if len(node.Lhs) == 1 && len(node.Rhs) == 1 {
				if call, ok := node.Rhs[0].(*ast.CallExpr); ok && types.ExprString(call.Fun) == "id1.LimitBody" {
					if ident, ok := node.Lhs[0].(*ast.Ident); ok {
						wiring.limitedName = ident.Name
					}
				}
			}
		case *ast.CallExpr:
			switch types.ExprString(node.Fun) {
			case "id1.LimitBody":
				wiring.limitBodyCalls++
			case "http.ListenAndServe":
				if len(node.Args) == 2 {
					wiring.listenHandlers = append(wiring.listenHandlers, types.ExprString(node.Args[1]))
				}
			case "http.HandleFunc", "http.Handle":
				if len(node.Args) == 2 {
					if lit, ok := node.Args[0].(*ast.BasicLit); ok {
						if pattern, unquoteErr := strconv.Unquote(lit.Value); unquoteErr == nil {
							wiring.handlePatterns = append(wiring.handlePatterns, pattern)
						}
					}
				}
			}
		case *ast.CompositeLit:
			if node.Type != nil && types.ExprString(node.Type) == "http.Server" {
				handler := ""
				for _, element := range node.Elts {
					if pair, ok := element.(*ast.KeyValueExpr); ok && types.ExprString(pair.Key) == "Handler" {
						handler = types.ExprString(pair.Value)
					}
				}
				wiring.serverHandlers = append(wiring.serverHandlers, handler)
			}
		}
		return true
	})
	return wiring
}

// TestMainWiringDerivationWorks proves the parser reads a file in both
// directions: it reports a wrapped and an unwrapped server alike. Without it,
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
}
`
	if err := os.WriteFile(path, []byte(source), 0o644); err != nil {
		t.Fatalf("writing synthetic source: %v", err)
	}
	got := readMainWiring(t, path)
	want := mainWiring{
		limitBodyCalls: 1,
		limitedName:    "limited",
		listenHandlers: []string{"limited", "nil"},
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
		t.Error("main.go_ must assign the result of id1.LimitBody(...) to a variable that both server branches use")
	}
	if len(wiring.listenHandlers) == 0 {
		t.Error("derived no http.ListenAndServe call from main.go_; the derivation is broken or the plaintext branch is absent")
	}
	for _, handler := range wiring.listenHandlers {
		if wiring.limitedName == "" || handler != wiring.limitedName {
			t.Errorf("http.ListenAndServe must be given the wrapped handler, got %q", handler)
		}
	}
	if len(wiring.serverHandlers) == 0 {
		t.Error("derived no http.Server literal from main.go_; the derivation is broken or the TLS branch is absent")
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
