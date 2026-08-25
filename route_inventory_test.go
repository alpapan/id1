package id1

// Route inventory: every HTTP path this repository can register must appear in
// the allow-list below, classified by how it is exposed.
//
// Why this guard exists. All 18 of id1's route registrations live in main.go_,
// whose trailing underscore hides it from the Go toolchain: `go list` does not
// name it, `go build ./...` does not compile it, and `go test ./...` cannot
// reach it. Two more registrations live in the build-tagged files demo_on.go
// and testmint_on.go, which an untagged build also leaves out. The result is
// that the boundary between id1's public surface and its internal-only surface
// - the difference between a browser reaching an endpoint and only an
// in-cluster caller reaching it - was enforced by nothing but a reader noticing.
//
// Why this is a plain test and not an integration one. It reads source and
// parses it; it neither compiles main.go_ nor starts a server, so it needs no
// binary, no network and no build tag. That lets it run in the default
// `go test ./...` and therefore in the pre-commit hook, which is where a new
// route is actually added. main_integration_test.go remains the layer that
// asserts runtime behaviour of individual routes; this one asserts the
// inventory.
//
// The inventory is DERIVED by walking every non-test Go source file in the
// package directory and parsing it, not read from a list of filenames: a route
// added to a file that does not exist today is still found. A registration
// whose path is not a plain string literal is refused rather than skipped, so
// a computed path fails the guard instead of slipping past it. The derivation
// and the comparison are both exercised against synthetic trees below, so this
// guard has demonstrated it can fail rather than only ever having passed.
//
// Two limits, stated rather than papered over. The walk is syntactic, so a
// route registered through an indirection this file cannot see - a handler
// table built at run time, a path assembled from a constant in another package
// - is outside it. And the walk is flat; a subpackage would escape it, which is
// why assertNoSubpackageEscapesTheWalk fails instead of reporting green.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// exposure records how a registered path is reachable. Adding a route forces a
// deliberate choice here, which is the point: an internal endpoint that lands
// on the public list is the failure this file exists to prevent.
type exposure int

const (
	// exposurePublic: on Curatorium's Traefik public route list, so the open
	// internet reaches it. Every one of these must authenticate its own caller.
	exposurePublic exposure = iota
	// exposureInternal: ClusterIP-only. No Traefik matcher reaches it, by an
	// exact path or by a prefix, and no Next.js rewrite names it.
	exposureInternal
	// exposureBuildTagged: compiled in only under a build tag, so a binary
	// built without that tag carries neither the route nor its handler.
	exposureBuildTagged
	// exposureEdgeFallThrough: not named by any matcher, but still reachable
	// from the edge, because two of Traefik's matchers are PathPrefix rather
	// than exact Path. A Go 1.22 ServeMux catch-all absorbs every forwarded
	// path no more specific pattern claims, so anything under /sync or
	// /auth/sovereign that id1 does not register by name arrives here - as does
	// /auth/logout, which next.config.mjs rewrites to id1 although id1
	// registers no such handler. The consequence is that this route's OWN
	// authentication is load-bearing rather than defence in depth: it is not
	// behind a closed perimeter, whatever its path looks like.
	exposureEdgeFallThrough
)

// wantRoutes is the declared inventory. A registration missing from here fails
// the test; an entry here with no registration fails it too.
var wantRoutes = map[string]exposure{
	// --- Public: Traefik routes these to id1. ---
	// The matchers are enumerated in config.py::_frontend_traefik_route_yaml:
	// PathPrefix /sync and /auth/sovereign, the exact paths /auth/orcid,
	// /auth/orcid/callback, /auth/refresh, /auth/sync_ticket and
	// /pub/jwks.json, and PathPrefix /nextcloud/remote.php/dav. There is no
	// /auth/* sweep, which is why the two build-tagged mints below are not
	// public despite sitting under /auth/, and only the WebDAV subpath of the
	// Nextcloud proxy is reachable rather than the whole prefix.
	"/auth/orcid":                     exposurePublic,
	"/auth/orcid/callback":            exposurePublic,
	"/auth/refresh":                   exposurePublic,
	"/auth/sync_ticket":               exposurePublic,
	"/auth/sovereign/token":           exposurePublic,
	"/auth/sovereign/register/begin":  exposurePublic,
	"/auth/sovereign/register/commit": exposurePublic,
	"/auth/sovereign/devices":         exposurePublic,
	"/pub/jwks.json":                  exposurePublic,
	"/sync":                           exposurePublic,
	"/sync/":                          exposurePublic,
	"/nextcloud":                      exposurePublic,
	"/nextcloud/":                     exposurePublic,

	// --- Internal: in-cluster callers only. ---
	// No matcher reaches these by an exact path OR by either PathPrefix, and no
	// Next.js rewrite names them. /internal/ sits under neither /sync nor
	// /auth/sovereign, so the prefix fall-through described below cannot reach
	// it. The two Nextcloud bridges and the trusted-provisioner registration are
	// additionally gated by X-ID1-Internal-Secret and mTLS respectively, but the
	// gate is the second line of defence; not being routed is the first.
	"/internal/nc-token":           exposureInternal,
	"/internal/nc-provision":       exposureInternal,
	"/internal/sovereign/register": exposureInternal,
	// Kubernetes probe target. Returns a fixed status object and no identity.
	"/health": exposureInternal,

	// --- Reachable from the edge as a prefix fall-through. ---
	// The key/value catch-all, registered last so every pattern above wins;
	// without it the key/value protocol has no handler at all. It is NOT behind
	// a closed perimeter: see exposureEdgeFallThrough. Its own gate is what
	// stands in front of the KV store - auth() in auth.go, which answers 404 for
	// an unknown id, 401 with a challenge for a known one, and grants a read
	// only for an owner or a {id}/pub/ path.
	"/{key...}": exposureEdgeFallThrough,

	// --- Build-tagged: absent from a binary built without the tag. ---
	// testmint: mints an RS256 token for an arbitrary ORCID iD, and even with
	// the tag it registers only when ENV is dev or test.
	"/auth/test_user": exposureBuildTagged,
	// curatoriumdemo: the anonymous demo identity, reached only through the
	// frontend's rate-limited in-cluster proxy.
	"/auth/unauth_demo": exposureBuildTagged,
}

// registration is one derived route: the path pattern and the file it came from.
type registration struct {
	pattern string
	file    string
}

// collectRegistrations parses every non-test Go source file in dir and returns
// the HTTP path patterns they register.
//
// main.go_ is carried deliberately - it is the file the toolchain cannot see
// and therefore the whole reason for this walk. A registration whose path is
// not a string literal returns an error: the guard must not silently skip the
// one shape that would let a route in unclassified.
func collectRegistrations(dir string) ([]registration, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}

	var found []registration
	var failure error
	fset := token.NewFileSet()
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, ".go_") {
			continue
		}
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", name, err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			isRegistration, refuseNonLiteral := isRegistrationCall(selector, call)
			if !isRegistration || len(call.Args) == 0 {
				return true
			}
			literal, ok := call.Args[0].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				if !refuseNonLiteral {
					return true
				}
				if failure == nil {
					failure = fmt.Errorf(
						"%s registers a route with a non-literal path at %s: this guard cannot "+
							"classify a computed path, which is exactly what it must not miss",
						name, fset.Position(call.Lparen),
					)
				}
				return false
			}
			pattern, unquoteErr := strconv.Unquote(literal.Value)
			if unquoteErr != nil {
				if failure == nil {
					failure = fmt.Errorf("%s: unquote %s: %w", name, literal.Value, unquoteErr)
				}
				return false
			}
			found = append(found, registration{pattern: pattern, file: name})
			return true
		})
	}
	if failure != nil {
		return nil, failure
	}
	return found, nil
}

// isRegistrationCall reports whether a selector call registers an HTTP handler,
// and whether a non-literal path in it should be refused rather than ignored.
//
// HandleFunc on any receiver is a registration: it is http.HandleFunc on the
// default mux in main.go_ and mux.HandleFunc on an injected one in the
// build-tagged files.
//
// Handle is harder, because id1's own Handle - the key/value entrypoint - and
// webSocketHandler.Handle share the name while registering nothing. The
// discriminator is the call's SHAPE, not the receiver's name: a registration is
// Handle(pattern, handler), exactly two arguments with a string literal first.
// Keying on the receiver instead would miss router.Handle or srv.Handle, which
// is the "the gap and the guard get drawn by the same incomplete mental model"
// failure a derived guard exists to avoid.
//
// One case cannot be settled from syntax alone: Handle with two arguments whose
// first is NOT a string literal is either a computed route path or one of id1's
// own two-argument Handle calls. Where the receiver does name an http or mux
// value, treat it as a computed path and refuse; otherwise ignore it. That
// keeps the receiver heuristic only for choosing what to refuse, never for
// choosing what to count.
func isRegistrationCall(selector *ast.SelectorExpr, call *ast.CallExpr) (isRegistration, refuseNonLiteral bool) {
	switch selector.Sel.Name {
	case "HandleFunc":
		return true, true
	case "Handle":
		if len(call.Args) != 2 {
			return false, false
		}
		if literal, ok := call.Args[0].(*ast.BasicLit); ok && literal.Kind == token.STRING {
			return true, true
		}
		receiver, ok := selector.X.(*ast.Ident)
		if ok && (receiver.Name == "http" || strings.Contains(strings.ToLower(receiver.Name), "mux")) {
			return true, true
		}
		return false, false
	default:
		return false, false
	}
}

// undeclaredRoutes returns the patterns registered but absent from wantRoutes.
func undeclaredRoutes(found []registration) []string {
	var undeclared []string
	for _, registered := range found {
		if _, declared := wantRoutes[registered.pattern]; !declared {
			undeclared = append(undeclared, registered.pattern+" (registered in "+registered.file+")")
		}
	}
	sort.Strings(undeclared)
	return undeclared
}

// packageRegistrations derives the real package's routes and applies the
// canaries. A walk that matched nothing would make every assertion below pass
// vacuously, and the commonest cause - main.go_ renamed, moved, or finally
// promoted to a real .go file elsewhere - is precisely the condition that would
// otherwise silence this guard for good.
func packageRegistrations(t *testing.T) []registration {
	t.Helper()
	dir, err := os.Getwd() // `go test` runs in the package directory.
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "main.go_")); err != nil {
		t.Fatalf("main.go_ not found in %s: %v; the walk cannot see id1's routes", dir, err)
	}
	found, err := collectRegistrations(dir)
	if err != nil {
		t.Fatalf("derive routes from %s: %v", dir, err)
	}
	// The floor is the declared inventory's own size: 18 registrations in
	// main.go_ plus one each in demo_on.go and testmint_on.go. Set below that,
	// a deletion of several routes would leave the canary satisfied and rest
	// entirely on the registered-nowhere check.
	if len(found) < len(wantRoutes) {
		t.Fatalf("implausibly few route registrations derived: %d, want at least %d", len(found), len(wantRoutes))
	}
	assertNoSubpackageEscapesTheWalk(t, dir)
	return found
}

// assertNoSubpackageEscapesTheWalk enforces the precondition the flat walk
// rests on: id1 is one package, every source file sitting directly in this
// directory. A subpackage added later could register routes the walk above
// would never see, and the walk would keep reporting green over them - so the
// layout change fails here instead, where the message says what to do about it.
func assertNoSubpackageEscapesTheWalk(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	for _, entry := range entries {
		name := entry.Name()
		// Tooling and build output, not Go source: .git, .pixi, .audit, scripts.
		if !entry.IsDir() || strings.HasPrefix(name, ".") {
			continue
		}
		sub, err := os.ReadDir(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		for _, child := range sub {
			if strings.HasSuffix(child.Name(), ".go") || strings.HasSuffix(child.Name(), ".go_") {
				t.Fatalf(
					"%s/%s holds Go source, but this guard walks only %s. Make the walk "+
						"recursive before adding a subpackage, or its routes go unchecked.",
					name, child.Name(), dir,
				)
			}
		}
	}
}

func TestRegisteredRoutesMatchTheDeclaredInventory(t *testing.T) {
	found := packageRegistrations(t)

	if undeclared := undeclaredRoutes(found); len(undeclared) > 0 {
		t.Errorf(
			"routes registered but not declared in wantRoutes: %v\n"+
				"Add each with its exposure. A route reachable from the internet is "+
				"exposurePublic and must authenticate its own caller.",
			undeclared,
		)
	}

	registered := map[string]bool{}
	for _, one := range found {
		registered[one.pattern] = true
	}
	var missing []string
	for pattern := range wantRoutes {
		if !registered[pattern] {
			missing = append(missing, pattern)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("declared in wantRoutes but registered nowhere: %v", missing)
	}
}

func TestEveryInternalPrefixedRouteIsClassifiedInternal(t *testing.T) {
	// The /internal/ prefix is what keeps a path off Traefik's route list, so a
	// route under it that the inventory calls public is a contradiction one of
	// the two sides has to lose.
	for pattern, how := range wantRoutes {
		if strings.HasPrefix(pattern, "/internal/") && how != exposureInternal {
			t.Errorf("%s is under /internal/ but is not classified exposureInternal", pattern)
		}
	}
}

func TestTheKeyValueCatchAllIsRegistered(t *testing.T) {
	// Every specific pattern depends on this one existing to fall back to;
	// without it an unmatched path 404s from the mux rather than reaching the
	// key/value protocol, which is the difference between "no such key" and "no
	// such endpoint" for every client.
	for _, registered := range packageRegistrations(t) {
		if registered.pattern == "/{key...}" {
			return
		}
	}
	t.Fatal("the /{key...} key-value catch-all is not registered")
}

// writeSyntheticPackage lays out a temporary directory holding the named files
// and returns its path.
func writeSyntheticPackage(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, source := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

// TestRouteDerivationFailsOnASyntheticViolation is the mutation proof. A guard
// only ever run against clean source has never demonstrated it can fail, and
// this file's assertions are otherwise green by construction because the
// inventory was written from the tree it checks.
func TestRouteDerivationFailsOnASyntheticViolation(t *testing.T) {
	t.Run("a_route_absent_from_the_inventory_is_reported", func(t *testing.T) {
		dir := writeSyntheticPackage(t, map[string]string{
			"main.go_": `package main

import "net/http"

func main() {
	http.HandleFunc("/internal/rogue-endpoint", nil)
	http.HandleFunc("/health", nil)
}
`,
		})
		found, err := collectRegistrations(dir)
		if err != nil {
			t.Fatalf("collect: %v", err)
		}
		undeclared := undeclaredRoutes(found)
		if len(undeclared) != 1 || !strings.HasPrefix(undeclared[0], "/internal/rogue-endpoint ") {
			t.Fatalf("undeclared route not reported; got %v", undeclared)
		}
	})

	t.Run("a_route_registered_on_an_injected_mux_is_found", func(t *testing.T) {
		// demo_on.go and testmint_on.go register this way rather than on the
		// default mux, so a derivation that only recognised http.HandleFunc
		// would miss both anonymous mint endpoints.
		dir := writeSyntheticPackage(t, map[string]string{
			"tagged.go": `package id1

import "net/http"

func RegisterX(mux *http.ServeMux) {
	mux.HandleFunc("/auth/some_mint", nil)
}
`,
		})
		found, err := collectRegistrations(dir)
		if err != nil {
			t.Fatalf("collect: %v", err)
		}
		if len(found) != 1 || found[0].pattern != "/auth/some_mint" {
			t.Fatalf("mux registration not derived; got %v", found)
		}
	})

	t.Run("Handle_on_an_arbitrarily_named_receiver_is_found", func(t *testing.T) {
		// The receiver name is not the discriminator; the call's shape is.
		// Keying on a name would let router.Handle or srv.Handle register a
		// route the derivation never sees.
		dir := writeSyntheticPackage(t, map[string]string{
			"main.go_": `package main

import "net/http"

func main() {
	router := http.NewServeMux()
	router.Handle("/internal/x", nil)
	srv.Handle("/internal/y", nil)
}
`,
		})
		found, err := collectRegistrations(dir)
		if err != nil {
			t.Fatalf("collect: %v", err)
		}
		patterns := map[string]bool{}
		for _, one := range found {
			patterns[one.pattern] = true
		}
		if !patterns["/internal/x"] || !patterns["/internal/y"] {
			t.Fatalf("Handle on a non-mux-named receiver was not derived; got %v", found)
		}
	})

	t.Run("a_computed_path_is_refused_rather_than_skipped", func(t *testing.T) {
		dir := writeSyntheticPackage(t, map[string]string{
			"main.go_": `package main

import "net/http"

func main() {
	prefix := "/internal"
	http.HandleFunc(prefix+"/hidden", nil)
}
`,
		})
		if _, err := collectRegistrations(dir); err == nil {
			t.Fatal("a computed route path was accepted; the guard can be evaded")
		}
	})

	t.Run("a_test_file_is_not_scanned", func(t *testing.T) {
		// Test files stand up their own httptest muxes on arbitrary paths.
		// Counting those would flood the inventory with paths no binary serves.
		dir := writeSyntheticPackage(t, map[string]string{
			"thing_test.go": `package id1

import "net/http"

func helper(mux *http.ServeMux) {
	mux.HandleFunc("/only-in-a-test", nil)
}
`,
		})
		found, err := collectRegistrations(dir)
		if err != nil {
			t.Fatalf("collect: %v", err)
		}
		if len(found) != 0 {
			t.Fatalf("a test file was scanned; got %v", found)
		}
	})

	t.Run("the_key_value_entrypoint_is_not_mistaken_for_a_registration", func(t *testing.T) {
		// id1.Handle(dbpath, ctx) and wsHandler.Handle(w, r) share the name
		// with http.Handle but register nothing.
		dir := writeSyntheticPackage(t, map[string]string{
			"caller.go": `package id1

func caller(dbpath string, ctx interface{}, h interface{ Handle(a, b int) }) {
	_ = id1.Handle(dbpath, ctx)
	h.Handle(1, 2)
}
`,
		})
		found, err := collectRegistrations(dir)
		if err != nil {
			t.Fatalf("collect: %v", err)
		}
		if len(found) != 0 {
			t.Fatalf("a non-registration Handle call was counted; got %v", found)
		}
	})
}
