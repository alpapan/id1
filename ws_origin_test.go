// apps/id1/ws_origin_test.go
//
// group: server
// tags: websocket, origin, security, testing
// summary: Tests that WebSocket upgrades are accepted only from the configured browser origin.
//
//

package id1

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const foreignWSOrigin = "https://evil.example"

// checkBrowserOriginCases are the Origin header shapes the rule is held to.
// values is the full list of Origin header values on the request; nil means no
// Origin header at all. Only an absent header and exactly one value equal to the
// configured origin may pass.
var checkBrowserOriginCases = []struct {
	name   string
	values []string
	want   bool
}{
	{"exact match", []string{testBrowserOrigin}, true},
	{"no origin header", nil, true},
	{"empty origin value", []string{""}, false},
	{"duplicated origin header", []string{testBrowserOrigin, testBrowserOrigin}, false},
	{"another site", []string{foreignWSOrigin}, false},
	{"configured origin as a prefix of another host", []string{"https://curatorium.example.evil.test"}, false},
	{"different scheme", []string{"http://curatorium.example"}, false},
	{"trailing slash", []string{testBrowserOrigin + "/"}, false},
	{"upper case", []string{"HTTPS://CURATORIUM.EXAMPLE"}, false},
	{"null origin", []string{"null"}, false},
}

func TestCheckBrowserOrigin(t *testing.T) {
	t.Setenv("CURATORIUM_BROWSER_ORIGIN", testBrowserOrigin)
	for _, tc := range checkBrowserOriginCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/sync", nil)
			if tc.values != nil {
				req.Header["Origin"] = tc.values
			}
			if got := checkBrowserOrigin(req); got != tc.want {
				t.Errorf("checkBrowserOrigin with Origin %q = %v, want %v", tc.values, got, tc.want)
			}
		})
	}
}

// TestCheckBrowserOriginCaseListIsComplete is the tripwire over the table
// above: dropping a row drops an assertion, so the list is asserted too.
func TestCheckBrowserOriginCaseListIsComplete(t *testing.T) {
	wantNames := []string{
		"exact match",
		"no origin header",
		"empty origin value",
		"duplicated origin header",
		"another site",
		"configured origin as a prefix of another host",
		"different scheme",
		"trailing slash",
		"upper case",
		"null origin",
	}
	if len(checkBrowserOriginCases) != len(wantNames) {
		t.Fatalf("case table has %d rows, want %d", len(checkBrowserOriginCases), len(wantNames))
	}
	for i, tc := range checkBrowserOriginCases {
		if tc.name != wantNames[i] {
			t.Errorf("case %d is %q, want %q", i, tc.name, wantNames[i])
		}
	}
}

// TestWebSocketRefusesForeignOrigin - an authenticated key/value upgrade that
// carries a foreign Origin must be refused with 403.
func TestWebSocketRefusesForeignOrigin(t *testing.T) {
	t.Setenv("CURATORIUM_BROWSER_ORIGIN", testBrowserOrigin)
	tmpDir := seedVictim(t)
	token := mustHMACToken(t, "alice")
	srv := startKVServer(t, tmpDir)

	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)
	header.Set("Origin", foreignWSOrigin)
	conn, resp, err := websocket.DefaultDialer.Dial(wsURLFor(srv, "/alice/inbox"), header)
	if err == nil {
		t.Cleanup(func() {
			conn.Close()
			sessionWG.Wait()
		})
		t.Fatalf("SECURITY: an upgrade from a foreign Origin was accepted")
	}
	if resp == nil {
		t.Fatalf("refused upgrade returned no HTTP response: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("a foreign-origin upgrade must answer 403, got %d", resp.StatusCode)
	}
}

// TestWebSocketAcceptsConfiguredOrigin is the control: the configured browser
// origin still opens the key/value socket.
func TestWebSocketAcceptsConfiguredOrigin(t *testing.T) {
	t.Setenv("CURATORIUM_BROWSER_ORIGIN", testBrowserOrigin)
	tmpDir := seedVictim(t)
	token := mustHMACToken(t, "alice")
	srv := startKVServer(t, tmpDir)

	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)
	header.Set("Origin", testBrowserOrigin)
	conn, resp, err := websocket.DefaultDialer.Dial(wsURLFor(srv, "/alice/inbox"), header)
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		t.Fatalf("an upgrade from the configured origin must be accepted: %v (status %d)", err, status)
	}
	t.Cleanup(func() {
		conn.Close()
		sessionWG.Wait()
	})
}

// startSyncProxyWithTicket serves SyncProxy over HTTP with one valid
// grid-scoped ticket seeded, in front of a backend stand-in that accepts an
// upgrade.
func startSyncProxyWithTicket(t *testing.T, ticket string) *httptest.Server {
	t.Helper()
	t.Setenv("MTLS_ENABLED", "false")
	t.Setenv("CURATORIUM_BROWSER_ORIGIN", testBrowserOrigin)
	kv := setupTestKVStore(t)
	CmdSet(mustKK(t, "_syncticket", ticket), map[string]string{"x-id": "_syncticket", "ttl": "60"},
		gridTicketValue(t, "0000-0001-2345-6789", "test-automerge-id")).execUnauthorised()
	backend := stubBackendWS(t)
	t.Cleanup(backend.Close)
	handler, err := SyncProxy(strings.TrimPrefix(backend.URL, "http://"), kv)
	require.NoError(t, err)
	srv := httptest.NewServer(http.HandlerFunc(handler))
	t.Cleanup(srv.Close)
	return srv
}

// dialSyncWithOrigin dials /sync with the given query string and Origin; an
// empty origin sends no Origin header.
func dialSyncWithOrigin(srv *httptest.Server, query, origin string) (*websocket.Conn, *http.Response, error) {
	header := http.Header{}
	if origin != "" {
		header.Set("Origin", origin)
	}
	return websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http")+"/sync"+query, header)
}

// TestSyncProxyRefusesForeignOriginWithoutBurningTicket - a cross-origin
// request is refused with 403 before the ticket is read, so the ticket is
// still redeemable by the real page afterwards.
func TestSyncProxyRefusesForeignOriginWithoutBurningTicket(t *testing.T) {
	srv := startSyncProxyWithTicket(t, "origin-ticket")

	conn, resp, err := dialSyncWithOrigin(srv, "?ticket=origin-ticket", foreignWSOrigin)
	if conn != nil {
		conn.Close()
	}
	require.Error(t, err, "a foreign Origin must be refused")
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	_, getErr := CmdGet(mustKK(t, "_syncticket", "origin-ticket")).execUnauthorised()
	require.NoError(t, getErr, "a refused cross-origin request must not burn the ticket")

	// The origin check comes before the ticket check: no ticket at all, foreign
	// origin, still 403 and not 401.
	conn2, resp2, err2 := dialSyncWithOrigin(srv, "", foreignWSOrigin)
	if conn2 != nil {
		conn2.Close()
	}
	require.Error(t, err2)
	require.NotNil(t, resp2)
	assert.Equal(t, http.StatusForbidden, resp2.StatusCode, "the origin is refused before the ticket is looked at")

	// The real page still redeems the same ticket.
	conn3, resp3, err3 := dialSyncWithOrigin(srv, "?ticket=origin-ticket", testBrowserOrigin)
	if conn3 != nil {
		conn3.Close()
	}
	status := 0
	if resp3 != nil {
		status = resp3.StatusCode
	}
	require.NoError(t, err3, "the configured origin must redeem the ticket (status %d)", status)
}

// TestSyncProxyAcceptsConfiguredOrigin - the configured origin upgrades, and a
// client that sends no Origin at all (not a browser) still upgrades.
func TestSyncProxyAcceptsConfiguredOrigin(t *testing.T) {
	srv := startSyncProxyWithTicket(t, "origin-ticket-a")
	CmdSet(mustKK(t, "_syncticket", "origin-ticket-b"), map[string]string{"x-id": "_syncticket", "ttl": "60"},
		gridTicketValue(t, "0000-0001-2345-6789", "test-automerge-id")).execUnauthorised()

	connA, _, errA := dialSyncWithOrigin(srv, "?ticket=origin-ticket-a", testBrowserOrigin)
	if connA != nil {
		connA.Close()
	}
	require.NoError(t, errA, "the configured origin must upgrade")

	connB, _, errB := dialSyncWithOrigin(srv, "?ticket=origin-ticket-b", "")
	if connB != nil {
		connB.Close()
	}
	require.NoError(t, errB, "a client that sends no Origin must upgrade")
}

// checkOriginValues parses one Go file (from disk when src is nil, else from the
// given source text) and returns the source text of every value assigned to a
// CheckOrigin field: both the keyed field of a composite literal and an
// assignment to a .CheckOrigin selector.
func checkOriginValues(t *testing.T, filename string, src any) []string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), filename, src, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", filename, err)
	}
	var values []string
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.KeyValueExpr:
			if types.ExprString(node.Key) == "CheckOrigin" {
				values = append(values, types.ExprString(node.Value))
			}
		case *ast.AssignStmt:
			for i, lhs := range node.Lhs {
				if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "CheckOrigin" && i < len(node.Rhs) {
					values = append(values, types.ExprString(node.Rhs[i]))
				}
			}
		}
		return true
	})
	return values
}

// TestCheckOriginDerivationWorks proves the parser sees a compliant and a
// non-compliant source alike. Without it, a derivation that found nothing
// would satisfy the real guard below.
func TestCheckOriginDerivationWorks(t *testing.T) {
	compliant := `package synthetic

func f() {
	a := websocket.Upgrader{CheckOrigin: checkBrowserOrigin}
	var b websocket.Upgrader
	b.CheckOrigin = checkBrowserOrigin
}
`
	got := checkOriginValues(t, "compliant.go", compliant)
	require.Equal(t, []string{"checkBrowserOrigin", "checkBrowserOrigin"}, got)

	nonCompliant := `package synthetic

func f() {
	a := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	var b websocket.Upgrader
	b.CheckOrigin = func(r *http.Request) bool { return true }
}
`
	bad := checkOriginValues(t, "noncompliant.go", nonCompliant)
	require.Len(t, bad, 2)
	for _, value := range bad {
		assert.NotEqual(t, "checkBrowserOrigin", value)
	}
}

// TestEveryCheckOriginIsCheckBrowserOrigin is the derived guard: every
// CheckOrigin set anywhere in the package's non-test source is the one shared
// function, so a new upgrader cannot be added that accepts every origin.
func TestEveryCheckOriginIsCheckBrowserOrigin(t *testing.T) {
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	total := 0
	perFile := map[string]int{}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		values := checkOriginValues(t, name, nil)
		perFile[name] = len(values)
		total += len(values)
		for _, value := range values {
			if value != "checkBrowserOrigin" {
				t.Errorf("%s sets CheckOrigin to %q; it must be checkBrowserOrigin", name, value)
			}
		}
	}
	if total < 2 {
		t.Errorf("derived only %d CheckOrigin assignments from the non-test source; the two production upgraders are expected, so the derivation is broken", total)
	}
	for _, canary := range []string{"id1.go", "sync_proxy.go"} {
		if perFile[canary] < 1 {
			t.Errorf("%s has no CheckOrigin assignment; the guard does not see a known upgrader", canary)
		}
	}
}
