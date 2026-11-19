// apps/id1/host_daemon_test.go
//
// group: server
// tags: host-daemon, cors, origin, namespace, security, testing
// summary: Tests that the shared host daemon needs no namespace and no browser origin, and that every other id1 still does.
//
//

package id1

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHostDaemonIsOffUnlessDeclaredTrue(t *testing.T) {
	for _, value := range []string{"", "false", "1", "TRUE", "yes", " true"} {
		t.Setenv("ID1_HOST_DAEMON", value)
		assert.False(t, HostDaemon(), "ID1_HOST_DAEMON=%q must not select host-daemon mode", value)
	}
	t.Setenv("ID1_HOST_DAEMON", "true")
	assert.True(t, HostDaemon())
}

// A host daemon serves no page and runs in no cluster, so it starts with neither
// value set. The cluster id1 keeps both halts (TestBrowserOriginPanicsWhenUnset
// and TestCuratoriumNamespacePanicsWhenUnset).
func TestHostDaemonResolvesNoBrowserOriginAndNeedsNoValue(t *testing.T) {
	t.Setenv("ID1_HOST_DAEMON", "true")
	t.Setenv("CURATORIUM_BROWSER_ORIGIN", "")
	assert.NotPanics(t, func() { assert.Equal(t, "", BrowserOrigin()) })
}

// A value left in the environment by an earlier install is never read, so a
// stale lane origin cannot be honoured by the shared daemon.
func TestHostDaemonIgnoresAnyConfiguredBrowserOrigin(t *testing.T) {
	t.Setenv("ID1_HOST_DAEMON", "true")
	t.Setenv("CURATORIUM_BROWSER_ORIGIN", testBrowserOrigin)
	assert.Equal(t, "", BrowserOrigin())

	rec := httptest.NewRecorder()
	cors(rec, corsRequest(testBrowserOrigin))
	assert.Empty(t, rec.Header().Values("Access-Control-Allow-Origin"))
}

func TestHostDaemonCORSNeverAllowsAnyOrigin(t *testing.T) {
	t.Setenv("ID1_HOST_DAEMON", "true")
	t.Setenv("CURATORIUM_BROWSER_ORIGIN", "")
	for _, c := range corsOriginCases {
		rec := httptest.NewRecorder()
		cors(rec, corsRequest(c.origin))
		assert.Empty(t, rec.Header().Values("Access-Control-Allow-Origin"), "Origin %q", c.origin)
		assert.Equal(t, "Origin", rec.Header().Get("Vary"))
	}
}

// With no browser origin configured, a WebSocket handshake that names any
// Origin, an empty one included, is refused; only a non-browser client (no
// Origin header) passes.
func TestHostDaemonWebSocketOriginIsFailClosed(t *testing.T) {
	t.Setenv("ID1_HOST_DAEMON", "true")
	t.Setenv("CURATORIUM_BROWSER_ORIGIN", "")
	cases := []struct {
		name   string
		values []string
		want   bool
	}{
		{"no origin header", nil, true},
		{"empty origin value", []string{""}, false},
		{"a site", []string{testBrowserOrigin}, false},
		{"another site", []string{foreignWSOrigin}, false},
		{"duplicated origin header", []string{"", ""}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/ws", nil)
			if tc.values != nil {
				req.Header["Origin"] = tc.values
			}
			assert.Equal(t, tc.want, checkBrowserOrigin(req))
		})
	}
}

// Off host-daemon mode the origin halt is unchanged, whatever else is set.
func TestNonHostDaemonStillPanicsWithoutBrowserOrigin(t *testing.T) {
	t.Setenv("ID1_HOST_DAEMON", "false")
	t.Setenv("CURATORIUM_BROWSER_ORIGIN", "")
	assert.Panics(t, func() { browserOrigin() })
}

// A host daemon holds no Kubernetes Secret: it never attempts the write, and
// never resolves a namespace, even if a service-account token were present.
func TestHostDaemonSkipsTheKubernetesSecretWriteAndNeedsNoNamespace(t *testing.T) {
	t.Setenv("ID1_HOST_DAEMON", "true")
	t.Setenv("CURATORIUM_NAMESPACE", "")
	useTokenFile(t, true)
	calls := stubSecretWriter(t, nil)
	require.NotPanics(t, func() { persistKeyToKubeSecret([]byte("irrelevant"), "irrelevant") })
	assert.Equal(t, 0, *calls)
}

func TestNonHostDaemonStillAttemptsTheKubernetesSecretWrite(t *testing.T) {
	t.Setenv("ID1_HOST_DAEMON", "false")
	t.Setenv("CURATORIUM_NAMESPACE", "curatorium-somewhere-else")
	calls := stubSecretWriter(t, nil)
	persistKeyToKubeSecret([]byte("irrelevant"), "irrelevant")
	assert.Equal(t, 1, *calls)
}
