// apps/backend/containers/id1/sync_proxy_test.go
//
// group: middleware
// tags: websocket, proxy, testing
// summary: Tests for WebSocket sync server proxy.
//
//

package id1

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubBackendWS is a minimal upstream WebSocket server that accepts an upgrade and
// immediately closes; enough for a valid /sync upgrade to complete on the client side.
func stubBackendWS(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		c, _ := up.Upgrade(w, r, nil)
		if c != nil {
			c.Close()
		}
	}))
}

// TestSyncProxy_NoTicket_Rejected is the load-bearing security test: a /sync upgrade
// with no ticket must be refused BEFORE the upgrade (the backend is never dialed).
func TestSyncProxy_NoTicket_Rejected(t *testing.T) {
	t.Setenv("MTLS_ENABLED", "false")
	setupTestKVStore(t)
	handler, err := SyncProxy("127.0.0.1:1") // rejected pre-upgrade; backend never dialed
	require.NoError(t, err)
	srv := httptest.NewServer(http.HandlerFunc(handler))
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/sync"
	_, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.Error(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestSyncProxy_ExpiredOrUnknownTicket_Rejected verifies an unknown/expired ticket
// (absent from the KV) is refused; an expired ticket is swept by TTL so its CmdDel
// returns not-found -> the same reject path.
func TestSyncProxy_ExpiredOrUnknownTicket_Rejected(t *testing.T) {
	t.Setenv("MTLS_ENABLED", "false")
	setupTestKVStore(t)
	handler, err := SyncProxy("127.0.0.1:1")
	require.NoError(t, err)
	srv := httptest.NewServer(http.HandlerFunc(handler))
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/sync?ticket=does-not-exist"
	_, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.Error(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestSyncProxy_ValidTicket_BurnedAfterUse verifies a valid ticket admits exactly one
// upgrade and is then burned (deleted) so a second use is rejected.
func TestSyncProxy_ValidTicket_BurnedAfterUse(t *testing.T) {
	t.Setenv("MTLS_ENABLED", "false")
	setupTestKVStore(t)
	// seed a ticket as the mint endpoint would
	CmdSet(KK("_syncticket", "good-ticket"), map[string]string{"x-id": "_syncticket", "ttl": "60"},
		[]byte("0000-0001-2345-6789")).Exec()
	backend := stubBackendWS(t)
	defer backend.Close()
	handler, err := SyncProxy(strings.TrimPrefix(backend.URL, "http://"))
	require.NoError(t, err)
	srv := httptest.NewServer(http.HandlerFunc(handler))
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/sync?ticket=good-ticket"
	c, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err) // first use accepted
	if c != nil {
		c.Close()
	}
	// ticket burned: gone from KV, so a second use is rejected
	_, getErr := CmdGet(KK("_syncticket", "good-ticket")).Exec()
	assert.Error(t, getErr, "ticket must be burned (deleted) after first use")
	c2, resp2, err2 := websocket.DefaultDialer.Dial(wsURL, nil)
	require.Error(t, err2)
	if c2 != nil {
		c2.Close()
	}
	require.NotNil(t, resp2)
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode, "burned ticket cannot be reused")
}

// TestSyncProxy_ConcurrentTicketUse_SingleWinner proves the single-use guarantee holds
// under a race: two simultaneous upgrades with the same ticket, exactly one wins.
func TestSyncProxy_ConcurrentTicketUse_SingleWinner(t *testing.T) {
	t.Setenv("MTLS_ENABLED", "false")
	setupTestKVStore(t)
	CmdSet(KK("_syncticket", "race-ticket"), map[string]string{"x-id": "_syncticket", "ttl": "60"},
		[]byte("0000-0001-2345-6789")).Exec()
	backend := stubBackendWS(t)
	defer backend.Close()
	handler, err := SyncProxy(strings.TrimPrefix(backend.URL, "http://"))
	require.NoError(t, err)
	srv := httptest.NewServer(http.HandlerFunc(handler))
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/sync?ticket=race-ticket"

	var wg sync.WaitGroup
	success := make([]bool, 2)
	loserStatus := make([]int, 2)
	start := make(chan struct{})
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			c, resp, dialErr := websocket.DefaultDialer.Dial(wsURL, nil)
			if dialErr == nil {
				success[idx] = true
				if c != nil {
					c.Close()
				}
				return
			}
			if resp != nil {
				loserStatus[idx] = resp.StatusCode
			}
		}(i)
	}
	close(start)
	wg.Wait()

	winners := 0
	for _, s := range success {
		if s {
			winners++
		}
	}
	assert.Equal(t, 1, winners, "exactly one concurrent upgrade may win the single-use ticket")
	assert.Equal(t, http.StatusUnauthorized, loserStatus[0]+loserStatus[1], "the loser of the race must be rejected 401")
}

func TestSyncProxyInvalidURL(t *testing.T) {
	t.Setenv("MTLS_ENABLED", "false")
	_, err := SyncProxy("[::1")
	if err == nil {
		t.Error("expected error for invalid target URL")
	}
}

func TestSyncProxyRelaysFrames(t *testing.T) {
	t.Setenv("MTLS_ENABLED", "false")

	// Upstream WebSocket echo server
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Logf("upstream upgrade error: %v", err)
			return
		}
		defer conn.Close()
		for {
			mt, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if err := conn.WriteMessage(mt, msg); err != nil {
				return
			}
		}
	}))
	defer upstream.Close()

	target := strings.TrimPrefix(upstream.URL, "http://")
	setupTestKVStore(t)
	handler, err := SyncProxy(target)
	if err != nil {
		t.Fatalf("SyncProxy error: %v", err)
	}
	CmdSet(KK("_syncticket", "relay-ticket"), map[string]string{"x-id": "_syncticket", "ttl": "60"}, []byte("0000-0001-2345-6789")).Exec()

	// Proxy server
	proxy := httptest.NewServer(handler)
	defer proxy.Close()

	// Connect client to proxy
	wsURL := "ws" + strings.TrimPrefix(proxy.URL, "http") + "/sync?ticket=relay-ticket"
	client, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("client dial failed: %v", err)
	}
	defer client.Close()

	// Send a message and verify echo
	testMsg := []byte("hello automerge")
	if err := client.WriteMessage(websocket.TextMessage, testMsg); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	mt, msg, err := client.ReadMessage()
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if mt != websocket.TextMessage || string(msg) != "hello automerge" {
		t.Errorf("expected TextMessage 'hello automerge', got type=%d msg=%q", mt, msg)
	}
}

func TestSyncProxyBinaryFrames(t *testing.T) {
	t.Setenv("MTLS_ENABLED", "false")

	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			mt, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			conn.WriteMessage(mt, msg)
		}
	}))
	defer upstream.Close()

	target := strings.TrimPrefix(upstream.URL, "http://")
	setupTestKVStore(t)
	handler, err := SyncProxy(target)
	if err != nil {
		t.Fatalf("SyncProxy error: %v", err)
	}
	CmdSet(KK("_syncticket", "relay-ticket"), map[string]string{"x-id": "_syncticket", "ttl": "60"}, []byte("0000-0001-2345-6789")).Exec()

	proxy := httptest.NewServer(handler)
	defer proxy.Close()

	wsURL := "ws" + strings.TrimPrefix(proxy.URL, "http") + "/sync?ticket=relay-ticket"
	client, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer client.Close()

	binMsg := []byte{0x00, 0x01, 0x02, 0xFF}
	if err := client.WriteMessage(websocket.BinaryMessage, binMsg); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	mt, msg, err := client.ReadMessage()
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if mt != websocket.BinaryMessage {
		t.Errorf("expected BinaryMessage, got %d", mt)
	}
	if string(msg) != string(binMsg) {
		t.Errorf("binary mismatch: got %v", msg)
	}
}

func TestSyncProxyUpstreamUnavailable(t *testing.T) {
	t.Setenv("MTLS_ENABLED", "false")
	setupTestKVStore(t)
	handler, err := SyncProxy("127.0.0.1:19999")
	if err != nil {
		t.Fatalf("SyncProxy error: %v", err)
	}
	CmdSet(KK("_syncticket", "relay-ticket"), map[string]string{"x-id": "_syncticket", "ttl": "60"}, []byte("0000-0001-2345-6789")).Exec()

	// The proxy authenticates the ticket, upgrades the client, then dials the backend.
	// If the backend is unreachable, the upgraded connection closes immediately.
	proxy := httptest.NewServer(handler)
	defer proxy.Close()

	wsURL := "ws" + strings.TrimPrefix(proxy.URL, "http") + "/sync?ticket=relay-ticket"
	client, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		// Upgrade itself failed - also acceptable
		return
	}
	defer client.Close()

	// Connection was upgraded but backend is down - next read should fail
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _, err = client.ReadMessage()
	if err == nil {
		t.Error("expected read to fail when upstream is unavailable")
	}
}

// __END_OF_FILE_MARKER__
