// apps/id1/sync_proxy_read_limit_test.go
//
// group: middleware
// tags: websocket, proxy, limits, security, testing
// summary: Tests that the /sync proxy refuses a client message larger than the message cap.
//
//

package id1

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// syncReadLimitFixture starts a /sync proxy in front of an upstream that
// records the size of every message it receives and echoes it back.
func syncReadLimitFixture(t *testing.T) (client *websocket.Conn, received func() []int) {
	t.Helper()
	t.Setenv("MTLS_ENABLED", "false")

	var mu sync.Mutex
	var sizes []int
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
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
			mu.Lock()
			sizes = append(sizes, len(msg))
			mu.Unlock()
			if err := conn.WriteMessage(mt, msg[:1]); err != nil {
				return
			}
		}
	}))
	t.Cleanup(upstream.Close)

	handler, err := SyncProxy(strings.TrimPrefix(upstream.URL, "http://"), setupTestKVStore(t))
	if err != nil {
		t.Fatalf("SyncProxy error: %v", err)
	}
	CmdSet(mustKK(t, "_syncticket", "limit-ticket"), map[string]string{"x-id": "_syncticket", "ttl": "60"},
		gridTicketValue(t, "0000-0001-2345-6789", "test-automerge-id")).execUnauthorised()

	proxy := httptest.NewServer(handler)
	t.Cleanup(proxy.Close)

	wsURL := "ws" + strings.TrimPrefix(proxy.URL, "http") + "/sync?ticket=limit-ticket"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("client dial failed: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn, func() []int {
		mu.Lock()
		defer mu.Unlock()
		return append([]int(nil), sizes...)
	}
}

// TestSyncProxyReadLimitClosesOnAnOversizeClientMessage - a client message one
// byte over the cap must end the connection and never reach the backend.
func TestSyncProxyReadLimitClosesOnAnOversizeClientMessage(t *testing.T) {
	client, received := syncReadLimitFixture(t)
	client.SetReadDeadline(time.Now().Add(10 * time.Second))
	// The proxy may close while this large write is still going out, so a
	// write error is expected and is not the assertion.
	_ = client.WriteMessage(websocket.BinaryMessage, make([]byte, KVBodyLimitBytes+1))
	var err error
	for err == nil {
		_, _, err = client.ReadMessage()
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatalf("SECURITY: the proxy kept the connection open after a message over the cap: %v", err)
	}
	for _, size := range received() {
		if int64(size) > KVBodyLimitBytes {
			t.Errorf("SECURITY: the backend received a %d byte message, over the %d byte cap", size, KVBodyLimitBytes)
		}
	}
}

// TestSyncProxyReadLimitRelaysAMessageAtTheLimit is the control: a message of
// exactly the cap is relayed to the backend.
func TestSyncProxyReadLimitRelaysAMessageAtTheLimit(t *testing.T) {
	client, received := syncReadLimitFixture(t)
	client.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err := client.WriteMessage(websocket.BinaryMessage, make([]byte, KVBodyLimitBytes)); err != nil {
		t.Fatalf("writing a message exactly at the cap: %v", err)
	}
	if _, _, err := client.ReadMessage(); err != nil {
		t.Fatalf("reading the backend's reply to an at-cap message: %v", err)
	}
	sizes := received()
	if len(sizes) != 1 || int64(sizes[0]) != KVBodyLimitBytes {
		t.Errorf("backend received sizes %v, want one message of %d bytes", sizes, KVBodyLimitBytes)
	}
}
