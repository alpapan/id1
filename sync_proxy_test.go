package id1

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

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
	handler, err := SyncProxy(target)
	if err != nil {
		t.Fatalf("SyncProxy error: %v", err)
	}

	// Proxy server
	proxy := httptest.NewServer(handler)
	defer proxy.Close()

	// Connect client to proxy
	wsURL := "ws" + strings.TrimPrefix(proxy.URL, "http")
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
	handler, err := SyncProxy(target)
	if err != nil {
		t.Fatalf("SyncProxy error: %v", err)
	}

	proxy := httptest.NewServer(handler)
	defer proxy.Close()

	wsURL := "ws" + strings.TrimPrefix(proxy.URL, "http")
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
	handler, err := SyncProxy("127.0.0.1:19999")
	if err != nil {
		t.Fatalf("SyncProxy error: %v", err)
	}

	// The proxy upgrades the client first, then dials the backend.
	// If the backend is unreachable, the upgraded connection closes immediately.
	proxy := httptest.NewServer(handler)
	defer proxy.Close()

	wsURL := "ws" + strings.TrimPrefix(proxy.URL, "http")
	client, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		// Upgrade itself failed — also acceptable
		return
	}
	defer client.Close()

	// Connection was upgraded but backend is down — next read should fail
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _, err = client.ReadMessage()
	if err == nil {
		t.Error("expected read to fail when upstream is unavailable")
	}
}

// __END_OF_FILE_MARKER__
