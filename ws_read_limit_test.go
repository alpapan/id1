// apps/id1/ws_read_limit_test.go
//
// group: server
// tags: websocket, limits, security, testing
// summary: Tests that the key/value WebSocket refuses a message larger than the key/value body cap.
//
//

package id1

import (
	"bytes"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// paddedComment returns a message of exactly size bytes that ParseCommand
// refuses as "not a command" (it starts with #), so the size is exercised
// without any key being written.
func paddedComment(size int64) []byte {
	return append([]byte("#"), bytes.Repeat([]byte("x"), int(size)-1)...)
}

func dialKVAsAlice(t *testing.T) (*websocket.Conn, string) {
	t.Helper()
	tmpDir := seedVictim(t)
	token := mustHMACToken(t, "alice")
	srv := startKVServer(t, tmpDir)
	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)
	conn, resp, err := websocket.DefaultDialer.Dial(wsURLFor(srv, "/alice/inbox"), header)
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		t.Fatalf("an authenticated upgrade must be accepted: %v (status %d)", err, status)
	}
	t.Cleanup(func() {
		conn.Close()
		sessionWG.Wait()
	})
	return conn, tmpDir
}

// TestWebSocketReadLimitClosesOnAnOversizeMessage - a message one byte over the
// key/value cap must make the server close the connection, not buffer it.
func TestWebSocketReadLimitClosesOnAnOversizeMessage(t *testing.T) {
	conn, _ := dialKVAsAlice(t)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	// The server may close while this large write is still going out, so a
	// write error is expected and is not the assertion.
	_ = conn.WriteMessage(websocket.BinaryMessage, paddedComment(KVBodyLimitBytes+1))
	// The server publishes its own online marker to this connection when the
	// session starts, so messages may arrive first; only an error ends the loop.
	var err error
	for err == nil {
		_, _, err = conn.ReadMessage()
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatalf("SECURITY: the server kept the connection open after a message over the key/value cap: %v", err)
	}
	var closeErr *websocket.CloseError
	if errors.As(err, &closeErr) && closeErr.Code != websocket.CloseMessageTooBig {
		t.Errorf("close code = %d, want %d (message too big)", closeErr.Code, websocket.CloseMessageTooBig)
	}
}

// TestWebSocketReadLimitAcceptsAMessageAtTheLimit is the control: a message of
// exactly the cap is read (and refused by ParseCommand as a comment), and the
// connection stays usable for the next command.
func TestWebSocketReadLimitAcceptsAMessageAtTheLimit(t *testing.T) {
	conn, tmpDir := dialKVAsAlice(t)
	if err := conn.WriteMessage(websocket.BinaryMessage, paddedComment(KVBodyLimitBytes)); err != nil {
		t.Fatalf("writing a message exactly at the cap: %v", err)
	}
	if err := conn.WriteMessage(websocket.BinaryMessage, []byte("set:/alice/note\nhello")); err != nil {
		t.Fatalf("writing the follow-up frame: %v", err)
	}
	if !fileBecomes(filepath.Join(tmpDir, "alice", "note"), "hello") {
		t.Errorf("a message exactly at the cap must be read and leave the connection usable")
	}
}
