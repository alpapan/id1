package id1

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
)

// mustHMACToken mints the session token the key/value protocol uses: a JWT
// signed with the identity's own daily HMAC secret, which only that identity's
// key holder can derive from the challenge.
func mustHMACToken(t *testing.T, id string) string {
	t.Helper()
	secret, err := generateSecret(id)
	if err != nil {
		t.Fatalf("generateSecret(%q): %v", id, err)
	}
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   id,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("signing a token for %q: %v", id, err)
	}
	return signed
}

// startKVServer serves the real key/value handler over HTTP so a WebSocket
// client can dial it.
func startKVServer(t *testing.T, tmpDir string) *httptest.Server {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv := httptest.NewServer(http.HandlerFunc(Handle(tmpDir, ctx)))
	t.Cleanup(srv.Close)
	return srv
}

func wsURLFor(srv *httptest.Server, keyPath string) string {
	return "ws" + strings.TrimPrefix(srv.URL, "http") + keyPath
}

// fileBecomes reports whether path holds want at any point within the deadline.
// Commands arriving over a socket are handled asynchronously, so the assertion
// has to wait rather than read once.
func fileBecomes(path, want string) bool {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(path); err == nil && string(data) == want {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// TestWebSocketRefusesUnauthenticatedUpgrade - opening a socket on a public path
// is a public READ, which is not enough to open a session that acts as somebody.
func TestWebSocketRefusesUnauthenticatedUpgrade(t *testing.T) {
	tmpDir := seedVictim(t)
	if _, err := CmdSet(mustK(t, "victim/pub/keys/default"), map[string]string{"x-id": "victim"}, []byte(testPubKey1)).Exec(); err != nil {
		t.Fatalf("seed victim device key: %v", err)
	}
	srv := startKVServer(t, tmpDir)

	conn, resp, err := websocket.DefaultDialer.Dial(wsURLFor(srv, "/victim/pub/anything"), nil)
	if err == nil {
		conn.Close()
		t.Fatalf("SECURITY: an unauthenticated WebSocket upgrade was accepted")
	}
	if resp == nil {
		t.Fatalf("refused upgrade returned no HTTP response: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("a refused upgrade must answer 401 with a challenge, got %d", resp.StatusCode)
	}
}

// TestWebSocketBindsSessionToTokenSubjectNotPath - the core property. Alice
// authenticates, but opens the socket on the victim's public path. The session
// must be Alice's, so a command naming the victim's namespace is refused.
func TestWebSocketBindsSessionToTokenSubjectNotPath(t *testing.T) {
	tmpDir := seedVictim(t)
	if _, err := CmdSet(mustK(t, "victim/pub/keys/default"), map[string]string{"x-id": "victim"}, []byte("VICTIM-KEY")).Exec(); err != nil {
		t.Fatalf("seed victim key: %v", err)
	}
	token := mustHMACToken(t, "alice")
	srv := startKVServer(t, tmpDir)

	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)
	conn, resp, err := websocket.DefaultDialer.Dial(wsURLFor(srv, "/victim/pub/anything"), header)
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		t.Fatalf("an authenticated upgrade must be accepted: %v (status %d)", err, status)
	}
	defer conn.Close()

	if err := conn.WriteMessage(websocket.BinaryMessage, []byte("set:/victim/pub/keys/default\nATTACKER-KEY")); err != nil {
		t.Fatalf("writing the frame: %v", err)
	}

	victimKeyPath := filepath.Join(tmpDir, "victim", "pub", "keys", "default")
	if fileBecomes(victimKeyPath, "ATTACKER-KEY") {
		t.Errorf("SECURITY: a socket opened on the victim's path wrote into the victim's namespace")
	}
	data, readErr := os.ReadFile(victimKeyPath)
	if readErr != nil {
		t.Errorf("the victim's key was destroyed: %v", readErr)
	} else if string(data) != "VICTIM-KEY" {
		t.Errorf("the victim's key was altered: %q", string(data))
	}
}

// TestWebSocketAuthenticatedSessionWritesItsOwnNamespace is the control: the
// feature must still work for the identity that proved who it is.
func TestWebSocketAuthenticatedSessionWritesItsOwnNamespace(t *testing.T) {
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
	defer conn.Close()

	if err := conn.WriteMessage(websocket.BinaryMessage, []byte("set:/alice/note\nhello")); err != nil {
		t.Fatalf("writing the frame: %v", err)
	}

	if !fileBecomes(filepath.Join(tmpDir, "alice", "note"), "hello") {
		t.Errorf("an authenticated session must still write inside its own namespace")
	}
}
