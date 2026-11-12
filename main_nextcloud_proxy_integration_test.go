//go:build integration

package id1

// TestID1RefusesToStartWithAnIncompleteNextcloudProxy builds the real main.go_ binary
// (go test cannot compile main.go_ itself) and checks that a declared Nextcloud proxy
// with no edge-proof method stops the process at boot, naming the key, before any
// listener opens.

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestID1RefusesToStartWithAnIncompleteNextcloudProxy(t *testing.T) {
	bin := buildID1Binary(t, "")
	port := freePort(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin)
	cmd.Env = append(os.Environ(),
		"PORT="+port,
		"DBPATH="+t.TempDir(),
		"MTLS_ENABLED=false",
		"BIND_ADDR=127.0.0.1",
		"ENV=test",
		"NEXTCLOUD_PROXY_URL=https://127.0.0.1:1",
		// Explicitly empty, overriding whatever .env.test put in the environment.
		// Later entries win in exec, so this is the unset case.
		"EDGE_PROOF_METHOD=",
	)
	output, err := cmd.CombinedOutput()

	if ctx.Err() != nil {
		t.Fatalf("id1 kept running with no EDGE_PROOF_METHOD; it must refuse to boot.\n%s", output)
	}
	if err == nil {
		t.Fatalf("id1 exited cleanly with no EDGE_PROOF_METHOD; it must refuse to boot.\n%s", output)
	}
	if !strings.Contains(string(output), "EDGE_PROOF_METHOD") {
		t.Fatalf("the refusal must name EDGE_PROOF_METHOD; got:\n%s", output)
	}
	if resp, err := (&http.Client{Timeout: 2 * time.Second}).Get("http://127.0.0.1:" + port + "/health"); err == nil {
		resp.Body.Close()
		t.Fatal("id1 served /health despite an incomplete Nextcloud proxy configuration")
	}
}
