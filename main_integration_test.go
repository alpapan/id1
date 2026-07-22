//go:build integration

package id1

// Live end-to-end integration test for the id1 entrypoint. The standard `go test ./...`
// CANNOT compile main.go_ (the `.go_` suffix hides it from the toolchain; the Dockerfile
// copies it to cmd/main.go and builds a separate module), so unit tests never exercise
// main()'s config resolution or the TLS-mode branch. This test builds the real binary
// exactly as the Dockerfile does, then runs it in BOTH mTLS modes on temp ports + temp
// DBPATHs and asserts /pub/jwks.json serves an RSA key. It is the regression guard for
// ResolveConfig (PORT/DBPATH must come from the environment) and the http-vs-https
// server branch.
//
// Gated behind the `integration` build tag so the default `go test ./...` (and the
// pre-commit hook) skip it. Run it with:
//
//	set -a && source .env.test && set +a && go test -tags=integration -run TestID1 -v
//	# or: pixi run -m apps/id1/pixi.toml test-integration

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestID1ServesJWKSInBothTLSModes(t *testing.T) {
	bin := buildID1Binary(t, "")

	t.Run("mtls_disabled_serves_over_http", func(t *testing.T) {
		port := freePort(t)
		startID1(t, bin, map[string]string{
			"PORT":         port,
			"DBPATH":       t.TempDir(),
			"MTLS_ENABLED": "false",
			"ENV":          "test",
		})
		client := &http.Client{Timeout: 3 * time.Second}
		assertJWKSHasRSAKey(t, client, "http://127.0.0.1:"+port+"/pub/jwks.json")
		assertStatus(t, client, "http://127.0.0.1:"+port+"/health", http.StatusOK)
	})

	t.Run("mtls_enabled_serves_over_https", func(t *testing.T) {
		port := freePort(t)
		certFile, keyFile := selfSignedCert(t)
		startID1(t, bin, map[string]string{
			"PORT":         port,
			"DBPATH":       t.TempDir(),
			"MTLS_ENABLED": "true",
			"SSL_CERTFILE": certFile,
			"SSL_KEYFILE":  keyFile,
			"ENV":          "test",
		})
		// Self-signed server cert -> skip verification; client cert is optional
		// (ClientAuth=VerifyClientCertIfGiven), so a certless client reaches /pub/jwks.json.
		httpsClient := &http.Client{
			Timeout: 3 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test-only self-signed cert
			},
		}
		assertJWKSHasRSAKey(t, httpsClient, "https://127.0.0.1:"+port+"/pub/jwks.json")
		// Plain HTTP against the TLS port must NOT succeed.
		if resp, err := (&http.Client{Timeout: 2 * time.Second}).Get("http://127.0.0.1:" + port + "/pub/jwks.json"); err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				t.Fatalf("plain HTTP on the TLS port returned 200; TLS not enforced")
			}
		}
	})
}

// TestID1MintsRequireBuildTags builds the real main.go_ in the three shapes that
// actually get deployed and asserts both anonymous mints against each:
//
//   - bare (no tags): the annot8r_id1 shape. It has no ORCID, no browser, no
//     Traefik route list, and no rate-limited proxy in front of it, so it must
//     carry NEITHER mint, in every environment - this is the security property
//     the `curatoriumdemo` tag exists to guarantee.
//   - curatoriumdemo only: Curatorium's production shape. The demo mint is
//     production surface (the four demo pages depend on it via the frontend's
//     rate-limited proxy) so it must be present in every environment; the
//     arbitrary-ORCID mint must still be absent.
//   - testmint,curatoriumdemo: Curatorium's dev/test shape. Both mints present,
//     with the arbitrary-ORCID one still gated by ENV at registration time.
//
// Non-reachability of either mint from the internet is otherwise a route-list
// property of Curatorium's own deployment (Traefik + next.config.mjs), not a
// binary property - this test is what proves the binary-level half holds.
func TestID1MintsRequireBuildTags(t *testing.T) {
	bareBin := buildID1Binary(t, "")
	curatoriumProdBin := buildID1Binary(t, "curatoriumdemo")
	curatoriumDevTestBin := buildID1Binary(t, "testmint,curatoriumdemo")

	cases := []struct {
		name           string
		bin            string
		env            string
		wantTestUser   int
		wantUnauthDemo int
	}{
		{"bare_prod_env", bareBin, "prod", http.StatusNotFound, http.StatusNotFound},
		{"bare_test_env", bareBin, "test", http.StatusNotFound, http.StatusNotFound},
		{"curatorium_prod_shape_prod_env", curatoriumProdBin, "prod", http.StatusNotFound, http.StatusOK},
		{"curatorium_prod_shape_test_env", curatoriumProdBin, "test", http.StatusNotFound, http.StatusOK},
		{"curatorium_devtest_shape_prod_env", curatoriumDevTestBin, "prod", http.StatusNotFound, http.StatusOK},
		{"curatorium_devtest_shape_test_env", curatoriumDevTestBin, "test", http.StatusOK, http.StatusOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			port := freePort(t)
			startID1(t, tc.bin, map[string]string{
				"PORT":         port,
				"DBPATH":       t.TempDir(),
				"MTLS_ENABLED": "false",
				"ENV":          tc.env,
			})
			client := &http.Client{Timeout: 3 * time.Second}
			// /pub/jwks.json is registered in every env; polling it confirms readiness,
			// by which point the (un)registered mint routes are already decided.
			assertJWKSHasRSAKey(t, client, "http://127.0.0.1:"+port+"/pub/jwks.json")
			assertStatus(t, client, "http://127.0.0.1:"+port+"/auth/test_user", tc.wantTestUser)
			assertStatus(t, client, "http://127.0.0.1:"+port+"/auth/unauth_demo", tc.wantUnauthDemo)
		})
	}
}

// buildID1Binary compiles main.go_ into a runnable binary, mirroring apps/id1/Dockerfile:
// a separate module that references the local id1 library via a replace directive.
// goTags is passed to `go build -tags=...`; "" builds the production shape.
func buildID1Binary(t *testing.T, goTags string) string {
	t.Helper()
	idSrc, err := os.Getwd() // `go test` runs in the package dir = the id1 module root
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	mainSrc := filepath.Join(idSrc, "main.go_")
	if _, err := os.Stat(mainSrc); err != nil {
		t.Fatalf("main.go_ not found at %s: %v", mainSrc, err)
	}
	data, err := os.ReadFile(mainSrc)
	if err != nil {
		t.Fatalf("read main.go_: %v", err)
	}
	buildDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(buildDir, "main.go"), data, 0o644); err != nil {
		t.Fatalf("write main.go: %v", err)
	}
	binPath := filepath.Join(buildDir, "id1app")
	steps := [][]string{
		{"go", "mod", "init", "id1-main-itest"},
		{"go", "mod", "edit", "-replace", "github.com/qodex/id1=" + idSrc},
		{"go", "get", "github.com/joho/godotenv@v1.5.1"},
		{"go", "mod", "tidy"},
		{"go", "build", "-tags=" + goTags, "-o", binPath, "."},
	}
	for _, args := range steps {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = buildDir
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build step %v failed: %v\n%s", args, err, out)
		}
	}
	return binPath
}

// startID1 launches the binary with the given env and registers cleanup that kills it.
func startID1(t *testing.T, bin string, env map[string]string) {
	t.Helper()
	cmd := exec.Command(bin)
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start id1: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
}

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for free port: %v", err)
	}
	defer l.Close()
	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	return port
}

// assertJWKSHasRSAKey polls url until it returns 200 with a JWKS containing an RSA key,
// or fails after a startup grace window.
func assertJWKSHasRSAKey(t *testing.T, client *http.Client, url string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err != nil {
			lastErr = err
			time.Sleep(250 * time.Millisecond)
			continue
		}
		var body struct {
			Keys []struct {
				Kty string `json:"kty"`
			} `json:"keys"`
		}
		dec := json.NewDecoder(resp.Body)
		derr := dec.Decode(&body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK && derr == nil && len(body.Keys) > 0 && body.Keys[0].Kty == "RSA" {
			return
		}
		lastErr = err
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("JWKS at %s never returned an RSA key: %v", url, lastErr)
}

func assertStatus(t *testing.T, client *http.Client, url string, want int) {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != want {
		t.Fatalf("GET %s = %d, want %d", url, resp.StatusCode, want)
	}
}

func selfSignedCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	dir := t.TempDir()
	certFile = filepath.Join(dir, "server.crt")
	keyFile = filepath.Join(dir, "server.key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustMarshalPKCS8(t, key)})
	if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certFile, keyFile
}

func mustMarshalPKCS8(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return b
}
