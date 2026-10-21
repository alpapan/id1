package id1

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// deregisterTestOrcid is an iD in the reserved test range (0000-0000-, body 9001).
const deregisterTestOrcid = "0000-0000-0009-0019"

// withDeregisterTestStore points the package store at a fresh temporary
// directory for one test and restores the previous one when the test ends.
func withDeregisterTestStore(t *testing.T) {
	t.Helper()
	originalDbpath := dbpath
	dbpath = t.TempDir()
	t.Cleanup(func() { dbpath = originalDbpath })
}

// deregisterSeedKey stores a device key and its .name label for id and device.
func deregisterSeedKey(t *testing.T, id, device string) {
	t.Helper()
	if _, err := CmdSet(mustKK(t, id, "pub", "keys", device), map[string]string{"x-id": id}, []byte(genTestRSAPubPEM(t))).execUnauthorised(); err != nil {
		t.Fatalf("seed device key: %v", err)
	}
	if _, err := CmdSet(mustKK(t, id, "pub", "keys", device+".name"), map[string]string{"x-id": id}, []byte("Curatorium")).execUnauthorised(); err != nil {
		t.Fatalf("seed device name: %v", err)
	}
}

// deregisterKeyStored reports whether {id}/pub/keys/{segment} holds a value.
func deregisterKeyStored(t *testing.T, id, segment string) bool {
	t.Helper()
	data, err := CmdGet(mustKK(t, id, "pub", "keys", segment)).execUnauthorised()
	return err == nil && len(data) > 0
}

func postDeregister(t *testing.T, h http.HandlerFunc, connState *tls.ConnectionState, body InternalDeregisterRequest) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/internal/sovereign/deregister", bytes.NewReader(raw))
	req.TLS = connState
	rr := httptest.NewRecorder()
	h(rr, req)
	return rr
}

func TestInternalDeregister_VerifiedCertRemovesTheKeyAndItsName(t *testing.T) {
	withDeregisterTestStore(t)
	deregisterSeedKey(t, deregisterTestOrcid, "cur-a")
	deregisterSeedKey(t, deregisterTestOrcid, "cur-b")

	rr := postDeregister(t, HandleInternalDeregisterKey(), verifiedTLS(t, "cur-a"), InternalDeregisterRequest{ID: deregisterTestOrcid, Device: "cur-a"})
	if rr.Code != http.StatusOK {
		t.Fatalf("deregister: want 200, got %d (%s)", rr.Code, rr.Body.String())
	}
	want := `{"status":"deregistered","id":"0000-0000-0009-0019","device":"cur-a"}`
	if rr.Body.String() != want {
		t.Fatalf("deregister body: want %s, got %s", want, rr.Body.String())
	}
	if deregisterKeyStored(t, deregisterTestOrcid, "cur-a") {
		t.Fatal("device key still stored after deregister")
	}
	if deregisterKeyStored(t, deregisterTestOrcid, "cur-a.name") {
		t.Fatal("device name label still stored after deregister")
	}
	if !deregisterKeyStored(t, deregisterTestOrcid, "cur-b") || !deregisterKeyStored(t, deregisterTestOrcid, "cur-b.name") {
		t.Fatal("another curatorium's device slot is missing after the deregister")
	}
}

func TestInternalDeregister_AbsentKeyAnswersDeregistered(t *testing.T) {
	withDeregisterTestStore(t)

	rr := postDeregister(t, HandleInternalDeregisterKey(), verifiedTLS(t, "cur-a"), InternalDeregisterRequest{ID: deregisterTestOrcid, Device: "cur-a"})
	if rr.Code != http.StatusOK {
		t.Fatalf("absent key: want 200, got %d (%s)", rr.Code, rr.Body.String())
	}
}

// TestInternalDeregister_StoreFailureAnswers500: a store that cannot be opened
// is a failure, never "deregistered", so the caller keeps its private key and
// repeats the call.
func TestInternalDeregister_StoreFailureAnswers500(t *testing.T) {
	notADir := filepath.Join(t.TempDir(), "store-is-a-file")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatalf("write placeholder file: %v", err)
	}
	originalDbpath := dbpath
	dbpath = notADir
	t.Cleanup(func() { dbpath = originalDbpath })

	rr := postDeregister(t, HandleInternalDeregisterKey(), verifiedTLS(t, "cur-a"), InternalDeregisterRequest{ID: deregisterTestOrcid, Device: "cur-a"})
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("unopenable store: want 500, got %d (%s)", rr.Code, rr.Body.String())
	}
}

func TestInternalDeregister_NoTLS_Rejected(t *testing.T) {
	withDeregisterTestStore(t)
	deregisterSeedKey(t, deregisterTestOrcid, "cur-a")

	rr := postDeregister(t, HandleInternalDeregisterKey(), nil, InternalDeregisterRequest{ID: deregisterTestOrcid, Device: "cur-a"})
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("no TLS: want 401, got %d", rr.Code)
	}
	if !deregisterKeyStored(t, deregisterTestOrcid, "cur-a") {
		t.Fatal("key removed despite no TLS")
	}
}

func TestInternalDeregister_EmptyVerifiedChains_Rejected(t *testing.T) {
	withDeregisterTestStore(t)
	deregisterSeedKey(t, deregisterTestOrcid, "cur-a")

	rr := postDeregister(t, HandleInternalDeregisterKey(), &tls.ConnectionState{}, InternalDeregisterRequest{ID: deregisterTestOrcid, Device: "cur-a"})
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("empty chains: want 401, got %d", rr.Code)
	}
	if !deregisterKeyStored(t, deregisterTestOrcid, "cur-a") {
		t.Fatal("key removed despite empty verified chains")
	}
}

func TestInternalDeregister_DeviceMustMatchCN(t *testing.T) {
	withDeregisterTestStore(t)
	deregisterSeedKey(t, deregisterTestOrcid, "cur-b")

	rr := postDeregister(t, HandleInternalDeregisterKey(), verifiedTLS(t, "cur-a"), InternalDeregisterRequest{ID: deregisterTestOrcid, Device: "cur-b"})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("device!=CN: want 403, got %d", rr.Code)
	}
	if !deregisterKeyStored(t, deregisterTestOrcid, "cur-b") {
		t.Fatal("cross-tenant device key is missing after a refused request")
	}
}

func TestInternalDeregister_RejectsBadInput(t *testing.T) {
	withDeregisterTestStore(t)
	deregisterSeedKey(t, deregisterTestOrcid, "cur-a")

	h := HandleInternalDeregisterKey()
	cases := []struct {
		name string
		cn   string
		body InternalDeregisterRequest
	}{
		{"malformed id", "cur-a", InternalDeregisterRequest{ID: "not-an-orcid", Device: "cur-a"}},
		{"empty id", "cur-a", InternalDeregisterRequest{ID: "", Device: "cur-a"}},
		{"empty device", "cur-a", InternalDeregisterRequest{ID: deregisterTestOrcid, Device: ""}},
		{"malformed device", "cur-a", InternalDeregisterRequest{ID: deregisterTestOrcid, Device: "bad/seg"}},
		{"dot device", ".", InternalDeregisterRequest{ID: deregisterTestOrcid, Device: "."}},
		{"dotdot device", "..", InternalDeregisterRequest{ID: deregisterTestOrcid, Device: ".."}},
		{"name label as device", "cur-a.name", InternalDeregisterRequest{ID: deregisterTestOrcid, Device: "cur-a.name"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := postDeregister(t, h, verifiedTLS(t, tc.cn), tc.body)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("%s: want 400, got %d", tc.name, rr.Code)
			}
		})
	}
	if !deregisterKeyStored(t, deregisterTestOrcid, "cur-a") || !deregisterKeyStored(t, deregisterTestOrcid, "cur-a.name") {
		t.Fatal("a rejected request removed the device key or its label")
	}
}

func TestInternalDeregister_RejectsNonPost(t *testing.T) {
	withDeregisterTestStore(t)

	req := httptest.NewRequest(http.MethodDelete, "/internal/sovereign/deregister", nil)
	req.TLS = verifiedTLS(t, "cur-a")
	rr := httptest.NewRecorder()
	HandleInternalDeregisterKey()(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE: want 405, got %d", rr.Code)
	}
}

// TestInternalDeregister_BodyCapped verifies the 64 KiB MaxBytesReader cap
// rejects an oversized body rather than decoding it.
func TestInternalDeregister_BodyCapped(t *testing.T) {
	withDeregisterTestStore(t)
	deregisterSeedKey(t, deregisterTestOrcid, "cur-a")

	huge := make([]byte, 128<<10)
	for i := range huge {
		huge[i] = 'A'
	}
	rr := postDeregister(t, HandleInternalDeregisterKey(), verifiedTLS(t, "cur-a"), InternalDeregisterRequest{ID: string(huge), Device: "cur-a"})
	if rr.Code == http.StatusOK {
		t.Fatal("oversized body accepted (got 200); MaxBytesReader cap not enforced")
	}
	if !deregisterKeyStored(t, deregisterTestOrcid, "cur-a") {
		t.Fatal("key removed from an oversized body")
	}
}

// TestInternalDeregister_RealHandshake mirrors production: VerifyClientCertIfGiven
// with a dedicated CA pool. A CA-signed client removes its own slot; a certless
// client and a client signed by another CA never get a 200 and remove nothing.
func TestInternalDeregister_RealHandshake(t *testing.T) {
	withDeregisterTestStore(t)

	ca, _, caKey := makeCert(t, "federation-ca", true, nil, nil)
	_, srvDER, srvKey := makeCert(t, "annot8r-id1", false, ca, caKey)
	_, cliDER, cliKey := makeCert(t, "cur-a", false, ca, caKey)
	caPool := x509.NewCertPool()
	caPool.AddCert(ca)

	srv := httptest.NewUnstartedServer(HandleInternalDeregisterKey())
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCertOf(srvDER, srvKey)},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    caPool,
	}
	srv.StartTLS()
	defer srv.Close()

	body, _ := json.Marshal(InternalDeregisterRequest{ID: deregisterTestOrcid, Device: "cur-a"})

	// (a) No client cert: the handshake succeeds and the handler answers 401.
	deregisterSeedKey(t, deregisterTestOrcid, "cur-a")
	noCert := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: caPool}}}
	resp, err := noCert.Post(srv.URL+"/internal/sovereign/deregister", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("certless client should complete handshake: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("certless: want 401, got %d", resp.StatusCode)
	}
	if !deregisterKeyStored(t, deregisterTestOrcid, "cur-a") {
		t.Fatal("certless client removed the device key")
	}

	// (b) Client cert from an untrusted CA: never a 200, key kept.
	otherCA, _, otherKey := makeCert(t, "rogue-ca", true, nil, nil)
	_, rogueDER, rogueKey := makeCert(t, "cur-a", false, otherCA, otherKey)
	rogue := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:      caPool,
		Certificates: []tls.Certificate{tlsCertOf(rogueDER, rogueKey)},
	}}}
	resp2, err := rogue.Post(srv.URL+"/internal/sovereign/deregister", "application/json", bytes.NewReader(body))
	if err == nil {
		resp2.Body.Close()
		if resp2.StatusCode == http.StatusOK {
			t.Fatal("untrusted-CA client got 200")
		}
	}
	if !deregisterKeyStored(t, deregisterTestOrcid, "cur-a") {
		t.Fatal("untrusted-CA client removed the device key")
	}

	// (c) CA-signed client cert, CN=cur-a, device=cur-a: 200 and the key is gone.
	okClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:      caPool,
		Certificates: []tls.Certificate{tlsCertOf(cliDER, cliKey)},
	}}}
	resp3, err := okClient.Post(srv.URL+"/internal/sovereign/deregister", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("trusted client POST: %v", err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("trusted client: want 200, got %d", resp3.StatusCode)
	}
	if deregisterKeyStored(t, deregisterTestOrcid, "cur-a") {
		t.Fatal("device key still stored after a trusted deregister")
	}
}
