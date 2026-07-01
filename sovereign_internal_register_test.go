package id1

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
)

// genTestRSAPubPEM returns a fresh RSA public key in PKIX PEM form.
func genTestRSAPubPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// The internal registration endpoint writes the singular {id}/pub/key and, crucially,
// OVERWRITES an existing one - this is what makes curatorium-side rotation feasible
// (plan review C1: id1's owner-write auth is HMAC-only and rejects the RS256 sovereign
// JWT, so curatorium cannot overwrite by minting; the trusted-secret endpoint can).
func TestHandleInternalRegisterKey_WritesThenOverwrites(t *testing.T) {
	originalDbpath := dbpath
	dbpath = t.TempDir()
	t.Cleanup(func() { dbpath = originalDbpath })

	const secret = "internal-secret"
	const id = "0000-0001-2345-6789"
	h := HandleInternalRegisterKey(secret)

	pem1 := genTestRSAPubPEM(t)
	body1, _ := json.Marshal(InternalRegisterRequest{ID: id, PublicKeyPEM: pem1})
	req := httptest.NewRequest(http.MethodPost, "/internal/sovereign/register", bytes.NewReader(body1))
	req.Header.Set("X-ID1-Internal-Secret", secret)
	rr := httptest.NewRecorder()
	h(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("first register: want 200, got %d (%s)", rr.Code, rr.Body.String())
	}
	stored, err := CmdGet(KK(id, "pub", "key")).Exec()
	if err != nil || string(stored) != pem1 {
		t.Fatalf("stored key mismatch after first register: err=%v", err)
	}

	// Rotate: a second register with a DIFFERENT key must overwrite the first,
	// even though {id}/pub/key already exists (bypasses the !idExists gate).
	pem2 := genTestRSAPubPEM(t)
	if pem2 == pem1 {
		t.Fatal("two generated keys identical - test cannot distinguish overwrite")
	}
	body2, _ := json.Marshal(InternalRegisterRequest{ID: id, PublicKeyPEM: pem2})
	req2 := httptest.NewRequest(http.MethodPost, "/internal/sovereign/register", bytes.NewReader(body2))
	req2.Header.Set("X-ID1-Internal-Secret", secret)
	rr2 := httptest.NewRecorder()
	h(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("rotate register: want 200, got %d (%s)", rr2.Code, rr2.Body.String())
	}
	stored2, err := CmdGet(KK(id, "pub", "key")).Exec()
	if err != nil || string(stored2) != pem2 {
		t.Fatalf("key not overwritten on rotate: err=%v", err)
	}
}

func TestHandleInternalRegisterKey_WrongOrMissingSecret(t *testing.T) {
	originalDbpath := dbpath
	dbpath = t.TempDir()
	t.Cleanup(func() { dbpath = originalDbpath })

	const secret = "internal-secret"
	const id = "0000-0001-2345-6789"
	h := HandleInternalRegisterKey(secret)
	body, _ := json.Marshal(InternalRegisterRequest{ID: id, PublicKeyPEM: genTestRSAPubPEM(t)})

	// Wrong secret -> 401.
	req := httptest.NewRequest(http.MethodPost, "/internal/sovereign/register", bytes.NewReader(body))
	req.Header.Set("X-ID1-Internal-Secret", "wrong")
	rr := httptest.NewRecorder()
	h(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("wrong secret: want 401, got %d", rr.Code)
	}

	// Missing secret header -> 401.
	req2 := httptest.NewRequest(http.MethodPost, "/internal/sovereign/register", bytes.NewReader(body))
	rr2 := httptest.NewRecorder()
	h(rr2, req2)
	if rr2.Code != http.StatusUnauthorized {
		t.Fatalf("missing secret: want 401, got %d", rr2.Code)
	}

	// No write must have happened.
	if data, err := CmdGet(KK(id, "pub", "key")).Exec(); err == nil && len(data) > 0 {
		t.Fatalf("key was written despite bad secret")
	}
}

// When the configured secret is empty the endpoint is DISABLED. This guards the
// naive-compare trap: a request with no header has Get()=="" which would "match"
// an empty secret under ==, so an explicit empty-secret guard is required.
func TestHandleInternalRegisterKey_DisabledWhenSecretEmpty(t *testing.T) {
	originalDbpath := dbpath
	dbpath = t.TempDir()
	t.Cleanup(func() { dbpath = originalDbpath })

	const id = "0000-0001-2345-6789"
	h := HandleInternalRegisterKey("")
	body, _ := json.Marshal(InternalRegisterRequest{ID: id, PublicKeyPEM: genTestRSAPubPEM(t)})

	req := httptest.NewRequest(http.MethodPost, "/internal/sovereign/register", bytes.NewReader(body))
	req.Header.Set("X-ID1-Internal-Secret", "") // empty header, empty secret
	rr := httptest.NewRecorder()
	h(rr, req)
	if rr.Code == http.StatusOK {
		t.Fatalf("disabled endpoint accepted request (got 200)")
	}
	if data, err := CmdGet(KK(id, "pub", "key")).Exec(); err == nil && len(data) > 0 {
		t.Fatalf("key written while endpoint disabled")
	}
}

func TestHandleInternalRegisterKey_RejectsBadInput(t *testing.T) {
	originalDbpath := dbpath
	dbpath = t.TempDir()
	t.Cleanup(func() { dbpath = originalDbpath })

	const secret = "internal-secret"
	h := HandleInternalRegisterKey(secret)
	goodPEM := genTestRSAPubPEM(t)

	cases := []struct {
		name string
		body InternalRegisterRequest
		want int
	}{
		{"malformed id", InternalRegisterRequest{ID: "not-an-orcid", PublicKeyPEM: goodPEM}, http.StatusBadRequest},
		{"empty id", InternalRegisterRequest{ID: "", PublicKeyPEM: goodPEM}, http.StatusBadRequest},
		{"missing pem", InternalRegisterRequest{ID: "0000-0001-2345-6789", PublicKeyPEM: ""}, http.StatusBadRequest},
		{"garbage pem", InternalRegisterRequest{ID: "0000-0001-2345-6789", PublicKeyPEM: "not a pem"}, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(tc.body)
			req := httptest.NewRequest(http.MethodPost, "/internal/sovereign/register", bytes.NewReader(body))
			req.Header.Set("X-ID1-Internal-Secret", secret)
			rr := httptest.NewRecorder()
			h(rr, req)
			if rr.Code != tc.want {
				t.Fatalf("%s: want %d, got %d", tc.name, tc.want, rr.Code)
			}
		})
	}
}

func TestHandleInternalRegisterKey_RejectsNonPost(t *testing.T) {
	originalDbpath := dbpath
	dbpath = t.TempDir()
	t.Cleanup(func() { dbpath = originalDbpath })

	h := HandleInternalRegisterKey("internal-secret")
	req := httptest.NewRequest(http.MethodGet, "/internal/sovereign/register", nil)
	req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
	rr := httptest.NewRecorder()
	h(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: want 405, got %d", rr.Code)
	}
}
