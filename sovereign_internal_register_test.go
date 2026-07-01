package id1

import (
	"bytes"
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
	"net/http/httptest"
	"testing"
	"time"
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

// clientCertWithCN builds a self-signed leaf cert carrying the given CN, to inject
// as a CA-verified client cert in req.TLS.VerifiedChains (unit-level; the real
// handshake is exercised in TestInternalRegister_RealHandshake below).
func clientCertWithCN(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return cert
}

func verifiedTLS(t *testing.T, cn string) *tls.ConnectionState {
	return &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{clientCertWithCN(t, cn)}}}
}

func postRegister(t *testing.T, h http.HandlerFunc, connState *tls.ConnectionState, body InternalRegisterRequest) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/internal/sovereign/register", bytes.NewReader(raw))
	req.TLS = connState
	rr := httptest.NewRecorder()
	h(rr, req)
	return rr
}

func TestInternalRegister_VerifiedCertWritesThenOverwrites(t *testing.T) {
	originalDbpath := dbpath
	dbpath = t.TempDir()
	t.Cleanup(func() { dbpath = originalDbpath })

	const id = "0000-0001-2345-6789"
	const device = "cur-a"
	h := HandleInternalRegisterKey()

	pem1 := genTestRSAPubPEM(t)
	rr := postRegister(t, h, verifiedTLS(t, device), InternalRegisterRequest{ID: id, Device: device, PublicKeyPEM: pem1})
	if rr.Code != http.StatusOK {
		t.Fatalf("first register: want 200, got %d (%s)", rr.Code, rr.Body.String())
	}
	stored, err := CmdGet(KK(id, "pub", "keys", device)).Exec()
	if err != nil || string(stored) != pem1 {
		t.Fatalf("stored device key mismatch after first register: err=%v", err)
	}

	pem2 := genTestRSAPubPEM(t)
	if pem2 == pem1 {
		t.Fatal("two generated keys identical - test cannot distinguish overwrite")
	}
	rr2 := postRegister(t, h, verifiedTLS(t, device), InternalRegisterRequest{ID: id, Device: device, PublicKeyPEM: pem2})
	if rr2.Code != http.StatusOK {
		t.Fatalf("rotate register: want 200, got %d (%s)", rr2.Code, rr2.Body.String())
	}
	stored2, err := CmdGet(KK(id, "pub", "keys", device)).Exec()
	if err != nil || string(stored2) != pem2 {
		t.Fatalf("device key not overwritten on rotate: err=%v", err)
	}
}

func TestInternalRegister_NoTLS_Rejected(t *testing.T) {
	originalDbpath := dbpath
	dbpath = t.TempDir()
	t.Cleanup(func() { dbpath = originalDbpath })

	const id = "0000-0001-2345-6789"
	h := HandleInternalRegisterKey()
	rr := postRegister(t, h, nil, InternalRegisterRequest{ID: id, Device: "cur-a", PublicKeyPEM: genTestRSAPubPEM(t)})
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("no TLS: want 401, got %d", rr.Code)
	}
	if data, err := CmdGet(KK(id, "pub", "keys", "cur-a")).Exec(); err == nil && len(data) > 0 {
		t.Fatalf("key written despite no TLS")
	}
}

func TestInternalRegister_EmptyVerifiedChains_Rejected(t *testing.T) {
	originalDbpath := dbpath
	dbpath = t.TempDir()
	t.Cleanup(func() { dbpath = originalDbpath })

	const id = "0000-0001-2345-6789"
	h := HandleInternalRegisterKey()
	rr := postRegister(t, h, &tls.ConnectionState{}, InternalRegisterRequest{ID: id, Device: "cur-a", PublicKeyPEM: genTestRSAPubPEM(t)})
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("empty chains: want 401, got %d", rr.Code)
	}
	if data, err := CmdGet(KK(id, "pub", "keys", "cur-a")).Exec(); err == nil && len(data) > 0 {
		t.Fatalf("key written despite empty verified chains")
	}
}

func TestInternalRegister_DeviceMustMatchCN(t *testing.T) {
	originalDbpath := dbpath
	dbpath = t.TempDir()
	t.Cleanup(func() { dbpath = originalDbpath })

	const id = "0000-0001-2345-6789"
	h := HandleInternalRegisterKey()
	rr := postRegister(t, h, verifiedTLS(t, "cur-a"), InternalRegisterRequest{ID: id, Device: "cur-b", PublicKeyPEM: genTestRSAPubPEM(t)})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("device!=CN: want 403, got %d", rr.Code)
	}
	if data, err := CmdGet(KK(id, "pub", "keys", "cur-b")).Exec(); err == nil && len(data) > 0 {
		t.Fatalf("cross-tenant device key was written")
	}
}

func TestInternalRegister_RejectsBadInput(t *testing.T) {
	originalDbpath := dbpath
	dbpath = t.TempDir()
	t.Cleanup(func() { dbpath = originalDbpath })

	h := HandleInternalRegisterKey()
	goodPEM := genTestRSAPubPEM(t)
	cases := []struct {
		name string
		cn   string
		body InternalRegisterRequest
		want int
	}{
		{"malformed id", "cur-a", InternalRegisterRequest{ID: "not-an-orcid", Device: "cur-a", PublicKeyPEM: goodPEM}, http.StatusBadRequest},
		{"empty id", "cur-a", InternalRegisterRequest{ID: "", Device: "cur-a", PublicKeyPEM: goodPEM}, http.StatusBadRequest},
		{"empty device", "cur-a", InternalRegisterRequest{ID: "0000-0001-2345-6789", Device: "", PublicKeyPEM: goodPEM}, http.StatusBadRequest},
		{"malformed device", "cur-a", InternalRegisterRequest{ID: "0000-0001-2345-6789", Device: "bad/seg", PublicKeyPEM: goodPEM}, http.StatusBadRequest},
		{"dot device", ".", InternalRegisterRequest{ID: "0000-0001-2345-6789", Device: ".", PublicKeyPEM: goodPEM}, http.StatusBadRequest},
		{"dotdot device", "..", InternalRegisterRequest{ID: "0000-0001-2345-6789", Device: "..", PublicKeyPEM: goodPEM}, http.StatusBadRequest},
		{"missing pem", "cur-a", InternalRegisterRequest{ID: "0000-0001-2345-6789", Device: "cur-a", PublicKeyPEM: ""}, http.StatusBadRequest},
		{"garbage pem", "cur-a", InternalRegisterRequest{ID: "0000-0001-2345-6789", Device: "cur-a", PublicKeyPEM: "not a pem"}, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := postRegister(t, h, verifiedTLS(t, tc.cn), tc.body)
			if rr.Code != tc.want {
				t.Fatalf("%s: want %d, got %d", tc.name, tc.want, rr.Code)
			}
		})
	}
}

func TestInternalRegister_RejectsNonPost(t *testing.T) {
	originalDbpath := dbpath
	dbpath = t.TempDir()
	t.Cleanup(func() { dbpath = originalDbpath })

	h := HandleInternalRegisterKey()
	req := httptest.NewRequest(http.MethodGet, "/internal/sovereign/register", nil)
	req.TLS = verifiedTLS(t, "cur-a")
	rr := httptest.NewRecorder()
	h(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: want 405, got %d", rr.Code)
	}
}

// --- Real-handshake integration (mirrors production VerifyClientCertIfGiven + ClientCAs) ---

// makeCert creates a cert signed by parent/parentKey; when parent is nil it self-signs
// (for a CA). Leaf certs carry 127.0.0.1 so httptest's TLS server is verifiable.
func makeCert(t *testing.T, cn string, isCA bool, parent *x509.Certificate, parentKey *rsa.PrivateKey) (*x509.Certificate, []byte, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(int64(len(cn)) + 3),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
	}
	if isCA {
		tmpl.IsCA = true
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	} else {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		tmpl.DNSNames = []string{"localhost"}
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("createcert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return cert, der, key
}

func tlsCertOf(der []byte, key *rsa.PrivateKey) tls.Certificate {
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestInternalRegister_RealHandshake(t *testing.T) {
	originalDbpath := dbpath
	dbpath = t.TempDir()
	t.Cleanup(func() { dbpath = originalDbpath })

	ca, _, caKey := makeCert(t, "federation-ca", true, nil, nil)
	_, srvDER, srvKey := makeCert(t, "annot8r-id1", false, ca, caKey)
	_, cliDER, cliKey := makeCert(t, "cur-a", false, ca, caKey)

	caPool := x509.NewCertPool()
	caPool.AddCert(ca)

	srv := httptest.NewUnstartedServer(HandleInternalRegisterKey())
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCertOf(srvDER, srvKey)},
		ClientAuth:   tls.VerifyClientCertIfGiven, // matches production BuildTLSConfig
		ClientCAs:    caPool,
	}
	srv.StartTLS()
	defer srv.Close()

	const id = "0000-0001-2345-6789"
	pemA := genTestRSAPubPEM(t)
	body, _ := json.Marshal(InternalRegisterRequest{ID: id, Device: "cur-a", PublicKeyPEM: pemA})

	// (a) CA-signed client cert, CN=cur-a, device=cur-a -> 200 + key stored.
	okClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:      caPool,
		Certificates: []tls.Certificate{tlsCertOf(cliDER, cliKey)},
	}}}
	resp, err := okClient.Post(srv.URL+"/internal/sovereign/register", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("trusted client POST: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("trusted client: want 200, got %d", resp.StatusCode)
	}
	if v, err := CmdGet(KK(id, "pub", "keys", "cur-a")).Exec(); err != nil || len(v) == 0 {
		t.Fatalf("device key not written on real handshake: %v", err)
	}

	// (b) No client cert -> handshake SUCCEEDS (VerifyClientCertIfGiven), handler 401.
	noCert := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: caPool}}}
	resp2, err := noCert.Post(srv.URL+"/internal/sovereign/register", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("certless client should complete handshake: %v", err)
	}
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("certless: want 401 from handler, got %d", resp2.StatusCode)
	}

	// (c) Client cert signed by an UNTRUSTED CA must NOT be able to register. Go's TLS
	// client won't send a cert whose issuer the server did not advertise (from ClientCAs),
	// so it connects certless and the handler 401s; a force-sent untrusted cert would
	// instead fail the handshake under VerifyClientCertIfGiven. Either way: never a 200.
	otherCA, _, otherKey := makeCert(t, "rogue-ca", true, nil, nil)
	_, rogueDER, rogueKey := makeCert(t, "cur-a", false, otherCA, otherKey)
	rogue := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:      caPool,
		Certificates: []tls.Certificate{tlsCertOf(rogueDER, rogueKey)},
	}}}
	rogueBody, _ := json.Marshal(InternalRegisterRequest{ID: id, Device: "cur-a", PublicKeyPEM: genTestRSAPubPEM(t)})
	resp3, err := rogue.Post(srv.URL+"/internal/sovereign/register", "application/json", bytes.NewReader(rogueBody))
	if err == nil && resp3.StatusCode != http.StatusUnauthorized {
		t.Fatalf("untrusted-CA client connected certless but was not rejected: got %d", resp3.StatusCode)
	}
	// The rogue must not have overwritten the legit key from case (a).
	if stored, err := CmdGet(KK(id, "pub", "keys", "cur-a")).Exec(); err != nil || string(stored) != pemA {
		t.Fatalf("untrusted-CA client overwrote the device key")
	}
}

// TestInternalRegister_BodyCapped verifies the 64 KiB MaxBytesReader cap rejects an
// oversized body rather than decoding it (a trusted-but-buggy/compromised caller).
func TestInternalRegister_BodyCapped(t *testing.T) {
	originalDbpath := dbpath
	dbpath = t.TempDir()
	t.Cleanup(func() { dbpath = originalDbpath })

	h := HandleInternalRegisterKey()
	// A publicKeyPem far over the 64 KiB cap (valid JSON, but the reader truncates).
	huge := make([]byte, 128<<10)
	for i := range huge {
		huge[i] = 'A'
	}
	rr := postRegister(t, h, verifiedTLS(t, "cur-a"), InternalRegisterRequest{
		ID: "0000-0001-2345-6789", Device: "cur-a", PublicKeyPEM: string(huge),
	})
	if rr.Code == http.StatusOK {
		t.Fatalf("oversized body accepted (got 200); MaxBytesReader cap not enforced")
	}
	if data, err := CmdGet(KK("0000-0001-2345-6789", "pub", "keys", "cur-a")).Exec(); err == nil && len(data) > 0 {
		t.Fatalf("key written from an oversized body")
	}
}
