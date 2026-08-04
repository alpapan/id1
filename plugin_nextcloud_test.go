// apps/backend/containers/id1/plugin_nextcloud_test.go
//
// group: config
// tags: nextcloud, integration, testing
// summary: Tests for Nextcloud plugin and WebDAV integration.
//
//

package id1

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// DeriveNextcloudPassword - HMAC-SHA256 based deterministic password derivation.
// ---------------------------------------------------------------------------

func TestDeriveNextcloudPassword_Deterministic(t *testing.T) {
	key := []byte("test-derivation-key")
	orcid := "0009-0002-8023-3658"
	pw1, err := DeriveNextcloudPassword(key, orcid)
	require.NoError(t, err)
	pw2, err := DeriveNextcloudPassword(key, orcid)
	require.NoError(t, err)
	assert.Equal(t, pw1, pw2, "same inputs must produce same output")
}

func TestDeriveNextcloudPassword_DifferentKeys(t *testing.T) {
	orcid := "0009-0002-8023-3658"
	pw1, err := DeriveNextcloudPassword([]byte("key1"), orcid)
	require.NoError(t, err)
	pw2, err := DeriveNextcloudPassword([]byte("key2"), orcid)
	require.NoError(t, err)
	assert.NotEqual(t, pw1, pw2, "different keys must produce different outputs")
}

func TestDeriveNextcloudPassword_DifferentOrcids(t *testing.T) {
	key := []byte("test-derivation-key")
	pw1, err := DeriveNextcloudPassword(key, "0009-0002-8023-3658")
	require.NoError(t, err)
	pw2, err := DeriveNextcloudPassword(key, "0000-0002-1825-0097")
	require.NoError(t, err)
	assert.NotEqual(t, pw1, pw2, "different orcids must produce different outputs")
}

func TestDeriveNextcloudPassword_NCPrefix(t *testing.T) {
	pw, err := DeriveNextcloudPassword([]byte("test-derivation-key"), "0009-0002-8023-3658")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(pw, "NC_"), "derived password must start with NC_ prefix")
}

func TestDeriveNextcloudPassword_EmptyKey(t *testing.T) {
	_, err := DeriveNextcloudPassword([]byte{}, "0009-0002-8023-3658")
	assert.Error(t, err, "empty derivation key must return error")
}

func TestDeriveNextcloudPassword_EmptyOrcid(t *testing.T) {
	_, err := DeriveNextcloudPassword([]byte("test-key"), "")
	assert.Error(t, err, "empty orcid must return error")
}

// ---------------------------------------------------------------------------
// NextcloudClient type - stateless HTTP client for Nextcloud OCS API.
// ---------------------------------------------------------------------------

func TestNewNextcloudClient_ReadsEnv(t *testing.T) {
	t.Setenv("NEXTCLOUD_URL", "http://test.example")
	t.Setenv("NC_PROVISIONER_USER", "admin")
	t.Setenv("NC_PROVISIONER_PASSWORD", "secret")

	c := NewNextcloudClient()

	assert.Equal(t, "http://test.example", c.URL)
	assert.Equal(t, "admin", c.Username)
	assert.Equal(t, "secret", c.Password)
}

func TestNewNextcloudClient_MissingEnvReturnsZeros(t *testing.T) {
	t.Setenv("NEXTCLOUD_URL", "")
	t.Setenv("NC_PROVISIONER_USER", "")
	t.Setenv("NC_PROVISIONER_PASSWORD", "")

	c := NewNextcloudClient()

	assert.Equal(t, "", c.URL)
	assert.Equal(t, "", c.Username)
	assert.Equal(t, "", c.Password)
}

// ---------------------------------------------------------------------------
// NextcloudClient.EnsureUserExists - idempotent OCS user-creation call.
// ---------------------------------------------------------------------------

func TestNextcloudClient_EnsureUserExists_Created(t *testing.T) {
	var gotPayload url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/ocs/v2.php/cloud/users", r.URL.Path)
		assert.Equal(t, "true", r.Header.Get("OCS-APIREQUEST"))
		body, _ := io.ReadAll(r.Body)
		gotPayload, _ = url.ParseQuery(string(body))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ocs":{"meta":{"statuscode":100,"status":"ok","message":"OK"},"data":{}}}`)
	}))
	defer server.Close()

	c := &NextcloudClient{URL: server.URL, Username: "admin", Password: "secret"}
	err := c.EnsureUserExists(context.Background(), "0009-0002-8023-3658", "NC_derivedPw")

	require.NoError(t, err)
	assert.Equal(t, "0009-0002-8023-3658", gotPayload.Get("userid"))
	assert.Equal(t, "NC_derivedPw", gotPayload.Get("password"))
}

// Nextcloud 32 OCS v2 returns statuscode 200 on successful user creation
// (older OCS v1 convention was 100). Both must be accepted.
func TestNextcloudClient_EnsureUserExists_Created200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ocs":{"meta":{"statuscode":200,"status":"ok","message":"OK"},"data":{"id":"0009-0002-8023-3658"}}}`)
	}))
	defer server.Close()

	c := &NextcloudClient{URL: server.URL, Username: "admin", Password: "secret"}
	err := c.EnsureUserExists(context.Background(), "0009-0002-8023-3658", "NC_derivedPw")

	assert.NoError(t, err, "OCS v2 statuscode 200 must be treated as success")
}

func TestNextcloudClient_EnsureUserExists_AlreadyExists(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ocs":{"meta":{"statuscode":102,"status":"failure","message":"User already exists"},"data":null}}`)
	}))
	defer server.Close()

	c := &NextcloudClient{URL: server.URL, Username: "admin", Password: "secret"}
	err := c.EnsureUserExists(context.Background(), "0009-0002-8023-3658", "NC_derivedPw")

	assert.NoError(t, err, "102 (already exists) must be treated as success")
}

func TestNextcloudClient_EnsureUserExists_OCSError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ocs":{"meta":{"statuscode":101,"status":"failure","message":"Invalid input"},"data":null}}`)
	}))
	defer server.Close()

	c := &NextcloudClient{URL: server.URL, Username: "admin", Password: "secret"}
	err := c.EnsureUserExists(context.Background(), "0009-0002-8023-3658", "NC_derivedPw")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "OCS error 101")
}

// Known OCS statuscodes from the Provisioning API should be annotated with
// a human-readable hint so log readers don't have to look up the code.
func TestNextcloudClient_EnsureUserExists_KnownErrorCodesAreExplained(t *testing.T) {
	cases := []struct {
		code        int
		hintPortion string
	}{
		{101, "invalid input"},
		{103, "unknown error"},
		{104, "group does not exist"},
		{107, "password"},
		{109, "failed to create user"},
		{111, "invalid email"},
		{113, "invalid quota"},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("code_%d", tc.code), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"ocs":{"meta":{"statuscode":%d,"status":"failure","message":"server msg"},"data":null}}`, tc.code)
			}))
			defer server.Close()

			c := &NextcloudClient{URL: server.URL, Username: "admin", Password: "secret"}
			err := c.EnsureUserExists(context.Background(), "0009-0002-8023-3658", "NC_derivedPw")

			require.Error(t, err)
			assert.Contains(t, err.Error(), fmt.Sprintf("%d", tc.code), "error should contain OCS code")
			assert.Contains(t, err.Error(), "server msg", "error should contain server message")
			assert.Contains(t, strings.ToLower(err.Error()), tc.hintPortion, "error should contain OCS hint")
		})
	}
}

func TestNextcloudClient_EnsureUserExists_UnknownCodeFallsBackToGenericHint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ocs":{"meta":{"statuscode":999,"status":"failure","message":"odd"},"data":null}}`)
	}))
	defer server.Close()

	c := &NextcloudClient{URL: server.URL, Username: "admin", Password: "secret"}
	err := c.EnsureUserExists(context.Background(), "0009-0002-8023-3658", "NC_derivedPw")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "999")
	assert.Contains(t, err.Error(), "odd")
}

// ---------------------------------------------------------------------------
// NextcloudClient.MintAppToken - OCS getapppassword call as the user.
// ---------------------------------------------------------------------------

func TestNextcloudClient_MintAppToken_Success(t *testing.T) {
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/ocs/v2.php/core/getapppassword", r.URL.Path)
		assert.Equal(t, "true", r.Header.Get("OCS-APIREQUEST"))
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ocs":{"meta":{"statuscode":200,"status":"ok","message":"OK"},"data":{"apppassword":"PLAINTEXT-TOKEN-abc123"}}}`)
	}))
	defer server.Close()

	c := &NextcloudClient{URL: server.URL}
	token, err := c.MintAppToken(context.Background(), "0009-0002-8023-3658", "NC_derivedPw")

	require.NoError(t, err)
	assert.Equal(t, "PLAINTEXT-TOKEN-abc123", token)
	assert.NotEmpty(t, gotAuth, "Basic Auth header must be set")
}

func TestNextcloudClient_MintAppToken_BadPassword(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	c := &NextcloudClient{URL: server.URL}
	_, err := c.MintAppToken(context.Background(), "0009-0002-8023-3658", "wrong")

	require.Error(t, err)
}

func TestNextcloudClient_MintAppToken_OCSNon200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"ocs":{"meta":{"statuscode":403,"status":"failure","message":"forbidden"},"data":null}}`)
	}))
	defer server.Close()

	c := &NextcloudClient{URL: server.URL}
	_, err := c.MintAppToken(context.Background(), "0009-0002-8023-3658", "NC_pw")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "OCS error 403")
}

// ---------------------------------------------------------------------------
// HandleNcToken - HTTP handler for GET /internal/nc-token?orcid=<X>.
// ---------------------------------------------------------------------------

func TestHandleNcToken_HappyPath(t *testing.T) {
	ncURL, userCalls, mintCalls, cleanup := countingNextcloud(t, "MINTED-TOKEN")
	defer cleanup()

	handler := HandleNcToken(&NextcloudClient{URL: ncURL, Username: "admin", Password: "secret"}, []byte("test-key"), "internal-secret", 2*time.Second)

	req := httptest.NewRequest("GET", "/internal/nc-token?orcid=0009-0002-8023-3658", nil)
	req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	var body map[string]string
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, "MINTED-TOKEN", body["token"])
	assert.Equal(t, int32(0), atomic.LoadInt32(userCalls), "mint-only must never call the provisioning endpoint")
	assert.Equal(t, int32(1), atomic.LoadInt32(mintCalls))
}

func TestHandleNcToken_MissingOrcid(t *testing.T) {
	handler := HandleNcToken(&NextcloudClient{}, []byte("test-key"), "internal-secret", 2*time.Second)

	req := httptest.NewRequest("GET", "/internal/nc-token", nil)
	req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleNcToken_MalformedOrcid(t *testing.T) {
	handler := HandleNcToken(&NextcloudClient{}, []byte("test-key"), "internal-secret", 2*time.Second)

	req := httptest.NewRequest("GET", "/internal/nc-token?orcid=not-an-orcid", nil)
	req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleNcToken_MissingInternalSecret(t *testing.T) {
	handler := HandleNcToken(&NextcloudClient{}, []byte("test-key"), "internal-secret", 2*time.Second)

	req := httptest.NewRequest("GET", "/internal/nc-token?orcid=0009-0002-8023-3658", nil)
	// no X-ID1-Internal-Secret header
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestHandleNcToken_WrongInternalSecret(t *testing.T) {
	handler := HandleNcToken(&NextcloudClient{}, []byte("test-key"), "internal-secret", 2*time.Second)

	req := httptest.NewRequest("GET", "/internal/nc-token?orcid=0009-0002-8023-3658", nil)
	req.Header.Set("X-ID1-Internal-Secret", "wrong")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestHandleNcToken_NextcloudDown(t *testing.T) {
	// Point at a closed server to force connection failure.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close()

	handler := HandleNcToken(&NextcloudClient{URL: srv.URL, Username: "admin", Password: "secret"}, []byte("test-key"), "internal-secret", 2*time.Second)

	req := httptest.NewRequest("GET", "/internal/nc-token?orcid=0009-0002-8023-3658", nil)
	req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadGateway, rr.Code)
}

// countingNextcloud starts a fake Nextcloud that records which OCS endpoints
// were called, so a test can assert that a request never reached Nextcloud at
// all - the difference between "rejected at the gate" and "rejected later".
func countingNextcloud(t *testing.T, tokenToReturn string) (ncURL string, users *int32, mints *int32, cleanup func()) {
	t.Helper()
	var userCalls, mintCalls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/ocs/v2.php/cloud/users":
			atomic.AddInt32(&userCalls, 1)
			fmt.Fprint(w, `{"ocs":{"meta":{"statuscode":100,"status":"ok","message":"OK"},"data":{}}}`)
		case "/ocs/v2.php/core/getapppassword":
			atomic.AddInt32(&mintCalls, 1)
			fmt.Fprintf(w, `{"ocs":{"meta":{"statuscode":200,"status":"ok","message":"OK"},"data":{"apppassword":"%s"}}}`, tokenToReturn)
		default:
			http.NotFound(w, r)
		}
	}))
	return srv.URL, &userCalls, &mintCalls, srv.Close
}

// An unset ID1_INTERNAL_SECRET must never authorise a caller. Before the gate
// was fixed, an empty configured secret compared equal to an absent header, so
// any in-cluster caller could mint Nextcloud app passwords.
func TestHandleNcToken_EmptyConfiguredSecretRejectsEmptyHeader(t *testing.T) {
	ncURL, userCalls, mintCalls, cleanup := countingNextcloud(t, "SHOULD-NOT-BE-MINTED")
	defer cleanup()

	handler := HandleNcToken(&NextcloudClient{URL: ncURL, Username: "admin", Password: "secret"}, []byte("test-key"), "", 2*time.Second)

	req := httptest.NewRequest("GET", "/internal/nc-token?orcid=0009-0002-8023-3658", nil)
	// no X-ID1-Internal-Secret header, and no configured secret either
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Equal(t, int32(0), atomic.LoadInt32(userCalls), "an unconfigured secret must never reach Nextcloud")
	assert.Equal(t, int32(0), atomic.LoadInt32(mintCalls), "an unconfigured secret must never mint anything")
}

func TestSecretMatches(t *testing.T) {
	assert.True(t, secretMatches("s3cret", "s3cret"))
	assert.False(t, secretMatches("s3cret", "other"))
	assert.False(t, secretMatches("", ""), "an unset secret must never match an absent header")
	assert.False(t, secretMatches("", "s3cret"), "an absent header must never match")
	assert.False(t, secretMatches("s3cret", ""), "an unset secret must never match")
}

func TestHandleNcToken_RejectsNonGet(t *testing.T) {
	handler := HandleNcToken(&NextcloudClient{}, []byte("test-key"), "internal-secret", 2*time.Second)

	req := httptest.NewRequest("POST", "/internal/nc-token?orcid=0009-0002-8023-3658", nil)
	req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

// Nextcloud answers a getapppassword for an account that does not exist with
// HTTP 401. The backend needs that distinguishable from "Nextcloud is down" so
// it can provision and retry exactly once.
func TestHandleNcToken_CredentialsRejectedReturns409(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	handler := HandleNcToken(&NextcloudClient{URL: srv.URL}, []byte("test-key"), "internal-secret", 2*time.Second)

	req := httptest.NewRequest("GET", "/internal/nc-token?orcid=0009-0002-8023-3658", nil)
	req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusConflict, rr.Code)
	var body map[string]string
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, "nextcloud_credentials_rejected", body["error"])
}

// Nextcloud can answer HTTP 200 with an OCS failure statuscode instead. id1's
// own ocsAuthHints names 997 ("unauthorised (basic auth failed)") and 403
// ("forbidden (credentials rejected ...)") as the same class. A shape that is
// not mapped leaves the user permanently 502ing with the lazy provisioning
// path never firing.
func TestHandleNcToken_OCSAuthFailuresReturn409(t *testing.T) {
	for _, code := range []int{997, 403} {
		t.Run(fmt.Sprintf("ocs_%d", code), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"ocs":{"meta":{"statuscode":%d,"status":"failure","message":"denied"},"data":null}}`, code)
			}))
			defer srv.Close()

			handler := HandleNcToken(&NextcloudClient{URL: srv.URL}, []byte("test-key"), "internal-secret", 2*time.Second)

			req := httptest.NewRequest("GET", "/internal/nc-token?orcid=0009-0002-8023-3658", nil)
			req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusConflict, rr.Code)
		})
	}
}

// id1 registers no server-side ReadTimeout/WriteTimeout, so each handler must
// bound itself rather than relying on the caller's socket.
func TestHandleNcToken_BoundsItselfWithItsOwnTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ocs":{"meta":{"statuscode":200,"status":"ok","message":"OK"},"data":{"apppassword":"LATE"}}}`)
	}))
	defer srv.Close()

	handler := HandleNcToken(&NextcloudClient{URL: srv.URL}, []byte("test-key"), "internal-secret", 100*time.Millisecond)

	req := httptest.NewRequest("GET", "/internal/nc-token?orcid=0009-0002-8023-3658", nil)
	req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
	rr := httptest.NewRecorder()
	start := time.Now()
	handler.ServeHTTP(rr, req)
	elapsed := time.Since(start)

	assert.Equal(t, http.StatusGatewayTimeout, rr.Code)
	assert.Less(t, elapsed, time.Second, "the handler must give up on its own budget, not wait for Nextcloud")
}

// A caller that hangs up cancels the request context, which is not the
// handler's own deadline expiring. Reporting it as a Nextcloud outage puts a
// false outage line in id1's log for every abandoned request, and the eager
// background provisioning hook abandons requests routinely at shutdown.
func TestHandleNcToken_ClientDisconnectIsNotReportedAsAnOutage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()

	handler := HandleNcToken(&NextcloudClient{URL: srv.URL}, []byte("test-key"), "internal-secret", 5*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest("GET", "/internal/nc-token?orcid=0009-0002-8023-3658", nil).WithContext(ctx)
	req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
	rr := httptest.NewRecorder()
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	handler.ServeHTTP(rr, req)

	assert.NotEqual(t, http.StatusBadGateway, rr.Code, "an abandoned request is not a Nextcloud outage")
	assert.Empty(t, rr.Body.String(), "nothing should be written to a connection the caller closed")
}

func TestHandleNcProvision_ClientDisconnectIsNotReportedAsAnOutage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()

	handler := HandleNcProvision(&NextcloudClient{URL: srv.URL, Username: "admin", Password: "secret"}, []byte("test-key"), "internal-secret", 5*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest("POST", "/internal/nc-provision?orcid=0009-0002-8023-3658", nil).WithContext(ctx)
	req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
	rr := httptest.NewRecorder()
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	handler.ServeHTTP(rr, req)

	assert.NotEqual(t, http.StatusBadGateway, rr.Code, "an abandoned request is not a Nextcloud outage")
	assert.Empty(t, rr.Body.String(), "nothing should be written to a connection the caller closed")
}

// The handler budgets are only meaningful while they bind before the
// per-request client timeout. Asserting against the real constant rather than
// a duplicated literal means lowering the client timeout breaks this test
// instead of silently falsifying the invariant it names.
func TestHandlerBudgetsBindBeforeTheClientTimeout(t *testing.T) {
	assert.Less(t, NcTokenTimeout, ncHTTPClientTimeout)
	assert.Less(t, NcProvisionTimeout, ncHTTPClientTimeout)
	assert.Greater(t, NcProvisionTimeout, NcTokenTimeout, "provisioning gets the wider budget")
}

// Both endpoints are gated by the internal secret, so registering them without
// one turns every Nextcloud file operation into a 401 with nothing at startup
// to say why. Reporting "not enabled" lets main say so once, loudly.
func TestNcEndpointsEnabled(t *testing.T) {
	fullKey := strings.Repeat("ab", 32) // what `openssl rand -hex 32` provisions
	assert.True(t, NcEndpointsEnabled(fullKey, "s3cret"))
	assert.False(t, NcEndpointsEnabled("", "s3cret"), "no derivation key, no endpoints")
	assert.False(t, NcEndpointsEnabled(fullKey, ""), "no internal secret, no endpoints")
	assert.False(t, NcEndpointsEnabled("", ""))
}

// A key can be perfectly valid hex and still be far too short to be worth
// anything as an HMAC key. `openssl rand -hex 32` is what provisions it, so a
// short key is as much a misconfiguration as one that does not decode, and gets
// the same answer: the endpoints do not register.
func TestNcEndpointsEnabled_RejectsAKeyThatIsNotThirtyTwoBytes(t *testing.T) {
	assert.False(t, NcEndpointsEnabled("2206", "s3cret"), "two bytes is not a key")
	assert.False(t, NcEndpointsEnabled("deadbeef", "s3cret"), "four bytes is not a key")
	assert.False(t, NcEndpointsEnabled(strings.Repeat("ab", 31), "s3cret"), "31 bytes is short")
	assert.False(t, NcEndpointsEnabled(strings.Repeat("ab", 33), "s3cret"), "33 bytes is not the provisioned shape")
}

// A derivation key that is not hex cannot produce the passwords the bash
// rotation script computes, so the endpoints must not be registered with it.
// Reporting it here is what lets the caller decline to register rather than
// kill a process that also serves ORCID login, JWKS and the sovereign-key
// surface.
func TestNcEndpointsEnabled_RejectsAKeyThatIsNotHex(t *testing.T) {
	assert.False(t, NcEndpointsEnabled("not-hex-at-all", "s3cret"), "a non-hex key derives nothing usable")
	assert.False(t, NcEndpointsEnabled("abc", "s3cret"), "an odd-length hex string decodes partially")
	assert.False(t, NcEndpointsEnabled("00112233gg", "s3cret"), "a non-hex digit decodes partially")
}

// captureLog redirects the standard logger for the duration of a test and
// returns a func giving what was written.
func captureLog(t *testing.T) func() string {
	t.Helper()
	var buf strings.Builder
	previousOut := log.Writer()
	previousFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(previousOut)
		log.SetFlags(previousFlags)
	})
	return buf.String
}

// An account that does not exist yet is refused with HTTP 401, so that shape is
// the expected answer on a brand-new user's first login and must not be logged:
// otherwise every normal first login reads exactly like a misconfiguration. The
// in-band OCS forms are different - Nextcloud only emits those when it actively
// refuses an existing context, so they are anomalous whenever they appear and
// are logged on sight. MintAppToken is where the shapes are still
// distinguishable; the handler collapses all of them into one 409.
func TestMintAppToken_LogsWhichRejectionShapeNextcloudReturned(t *testing.T) {
	cases := []struct {
		name    string
		handler http.HandlerFunc
		want    []string
	}{
		{
			name: "ocs_403",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{"ocs":{"meta":{"statuscode":403,"status":"failure","message":"forbidden"},"data":null}}`)
			},
			want: []string{"OCS 403", "forbidden"},
		},
		{
			name: "ocs_997",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{"ocs":{"meta":{"statuscode":997,"status":"failure","message":"denied"},"data":null}}`)
			},
			want: []string{"OCS 997", "denied"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()
			logged := captureLog(t)

			_, err := (&NextcloudClient{URL: srv.URL}).MintAppToken(context.Background(), "0009-0002-8023-3658", "NC_pw")

			require.Error(t, err)
			require.ErrorIs(t, err, ErrNextcloudCredentialsRejected)
			for _, want := range tc.want {
				assert.Contains(t, logged(), want, "the log must name which rejection shape Nextcloud returned")
			}
			assert.Contains(t, logged(), "0009-0002-8023-3658", "the log must name the user it concerns")
		})
	}
}

// rejectingNextcloud serves HTTP 401 until told to succeed, so a test can drive
// a streak of rejections, a success, and a further streak against one client.
func rejectingNextcloud(t *testing.T) (client *NextcloudClient, setSucceeding func(bool), cleanup func()) {
	t.Helper()
	var ok atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ok.Load() {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"ocs":{"meta":{"statuscode":200,"status":"ok","message":"OK"},"data":{"apppassword":"TOKEN"}}}`)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	return &NextcloudClient{URL: srv.URL}, ok.Store, srv.Close
}

// The single most common case in the whole system: a brand-new user logs in,
// their account does not exist yet, the mint is refused once, the backend
// provisions and the next mint succeeds. That must leave no trace in the log,
// or every new user looks like a broken deployment.
func TestMintAppToken_DoesNotLogTheExpectedFirstLoginRejection(t *testing.T) {
	nc, _, cleanup := rejectingNextcloud(t)
	defer cleanup()
	logged := captureLog(t)

	_, err := nc.MintAppToken(context.Background(), "0009-0002-8023-3658", "NC_pw")

	require.ErrorIs(t, err, ErrNextcloudCredentialsRejected)
	assert.Equal(t, "", logged(), "one rejection is a first login, not a misconfiguration")
}

// What separates a first login from a misaimed NEXTCLOUD_URL is not the shape -
// both are HTTP 401 - but that a misconfiguration never stops. A run of
// rejections with no successful mint between them is the signal, and it is
// reported once rather than per request.
func TestMintAppToken_ReportsAStreakOfRejectionsAsALikelyMisconfiguration(t *testing.T) {
	nc, _, cleanup := rejectingNextcloud(t)
	defer cleanup()
	logged := captureLog(t)

	for attempt := 1; attempt < ncRejectionStreakAlertThreshold; attempt++ {
		_, err := nc.MintAppToken(context.Background(), "0009-0002-8023-3658", "NC_pw")
		require.ErrorIs(t, err, ErrNextcloudCredentialsRejected)
		assert.Equal(t, "", logged(), "still under the threshold at attempt %d", attempt)
	}

	_, err := nc.MintAppToken(context.Background(), "0009-0002-8023-3658", "NC_pw")
	require.ErrorIs(t, err, ErrNextcloudCredentialsRejected)
	assert.Contains(t, logged(), "NEXTCLOUD_URL", "the alert must name what to go and check")
	assert.Contains(t, logged(), fmt.Sprintf("%d", ncRejectionStreakAlertThreshold))

	// Reported once per streak, not once per request from here on.
	before := logged()
	_, err = nc.MintAppToken(context.Background(), "0009-0002-8023-3658", "NC_pw")
	require.ErrorIs(t, err, ErrNextcloudCredentialsRejected)
	assert.Equal(t, before, logged(), "the alert must not repeat for every later rejection")
}

// A successful mint proves the URL and the key are fine, so the run of
// rejections before it was ordinary first-login traffic and must not
// accumulate towards an alert.
func TestMintAppToken_ASuccessfulMintResetsTheRejectionStreak(t *testing.T) {
	nc, setSucceeding, cleanup := rejectingNextcloud(t)
	defer cleanup()
	logged := captureLog(t)

	// A burst of brand-new users, all one short of the threshold.
	for attempt := 1; attempt < ncRejectionStreakAlertThreshold; attempt++ {
		_, err := nc.MintAppToken(context.Background(), "0009-0002-8023-3658", "NC_pw")
		require.ErrorIs(t, err, ErrNextcloudCredentialsRejected)
	}

	setSucceeding(true)
	token, err := nc.MintAppToken(context.Background(), "0009-0002-8023-3658", "NC_pw")
	require.NoError(t, err)
	require.Equal(t, "TOKEN", token)

	// The counter is back to zero, so the same number of rejections again stays
	// silent. Without the reset this second run would cross the threshold.
	setSucceeding(false)
	for attempt := 1; attempt < ncRejectionStreakAlertThreshold; attempt++ {
		_, err := nc.MintAppToken(context.Background(), "0009-0002-8023-3658", "NC_pw")
		require.ErrorIs(t, err, ErrNextcloudCredentialsRejected)
	}

	assert.Equal(t, "", logged(), "a success between the runs means neither is a misconfiguration")
}

// perUserNextcloud refuses every user except those switched to succeeding, so a
// test can hold one user failing while others mint normally around them.
func perUserNextcloud(t *testing.T) (client *NextcloudClient, succeedFor func(string), cleanup func()) {
	t.Helper()
	var mu sync.Mutex
	ok := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, _, _ := r.BasicAuth()
		mu.Lock()
		succeeding := ok[user]
		mu.Unlock()
		if succeeding {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"ocs":{"meta":{"statuscode":200,"status":"ok","message":"OK"},"data":{"apppassword":"TOKEN"}}}`)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	return &NextcloudClient{URL: srv.URL}, func(user string) {
		mu.Lock()
		ok[user] = true
		mu.Unlock()
	}, srv.Close
}

// The case this alert exists to catch: one user whose Nextcloud password has
// permanently diverged from the derivation key. Provisioning cannot repair it -
// EnsureUserExists accepts "already exists" without resetting the password - so
// they are refused forever while everyone else works. Counting rejections
// globally would let each successful mint by another user erase their streak
// and the failure would never be reported at all.
func TestMintAppToken_TracksRejectionStreaksPerUser(t *testing.T) {
	const stuck = "0009-0002-8023-3658"
	const healthy = "0000-0002-1825-0097"
	nc, succeedFor, cleanup := perUserNextcloud(t)
	defer cleanup()
	succeedFor(healthy)
	logged := captureLog(t)

	for attempt := 1; attempt < ncRejectionStreakAlertThreshold; attempt++ {
		_, err := nc.MintAppToken(context.Background(), stuck, "NC_pw")
		require.ErrorIs(t, err, ErrNextcloudCredentialsRejected)
		// A healthy user mints between every one of the stuck user's attempts.
		_, err = nc.MintAppToken(context.Background(), healthy, "NC_pw")
		require.NoError(t, err)
	}
	require.Equal(t, "", logged(), "still under the threshold for the stuck user")

	_, err := nc.MintAppToken(context.Background(), stuck, "NC_pw")
	require.ErrorIs(t, err, ErrNextcloudCredentialsRejected)

	assert.Contains(t, logged(), stuck, "the alert must name the user that is stuck")
	assert.NotContains(t, logged(), healthy, "the healthy user is not part of the streak")
	assert.Contains(t, logged(), "HTTP 401", "the alert must name the refusal shape")
	assert.Contains(t, logged(), "NEXTCLOUD_URL", "the alert must name what to go and check")
}

// A burst of genuinely new users each refused once is ordinary first-login
// traffic, however many of them arrive together. Only a run against the SAME
// user means something is wrong.
func TestMintAppToken_DoesNotAlertWhenSeveralNewUsersEachFailOnce(t *testing.T) {
	nc, _, cleanup := perUserNextcloud(t)
	defer cleanup()
	logged := captureLog(t)

	for n := 0; n < ncRejectionStreakAlertThreshold*2; n++ {
		orcid := fmt.Sprintf("0000-0000-0000-%04d", n)
		_, err := nc.MintAppToken(context.Background(), orcid, "NC_pw")
		require.ErrorIs(t, err, ErrNextcloudCredentialsRejected)
	}

	assert.Equal(t, "", logged(), "distinct users failing once each are new users, not a misconfiguration")
}

// The 409-vs-502 boundary from the other side: an OCS code that is not one of
// the credential-rejection shapes must NOT become the sentinel, or the backend
// would provision-and-retry against an unrelated failure.
func TestMintAppToken_AnUnrelatedOCSCodeIsNotACredentialsRejection(t *testing.T) {
	for _, code := range []int{101, 999} {
		t.Run(fmt.Sprintf("ocs_%d", code), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"ocs":{"meta":{"statuscode":%d,"status":"failure","message":"other"},"data":null}}`, code)
			}))
			defer srv.Close()

			_, err := (&NextcloudClient{URL: srv.URL}).MintAppToken(context.Background(), "0009-0002-8023-3658", "NC_pw")

			require.Error(t, err)
			require.NotErrorIs(t, err, ErrNextcloudCredentialsRejected,
				"only 401, OCS 403 and OCS 997 mean the credentials were refused")
			assert.Contains(t, err.Error(), fmt.Sprintf("OCS error %d", code))
		})
	}
}

// A successful mint is not a rejection and must log nothing.
func TestMintAppToken_LogsNothingOnSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ocs":{"meta":{"statuscode":200,"status":"ok","message":"OK"},"data":{"apppassword":"TOKEN"}}}`)
	}))
	defer srv.Close()
	logged := captureLog(t)

	token, err := (&NextcloudClient{URL: srv.URL}).MintAppToken(context.Background(), "0009-0002-8023-3658", "NC_pw")

	require.NoError(t, err)
	assert.Equal(t, "TOKEN", token)
	assert.Equal(t, "", logged())
}

// ---------------------------------------------------------------------------
// HandleNcProvision - POST /internal/nc-provision?orcid=<X>
// ---------------------------------------------------------------------------

func TestHandleNcProvision_CreatesAccountOnly(t *testing.T) {
	ncURL, userCalls, mintCalls, cleanup := countingNextcloud(t, "UNUSED")
	defer cleanup()

	handler := HandleNcProvision(&NextcloudClient{URL: ncURL, Username: "admin", Password: "secret"}, []byte("test-key"), "internal-secret", 2*time.Second)

	req := httptest.NewRequest("POST", "/internal/nc-provision?orcid=0009-0002-8023-3658", nil)
	req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusNoContent, rr.Code)
	assert.Equal(t, int32(1), atomic.LoadInt32(userCalls))
	assert.Equal(t, int32(0), atomic.LoadInt32(mintCalls), "provisioning must never mint an app password")
}

// EnsureUserExists already treats OCS 102 as success, so a second call is a
// no-op. Provisioning is safe to fire eagerly on every new user, which means a
// repeat must answer 204 exactly as the first did and must mint nothing.
func TestHandleNcProvision_IsIdempotent(t *testing.T) {
	var userCalls, mintCalls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/ocs/v2.php/cloud/users":
			atomic.AddInt32(&userCalls, 1)
			// The second and later calls are what Nextcloud answers 102 to.
			fmt.Fprint(w, `{"ocs":{"meta":{"statuscode":102,"status":"failure","message":"User already exists"},"data":null}}`)
		case "/ocs/v2.php/core/getapppassword":
			atomic.AddInt32(&mintCalls, 1)
			fmt.Fprint(w, `{"ocs":{"meta":{"statuscode":200,"status":"ok","message":"OK"},"data":{"apppassword":"SHOULD-NOT-BE-MINTED"}}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	handler := HandleNcProvision(&NextcloudClient{URL: srv.URL, Username: "admin", Password: "secret"}, []byte("test-key"), "internal-secret", 2*time.Second)

	for attempt := 1; attempt <= 2; attempt++ {
		req := httptest.NewRequest("POST", "/internal/nc-provision?orcid=0009-0002-8023-3658", nil)
		req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNoContent, rr.Code, "attempt %d must answer 204", attempt)
	}

	assert.Equal(t, int32(2), atomic.LoadInt32(&userCalls))
	assert.Equal(t, int32(0), atomic.LoadInt32(&mintCalls), "a repeat provision must create no credential")
}

func TestHandleNcProvision_RejectsNonPost(t *testing.T) {
	handler := HandleNcProvision(&NextcloudClient{}, []byte("test-key"), "internal-secret", 2*time.Second)

	req := httptest.NewRequest("GET", "/internal/nc-provision?orcid=0009-0002-8023-3658", nil)
	req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

func TestHandleNcProvision_RejectsWrongSecret(t *testing.T) {
	handler := HandleNcProvision(&NextcloudClient{}, []byte("test-key"), "internal-secret", 2*time.Second)

	req := httptest.NewRequest("POST", "/internal/nc-provision?orcid=0009-0002-8023-3658", nil)
	req.Header.Set("X-ID1-Internal-Secret", "wrong")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestHandleNcProvision_RejectsEmptyConfiguredSecret(t *testing.T) {
	ncURL, userCalls, _, cleanup := countingNextcloud(t, "UNUSED")
	defer cleanup()

	handler := HandleNcProvision(&NextcloudClient{URL: ncURL, Username: "admin", Password: "secret"}, []byte("test-key"), "", 2*time.Second)

	req := httptest.NewRequest("POST", "/internal/nc-provision?orcid=0009-0002-8023-3658", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Equal(t, int32(0), atomic.LoadInt32(userCalls))
}

func TestHandleNcProvision_RejectsMalformedOrcid(t *testing.T) {
	handler := HandleNcProvision(&NextcloudClient{}, []byte("test-key"), "internal-secret", 2*time.Second)

	req := httptest.NewRequest("POST", "/internal/nc-provision?orcid=not-an-orcid", nil)
	req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleNcProvision_NextcloudDownReturns502(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close()

	handler := HandleNcProvision(&NextcloudClient{URL: srv.URL, Username: "admin", Password: "secret"}, []byte("test-key"), "internal-secret", 2*time.Second)

	req := httptest.NewRequest("POST", "/internal/nc-provision?orcid=0009-0002-8023-3658", nil)
	req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadGateway, rr.Code)
}

func TestHandleNcProvision_BoundsItselfWithItsOwnTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ocs":{"meta":{"statuscode":100,"status":"ok","message":"OK"},"data":{}}}`)
	}))
	defer srv.Close()

	handler := HandleNcProvision(&NextcloudClient{URL: srv.URL, Username: "admin", Password: "secret"}, []byte("test-key"), "internal-secret", 100*time.Millisecond)

	req := httptest.NewRequest("POST", "/internal/nc-provision?orcid=0009-0002-8023-3658", nil)
	req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
	rr := httptest.NewRecorder()
	start := time.Now()
	handler.ServeHTTP(rr, req)
	elapsed := time.Since(start)

	assert.Equal(t, http.StatusGatewayTimeout, rr.Code)
	assert.Less(t, elapsed, time.Second)
}

// __END_OF_FILE_MARKER__
