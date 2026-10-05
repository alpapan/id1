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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
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

// Nextcloud's UsersController::addUser maps any unexpected exception to OCS
// 101, including the unique-constraint failure of the loser of two concurrent
// creates of one user. A hint naming only input format and password policy
// sends the reader the wrong way.
func TestNextcloudClient_EnsureUserExists_101HintNamesTheConcurrentCreate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ocs":{"meta":{"statuscode":101,"status":"failure","message":"Bad request"},"data":null}}`)
	}))
	defer server.Close()

	c := &NextcloudClient{URL: server.URL, Username: "admin", Password: "secret"}
	err := c.EnsureUserExists(context.Background(), "0009-0002-8023-3658", "NC_derivedPw")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "concurrent request created the same user")
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

// ncUserLookupPrefix is the path prefix of Nextcloud's single-user read,
// GET /ocs/v2.php/cloud/users/{userid}, which HandleNcToken calls as the
// provisioning account before any login as the user.
const ncUserLookupPrefix = "/ocs/v2.php/cloud/users/"

// withAccountLookup answers Nextcloud's single-user read with an account that
// exists (OCS 200, as the v2 endpoint answers) or is missing (OCS 404 served
// as HTTP 404, as Nextcloud serves it), and passes every other request to
// next. A fake that answers every request the same way would otherwise also
// answer the existence read.
func withAccountLookup(exists bool, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, ncUserLookupPrefix) {
			next(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if exists {
			fmt.Fprint(w, `{"ocs":{"meta":{"statuscode":200,"status":"ok","message":"OK"},"data":{"id":"0009-0002-8023-3658","enabled":true}}}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"ocs":{"meta":{"statuscode":404,"status":"failure","message":"User does not exist"},"data":[]}}`)
	}
}

// countingNextcloud starts a fake Nextcloud that records which OCS endpoints
// were called, so a test can assert that a request never reached Nextcloud at
// all - the difference between "rejected at the gate" and "rejected later".
// The single-user read answers that the account exists.
func countingNextcloud(t *testing.T, tokenToReturn string) (ncURL string, users *int32, mints *int32, cleanup func()) {
	t.Helper()
	var userCalls, mintCalls int32
	srv := httptest.NewServer(withAccountLookup(true, func(w http.ResponseWriter, r *http.Request) {
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

// Nextcloud records a login to an account that does not exist as a failed
// login against the caller's address, and id1 is one address for every user.
// So for an account Nextcloud reports missing, HandleNcToken answers 409
// nextcloud_credentials_rejected - the code the backend provisions on -
// without attempting a single login as the user, even with a previous
// derivation key armed.
func TestHandleNcToken_MissingAccountIsNeverLoggedInAs(t *testing.T) {
	var logins int32
	srv := httptest.NewServer(withAccountLookup(false, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&logins, 1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	handler := HandleNcToken(&NextcloudClient{URL: srv.URL, Username: "admin", Password: "secret"}, []byte("current-key"), "internal-secret", 2*time.Second, []byte("previous-key"))

	req := httptest.NewRequest("GET", "/internal/nc-token?orcid=0009-0002-8023-3658", nil)
	req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusConflict, rr.Code)
	var body map[string]string
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, "nextcloud_credentials_rejected", body["error"])
	assert.Equal(t, int32(0), atomic.LoadInt32(&logins), "a missing account must never be logged in as")
}

// Nextcloud can answer HTTP 200 with an OCS failure statuscode instead. id1's
// own ocsAuthHints names 997 ("unauthorised (basic auth failed)") and 403
// ("forbidden (credentials rejected ...)") as the same class. A shape that is
// not mapped leaves the user permanently 502ing with the lazy provisioning
// path never firing.
func TestHandleNcToken_OCSAuthFailuresReturn409(t *testing.T) {
	for _, code := range []int{997, 403} {
		t.Run(fmt.Sprintf("ocs_%d", code), func(t *testing.T) {
			srv := httptest.NewServer(withAccountLookup(true, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"ocs":{"meta":{"statuscode":%d,"status":"failure","message":"denied"},"data":null}}`, code)
			}))
			defer srv.Close()

			handler := HandleNcToken(&NextcloudClient{URL: srv.URL}, []byte("test-key"), "internal-secret", 2*time.Second)

			req := httptest.NewRequest("GET", "/internal/nc-token?orcid=0009-0002-8023-3658", nil)
			req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			require.Equal(t, http.StatusConflict, rr.Code)
			assert.JSONEq(t, `{"error":"nextcloud_password_rejected"}`, rr.Body.String(),
				"an existing account that refuses the key is not a missing account, so the caller must not provision")
		})
	}
}

// ---------------------------------------------------------------------------
// Rotation overlap - HandleNcToken accepts the previous derivation key.
// ---------------------------------------------------------------------------

// Rotating NC_DERIVATION_KEY resets every account's Nextcloud password to the
// value the new key derives, one account at a time, while id1 keeps deriving
// from whichever key its pod was started with. Without an overlap every account
// on the wrong side of that boundary is refused, so the outage scales with the
// user count rather than being the "~1 second window" the rotation was once
// documented as. Serving current-plus-previous is what jwt_signing.go already
// does for the RS256 signing key, and this is the same shape for the
// derivation key.
func TestHandleNcToken_FallsBackToThePreviousDerivationKey(t *testing.T) {
	currentKey := []byte("current-derivation-key")
	previousKey := []byte("previous-derivation-key")
	const orcid = "0009-0002-8023-3658"

	currentPassword, err := DeriveNextcloudPassword(currentKey, orcid)
	require.NoError(t, err)
	previousPassword, err := DeriveNextcloudPassword(previousKey, orcid)
	require.NoError(t, err)
	require.NotEqual(t, currentPassword, previousPassword, "the two keys must derive different passwords or this test proves nothing")

	var mu sync.Mutex
	var presented []string

	// This account's Nextcloud password has NOT been reset yet, so only the
	// previous key's derivation authenticates. The account exists, so the
	// existence read never reaches this recorder.
	srv := httptest.NewServer(withAccountLookup(true, func(w http.ResponseWriter, r *http.Request) {
		_, password, _ := r.BasicAuth()
		mu.Lock()
		presented = append(presented, password)
		mu.Unlock()
		if password != previousPassword {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ocs":{"meta":{"statuscode":200,"status":"ok","message":"OK"},"data":{"apppassword":"MINTED-WITH-PREVIOUS"}}}`)
	}))
	defer srv.Close()

	handler := HandleNcToken(&NextcloudClient{URL: srv.URL}, currentKey, "internal-secret", 2*time.Second, previousKey)

	req := httptest.NewRequest("GET", "/internal/nc-token?orcid="+orcid, nil)
	req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	var body map[string]string
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, "MINTED-WITH-PREVIOUS", body["token"])

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, presented, 2, "exactly two attempts: the current key, then the previous one")
	assert.Equal(t, currentPassword, presented[0], "the current key must be tried FIRST")
	assert.Equal(t, previousPassword, presented[1], "the previous key is the fallback, never the first choice")
}

// An account whose password matches NEITHER key is not a rotation problem - it
// is the ordinary "this account does not exist yet" case, and the caller
// provisions on 409. Exhausting the keys must reach exactly the same answer as
// having no previous key at all, or the lazy provisioning path stops firing for
// every new user for the duration of a rotation.
// An existing account whose password matches NEITHER key is not something
// provisioning can repair: its password has diverged from every key id1 holds.
// Exhausting the keys answers nextcloud_password_rejected, the code the backend
// never provisions on, after exactly one attempt per key.
func TestHandleNcToken_ReturnsConflictWhenNoKeyAuthenticates(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(withAccountLookup(true, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	handler := HandleNcToken(&NextcloudClient{URL: srv.URL}, []byte("current-key"), "internal-secret", 2*time.Second, []byte("previous-key"))

	req := httptest.NewRequest("GET", "/internal/nc-token?orcid=0009-0002-8023-3658", nil)
	req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusConflict, rr.Code)
	var body map[string]string
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, "nextcloud_password_rejected", body["error"])
	assert.Equal(t, int32(2), atomic.LoadInt32(&attempts), "both keys tried, neither retried further")
}

// A failure that is not a credentials rejection must not consume the fallback.
// A wedged or unreachable Nextcloud says nothing about which key is right, and
// a second attempt would double the load on a service that is already failing
// while still answering 502.
func TestHandleNcToken_DoesNotRetryOnAFailureThatIsNotACredentialsRejection(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(withAccountLookup(true, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ocs":{"meta":{"statuscode":998,"status":"failure","message":"not found"},"data":null}}`)
	}))
	defer srv.Close()

	handler := HandleNcToken(&NextcloudClient{URL: srv.URL}, []byte("current-key"), "internal-secret", 2*time.Second, []byte("previous-key"))

	req := httptest.NewRequest("GET", "/internal/nc-token?orcid=0009-0002-8023-3658", nil)
	req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadGateway, rr.Code)
	assert.Equal(t, int32(1), atomic.LoadInt32(&attempts), "OCS 998 is not a credentials rejection, so the previous key is never tried")
}

// The steady state: no rotation in flight, no previous key configured. One
// attempt, and the previous-key machinery is invisible.
func TestHandleNcToken_WithNoPreviousKeyMakesExactlyOneAttempt(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(withAccountLookup(true, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	handler := HandleNcToken(&NextcloudClient{URL: srv.URL}, []byte("current-key"), "internal-secret", 2*time.Second)

	req := httptest.NewRequest("GET", "/internal/nc-token?orcid=0009-0002-8023-3658", nil)
	req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusConflict, rr.Code)
	assert.Equal(t, int32(1), atomic.LoadInt32(&attempts))
}

// When Nextcloud signals it is rate-limiting (HTTP 429), the fallback must not
// consume the attempt on the previous key. Rate-limiting says nothing about
// which key is right - a second attempt would double the load on a service
// that is already throttling while still failing.
func TestHandleNcToken_DoesNotRetryOnHTTP429(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(withAccountLookup(true, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusTooManyRequests) // HTTP 429
	}))
	defer srv.Close()

	handler := HandleNcToken(&NextcloudClient{URL: srv.URL}, []byte("current-key"), "internal-secret", 2*time.Second, []byte("previous-key"))

	req := httptest.NewRequest("GET", "/internal/nc-token?orcid=0009-0002-8023-3658", nil)
	req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
	assert.Equal(t, int32(1), atomic.LoadInt32(&attempts), "HTTP 429 is not a credentials rejection, so the previous key is never tried")
}

// A throttled existence read is answered as a throttled mint is, 503, and no
// login as the user is attempted: a login would be refused by the same
// throttle and would only add to it.
func TestHandleNcToken_ThrottledExistenceReadReturns503WithoutALogin(t *testing.T) {
	var logins int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, ncUserLookupPrefix) {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		atomic.AddInt32(&logins, 1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ocs":{"meta":{"statuscode":200,"status":"ok","message":"OK"},"data":{"apppassword":"SHOULD-NOT-BE-MINTED"}}}`)
	}))
	defer srv.Close()

	handler := HandleNcToken(&NextcloudClient{URL: srv.URL, Username: "admin", Password: "secret"}, []byte("test-key"), "internal-secret", 2*time.Second)

	req := httptest.NewRequest("GET", "/internal/nc-token?orcid=0009-0002-8023-3658", nil)
	req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
	assert.Equal(t, int32(0), atomic.LoadInt32(&logins), "no login while Nextcloud throttles the existence read")
}

// Nextcloud answers the single-user read with OCS 998, served as HTTP 404,
// when the calling account has no rights over the target user - here, the
// provisioning account has lost its admin group. That is a fault in id1's own
// configuration, never evidence the account is missing: answering 409
// nextcloud_credentials_rejected would make the backend try to create an
// account that may already exist.
func TestHandleNcToken_ProvisionerWithoutRightsIsNotAMissingAccount(t *testing.T) {
	var logins int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(r.URL.Path, ncUserLookupPrefix) {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"ocs":{"meta":{"statuscode":998,"status":"failure","message":""},"data":[]}}`)
			return
		}
		atomic.AddInt32(&logins, 1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	handler := HandleNcToken(&NextcloudClient{URL: srv.URL, Username: "admin", Password: "secret"}, []byte("test-key"), "internal-secret", 2*time.Second)

	req := httptest.NewRequest("GET", "/internal/nc-token?orcid=0009-0002-8023-3658", nil)
	req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadGateway, rr.Code)
	assert.Equal(t, int32(0), atomic.LoadInt32(&logins), "no login when existence could not be established")
}

// Owner ruling: an existing account that rejects the derived password gets no
// retry and a block of at least 30 minutes. A second request for the same ORCID
// inside the block is answered without any login.
func TestHandleNcToken_PasswordRejectionBlocksFurtherLoginsForThatUser(t *testing.T) {
	var logins int32
	srv := httptest.NewServer(withAccountLookup(true, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&logins, 1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	handler := HandleNcToken(&NextcloudClient{URL: srv.URL, Username: "admin", Password: "secret"}, []byte("test-key"), "internal-secret", 2*time.Second)

	for attempt := 1; attempt <= 2; attempt++ {
		req := httptest.NewRequest("GET", "/internal/nc-token?orcid=0009-0002-8023-3658", nil)
		req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		require.Equal(t, http.StatusConflict, rr.Code, "request %d", attempt)
		assert.JSONEq(t, `{"error":"nextcloud_password_rejected"}`, rr.Body.String(), "request %d", attempt)
	}
	assert.Equal(t, int32(1), atomic.LoadInt32(&logins), "the second request must not log in while the block holds")
}

// The block is per user: one user's diverged password must not stop another
// user's mint.
func TestHandleNcToken_PasswordBlockIsPerUser(t *testing.T) {
	const blockedOrcid = "0009-0002-8023-3658"
	const otherOrcid = "0000-0002-1825-0097"
	srv := httptest.NewServer(withAccountLookup(true, func(w http.ResponseWriter, r *http.Request) {
		user, _, _ := r.BasicAuth()
		if user == blockedOrcid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ocs":{"meta":{"statuscode":200,"status":"ok","message":"OK"},"data":{"apppassword":"OTHER-USER-TOKEN"}}}`)
	}))
	defer srv.Close()

	handler := HandleNcToken(&NextcloudClient{URL: srv.URL, Username: "admin", Password: "secret"}, []byte("test-key"), "internal-secret", 2*time.Second)
	call := func(orcid string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/internal/nc-token?orcid="+orcid, nil)
		req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr
	}

	require.Equal(t, http.StatusConflict, call(blockedOrcid).Code)
	rr := call(otherOrcid)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.JSONEq(t, `{"token":"OTHER-USER-TOKEN"}`, rr.Body.String())
}

// setNcNow replaces the clock the password block reads for the duration of a
// test and returns a func that moves it.
func setNcNow(t *testing.T, start time.Time) func(time.Time) {
	t.Helper()
	now := start
	previous := ncNow
	ncNow = func() time.Time { return now }
	t.Cleanup(func() { ncNow = previous })
	return func(next time.Time) { now = next }
}

// Owner ruling: the block lasts at least 30 minutes.
func TestNcPasswordBlockCooldownIsAtLeastThirtyMinutes(t *testing.T) {
	assert.GreaterOrEqual(t, ncPasswordBlockCooldown, 30*time.Minute)
}

// No login can succeed while the block holds, because the block skips the
// login itself: a repaired password is not noticed until the cooldown ends.
// At the cooldown exactly one login is attempted, and a success then leaves
// the user unblocked.
func TestHandleNcToken_PasswordBlockLiftsAfterTheCooldown(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	moveClock := setNcNow(t, start)

	var logins int32
	var repaired atomic.Bool
	srv := httptest.NewServer(withAccountLookup(true, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&logins, 1)
		if !repaired.Load() {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ocs":{"meta":{"statuscode":200,"status":"ok","message":"OK"},"data":{"apppassword":"AFTER-REPAIR"}}}`)
	}))
	defer srv.Close()

	handler := HandleNcToken(&NextcloudClient{URL: srv.URL, Username: "admin", Password: "secret"}, []byte("test-key"), "internal-secret", 2*time.Second)
	call := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/internal/nc-token?orcid=0009-0002-8023-3658", nil)
		req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr
	}

	require.Equal(t, http.StatusConflict, call().Code)
	require.Equal(t, int32(1), atomic.LoadInt32(&logins))

	repaired.Store(true)
	moveClock(start.Add(ncPasswordBlockCooldown - time.Second))
	rr := call()
	require.Equal(t, http.StatusConflict, rr.Code)
	assert.JSONEq(t, `{"error":"nextcloud_password_rejected"}`, rr.Body.String())
	assert.Equal(t, int32(1), atomic.LoadInt32(&logins), "no login inside the cooldown")

	moveClock(start.Add(ncPasswordBlockCooldown))
	rr = call()
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, int32(2), atomic.LoadInt32(&logins), "exactly one login once the cooldown has passed")

	rr = call()
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, int32(3), atomic.LoadInt32(&logins), "a success leaves the user unblocked")
}

// The block table is bounded. When it is full, blocks that have already
// lifted are dropped first.
func TestNextcloudClient_PasswordBlockTableDropsLiftedBlocksFirst(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	setNcNow(t, start)

	c := &NextcloudClient{passwordBlocks: make(map[string]time.Time)}
	for i := 0; i < ncPasswordBlockMaxTracked; i++ {
		until := start.Add(time.Minute)
		if i%2 == 0 {
			until = start.Add(-time.Minute)
		}
		c.passwordBlocks[fmt.Sprintf("held-%05d", i)] = until
	}

	c.blockPassword("0009-0002-8023-3658")

	assert.Len(t, c.passwordBlocks, ncPasswordBlockMaxTracked/2+1, "every lifted block is dropped, every live one kept")
	assert.True(t, c.passwordBlocked("0009-0002-8023-3658"))
	assert.True(t, c.passwordBlocked("held-00001"), "a live block survives the clean-up")
}

// When the full table holds only live blocks, the one that lifts soonest is
// released - one ORCID, never the whole table.
func TestNextcloudClient_PasswordBlockTableReleasesTheSoonestLiftingBlock(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	setNcNow(t, start)

	c := &NextcloudClient{passwordBlocks: make(map[string]time.Time)}
	for i := 0; i < ncPasswordBlockMaxTracked; i++ {
		c.passwordBlocks[fmt.Sprintf("held-%05d", i)] = start.Add(time.Duration(i+1) * time.Second)
	}

	c.blockPassword("0009-0002-8023-3658")

	assert.Len(t, c.passwordBlocks, ncPasswordBlockMaxTracked, "the table never grows past its bound")
	assert.NotContains(t, c.passwordBlocks, "held-00000", "the block that lifts soonest is released")
	assert.Contains(t, c.passwordBlocks, "held-00001", "only one block is released")
	assert.True(t, c.passwordBlocked("0009-0002-8023-3658"))
}

func TestNextcloudClient_UserExists_ExistingAccount(t *testing.T) {
	for _, code := range []int{100, 200} {
		t.Run(fmt.Sprintf("ocs_%d", code), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"ocs":{"meta":{"statuscode":%d,"status":"ok","message":"OK"},"data":{"id":"0009-0002-8023-3658"}}}`, code)
			}))
			defer srv.Close()

			c := &NextcloudClient{URL: srv.URL, Username: "admin", Password: "secret"}
			exists, err := c.UserExists(context.Background(), "0009-0002-8023-3658")

			require.NoError(t, err)
			assert.True(t, exists)
		})
	}
}

func TestNextcloudClient_UserExists_MissingAccount(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"ocs":{"meta":{"statuscode":404,"status":"failure","message":"User does not exist"},"data":[]}}`)
	}))
	defer srv.Close()

	c := &NextcloudClient{URL: srv.URL, Username: "admin", Password: "secret"}
	exists, err := c.UserExists(context.Background(), "0009-0002-8023-3658")

	require.NoError(t, err)
	assert.False(t, exists)
}

func TestNextcloudClient_UserExists_ProvisionerWithoutRightsIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"ocs":{"meta":{"statuscode":998,"status":"failure","message":""},"data":[]}}`)
	}))
	defer srv.Close()

	c := &NextcloudClient{URL: srv.URL, Username: "admin", Password: "secret"}
	exists, err := c.UserExists(context.Background(), "0009-0002-8023-3658")

	require.Error(t, err, "OCS 998 means the provisioning account cannot see the user, not that the user is missing")
	assert.False(t, exists)
	assert.Contains(t, err.Error(), "998")
	assert.Contains(t, err.Error(), "admin group")
}

func TestNextcloudClient_UserExists_RateLimitIsReportedAsRateLimit(t *testing.T) {
	srv := throttlingNextcloud(t)
	logged := captureLog(t)

	c := &NextcloudClient{URL: srv.URL, Username: "admin", Password: "secret"}
	_, err := c.UserExists(context.Background(), "0009-0002-8023-3658")

	require.ErrorIs(t, err, ErrNextcloudRateLimited)
	assert.Contains(t, logged(), ncThrottleResetCommand,
		"a throttled existence read must tell the operator how to clear the throttle")
}

// The read is made as the provisioning account, never as the user: a login as
// the user is exactly the failed login the read exists to avoid.
func TestNextcloudClient_UserExists_ReadsAsTheProvisioningAccount(t *testing.T) {
	var method, path, user, password, ocsHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		path = r.URL.Path
		user, password, _ = r.BasicAuth()
		ocsHeader = r.Header.Get("OCS-APIREQUEST")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ocs":{"meta":{"statuscode":200,"status":"ok","message":"OK"},"data":{"id":"0009-0002-8023-3658"}}}`)
	}))
	defer srv.Close()

	c := &NextcloudClient{URL: srv.URL, Username: "provisioner", Password: "provisioner-secret"}
	_, err := c.UserExists(context.Background(), "0009-0002-8023-3658")

	require.NoError(t, err)
	assert.Equal(t, http.MethodGet, method)
	assert.Equal(t, "/ocs/v2.php/cloud/users/0009-0002-8023-3658", path)
	assert.Equal(t, "provisioner", user)
	assert.Equal(t, "provisioner-secret", password)
	assert.Equal(t, "true", ocsHeader)
}

// id1 registers no server-side ReadTimeout/WriteTimeout, so each handler must
// bound itself rather than relying on the caller's socket.
func TestHandleNcToken_BoundsItselfWithItsOwnTimeout(t *testing.T) {
	srv := httptest.NewServer(withAccountLookup(true, func(w http.ResponseWriter, r *http.Request) {
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

// A Nextcloud busy creating many accounts at once answers a read well past the
// few seconds it takes when idle. The production budget must outlast that
// answer, or the caller is told 504 for a lookup that was about to succeed.
func TestHandleNcToken_ProductionBudgetOutlastsASlowNextcloudRead(t *testing.T) {
	const slowRead = 6 * time.Second
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(slowRead)
		withAccountLookup(false, nil)(w, r)
	}))
	defer srv.Close()

	handler := HandleNcToken(&NextcloudClient{URL: srv.URL}, []byte("test-key"), "internal-secret", NcTokenTimeout)

	req := httptest.NewRequest("GET", "/internal/nc-token?orcid=0009-0002-8023-3658", nil)
	req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusConflict, rr.Code, "a read answered after %s must still be answered, not timed out", slowRead)
}

// A caller that hangs up cancels the request context, which is not the
// handler's own deadline expiring. Reporting it as a Nextcloud outage puts a
// false outage line in id1's log for every abandoned request, and the eager
// background provisioning hook abandons requests routinely at shutdown.
func TestHandleNcToken_ClientDisconnectIsNotReportedAsAnOutage(t *testing.T) {
	srv := httptest.NewServer(withAccountLookup(true, func(w http.ResponseWriter, r *http.Request) {
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

// A derivation key that is not hex cannot produce the passwords
// `curatorium admin nextcloud rotate-derivation-key` computes, so the
// endpoints must not be registered with it. Reporting it here is what lets
// the caller decline to register rather than kill a process that also serves
// ORCID login, JWKS and the sovereign-key surface.
func TestNcEndpointsEnabled_RejectsAKeyThatIsNotHex(t *testing.T) {
	assert.False(t, NcEndpointsEnabled("not-hex-at-all", "s3cret"), "a non-hex key derives nothing usable")
	assert.False(t, NcEndpointsEnabled("abc", "s3cret"), "an odd-length hex string decodes partially")
	assert.False(t, NcEndpointsEnabled("00112233gg", "s3cret"), "a non-hex digit decodes partially")
}

// NC_DERIVATION_KEY_PREV is absent in the steady state and present only for the
// duration of a rotation, so "not set" must be an ordinary answer rather than a
// misconfiguration. A value that IS set and cannot be used is the opposite: it
// means an operator intended an overlap and will not get one, which is the
// exact outage the overlap exists to remove, so the caller has to be able to
// tell the two apart and say so.
func TestNcPreviousDerivationKey(t *testing.T) {
	fullKey := strings.Repeat("cd", 32) // what `openssl rand -hex 32` provisions

	key, usable := NcPreviousDerivationKey(fullKey)
	assert.True(t, usable)
	assert.Len(t, key, NcDerivationKeyBytes)

	key, usable = NcPreviousDerivationKey("")
	assert.False(t, usable, "unset is the steady state, not a usable key")
	assert.Nil(t, key)
}

func TestNcPreviousDerivationKey_RefusesAKeyThatIsNotUsable(t *testing.T) {
	for _, bad := range []string{
		"2206",
		"deadbeef",
		strings.Repeat("ab", 31),
		strings.Repeat("ab", 33),
		"not-hex-at-all",
		"abc",
		"00112233gg",
	} {
		key, usable := NcPreviousDerivationKey(bad)
		assert.False(t, usable, "unusable previous key must not arm the fallback: %q", bad)
		assert.Nil(t, key, "an unusable key must yield no bytes at all: %q", bad)
	}
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

// captureStdout redirects os.Stdout for the duration of a test - some of this
// file's error logging goes through fmt.Printf rather than the log package,
// so captureLog cannot see it. The returned func restores os.Stdout and
// returns everything written since the call; it is single-shot, call it once
// after the code under test has run.
func captureStdout(t *testing.T) func() string {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	previous := os.Stdout
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var buf strings.Builder
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()
	return func() string {
		os.Stdout = previous
		require.NoError(t, w.Close())
		out := <-done
		require.NoError(t, r.Close())
		return out
	}
}

// ncLogInjectionCase names one handler whose default failure branch logs a
// formatOCSError-wrapped error with %v, plus the OCS statuscode that reaches
// that branch for it (any code neither of a handler's own special-cased
// codes recognises).
type ncLogInjectionCase struct {
	name    string
	ocsCode int
	// accountExists answers the single-user read with an existing account, so
	// the fake's OCS error reaches the login rather than the existence read.
	accountExists bool
	newHandler    func(ncURL string) http.HandlerFunc
	newRequest    func() *http.Request
}

var ncLogInjectionCases = []ncLogInjectionCase{
	{
		name:    "HandleNcProvision",
		ocsCode: 101,
		newHandler: func(ncURL string) http.HandlerFunc {
			return HandleNcProvision(&NextcloudClient{URL: ncURL, Username: "admin", Password: "secret"}, []byte("test-key"), "internal-secret", 2*time.Second)
		},
		newRequest: func() *http.Request {
			req := httptest.NewRequest("POST", "/internal/nc-provision?orcid=0009-0002-8023-3658", nil)
			req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
			return req
		},
	},
	{
		name:    "HandleNcToken",
		ocsCode: 999,
		newHandler: func(ncURL string) http.HandlerFunc {
			return HandleNcToken(&NextcloudClient{URL: ncURL}, []byte("test-key"), "internal-secret", 2*time.Second)
		},
		newRequest: func() *http.Request {
			req := httptest.NewRequest("GET", "/internal/nc-token?orcid=0009-0002-8023-3658", nil)
			req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
			return req
		},
	},
	{
		name:          "HandleNcTokenLogin",
		ocsCode:       999,
		accountExists: true,
		newHandler: func(ncURL string) http.HandlerFunc {
			return HandleNcToken(&NextcloudClient{URL: ncURL}, []byte("test-key"), "internal-secret", 2*time.Second)
		},
		newRequest: func() *http.Request {
			req := httptest.NewRequest("GET", "/internal/nc-token?orcid=0009-0002-8023-3658", nil)
			req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
			return req
		},
	},
}

// formatOCSError's message argument comes verbatim from Nextcloud's own OCS
// response. HandleNcProvision and HandleNcToken each print the resulting
// error with %v when it falls through to their default failure branch, so an
// unquoted embedded newline in that message would forge an extra line in
// id1's own log output - exactly the risk MintAppToken's own rejection-shape
// log line already guards against by quoting its message with %q. A
// Nextcloud response is not something id1 fully controls, so this must hold
// regardless of whether Nextcloud itself, or something it echoes back, is
// the source of the embedded newline.
func TestHandleNcProvisionAndHandleNcToken_LogNextcloudErrorMessageOnOneLine(t *testing.T) {
	wantCaseNames := []string{"HandleNcProvision", "HandleNcToken", "HandleNcTokenLogin"}
	require.Len(t, ncLogInjectionCases, len(wantCaseNames),
		"the case list must carry exactly these cases; a deleted case must fail this guard rather than pass quietly")
	gotCaseNames := make([]string, 0, len(ncLogInjectionCases))
	for _, tc := range ncLogInjectionCases {
		gotCaseNames = append(gotCaseNames, tc.name)
	}
	assert.ElementsMatch(t, wantCaseNames, gotCaseNames,
		"the case list must carry exactly these named cases; a deleted, renamed, or added case must fail this guard rather than pass quietly")

	for _, tc := range ncLogInjectionCases {
		t.Run(tc.name, func(t *testing.T) {
			var fake http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"ocs":{"meta":{"statuscode":%d,"status":"failure","message":"line one\nFAKE LOG LINE: forged"},"data":null}}`, tc.ocsCode)
			}
			if tc.accountExists {
				fake = withAccountLookup(true, fake)
			}
			srv := httptest.NewServer(fake)
			defer srv.Close()

			handler := tc.newHandler(srv.URL)
			stop := captureStdout(t)

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, tc.newRequest())

			output := stop()
			lines := strings.Split(strings.TrimRight(output, "\n"), "\n")
			assert.Len(t, lines, 1, "an embedded newline in Nextcloud's message must not forge a second log line: got %q", output)
		})
	}
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

// concurrencyTrackingNextcloud starts a fake Nextcloud whose /cloud/users
// endpoint records the peak number of requests it served at once. Each
// request waits, up to one second, for wantConcurrent requests to have
// arrived together before it answers - a barrier rather than a fixed sleep,
// so the test's result does not depend on how promptly the Go scheduler runs
// each goroutine. A request serialised by id1's own lock never sees a second
// arrival before the timeout, so it falls through on its own after roughly a
// second; wantConcurrent requests that reach Nextcloud with nothing
// serialising them release each other immediately instead.
func concurrencyTrackingNextcloud(t *testing.T, wantConcurrent int) (ncURL string, peak *int32, cleanup func()) {
	t.Helper()
	var inFlight, observedPeak int32
	arrived := make(chan struct{}, wantConcurrent)
	release := make(chan struct{})
	var closeOnce sync.Once

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := atomic.AddInt32(&inFlight, 1)
		for {
			prevPeak := atomic.LoadInt32(&observedPeak)
			if current <= prevPeak || atomic.CompareAndSwapInt32(&observedPeak, prevPeak, current) {
				break
			}
		}

		arrived <- struct{}{}
		if len(arrived) == wantConcurrent {
			closeOnce.Do(func() { close(release) })
		}
		select {
		case <-release:
		case <-time.After(time.Second):
		}

		atomic.AddInt32(&inFlight, -1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ocs":{"meta":{"statuscode":100,"status":"ok","message":"OK"},"data":{}}}`)
	}))
	return srv.URL, &observedPeak, srv.Close
}

// provisionConcurrently fires len(orcids) concurrent provisioning requests
// against handler, one per entry, and waits for all of them to answer 204.
func provisionConcurrently(t *testing.T, handler http.HandlerFunc, orcids []string) {
	t.Helper()
	var wg sync.WaitGroup
	for _, orcid := range orcids {
		wg.Add(1)
		go func(orcid string) {
			defer wg.Done()
			req := httptest.NewRequest("POST", "/internal/nc-provision?orcid="+orcid, nil)
			req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			assert.Equal(t, http.StatusNoContent, rr.Code)
		}(orcid)
	}
	wg.Wait()
}

// ncProvisionConcurrencyCase names one mix of ORCIDs fired at HandleNcProvision
// concurrently, and the peak number of those requests that must be in flight
// against Nextcloud at once.
type ncProvisionConcurrencyCase struct {
	name     string
	orcids   []string
	wantPeak int32
}

var ncProvisionConcurrencyCases = []ncProvisionConcurrencyCase{
	{
		name:     "SameOrcidSerialises",
		orcids:   []string{"0009-0002-8023-3658", "0009-0002-8023-3658"},
		wantPeak: 1,
	},
	{
		name:     "DifferentOrcidsRunConcurrently",
		orcids:   []string{"0009-0002-8023-3658", "0000-0002-1825-0097"},
		wantPeak: 2,
	},
}

// Nextcloud's own provisioning_api UsersController::addUser checks
// userExists then calls createUser with no transactional protection between
// the two, so two concurrent provisioning requests for the same ORCID can
// both pass the existence check before either commits the insert; the loser
// gets OCS 101 ("invalid input") from the unique-constraint violation
// instead of the idempotent 102 EnsureUserExists already treats as success.
// id1 must never let two such requests reach Nextcloud concurrently for the
// same ORCID - serialising means the second caller's HTTP request starts
// only after the first one has finished, so it lands on the idempotent path.
//
// That serialisation must be scoped to the ORCID being provisioned, not a
// single lock shared by every caller: a global lock would also make the
// same-ORCID case pass while quietly serialising every unrelated user's
// provisioning behind whichever request happened to arrive first, each
// holding the wide NcProvisionTimeout budget. Two distinct ORCIDs must be
// free to provision fully concurrently, which the second case checks.
func TestHandleNcProvision_ConcurrencyIsScopedToOrcid(t *testing.T) {
	wantCaseNames := []string{"SameOrcidSerialises", "DifferentOrcidsRunConcurrently"}
	require.Len(t, ncProvisionConcurrencyCases, len(wantCaseNames),
		"the case list must carry exactly these cases; a deleted case must fail this guard rather than pass quietly")
	gotCaseNames := make([]string, 0, len(ncProvisionConcurrencyCases))
	for _, tc := range ncProvisionConcurrencyCases {
		gotCaseNames = append(gotCaseNames, tc.name)
	}
	assert.ElementsMatch(t, wantCaseNames, gotCaseNames,
		"the case list must carry exactly these named cases; a deleted, renamed, or added case must fail this guard rather than pass quietly")

	for _, tc := range ncProvisionConcurrencyCases {
		t.Run(tc.name, func(t *testing.T) {
			ncURL, peak, cleanup := concurrencyTrackingNextcloud(t, len(tc.orcids))
			defer cleanup()

			nc := &NextcloudClient{URL: ncURL, Username: "admin", Password: "secret"}
			handler := HandleNcProvision(nc, []byte("test-key"), "internal-secret", 2*time.Second)

			provisionConcurrently(t, handler, tc.orcids)

			assert.Equal(t, tc.wantPeak, atomic.LoadInt32(peak))
		})
	}
}

// The per-ORCID lock entries are reference-counted and removed only once no
// request is holding or waiting on them, so the map never grows without bound
// across the lifetime of the process - it tracks in-flight provisioning
// attempts, not every ORCID ever provisioned. This drives the real two-caller
// shape: while the first caller holds the lock, a second concurrent caller
// for the same ORCID must share that exact lock (never mint a second one for
// the same key) and must keep the map entry alive until it, too, releases.
func TestNextcloudClient_ProvisionLockLifecycle(t *testing.T) {
	nc := &NextcloudClient{}
	const orcid = "0009-0002-8023-3658"

	first := nc.acquireProvisionLock(orcid)
	first.mu.Lock()

	secondAcquired := make(chan *ncProvisionLock, 1)
	secondLocked := make(chan struct{})
	go func() {
		second := nc.acquireProvisionLock(orcid)
		secondAcquired <- second
		second.mu.Lock()
		close(secondLocked)
	}()

	second := <-secondAcquired
	require.Same(t, first, second, "a concurrent acquire for the same ORCID must share the in-flight lock, not create a second one")

	// The second caller is now blocked in Lock(). Releasing the first
	// reference must not remove the map entry while the second is still
	// outstanding, or a third caller arriving now would mint a fresh lock and
	// run alongside the second instead of behind it.
	nc.releaseProvisionLock(orcid, first)

	select {
	case <-secondLocked:
	case <-time.After(time.Second):
		t.Fatal("second caller never acquired the lock after the first released it")
	}

	nc.provisionLocksMu.Lock()
	_, stillTracked := nc.provisionLocks[orcid]
	nc.provisionLocksMu.Unlock()
	assert.True(t, stillTracked, "the second caller is still holding the lock; the entry must not be removed yet")

	nc.releaseProvisionLock(orcid, second)

	nc.provisionLocksMu.Lock()
	_, stillTracked = nc.provisionLocks[orcid]
	nc.provisionLocksMu.Unlock()
	assert.False(t, stillTracked, "once every reference is released, the entry must be removed")
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

func TestNextcloudClient_MintAppToken_SendsExplicitUserAgent(t *testing.T) {
	var gotUserAgent string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUserAgent = r.Header.Get("User-Agent")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ocs":{"meta":{"statuscode":200,"status":"ok","message":"OK"},"data":{"apppassword":"PLAINTEXT-TOKEN-abc123"}}}`)
	}))
	defer server.Close()

	c := &NextcloudClient{URL: server.URL}
	_, err := c.MintAppToken(context.Background(), "0009-0002-8023-3658", "NC_derivedPw")

	require.NoError(t, err)
	assert.Equal(t, NcMintUserAgent, gotUserAgent,
		"Nextcloud names an app password after the mint request's User-Agent, so it must be one we assert")
	assert.NotEqual(t, "Go-http-client/1.1", gotUserAgent,
		"the Go net/http default is not a discriminator this project controls")
}

// ---------------------------------------------------------------------------
// Golden vectors - the executable form of the cross-language derivation contract.
//
// The same vectors are asserted by the Python implementation in
// scripts/curatorium_assistant, against its own independent copy of this
// fixture: apps/id1 and scripts/curatorium_assistant are separate submodules,
// so neither can portably read a file inside the other.
// scripts/admin/test_nc_derivation_vectors_match_across_languages.py compares
// the two copies for byte-identity, so drift between them is caught.
//
// This test reads the expected values; it never computes them. A test that
// generates its own expectations asserts nothing.
// ---------------------------------------------------------------------------

type ncDerivationVector struct {
	KeyHex   string
	Orcid    string
	Expected string
}

// readNcDerivationVectors parses the three-column vector fixture. Blank lines
// and lines opening with "#" are commentary and carry no vector.
func readNcDerivationVectors(t *testing.T, path string) []ncDerivationVector {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err, "the golden vector fixture must exist")

	var vectors []ncDerivationVector
	for index, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		require.Len(t, fields, 3,
			"line %d of %s must carry exactly three whitespace-separated fields", index+1, path)
		vectors = append(vectors, ncDerivationVector{
			KeyHex:   fields[0],
			Orcid:    fields[1],
			Expected: fields[2],
		})
	}
	return vectors
}

func TestDeriveNextcloudPassword_MatchesGoldenVectors(t *testing.T) {
	vectors := readNcDerivationVectors(t, filepath.Join("testdata", "nc_derivation_vectors.txt"))

	require.GreaterOrEqual(t, len(vectors), 4,
		"the fixture must carry at least four vectors; an emptied fixture would let this test pass while asserting nothing")

	orcids := make([]string, 0, len(vectors))
	for _, vector := range vectors {
		orcids = append(orcids, vector.Orcid)
	}
	assert.Subset(t, orcids, []string{
		"0000-0000-0000-0001",
		"0009-0002-8023-3658",
		"0000-0002-1825-0097",
		"0000-0001-5109-3700",
	}, "the fixture must carry these four canary ORCID iDs; their absence means the vectors were swapped for a different set")

	for _, vector := range vectors {
		key, err := hex.DecodeString(vector.KeyHex)
		require.NoError(t, err, "field 1 of every vector must be valid hex")

		got, err := DeriveNextcloudPassword(key, vector.Orcid)
		require.NoError(t, err)
		assert.Equal(t, vector.Expected, got,
			"derivation drifted for orcid %s", vector.Orcid)
	}
}

// ---------------------------------------------------------------------------
// Startup diagnostics: NcPreviousDerivationKey and fallback arming.
// ---------------------------------------------------------------------------

func TestNcStartupDiagnostics_PreviousKeyForFallback(t *testing.T) {
	// Table-driven per curatorium-testing's "collapse a family before you
	// report DONE": one function under test (NcPreviousKeyForFallback), same
	// setup/assertion shape, differing only by which of the five input
	// scenarios is exercised.
	currentKey := make([]byte, 32)
	currentKey[0] = 0x01
	differentUsableHex := "02" + strings.Repeat("00", 31)

	cases := []struct {
		name           string
		previousKeyHex string
		wantArmed      bool // previousKey expected non-nil (fallback armed)
		wantLogged     bool // logLine expected non-empty (operator warned)
	}{
		{
			name:           "UsableAndDifferent",
			previousKeyHex: differentUsableHex,
			wantArmed:      true,
			wantLogged:     true,
		},
		{
			name:           "UsableAndEqual",
			previousKeyHex: "01" + strings.Repeat("00", 31), // decodes equal to currentKey
			wantArmed:      false,
			wantLogged:     true,
		},
		{
			name:           "UnusableTooShort",
			previousKeyHex: "0102",
			wantArmed:      false,
			wantLogged:     true,
		},
		{
			name:           "UnusableInvalidHex",
			previousKeyHex: "zzzzzzzzzzzzzzzzzz",
			wantArmed:      false,
			wantLogged:     true,
		},
		{
			name:           "Absent",
			previousKeyHex: "",
			wantArmed:      false,
			wantLogged:     false,
		},
	}

	// Guard over the case list itself: a deleted case must fail this test
	// rather than let the table quietly shrink to fewer scenarios.
	wantCaseNames := []string{
		"UsableAndDifferent", "UsableAndEqual", "UnusableTooShort", "UnusableInvalidHex", "Absent",
	}
	require.Len(t, cases, len(wantCaseNames),
		"the case list must carry exactly these five cases; a deleted case must fail this guard rather than pass quietly")
	gotCaseNames := make([]string, 0, len(cases))
	for _, tc := range cases {
		gotCaseNames = append(gotCaseNames, tc.name)
	}
	assert.ElementsMatch(t, wantCaseNames, gotCaseNames,
		"the case list must carry exactly these named cases; a deleted, renamed, or added case must fail this guard rather than pass quietly")

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			previousKey, logLine := NcPreviousKeyForFallback(tc.previousKeyHex, currentKey)
			if tc.wantArmed {
				require.NotNil(t, previousKey, "case %s must arm the fallback", tc.name)
			} else {
				assert.Nil(t, previousKey, "case %s must not arm the fallback", tc.name)
			}
			if tc.wantLogged {
				assert.NotEmpty(t, logLine, "case %s must warn the operator", tc.name)
			} else {
				assert.Empty(t, logLine, "case %s must print nothing", tc.name)
			}

			if tc.name == "Absent" {
				// The absent-key case alone cannot distinguish a real
				// decision from a stub that always returns (nil, ""),
				// because that is exactly what the absent-key case itself
				// returns. Prove the function still makes a real decision
				// by also exercising a usable, different key here and
				// requiring it to arm the fallback with a non-empty log
				// line, so this subtest discriminates on its own.
				controlKey, controlLogLine := NcPreviousKeyForFallback(differentUsableHex, currentKey)
				require.NotNil(t, controlKey, "a usable, different previous key must still arm the fallback")
				assert.NotEmpty(t, controlLogLine, "an armed fallback must still be logged")
			}
		})
	}
}
