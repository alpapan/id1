package id1

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// DeriveNextcloudPassword — HMAC-SHA256 based deterministic password derivation.
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
// NextcloudClient type — stateless HTTP client for Nextcloud OCS API.
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
// NextcloudClient.EnsureUserExists — idempotent OCS user-creation call.
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

// ---------------------------------------------------------------------------
// NextcloudClient.MintAppToken — OCS getapppassword call as the user.
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
// HandleNcToken — HTTP handler for GET /internal/nc-token?orcid=<X>.
// ---------------------------------------------------------------------------

// fakeNextcloud starts an httptest.Server that handles the two OCS calls
// (EnsureUserExists + MintAppToken). Returns the URL and a cleanup func.
func fakeNextcloud(t *testing.T, _expectedPw, tokenToReturn string) (string, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/ocs/v2.php/cloud/users":
			fmt.Fprint(w, `{"ocs":{"meta":{"statuscode":100,"status":"ok","message":"OK"},"data":{}}}`)
		case "/ocs/v2.php/core/getapppassword":
			fmt.Fprintf(w, `{"ocs":{"meta":{"statuscode":200,"status":"ok","message":"OK"},"data":{"apppassword":"%s"}}}`, tokenToReturn)
		default:
			http.NotFound(w, r)
		}
	}))
	return srv.URL, srv.Close
}

func TestHandleNcToken_HappyPath(t *testing.T) {
	ncURL, cleanup := fakeNextcloud(t, "any", "MINTED-TOKEN")
	defer cleanup()

	handler := HandleNcToken(&NextcloudClient{URL: ncURL, Username: "admin", Password: "secret"}, []byte("test-key"), "internal-secret")

	req := httptest.NewRequest("GET", "/internal/nc-token?orcid=0009-0002-8023-3658", nil)
	req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	var body map[string]string
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, "MINTED-TOKEN", body["token"])
}

func TestHandleNcToken_MissingOrcid(t *testing.T) {
	handler := HandleNcToken(&NextcloudClient{}, []byte("test-key"), "internal-secret")

	req := httptest.NewRequest("GET", "/internal/nc-token", nil)
	req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleNcToken_MalformedOrcid(t *testing.T) {
	handler := HandleNcToken(&NextcloudClient{}, []byte("test-key"), "internal-secret")

	req := httptest.NewRequest("GET", "/internal/nc-token?orcid=not-an-orcid", nil)
	req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleNcToken_MissingInternalSecret(t *testing.T) {
	handler := HandleNcToken(&NextcloudClient{}, []byte("test-key"), "internal-secret")

	req := httptest.NewRequest("GET", "/internal/nc-token?orcid=0009-0002-8023-3658", nil)
	// no X-ID1-Internal-Secret header
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestHandleNcToken_WrongInternalSecret(t *testing.T) {
	handler := HandleNcToken(&NextcloudClient{}, []byte("test-key"), "internal-secret")

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

	handler := HandleNcToken(&NextcloudClient{URL: srv.URL, Username: "admin", Password: "secret"}, []byte("test-key"), "internal-secret")

	req := httptest.NewRequest("GET", "/internal/nc-token?orcid=0009-0002-8023-3658", nil)
	req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadGateway, rr.Code)
}

// __END_OF_FILE_MARKER__
