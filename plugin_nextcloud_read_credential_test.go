// apps/id1/plugin_nextcloud_read_credential_test.go
//
// group: config
// tags: nextcloud, app-password, security, testing
// summary: Tests for the provisioning account's READ app password: which requests
// present it, which keep the login password, and the startup check that refuses a
// bad one.
//
//

package id1

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	readCredTestOrcid    = "0009-0002-8023-3658"
	readCredTestAdmin    = "admin"
	readCredTestPassword = "login-password-aaa"
	readCredTestToken    = "read-token-bbb"

	readCredOKBody  = `{"ocs":{"meta":{"statuscode":200,"status":"ok","message":"OK"},"data":{"id":"admin"}}}`
	readCredDenied  = `{"ocs":{"meta":{"statuscode":997,"status":"failure","message":"Current user is not logged in"},"data":[]}}`
	readCredNoRight = `{"ocs":{"meta":{"statuscode":998,"status":"failure","message":""},"data":[]}}`
)

// readCredBasic is the Authorization header value net/http sends for these credentials.
func readCredBasic(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

// readCredFake is a real HTTP server standing in for Nextcloud. It records the method, path and
// Authorization header of every request and answers each with one fixed status and body.
type readCredFake struct {
	mu      sync.Mutex
	server  *httptest.Server
	methods []string
	paths   []string
	auths   []string
}

func newReadCredFake(t *testing.T, status int, body string) *readCredFake {
	t.Helper()
	f := &readCredFake{}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.methods = append(f.methods, r.Method)
		f.paths = append(f.paths, r.URL.Path)
		f.auths = append(f.auths, r.Header.Get("Authorization"))
		f.mu.Unlock()
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *readCredFake) seen() (methods, paths, auths []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.methods...), append([]string(nil), f.paths...), append([]string(nil), f.auths...)
}

func readCredClient(url string) *NextcloudClient {
	return &NextcloudClient{
		URL:          url,
		Username:     readCredTestAdmin,
		Password:     readCredTestPassword,
		ReadPassword: readCredTestToken,
	}
}

// ---------------------------------------------------------------------------
// Configuration from the environment.
// ---------------------------------------------------------------------------

func TestNewNextcloudClient_ReadsTheReadAppPasswordFromEnv(t *testing.T) {
	t.Setenv("NEXTCLOUD_URL", "http://test.example")
	t.Setenv("NC_PROVISIONER_USER", readCredTestAdmin)
	t.Setenv("NC_PROVISIONER_PASSWORD", readCredTestPassword)
	t.Setenv("NC_PROVISIONER_READ_APP_PASSWORD", readCredTestToken)

	c := NewNextcloudClient()

	assert.Equal(t, readCredTestToken, c.ReadPassword)
	assert.Equal(t, readCredTestPassword, c.Password)
}

func TestNewNextcloudClient_UnsetReadAppPasswordIsEmpty(t *testing.T) {
	t.Setenv("NC_PROVISIONER_READ_APP_PASSWORD", "")

	assert.Equal(t, "", NewNextcloudClient().ReadPassword)
}

// ---------------------------------------------------------------------------
// Which requests present which credential.
// ---------------------------------------------------------------------------

func TestNextcloudClient_UserExists_AuthenticatesWithTheReadAppPassword(t *testing.T) {
	fake := newReadCredFake(t, http.StatusOK, readCredOKBody)

	exists, err := readCredClient(fake.server.URL).UserExists(context.Background(), readCredTestOrcid)

	require.NoError(t, err)
	assert.True(t, exists)
	methods, paths, auths := fake.seen()
	assert.Equal(t, []string{http.MethodGet}, methods)
	assert.Equal(t, []string{"/ocs/v2.php/cloud/users/" + readCredTestOrcid}, paths)
	assert.Equal(t, []string{readCredBasic(readCredTestAdmin, readCredTestToken)}, auths)
}

func TestNextcloudClient_UserExists_WithoutAReadPasswordUsesThePassword(t *testing.T) {
	fake := newReadCredFake(t, http.StatusOK, readCredOKBody)
	c := &NextcloudClient{URL: fake.server.URL, Username: readCredTestAdmin, Password: readCredTestPassword}

	exists, err := c.UserExists(context.Background(), readCredTestOrcid)

	require.NoError(t, err)
	assert.True(t, exists)
	_, _, auths := fake.seen()
	assert.Equal(t, []string{readCredBasic(readCredTestAdmin, readCredTestPassword)}, auths)
}

func TestNextcloudClient_EnsureUserExists_KeepsThePasswordForTheWrite(t *testing.T) {
	fake := newReadCredFake(t, http.StatusOK, readCredOKBody)

	err := readCredClient(fake.server.URL).EnsureUserExists(context.Background(), readCredTestOrcid, "NC_derivedPw")

	require.NoError(t, err)
	methods, _, auths := fake.seen()
	assert.Equal(t, []string{http.MethodPost}, methods)
	assert.Equal(t, []string{readCredBasic(readCredTestAdmin, readCredTestPassword)}, auths)
}

// ---------------------------------------------------------------------------
// CheckProvisionerReadCredential.
// ---------------------------------------------------------------------------

func TestNextcloudClient_CheckProvisionerReadCredential_AcceptsAWorkingToken(t *testing.T) {
	fake := newReadCredFake(t, http.StatusOK, readCredOKBody)

	err := readCredClient(fake.server.URL).CheckProvisionerReadCredential(context.Background())

	require.NoError(t, err)
	methods, paths, auths := fake.seen()
	assert.Equal(t, []string{http.MethodGet}, methods)
	assert.Equal(t, []string{"/ocs/v2.php/cloud/users/" + readCredTestAdmin}, paths)
	assert.Equal(t, []string{readCredBasic(readCredTestAdmin, readCredTestToken)}, auths)
}

var readCredRefusals = []struct {
	name   string
	status int
	body   string
}{
	{"http_401", http.StatusUnauthorized, readCredDenied},
	{"http_403", http.StatusForbidden, `{}`},
	{"ocs_997_served_as_http_200", http.StatusOK, readCredDenied},
}

func TestNextcloudClient_CheckProvisionerReadCredential_ReportsARefusedToken(t *testing.T) {
	for _, tc := range readCredRefusals {
		t.Run(tc.name, func(t *testing.T) {
			fake := newReadCredFake(t, tc.status, tc.body)

			err := readCredClient(fake.server.URL).CheckProvisionerReadCredential(context.Background())

			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrNcReadCredentialRefused), "got %v", err)
			_, _, auths := fake.seen()
			assert.Len(t, auths, 1, "a refusal is never retried with the login password")
			assert.Equal(t, readCredBasic(readCredTestAdmin, readCredTestToken), auths[0])
		})
	}
}

func TestNextcloudClient_CheckProvisionerReadCredential_OtherFailuresAreNotARefusal(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"ocs_998_no_rights", http.StatusNotFound, readCredNoRight},
		{"http_500_not_json", http.StatusInternalServerError, `oops`},
	}
	require.Len(t, cases, 2)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newReadCredFake(t, tc.status, tc.body)

			err := readCredClient(fake.server.URL).CheckProvisionerReadCredential(context.Background())

			require.Error(t, err)
			assert.False(t, errors.Is(err, ErrNcReadCredentialRefused), "got %v", err)
		})
	}
}

func TestNextcloudClient_CheckProvisionerReadCredential_ThrottlingIsReportedAsSuch(t *testing.T) {
	fake := newReadCredFake(t, http.StatusTooManyRequests, `slow down`)

	err := readCredClient(fake.server.URL).CheckProvisionerReadCredential(context.Background())

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNextcloudRateLimited), "got %v", err)
	assert.False(t, errors.Is(err, ErrNcReadCredentialRefused))
}

func TestNextcloudClient_CheckProvisionerReadCredential_NoTokenSendsNothing(t *testing.T) {
	fake := newReadCredFake(t, http.StatusOK, readCredOKBody)
	c := &NextcloudClient{URL: fake.server.URL, Username: readCredTestAdmin, Password: readCredTestPassword}

	err := c.CheckProvisionerReadCredential(context.Background())

	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrNcReadCredentialRefused))
	_, _, auths := fake.seen()
	assert.Empty(t, auths, "an empty read token must not be replaced by the login password")
}

// ---------------------------------------------------------------------------
// HandleNcToken with a refused READ token.
// ---------------------------------------------------------------------------

func TestHandleNcToken_ARefusedReadTokenIsNeverRetriedWithThePasswordAndMintsNothing(t *testing.T) {
	for _, tc := range readCredRefusals {
		t.Run(tc.name, func(t *testing.T) {
			fake := newReadCredFake(t, tc.status, tc.body)
			handler := HandleNcToken(readCredClient(fake.server.URL), []byte("0123456789abcdef0123456789abcdef"), "internal-secret", 2*time.Second)
			req := httptest.NewRequest(http.MethodGet, "/internal/nc-token?orcid="+readCredTestOrcid, nil)
			req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusInternalServerError, rr.Code, "a lasting refusal is not a gateway status the caller retries")
			assert.JSONEq(t, `{"error":"nextcloud_read_credential_refused"}`, rr.Body.String())
			assert.NotContains(t, rr.Body.String(), readCredTestToken)
			assert.NotContains(t, rr.Body.String(), readCredTestPassword)
			methods, paths, auths := fake.seen()
			assert.Equal(t, []string{http.MethodGet}, methods, "no mint may follow a refused existence read")
			assert.Equal(t, []string{"/ocs/v2.php/cloud/users/" + readCredTestOrcid}, paths)
			assert.Equal(t, []string{readCredBasic(readCredTestAdmin, readCredTestToken)}, auths, "a refusal is never retried with the login password")
		})
	}
}

// ---------------------------------------------------------------------------
// VerifyNcReadCredentialAtBoot - the decision main.go_ acts on.
// ---------------------------------------------------------------------------

func TestVerifyNcReadCredentialAtBoot_EmptyTokenIsFatalAndNamesTheVariable(t *testing.T) {
	fake := newReadCredFake(t, http.StatusOK, readCredOKBody)
	c := &NextcloudClient{URL: fake.server.URL, Username: readCredTestAdmin, Password: readCredTestPassword}

	fatal, message := VerifyNcReadCredentialAtBoot(c)

	assert.True(t, fatal)
	assert.Contains(t, message, "NC_PROVISIONER_READ_APP_PASSWORD")
	assert.Contains(t, message, "reconcile-nextcloud-passwords")
	_, _, auths := fake.seen()
	assert.Empty(t, auths)
}

func TestVerifyNcReadCredentialAtBoot_RefusedTokenIsFatalAndNeverEchoesTheSecrets(t *testing.T) {
	fake := newReadCredFake(t, http.StatusUnauthorized, readCredDenied)

	fatal, message := VerifyNcReadCredentialAtBoot(readCredClient(fake.server.URL))

	assert.True(t, fatal)
	assert.Contains(t, message, "refused")
	assert.Contains(t, message, "NC_PROVISIONER_READ_APP_PASSWORD")
	assert.Contains(t, message, "curatorium k3s restart id1 --force-rollout")
	assert.NotContains(t, message, "k3s reboot")
	assert.NotContains(t, message, readCredTestToken)
	assert.NotContains(t, message, readCredTestPassword)
}

func TestVerifyNcReadCredentialAtBoot_AcceptedTokenIsNotFatal(t *testing.T) {
	fake := newReadCredFake(t, http.StatusOK, readCredOKBody)

	fatal, message := VerifyNcReadCredentialAtBoot(readCredClient(fake.server.URL))

	assert.False(t, fatal)
	assert.NotEmpty(t, message)
	assert.NotContains(t, message, readCredTestToken)
}

func TestVerifyNcReadCredentialAtBoot_UnreachableNextcloudIsLoggedNotFatal(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	url := server.URL
	server.Close()

	fatal, message := VerifyNcReadCredentialAtBoot(readCredClient(url))

	assert.False(t, fatal)
	assert.Contains(t, message, "unverified")
}

func TestVerifyNcReadCredentialAtBoot_AnyOtherAnswerIsLoggedNotFatal(t *testing.T) {
	fake := newReadCredFake(t, http.StatusInternalServerError, `oops`)

	fatal, message := VerifyNcReadCredentialAtBoot(readCredClient(fake.server.URL))

	assert.False(t, fatal)
	assert.Contains(t, message, "unverified")
}

// ---------------------------------------------------------------------------
// RecheckNcReadCredentialEvery - keeps the token in use so Nextcloud's idle
// cleanup never reaches it.
// ---------------------------------------------------------------------------

const recheckTestInterval = 10 * time.Millisecond

// recheckLog collects the lines the loop logs from its own goroutine.
type recheckLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *recheckLog) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *recheckLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.lines...)
}

// runRecheck starts the loop against c and returns a stop function that cancels its context and
// fails the test unless the loop returns promptly.
func runRecheck(t *testing.T, c *NextcloudClient, logger *recheckLog) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		RecheckNcReadCredentialEvery(ctx, c, recheckTestInterval, logger.logf)
	}()
	t.Cleanup(cancel)
	return func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("the recheck loop did not stop after its context was cancelled")
		}
	}
}

// waitForRequests blocks until the fake has answered at least n requests.
func waitForRequests(t *testing.T, fake *readCredFake, n int) {
	t.Helper()
	require.Eventually(t, func() bool {
		_, _, auths := fake.seen()
		return len(auths) >= n
	}, 2*time.Second, 5*time.Millisecond, "expected at least %d requests to reach Nextcloud", n)
}

func TestRecheckNcReadCredentialEvery_ChecksRepeatedlyWithTheReadToken(t *testing.T) {
	fake := newReadCredFake(t, http.StatusOK, readCredOKBody)
	logger := &recheckLog{}
	stop := runRecheck(t, readCredClient(fake.server.URL), logger)

	waitForRequests(t, fake, 2)
	stop()

	methods, paths, auths := fake.seen()
	for i := range auths {
		assert.Equal(t, http.MethodGet, methods[i])
		assert.Equal(t, "/ocs/v2.php/cloud/users/"+readCredTestAdmin, paths[i])
		assert.Equal(t, readCredBasic(readCredTestAdmin, readCredTestToken), auths[i])
	}
	assert.Empty(t, logger.snapshot(), "an accepted token logs nothing")
}

func TestRecheckNcReadCredentialEvery_ARefusedTokenIsLoggedAsAnErrorAndTheLoopKeepsRunning(t *testing.T) {
	fake := newReadCredFake(t, http.StatusUnauthorized, readCredDenied)
	logger := &recheckLog{}
	stop := runRecheck(t, readCredClient(fake.server.URL), logger)

	waitForRequests(t, fake, 2)
	stop()

	lines := logger.snapshot()
	require.NotEmpty(t, lines)
	for _, line := range lines {
		assert.Contains(t, line, "ERROR")
		assert.Contains(t, line, "refused")
		assert.Contains(t, line, "NC_PROVISIONER_READ_APP_PASSWORD")
		assert.NotContains(t, line, readCredTestToken)
		assert.NotContains(t, line, readCredTestPassword)
	}
}

func TestRecheckNcReadCredentialEvery_AnyOtherFailureIsLoggedAndTheLoopKeepsRunning(t *testing.T) {
	fake := newReadCredFake(t, http.StatusInternalServerError, `oops`)
	logger := &recheckLog{}
	stop := runRecheck(t, readCredClient(fake.server.URL), logger)

	waitForRequests(t, fake, 2)
	stop()

	lines := logger.snapshot()
	require.NotEmpty(t, lines)
	for _, line := range lines {
		assert.Contains(t, line, "unverified")
		assert.NotContains(t, line, readCredTestToken)
	}
}

func TestRecheckNcReadCredentialEvery_StopsWhenItsContextIsCancelled(t *testing.T) {
	fake := newReadCredFake(t, http.StatusOK, readCredOKBody)
	stop := runRecheck(t, readCredClient(fake.server.URL), &recheckLog{})

	waitForRequests(t, fake, 1)
	stop()

	_, _, before := fake.seen()
	time.Sleep(10 * recheckTestInterval)
	_, _, after := fake.seen()
	assert.Equal(t, len(before), len(after), "no request may leave after the loop has stopped")
}
