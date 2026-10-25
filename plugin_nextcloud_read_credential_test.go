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
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	readCredTestOrcid    = "0009-0002-8023-3658"
	readCredTestAdmin    = ncProvisionerTestUser
	readCredTestPassword = "login-password-aaa"
	readCredTestToken    = "read-token-bbb"

	readCredOKBody  = `{"ocs":{"meta":{"statuscode":200,"status":"ok","message":"OK"},"data":{"id":"0000-0000-0000-0009"}}}`
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

func TestRecheckNcReadCredentialEvery_ShutdownDuringACheckLogsNothing(t *testing.T) {
	arrived := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case arrived <- struct{}{}:
		default:
		}
		<-r.Context().Done()
	}))
	t.Cleanup(server.Close)
	logger := &recheckLog{}
	stop := runRecheck(t, readCredClient(server.URL), logger)

	select {
	case <-arrived:
	case <-time.After(2 * time.Second):
		t.Fatal("no check reached Nextcloud")
	}
	stop()

	assert.Empty(t, logger.snapshot(), "cancelling the loop's context while a check is in flight is a shutdown, not a finding about the token")
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

// ---------------------------------------------------------------------------
// A refused READ token is presented once, not once per request.
// ---------------------------------------------------------------------------

// switchableReadCredFake is a real HTTP server standing in for Nextcloud. It answers every request
// with HTTP 401 and the OCS 997 refusal until accept is called, then with readCredOKBody, and counts
// the requests it answered.
type switchableReadCredFake struct {
	mu       sync.Mutex
	server   *httptest.Server
	accepts  bool
	requests int
}

func newSwitchableReadCredFake(t *testing.T) *switchableReadCredFake {
	t.Helper()
	f := &switchableReadCredFake{}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requests++
		accepts := f.accepts
		f.mu.Unlock()
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		if accepts {
			fmt.Fprint(w, readCredOKBody)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, readCredDenied)
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *switchableReadCredFake) accept() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.accepts = true
}

func (f *switchableReadCredFake) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests
}

func TestHandleNcToken_ARefusedReadTokenIsPresentedOnceNotOncePerRequest(t *testing.T) {
	fake := newReadCredFake(t, http.StatusUnauthorized, readCredDenied)
	captureLog(t)
	handler := HandleNcToken(readCredClient(fake.server.URL), []byte("0123456789abcdef0123456789abcdef"), "internal-secret", 2*time.Second)

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/internal/nc-token?orcid="+readCredTestOrcid, nil)
		req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusInternalServerError, rr.Code, "attempt %d", i+1)
		assert.JSONEq(t, `{"error":"nextcloud_read_credential_refused"}`, rr.Body.String())
	}
	_, _, auths := fake.seen()
	assert.Len(t, auths, 1, "after a refusal the token is not presented again until a recheck accepts it")
}

func TestNextcloudClient_ARefusedRecheckStopsUserExistsPresentingTheToken(t *testing.T) {
	fake := newReadCredFake(t, http.StatusUnauthorized, readCredDenied)
	c := readCredClient(fake.server.URL)

	require.ErrorIs(t, c.CheckProvisionerReadCredential(context.Background()), ErrNcReadCredentialRefused)
	_, err := c.UserExists(context.Background(), readCredTestOrcid)

	require.ErrorIs(t, err, ErrNcReadCredentialRefused)
	_, _, auths := fake.seen()
	assert.Len(t, auths, 1, "a token the recheck saw refused is not presented by the existence read")
}

func TestNextcloudClient_AnAcceptedRecheckLetsUserExistsPresentTheTokenAgain(t *testing.T) {
	fake := newSwitchableReadCredFake(t)
	c := readCredClient(fake.server.URL)

	_, err := c.UserExists(context.Background(), readCredTestOrcid)
	require.ErrorIs(t, err, ErrNcReadCredentialRefused)
	_, err = c.UserExists(context.Background(), readCredTestOrcid)
	require.ErrorIs(t, err, ErrNcReadCredentialRefused)
	require.Equal(t, 1, fake.count(), "the second read must not present the token Nextcloud refused")

	fake.accept()
	require.NoError(t, c.CheckProvisionerReadCredential(context.Background()))
	exists, err := c.UserExists(context.Background(), readCredTestOrcid)

	require.NoError(t, err)
	assert.True(t, exists)
	assert.Equal(t, 3, fake.count())
}

func TestNextcloudClient_ARefusedReadTokenIsPresentedAgainAfterTheHold(t *testing.T) {
	moveClock := setNcNow(t, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	fake := newReadCredFake(t, http.StatusUnauthorized, readCredDenied)
	c := readCredClient(fake.server.URL)

	_, err := c.UserExists(context.Background(), readCredTestOrcid)
	require.ErrorIs(t, err, ErrNcReadCredentialRefused)
	moveClock(time.Date(2026, 1, 1, 0, 29, 0, 0, time.UTC))
	_, err = c.UserExists(context.Background(), readCredTestOrcid)
	require.ErrorIs(t, err, ErrNcReadCredentialRefused)
	_, _, auths := fake.seen()
	require.Len(t, auths, 1, "inside the 30-minute hold the token Nextcloud refused is not presented")

	moveClock(time.Date(2026, 1, 1, 0, 31, 0, 0, time.UTC))
	_, err = c.UserExists(context.Background(), readCredTestOrcid)

	require.ErrorIs(t, err, ErrNcReadCredentialRefused)
	_, _, auths = fake.seen()
	assert.Len(t, auths, 2, "once the hold has passed the token is presented once more")
}

// slowReadCredServer answers every request after a pause, with the status and
// body held in answer, and counts the requests it receives. The pause keeps
// concurrent callers in flight together.
type slowReadCredServer struct {
	server   *httptest.Server
	requests atomic.Int32
	status   atomic.Int32
	body     atomic.Value
}

func newSlowReadCredServer(t *testing.T, status int, body string) *slowReadCredServer {
	t.Helper()
	s := &slowReadCredServer{}
	s.status.Store(int32(status))
	s.body.Store(body)
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.requests.Add(1)
		time.Sleep(50 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(int(s.status.Load()))
		fmt.Fprint(w, s.body.Load().(string))
	}))
	t.Cleanup(s.server.Close)
	return s
}

func (s *slowReadCredServer) answer(status int, body string) {
	s.status.Store(int32(status))
	s.body.Store(body)
}

// userExistsTogether runs n UserExists calls at once and returns their results.
func userExistsTogether(c *NextcloudClient, n int) (exists []bool, errs []error) {
	exists = make([]bool, n)
	errs = make([]error, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			exists[i], errs[i] = c.UserExists(context.Background(), readCredTestOrcid)
		}(i)
	}
	close(start)
	wg.Wait()
	return exists, errs
}

func TestNextcloudClient_UserExists_SimultaneousRequestsAtHoldExpiryPresentARefusedTokenOnce(t *testing.T) {
	moveClock := setNcNow(t, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	server := newSlowReadCredServer(t, http.StatusUnauthorized, readCredDenied)
	c := readCredClient(server.server.URL)
	_, err := c.UserExists(context.Background(), readCredTestOrcid)
	require.ErrorIs(t, err, ErrNcReadCredentialRefused)
	require.EqualValues(t, 1, server.requests.Load())

	moveClock(time.Date(2026, 1, 1, 0, 31, 0, 0, time.UTC))
	_, errs := userExistsTogether(c, 8)

	for i, err := range errs {
		assert.ErrorIs(t, err, ErrNcReadCredentialRefused, "request %d", i)
	}
	assert.EqualValues(t, 2, server.requests.Load(), "the refused token is presented once at expiry, not once per simultaneous request")
}

func TestNextcloudClient_UserExists_AnAcceptedTokenAtHoldExpiryEndsTheRefusal(t *testing.T) {
	moveClock := setNcNow(t, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	server := newSlowReadCredServer(t, http.StatusUnauthorized, readCredDenied)
	c := readCredClient(server.server.URL)
	_, err := c.UserExists(context.Background(), readCredTestOrcid)
	require.ErrorIs(t, err, ErrNcReadCredentialRefused)

	server.answer(http.StatusOK, readCredOKBody)
	moveClock(time.Date(2026, 1, 1, 0, 31, 0, 0, time.UTC))
	exists, errs := userExistsTogether(c, 8)

	for i := range errs {
		assert.NoError(t, errs[i], "request %d", i)
		assert.True(t, exists[i], "request %d", i)
	}
	assert.EqualValues(t, 0, c.readCredentialRefusedAt.Load(), "an accepted token ends the refusal")
}

var readCredInconclusiveAnswers = []struct {
	name   string
	status int
	body   string
}{
	{"http_429", http.StatusTooManyRequests, `slow down`},
	{"http_500_not_json", http.StatusInternalServerError, `oops`},
	{"ocs_998_no_rights", http.StatusNotFound, readCredNoRight},
}

func TestNextcloudClient_UserExists_AnInconclusiveAnswerAtHoldExpiryLeavesTheRefusalForTheNextCaller(t *testing.T) {
	require.Len(t, readCredInconclusiveAnswers, 3, "a deleted case must fail this guard rather than pass quietly")
	for _, tc := range readCredInconclusiveAnswers {
		t.Run(tc.name, func(t *testing.T) {
			moveClock := setNcNow(t, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
			server := newSlowReadCredServer(t, http.StatusUnauthorized, readCredDenied)
			c := readCredClient(server.server.URL)
			_, err := c.UserExists(context.Background(), readCredTestOrcid)
			require.ErrorIs(t, err, ErrNcReadCredentialRefused)
			refusedAt := c.readCredentialRefusedAt.Load()
			require.NotZero(t, refusedAt)

			server.answer(tc.status, tc.body)
			moveClock(time.Date(2026, 1, 1, 0, 31, 0, 0, time.UTC))
			_, err = c.UserExists(context.Background(), readCredTestOrcid)
			require.Error(t, err)
			assert.False(t, errors.Is(err, ErrNcReadCredentialRefused), "an inconclusive answer is not a refusal: %v", err)
			assert.Equal(t, refusedAt, c.readCredentialRefusedAt.Load(), "an inconclusive answer neither ends nor renews the refusal")
			require.EqualValues(t, 2, server.requests.Load())

			// Nextcloud now refuses; callers that arrive together present the token once.
			server.answer(http.StatusUnauthorized, readCredDenied)
			_, errs := userExistsTogether(c, 8)

			for i, err := range errs {
				assert.ErrorIs(t, err, ErrNcReadCredentialRefused, "request %d", i)
			}
			assert.EqualValues(t, 3, server.requests.Load(), "the next caller presents the token once; the rest act on its refusal")
		})
	}
}

func TestVerifyNcReadCredentialAtBoot_EmptyProvisioningUserIsFatalAndSendsNothing(t *testing.T) {
	fake := newReadCredFake(t, http.StatusOK, readCredOKBody)
	c := &NextcloudClient{URL: fake.server.URL, Password: readCredTestPassword, ReadPassword: readCredTestToken}

	fatal, message := VerifyNcReadCredentialAtBoot(c)

	assert.True(t, fatal)
	assert.Contains(t, message, "NC_PROVISIONER_USER")
	assert.NotContains(t, message, readCredTestToken)
	assert.NotContains(t, message, readCredTestPassword)
	_, _, auths := fake.seen()
	assert.Empty(t, auths, "no request may name an empty account")
}
