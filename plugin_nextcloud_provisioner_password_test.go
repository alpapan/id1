// apps/id1/plugin_nextcloud_provisioner_password_test.go
//
// group: config
// tags: nextcloud, provisioning, security, testing
// summary: Tests for the provisioning account's login password: a refusal is presented to
// Nextcloud once and then answered without contacting it, and the startup check reports a
// wrong or empty password without stopping id1.
//
//

package id1

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ncPasswordRefusedPhrase is the text of the one log line a refusal writes.
const ncPasswordRefusedPhrase = "Nextcloud refused the provisioning account's login password"

var provisionerPasswordRefusals = []struct {
	name   string
	status int
	body   string
}{
	{"http_401", http.StatusUnauthorized, readCredDenied},
	{"ocs_997_served_as_http_200", http.StatusOK, readCredDenied},
}

func ncProvisionRequest() *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/internal/nc-provision?orcid="+readCredTestOrcid, nil)
	req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
	return req
}

// ---------------------------------------------------------------------------
// EnsureUserExists.
// ---------------------------------------------------------------------------

func TestNextcloudClient_EnsureUserExists_ARefusedPasswordIsSentOnceAndLoggedOnce(t *testing.T) {
	for _, tc := range provisionerPasswordRefusals {
		t.Run(tc.name, func(t *testing.T) {
			fake := newReadCredFake(t, tc.status, tc.body)
			logged := captureLog(t)
			c := readCredClient(fake.server.URL)

			for i := 0; i < 3; i++ {
				err := c.EnsureUserExists(context.Background(), readCredTestOrcid, "NC_derivedPw")
				require.Error(t, err)
				assert.True(t, errors.Is(err, ErrNcProvisionerPasswordRefused), "attempt %d: got %v", i+1, err)
			}

			_, _, auths := fake.seen()
			assert.Equal(t, []string{readCredBasic(readCredTestAdmin, readCredTestPassword)}, auths, "a refused login password is presented once, never again")
			assert.Equal(t, 1, strings.Count(logged(), ncPasswordRefusedPhrase), "the refusal is logged once")
			assert.Contains(t, logged(), "ERROR")
			assert.Contains(t, logged(), "curatorium k3s restart id1 --force-rollout")
			assert.NotContains(t, logged(), readCredTestPassword)
			assert.NotContains(t, logged(), readCredTestToken)
		})
	}
}

func TestNextcloudClient_EnsureUserExists_ConcurrentFirstRequestsPresentARefusedPasswordOnce(t *testing.T) {
	var mu sync.Mutex
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()
		time.Sleep(50 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, readCredDenied)
	}))
	t.Cleanup(server.Close)
	captureLog(t)
	c := readCredClient(server.URL)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := c.EnsureUserExists(context.Background(), readCredTestOrcid, "NC_derivedPw")
			assert.True(t, errors.Is(err, ErrNcProvisionerPasswordRefused), "got %v", err)
		}()
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 1, requests, "first requests that arrive together present a refused password once")
}

func TestNextcloudClient_EnsureUserExists_AnEmptyPasswordSendsNothing(t *testing.T) {
	fake := newReadCredFake(t, http.StatusOK, readCredOKBody)
	c := &NextcloudClient{URL: fake.server.URL, Username: readCredTestAdmin, ReadPassword: readCredTestToken}

	err := c.EnsureUserExists(context.Background(), readCredTestOrcid, "NC_derivedPw")

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNcProvisionerPasswordRefused), "got %v", err)
	_, _, auths := fake.seen()
	assert.Empty(t, auths, "an empty login password must not be sent")
}

func TestNextcloudClient_EnsureUserExists_OtherFailuresAreNotRemembered(t *testing.T) {
	fake := newReadCredFake(t, http.StatusInternalServerError, `oops`)
	c := readCredClient(fake.server.URL)

	for i := 0; i < 2; i++ {
		err := c.EnsureUserExists(context.Background(), readCredTestOrcid, "NC_derivedPw")
		require.Error(t, err)
		assert.False(t, errors.Is(err, ErrNcProvisionerPasswordRefused), "attempt %d: got %v", i+1, err)
	}
	_, _, auths := fake.seen()
	assert.Len(t, auths, 2, "a failure that is not a refusal does not stop the next attempt")
}

// ---------------------------------------------------------------------------
// HandleNcProvision.
// ---------------------------------------------------------------------------

func TestHandleNcProvision_ARefusedPasswordAnswers500AndContactsNextcloudOnce(t *testing.T) {
	fake := newReadCredFake(t, http.StatusUnauthorized, readCredDenied)
	captureLog(t)
	handler := HandleNcProvision(readCredClient(fake.server.URL), []byte("0123456789abcdef0123456789abcdef"), "internal-secret", 2*time.Second)

	for i := 0; i < 3; i++ {
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, ncProvisionRequest())

		assert.Equal(t, http.StatusInternalServerError, rr.Code, "attempt %d: a lasting refusal is not a gateway status the caller retries", i+1)
		assert.JSONEq(t, `{"error":"nextcloud_provisioner_password_refused"}`, rr.Body.String())
		assert.NotContains(t, rr.Body.String(), readCredTestPassword)
	}
	methods, _, _ := fake.seen()
	assert.Equal(t, []string{http.MethodPost}, methods, "only the first request reaches Nextcloud")
}

func TestHandleNcProvision_AnEmptyPasswordAnswers500WithoutContactingNextcloud(t *testing.T) {
	fake := newReadCredFake(t, http.StatusOK, readCredOKBody)
	nc := &NextcloudClient{URL: fake.server.URL, Username: readCredTestAdmin, ReadPassword: readCredTestToken}
	handler := HandleNcProvision(nc, []byte("0123456789abcdef0123456789abcdef"), "internal-secret", 2*time.Second)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, ncProvisionRequest())

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.JSONEq(t, `{"error":"nextcloud_provisioner_password_refused"}`, rr.Body.String())
	_, _, auths := fake.seen()
	assert.Empty(t, auths)
}

// ---------------------------------------------------------------------------
// CheckProvisionerPassword.
// ---------------------------------------------------------------------------

func TestNextcloudClient_CheckProvisionerPassword_AcceptsAWorkingPassword(t *testing.T) {
	fake := newReadCredFake(t, http.StatusOK, readCredOKBody)

	err := readCredClient(fake.server.URL).CheckProvisionerPassword(context.Background())

	require.NoError(t, err)
	methods, paths, auths := fake.seen()
	assert.Equal(t, []string{http.MethodGet}, methods)
	assert.Equal(t, []string{"/ocs/v2.php/cloud/users/" + readCredTestAdmin}, paths)
	assert.Equal(t, []string{readCredBasic(readCredTestAdmin, readCredTestPassword)}, auths)
}

func TestNextcloudClient_CheckProvisionerPassword_ARefusalIsRememberedForAccountCreation(t *testing.T) {
	for _, tc := range readCredRefusals {
		t.Run(tc.name, func(t *testing.T) {
			fake := newReadCredFake(t, tc.status, tc.body)
			c := readCredClient(fake.server.URL)

			err := c.CheckProvisionerPassword(context.Background())
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrNcProvisionerPasswordRefused), "got %v", err)

			err = c.EnsureUserExists(context.Background(), readCredTestOrcid, "NC_derivedPw")
			assert.True(t, errors.Is(err, ErrNcProvisionerPasswordRefused), "got %v", err)
			err = c.CheckProvisionerPassword(context.Background())
			assert.True(t, errors.Is(err, ErrNcProvisionerPasswordRefused), "got %v", err)

			_, _, auths := fake.seen()
			assert.Equal(t, []string{readCredBasic(readCredTestAdmin, readCredTestPassword)}, auths, "after a refusal nothing more is sent")
		})
	}
}

func TestNextcloudClient_CheckProvisionerPassword_OtherAnswersAreNotARefusal(t *testing.T) {
	cases := []struct {
		name        string
		status      int
		body        string
		rateLimited bool
	}{
		{"ocs_998_no_rights", http.StatusNotFound, readCredNoRight, false},
		{"http_500_not_json", http.StatusInternalServerError, `oops`, false},
		{"http_429", http.StatusTooManyRequests, `slow down`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newReadCredFake(t, tc.status, tc.body)
			captureLog(t)
			c := readCredClient(fake.server.URL)

			err := c.CheckProvisionerPassword(context.Background())

			require.Error(t, err)
			assert.False(t, errors.Is(err, ErrNcProvisionerPasswordRefused), "got %v", err)
			assert.Equal(t, tc.rateLimited, errors.Is(err, ErrNextcloudRateLimited), "got %v", err)
			_ = c.EnsureUserExists(context.Background(), readCredTestOrcid, "NC_derivedPw")
			_, _, auths := fake.seen()
			assert.Len(t, auths, 2, "nothing is remembered, so account creation is still attempted")
		})
	}
}

// ---------------------------------------------------------------------------
// VerifyNcProvisionerPasswordAtBoot - the line main.go_ prints.
// ---------------------------------------------------------------------------

func TestVerifyNcProvisionerPasswordAtBoot_AnEmptyPasswordIsReportedAndSendsNothing(t *testing.T) {
	fake := newReadCredFake(t, http.StatusOK, readCredOKBody)
	c := &NextcloudClient{URL: fake.server.URL, Username: readCredTestAdmin, ReadPassword: readCredTestToken}

	message := VerifyNcProvisionerPasswordAtBoot(c)

	assert.True(t, strings.HasPrefix(message, "ERROR: "), "got %q", message)
	assert.Contains(t, message, "NC_PROVISIONER_PASSWORD is empty")
	assert.Contains(t, message, "reconcile-nextcloud-passwords")
	assert.NotContains(t, message, readCredTestToken)
	_, _, auths := fake.seen()
	assert.Empty(t, auths)
}

func TestVerifyNcProvisionerPasswordAtBoot_ARefusedPasswordIsReportedAndRemembered(t *testing.T) {
	fake := newReadCredFake(t, http.StatusUnauthorized, readCredDenied)
	c := readCredClient(fake.server.URL)

	message := VerifyNcProvisionerPasswordAtBoot(c)

	assert.True(t, strings.HasPrefix(message, "ERROR: "), "got %q", message)
	assert.Contains(t, message, ncPasswordRefusedPhrase)
	assert.Contains(t, message, "curatorium k3s restart id1 --force-rollout")
	assert.NotContains(t, message, readCredTestPassword)
	assert.NotContains(t, message, readCredTestToken)
	err := c.EnsureUserExists(context.Background(), readCredTestOrcid, "NC_derivedPw")
	assert.True(t, errors.Is(err, ErrNcProvisionerPasswordRefused), "got %v", err)
	_, _, auths := fake.seen()
	assert.Len(t, auths, 1, "the startup check is the only request")
}

func TestVerifyNcProvisionerPasswordAtBoot_AnAcceptedPasswordIsReported(t *testing.T) {
	fake := newReadCredFake(t, http.StatusOK, readCredOKBody)

	message := VerifyNcProvisionerPasswordAtBoot(readCredClient(fake.server.URL))

	assert.Equal(t, "Nextcloud accepted the provisioning account's login password", message)
	_, paths, auths := fake.seen()
	assert.Equal(t, []string{"/ocs/v2.php/cloud/users/" + readCredTestAdmin}, paths)
	assert.Equal(t, []string{readCredBasic(readCredTestAdmin, readCredTestPassword)}, auths)
}

func TestVerifyNcProvisionerPasswordAtBoot_UnreachableNextcloudIsUnverifiedAndRemembersNothing(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	url := server.URL
	server.Close()
	c := readCredClient(url)

	message := VerifyNcProvisionerPasswordAtBoot(c)

	assert.Contains(t, message, "unverified")
	assert.False(t, strings.HasPrefix(message, "ERROR: "), "got %q", message)
	err := c.EnsureUserExists(context.Background(), readCredTestOrcid, "NC_derivedPw")
	assert.False(t, errors.Is(err, ErrNcProvisionerPasswordRefused), "got %v", err)
}
