package id1

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ncThrottleResetCommand is the Nextcloud command that clears recorded
// brute-force attempts for one address. A throttled address is refused before
// its credentials are checked, so no successful login can clear them. Every
// report of throttling must name this command or an operator who repairs the
// credential concludes the repair failed.
const ncThrottleResetCommand = "occ security:bruteforce:reset"

// throttlingNextcloud answers every request with HTTP 429 and an empty body,
// the shape Nextcloud's brute-force protection produces once a caller's
// address has exhausted its attempts.
func throttlingNextcloud(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestMintAppToken_RateLimitLogNamesTheResetCommand(t *testing.T) {
	srv := throttlingNextcloud(t)
	logged := captureLog(t)

	c := &NextcloudClient{URL: srv.URL}
	_, err := c.MintAppToken(context.Background(), "0009-0002-8023-3658", "NC_derivedPw")

	require.ErrorIs(t, err, ErrNextcloudRateLimited)
	assert.Contains(t, logged(), ncThrottleResetCommand,
		"a throttled mint must tell the operator how to clear the throttle")
}

func TestNextcloudClient_EnsureUserExists_RateLimitIsReportedAsRateLimit(t *testing.T) {
	srv := throttlingNextcloud(t)
	logged := captureLog(t)

	c := &NextcloudClient{URL: srv.URL, Username: "admin", Password: "secret"}
	err := c.EnsureUserExists(context.Background(), "0009-0002-8023-3658", "NC_derivedPw")

	require.ErrorIs(t, err, ErrNextcloudRateLimited,
		"HTTP 429 is throttling, not a malformed OCS response")
	assert.Contains(t, logged(), ncThrottleResetCommand,
		"a throttled provisioning call must tell the operator how to clear the throttle")
}

func TestHandleNcProvision_RateLimitedReturns503(t *testing.T) {
	srv := throttlingNextcloud(t)

	handler := HandleNcProvision(&NextcloudClient{URL: srv.URL, Username: "admin", Password: "secret"}, []byte("test-key"), "internal-secret", 2*time.Second)

	req := httptest.NewRequest("POST", "/internal/nc-provision?orcid=0009-0002-8023-3658", nil)
	req.Header.Set("X-ID1-Internal-Secret", "internal-secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code,
		"throttling is answered the same way /internal/nc-token answers it, not as an outage")
	assert.Equal(t, "nextcloud rate limited\n", rr.Body.String())
}
