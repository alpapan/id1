// apps/id1/orcid_exchange_test.go
//
// group: auth
// tags: orcid, oauth, authentication, single-use, testing
// summary: Tests for the one-time ORCID login code and the endpoint that redeems it.
//
//

package id1

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const exchangeTestOrcid = "0000-0002-1825-0097"

// newExchangeStore points the id1 KV store at a fresh temp directory for one test.
func newExchangeStore(t *testing.T) {
	t.Helper()
	originalDbpath := dbpath
	dbpath = t.TempDir()
	t.Cleanup(func() { dbpath = originalDbpath })
}

// postExchange sends one request body to HandleExchange and returns the response.
func postExchange(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	h := newTestOrcidHandler("", "http://localhost:19001")
	req := httptest.NewRequest(http.MethodPost, "/auth/orcid/exchange", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.HandleExchange(rec, req)
	return rec
}

// exchangeBody is the JSON body the browser sends for one code.
func exchangeBody(code string) string {
	encoded, _ := json.Marshal(map[string]string{"code": code})
	return string(encoded)
}

// startOrcidTokenStub stands in for ORCID's token endpoint and returns a
// valid token response carrying exchangeTestOrcid.
func startOrcidTokenStub(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"t","token_type":"bearer","orcid":%q,"scope":"/authenticate"}`, exchangeTestOrcid)
	}))
	t.Cleanup(server.Close)
	return server
}

func TestOrcidExchangeReturnsTheJWTOnceThenRefuses(t *testing.T) {
	newExchangeStore(t)
	code, err := storeOrcidLoginCode("signed.jwt.value")
	if err != nil {
		t.Fatalf("storeOrcidLoginCode: %v", err)
	}

	first := postExchange(t, exchangeBody(code))
	if first.Code != http.StatusOK {
		t.Fatalf("first exchange: expected 200, got %d: %s", first.Code, first.Body.String())
	}
	if got := first.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control: expected no-store, got %q", got)
	}
	if got := first.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type: expected application/json, got %q", got)
	}
	var response map[string]string
	if err := json.Unmarshal(first.Body.Bytes(), &response); err != nil {
		t.Fatalf("exchange response is not JSON: %v", err)
	}
	if response["jwt"] != "signed.jwt.value" {
		t.Errorf("expected the stored JWT back, got %q", response["jwt"])
	}

	second := postExchange(t, exchangeBody(code))
	if second.Code != http.StatusUnauthorized {
		t.Errorf("replay of a redeemed code: expected 401, got %d: %s", second.Code, second.Body.String())
	}
	if strings.Contains(second.Body.String(), "signed.jwt.value") {
		t.Error("a replayed code must not return the JWT")
	}
}

func TestOrcidExchangeRefusesCodesThatWereNeverIssued(t *testing.T) {
	newExchangeStore(t)
	cases := []struct {
		name string
		code string
	}{
		{"well formed but unknown", strings.Repeat("A", 43)},
		{"path traversal", "../" + strings.Repeat("A", 40)},
		{"contains a dot", strings.Repeat("A", 42) + "."},
		{"contains a slash", strings.Repeat("A", 42) + "/"},
		{"too short", "abc"},
		{"too long", strings.Repeat("A", 44)},
		{"padded", strings.Repeat("A", 42) + "="},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := postExchange(t, exchangeBody(tc.code))
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("expected 401, got %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestOrcidExchangeRejectsABadRequestWithoutTouchingTheStore(t *testing.T) {
	newExchangeStore(t)
	live, err := storeOrcidLoginCode("live.jwt.value")
	if err != nil {
		t.Fatalf("storeOrcidLoginCode: %v", err)
	}
	cases := []struct {
		name string
		body string
	}{
		{"empty code", `{"code":""}`},
		{"missing code", `{}`},
		{"not JSON", `not json`},
		{"empty body", ``},
		{"oversized body", `{"code":"` + strings.Repeat("a", orcidExchangeBodyLimit) + `"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := postExchange(t, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("expected 400, got %d: %s", rec.Code, rec.Body.String())
			}
		})
	}

	// An empty code must never reach the delete that would remove the whole
	// code directory: the live code is still redeemable after every refusal.
	rec := postExchange(t, exchangeBody(live))
	if rec.Code != http.StatusOK {
		t.Errorf("the live code was lost by a refused request: got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestOrcidExchangeAcceptsOnlyPost(t *testing.T) {
	newExchangeStore(t)
	code, err := storeOrcidLoginCode("post.only.jwt")
	if err != nil {
		t.Fatalf("storeOrcidLoginCode: %v", err)
	}
	h := newTestOrcidHandler("", "http://localhost:19001")
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodOptions} {
		req := httptest.NewRequest(method, "/auth/orcid/exchange", strings.NewReader(exchangeBody(code)))
		rec := httptest.NewRecorder()
		h.HandleExchange(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: expected 405, got %d", method, rec.Code)
		}
		if got := rec.Header().Get("Allow"); got != http.MethodPost {
			t.Errorf("%s: expected Allow: POST, got %q", method, got)
		}
	}
	// None of those requests consumed the code.
	rec := postExchange(t, exchangeBody(code))
	if rec.Code != http.StatusOK {
		t.Errorf("a refused method consumed the code: got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestOrcidExchangeHasExactlyOneWinnerWhenRacing(t *testing.T) {
	newExchangeStore(t)
	code, err := storeOrcidLoginCode("race.jwt.value")
	if err != nil {
		t.Fatalf("storeOrcidLoginCode: %v", err)
	}
	const racers = 8
	statuses := make([]int, racers)
	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(slot int) {
			defer wg.Done()
			h := newTestOrcidHandler("", "http://localhost:19001")
			req := httptest.NewRequest(http.MethodPost, "/auth/orcid/exchange", strings.NewReader(exchangeBody(code)))
			rec := httptest.NewRecorder()
			h.HandleExchange(rec, req)
			statuses[slot] = rec.Code
		}(i)
	}
	wg.Wait()

	winners := 0
	for _, status := range statuses {
		switch status {
		case http.StatusOK:
			winners++
		case http.StatusUnauthorized:
		default:
			t.Errorf("unexpected status %d from a racing exchange", status)
		}
	}
	if winners != 1 {
		t.Errorf("expected exactly one racer to receive the JWT, got %d (statuses %v)", winners, statuses)
	}
}

func TestOrcidLoginCodeIsScheduledForExpiry(t *testing.T) {
	newExchangeStore(t)
	code, err := storeOrcidLoginCode("expiring.jwt.value")
	if err != nil {
		t.Fatalf("storeOrcidLoginCode: %v", err)
	}
	if !orcidCodePattern.MatchString(code) {
		t.Errorf("issued code %q does not match the pattern the exchange accepts", code)
	}
	pointer, err := readTTLBookkeeping(mustKK(t, orcidCodePrefix, dotTTLDir, code))
	if err != nil {
		t.Fatalf("the login code has no expiry schedule: %v", err)
	}
	if !strings.Contains(string(pointer), ".after.") {
		t.Errorf("expected the schedule pointer to name an .after. key, got %q", string(pointer))
	}
}

// TestOrcidLoginCodeIsGarbageCollectedByDotAfter verifies the TTL-scheduled
// delete of a login code is authorised (x-id equals the prefix): a wrong x-id
// would leave the key undeleted and fail this test.
func TestOrcidLoginCodeIsGarbageCollectedByDotAfter(t *testing.T) {
	newExchangeStore(t)
	codeKey := mustKK(t, orcidCodePrefix, strings.Repeat("B", 43))
	if _, err := CmdSet(codeKey, map[string]string{"x-id": orcidCodePrefix, "ttl": "1"}, []byte("a.b.c")).execUnauthorised(); err != nil {
		t.Fatalf("seed with ttl: %v", err)
	}
	if data, err := CmdGet(codeKey).execUnauthorised(); err != nil || len(data) == 0 {
		t.Fatal("the code should be present immediately after seeding")
	}

	time.Sleep(1100 * time.Millisecond)
	dotAfter(dbpath)

	if data, err := CmdGet(codeKey).execUnauthorised(); err == nil && len(data) > 0 {
		t.Error("expired login code was not garbage-collected by dotAfter (check x-id authorization)")
	}
}

func TestOrcidCallbackRedirectCarriesALoginCodeNotTheJWT(t *testing.T) {
	newExchangeStore(t)
	kv := ID1KeyValueStore{}
	if _, _, err := GetOrCreateSigningKey(kv); err != nil {
		t.Fatalf("signing key: %v", err)
	}
	tokenServer := startOrcidTokenStub(t)
	h := newTestOrcidHandlerWithKVStore(tokenServer.URL, "http://localhost:19001", kv)
	seedState(t, "round_trip_state", stateEntry{created: time.Now(), verifier: "v"})

	callback := httptest.NewRecorder()
	h.HandleCallback(callback, httptest.NewRequest(http.MethodGet, "/auth/orcid/callback?state=round_trip_state&code=c", nil))
	if callback.Code != http.StatusFound {
		t.Fatalf("callback: expected 302, got %d: %s", callback.Code, callback.Body.String())
	}
	location := callback.Header().Get("Location")
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse Location %q: %v", location, err)
	}
	if strings.Contains(location, "token=") || parsed.Query().Get("token") != "" {
		t.Errorf("the redirect must not carry the JWT, got: %s", location)
	}
	code := parsed.Query().Get("code")
	if !orcidCodePattern.MatchString(code) {
		t.Fatalf("expected a 43-character login code in the redirect, got %q in %s", code, location)
	}

	jwtString := redeemLoginCode(t, h, location)
	claims, err := ValidateRS256JWTID1Claims(jwtString, kv)
	if err != nil {
		t.Fatalf("the redeemed JWT does not validate: %v", err)
	}
	if claims.Subject != exchangeTestOrcid {
		t.Errorf("expected subject %s, got %s", exchangeTestOrcid, claims.Subject)
	}
	if len(claims.AMR) != 1 || claims.AMR[0] != "orcid" {
		t.Errorf("expected amr [orcid], got %v", claims.AMR)
	}

	replay := postExchange(t, exchangeBody(code))
	if replay.Code != http.StatusUnauthorized {
		t.Errorf("replay of the redeemed code: expected 401, got %d", replay.Code)
	}
}

func TestOrcidCallbackFailsClosedWhenTheLoginCodeCannotBeStored(t *testing.T) {
	newExchangeStore(t)
	kv := ID1KeyValueStore{}
	if _, _, err := GetOrCreateSigningKey(kv); err != nil {
		t.Fatalf("signing key: %v", err)
	}
	tokenServer := startOrcidTokenStub(t)
	h := newTestOrcidHandlerWithKVStore(tokenServer.URL, "http://localhost:19001", kv)
	seedState(t, "store_failure_state", stateEntry{created: time.Now(), verifier: "v"})

	// A regular file where the code directory belongs makes every store of a
	// code fail, whoever runs the test (unlike a read-only directory, root
	// ignores a regular file standing in the way).
	if err := os.WriteFile(filepath.Join(dbpath, orcidCodePrefix), []byte("blocker"), 0o644); err != nil {
		t.Fatalf("plant the blocking file: %v", err)
	}
	getLog := captureLog(t)

	rec := httptest.NewRecorder()
	h.HandleCallback(rec, httptest.NewRequest(http.MethodGet, "/auth/orcid/callback?state=store_failure_state&code=c", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when the code cannot be stored, got %d: %s", rec.Code, rec.Body.String())
	}
	if location := rec.Header().Get("Location"); location != "" {
		t.Errorf("no redirect may be sent when no code was stored, got %q", location)
	}
	if !strings.Contains(rec.Body.String(), "Failed to issue login code") {
		t.Errorf("expected the failure reason in the body, got %q", rec.Body.String())
	}
	if !strings.Contains(getLog(), "orcid login code store failed") {
		t.Errorf("expected the store failure to be logged, got %q", getLog())
	}
}
