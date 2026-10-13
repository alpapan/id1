// apps/id1/orcid_binding_test.go
//
// group: auth
// tags: orcid, oauth, authentication, login-csrf, testing
// summary: Tests that an ORCID login is bound to the browser that started it.
//
//

package id1

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

// bindCookieWireName is the cookie name a browser carries between /auth/orcid,
// /auth/orcid/callback and /auth/orcid/exchange. Pinned here because a rename
// changes what every in-flight browser holds.
const bindCookieWireName = "id1_orcid_bind"

// bindingFixture is one handler wired to a real KV on a temp dir, a real
// signing key and a counting ORCID token stub.
type bindingFixture struct {
	h          *OrcidHandler
	kv         ID1KeyValueStore
	tokenCalls *int32
}

func newBindingFixture(t *testing.T) bindingFixture {
	t.Helper()
	newExchangeStore(t)
	kv := ID1KeyValueStore{}
	if _, _, err := GetOrCreateSigningKey(kv); err != nil {
		t.Fatalf("signing key: %v", err)
	}
	var calls int32
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"t","token_type":"bearer","orcid":"` + exchangeTestOrcid + `","scope":"/authenticate"}`))
	}))
	t.Cleanup(stub.Close)
	h := newTestOrcidHandlerWithKVStore(stub.URL, "http://localhost:19001", kv)
	return bindingFixture{h: h, kv: kv, tokenCalls: &calls}
}

// begin runs HandleBegin and returns the state parameter and the binding cookie
// the browser would receive (nil when none was set).
func (f bindingFixture) begin(t *testing.T) (string, *http.Cookie, *httptest.ResponseRecorder) {
	t.Helper()
	rec := httptest.NewRecorder()
	f.h.HandleBegin(rec, httptest.NewRequest(http.MethodGet, "/auth/orcid", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("begin: expected 302, got %d: %s", rec.Code, rec.Body.String())
	}
	state := stateFromRedirect(t, rec.Header().Get("Location"))
	var bind *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == bindCookieWireName {
			bind = c
		}
	}
	return state, bind, rec
}

func (f bindingFixture) callback(state string, cookie *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/auth/orcid/callback?state="+url.QueryEscape(state)+"&code=c", nil)
	if cookie != nil {
		req.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
	}
	rec := httptest.NewRecorder()
	f.h.HandleCallback(rec, req)
	return rec
}

func (f bindingFixture) exchange(code string, cookie *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/auth/orcid/exchange", strings.NewReader(exchangeBody(code)))
	if cookie != nil {
		req.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
	}
	rec := httptest.NewRecorder()
	f.h.HandleExchange(rec, req)
	return rec
}

func TestOrcidBeginSetsAnUnguessableBrowserBindingCookie(t *testing.T) {
	f := newBindingFixture(t)
	state, bind, _ := f.begin(t)
	if bind == nil {
		t.Fatal("begin must set the browser binding cookie")
	}
	if !bind.HttpOnly {
		t.Error("the binding cookie must be HttpOnly")
	}
	if bind.SameSite != http.SameSiteLaxMode {
		t.Errorf("the binding cookie must be SameSite=Lax so it survives ORCID's top-level redirect, got %v", bind.SameSite)
	}
	if bind.Path != "/auth/orcid" {
		t.Errorf("the binding cookie must be scoped to /auth/orcid, got %q", bind.Path)
	}
	if bind.MaxAge != 300 {
		t.Errorf("the binding cookie must live as long as the state (300 s), got %d", bind.MaxAge)
	}
	if bind.Secure {
		t.Error("an http callback origin must not mark the cookie Secure (browsers would drop it)")
	}
	if len(bind.Value) < 43 {
		t.Errorf("the binding value must carry 256 bits, got %q", bind.Value)
	}
	if bind.Value == state {
		t.Error("the binding value must be independent of the state parameter")
	}

	// The KV must not hold the cookie value itself.
	data, err := CmdGet(mustKK(t, stateKeyPrefix, state)).execUnauthorised()
	if err != nil {
		t.Fatalf("read stored state: %v", err)
	}
	if strings.Contains(string(data), bind.Value) {
		t.Error("the stored state must hold a digest of the binding, never the binding itself")
	}
}

func TestOrcidBeginMarksTheCookieSecureForAnHTTPSCallbackOrigin(t *testing.T) {
	f := newBindingFixture(t)
	f.h.oauth2Config.RedirectURL = "https://curatorium.example/auth/orcid/callback"
	_, bind, _ := f.begin(t)
	if bind == nil || !bind.Secure {
		t.Fatalf("an https callback origin must mark the binding cookie Secure, got %+v", bind)
	}
}

func TestOrcidCallbackRefusesABrowserThatDidNotStartTheLogin(t *testing.T) {
	cases := []struct {
		name   string
		cookie func(real *http.Cookie) *http.Cookie
	}{
		{"no cookie", func(*http.Cookie) *http.Cookie { return nil }},
		{"another browser's cookie", func(*http.Cookie) *http.Cookie {
			return &http.Cookie{Name: bindCookieWireName, Value: strings.Repeat("A", 43)}
		}},
		{"empty cookie", func(*http.Cookie) *http.Cookie {
			return &http.Cookie{Name: bindCookieWireName, Value: ""}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newBindingFixture(t)
			state, bind, _ := f.begin(t)
			rec := f.callback(state, tc.cookie(bind))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
			}
			if loc := rec.Header().Get("Location"); loc != "" {
				t.Errorf("no login code may be issued, got redirect %q", loc)
			}
			if got := atomic.LoadInt32(f.tokenCalls); got != 0 {
				t.Errorf("ORCID's token endpoint must not be called for an unbound browser, got %d calls", got)
			}
			// The attacker's state is burned: the real owner's callback cannot be replayed either.
			replay := f.callback(state, bind)
			if replay.Code != http.StatusBadRequest {
				t.Errorf("a state hit by an unbound browser must be consumed, replay got %d", replay.Code)
			}
		})
	}
}

func TestOrcidCallbackAcceptsTheBrowserThatStartedTheLoginAndRenewsTheBinding(t *testing.T) {
	f := newBindingFixture(t)
	state, bind, _ := f.begin(t)
	rec := f.callback(state, bind)
	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d: %s", rec.Code, rec.Body.String())
	}
	var renewed *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == bindCookieWireName {
			renewed = c
		}
	}
	if renewed == nil || renewed.Value != bind.Value {
		t.Fatalf("the callback must re-issue the same binding for the exchange step, got %+v", renewed)
	}
	if renewed.MaxAge != 60 {
		t.Errorf("the re-issued binding must live as long as a login code (60 s), got %d", renewed.MaxAge)
	}
}

func TestOrcidExchangeRefusesABrowserThatDidNotReceiveTheCode(t *testing.T) {
	cases := []struct {
		name   string
		cookie func(real *http.Cookie) *http.Cookie
	}{
		{"no cookie", func(*http.Cookie) *http.Cookie { return nil }},
		{"wrong cookie", func(*http.Cookie) *http.Cookie {
			return &http.Cookie{Name: bindCookieWireName, Value: strings.Repeat("B", 43)}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newBindingFixture(t)
			state, bind, _ := f.begin(t)
			cb := f.callback(state, bind)
			if cb.Code != http.StatusFound {
				t.Fatalf("callback: expected 302, got %d", cb.Code)
			}
			u, _ := url.Parse(cb.Header().Get("Location"))
			code := u.Query().Get("code")

			refused := f.exchange(code, tc.cookie(bind))
			if refused.Code != http.StatusUnauthorized {
				t.Fatalf("expected 401, got %d: %s", refused.Code, refused.Body.String())
			}
			if strings.Contains(refused.Body.String(), "jwt") {
				t.Error("a refused exchange must not return a JWT")
			}
			// The code is burned by the refusal: holding it later does not help an attacker.
			late := f.exchange(code, bind)
			if late.Code != http.StatusUnauthorized {
				t.Errorf("a code refused for a missing binding must be burned, got %d", late.Code)
			}
		})
	}
}

func TestOrcidExchangeAcceptsTheBoundBrowserOnceAndClearsTheBinding(t *testing.T) {
	f := newBindingFixture(t)
	state, bind, _ := f.begin(t)
	cb := f.callback(state, bind)
	u, _ := url.Parse(cb.Header().Get("Location"))
	code := u.Query().Get("code")

	rec := f.exchange(code, bind)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["jwt"] == "" {
		t.Fatalf("expected a JWT, got %q (%v)", rec.Body.String(), err)
	}
	var cleared bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == bindCookieWireName && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("a successful exchange must clear the binding cookie")
	}
}

func TestOrcidCallbackRefusesARequestCarryingTwoBindingCookies(t *testing.T) {
	// A sibling host can plant a second cookie of the same name; the genuine one
	// still rides along, and either order must be refused.
	for _, genuineFirst := range []bool{true, false} {
		name := "planted cookie first"
		if genuineFirst {
			name = "genuine cookie first"
		}
		t.Run(name, func(t *testing.T) {
			f := newBindingFixture(t)
			state, bind, _ := f.begin(t)
			req := httptest.NewRequest(http.MethodGet, "/auth/orcid/callback?state="+url.QueryEscape(state)+"&code=c", nil)
			genuine := &http.Cookie{Name: bindCookieWireName, Value: bind.Value}
			planted := &http.Cookie{Name: bindCookieWireName, Value: strings.Repeat("C", 43)}
			if genuineFirst {
				req.AddCookie(genuine)
				req.AddCookie(planted)
			} else {
				req.AddCookie(planted)
				req.AddCookie(genuine)
			}
			rec := httptest.NewRecorder()
			f.h.HandleCallback(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400 for an ambiguous binding, got %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
}
