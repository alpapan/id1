package id1

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestIngressValidationPatternsAcceptRealValues is the guard that stops this
// task's own fix from breaking legitimate traffic. A registration token is
// URL-safe base64 and MAY start with "-" or "_", which devicePattern forbids.
func TestIngressValidationPatternsAcceptRealValues(t *testing.T) {
	// These are deliberately unrealistic placeholders. Do NOT "improve" them
	// into realistic-looking tokens: a repo-wide guard test
	// (apps/id1/no_real_credentials_test.go) refuses any tracked file carrying
	// a credential-shaped literal, and a realistic 43-character base64url
	// token trips it and blocks every commit in the whole tree, not just this
	// one.
	//
	// That guard fires on a value of 40+ characters from [A-Za-z0-9+/_-] that
	// also mixes lower, upper and digit, when it appears after a "name:" or
	// "name=" separator. These placeholders are 24 characters, all lowercase,
	// with no digits, so they miss it on three counts at once.
	//
	// What this test actually needs from them is only their FIRST character -
	// "_", "-" and alphanumeric respectively - and a length inside
	// registrationTokenPattern's 16-64 bound. Realism buys nothing here.
	goodTokens := []string{
		"_placeholder_not_a_token",
		"-placeholder-not-a-token",
		"aplaceholder-not-a-token",
	}
	for _, tok := range goodTokens {
		if !registrationTokenPattern.MatchString(tok) {
			t.Errorf("registrationTokenPattern must accept the legitimate token %q", tok)
		}
	}
	badTokens := []string{
		"../victim/pub/keys/x",
		"..",
		"a/b",
		"",
		"tok en",
	}
	for _, tok := range badTokens {
		if registrationTokenPattern.MatchString(tok) {
			t.Errorf("registrationTokenPattern must reject %q", tok)
		}
	}

	goodDevices := []string{"default", "laptop-1", "Device.2", "a"}
	for _, d := range goodDevices {
		if !devicePattern.MatchString(d) {
			t.Errorf("devicePattern must accept %q", d)
		}
	}
	badDevices := []string{"../victim/pub/keys/x", "..", ".", "a/b", "", ".hidden"}
	for _, d := range badDevices {
		if devicePattern.MatchString(d) {
			t.Errorf("devicePattern must reject %q", d)
		}
	}
}

// registerCommitHostileFieldCases is the case list for
// TestIngressValidationRegisterCommitRejectsHostileField. Both cases hit the
// same handler with the same assertion shape, differing only in which field
// carries the hostile value - a family, collapsed into one table per
// curatorium-testing convention. No production registry names these two
// fields as a set, so the list is literal, not derived, and is asserted
// below for exact length and membership.
var registerCommitHostileFieldCases = []struct {
	name string
	req  RegisterCommitRequest
}{
	{
		name: "hostile deviceId",
		req: RegisterCommitRequest{
			RegistrationToken: "aplaceholder-not-a-token",
			Nonce:             "",
			DeviceId:          "../../../victim/pub/keys/evil",
			DeviceName:        "hostile",
		},
	},
	{
		name: "hostile registrationToken",
		req: RegisterCommitRequest{
			RegistrationToken: "../../../victim/priv/pending/x",
			Nonce:             "",
			DeviceId:          "default",
			DeviceName:        "n",
		},
	},
}

// TestIngressValidationRegisterCommitHostileFieldCaseListIsPopulated is the tripwire for the
// table below: dropping a row from registerCommitHostileFieldCases drops an
// assertion silently unless this also fails.
func TestIngressValidationRegisterCommitHostileFieldCaseListIsPopulated(t *testing.T) {
	if len(registerCommitHostileFieldCases) != 2 {
		t.Fatalf("expected exactly 2 cases, got %d", len(registerCommitHostileFieldCases))
	}
	names := map[string]bool{}
	for _, c := range registerCommitHostileFieldCases {
		names[c.name] = true
	}
	for _, want := range []string{"hostile deviceId", "hostile registrationToken"} {
		if !names[want] {
			t.Errorf("registerCommitHostileFieldCases is missing case %q", want)
		}
	}
}

// TestIngressValidationRegisterCommitRejectsHostileField is the load-bearing
// one: this is the publicly-routed endpoint named in the security review.
// Each case names a distinct field on the same handler that becomes a key
// segment.
func TestIngressValidationRegisterCommitRejectsHostileField(t *testing.T) {
	for _, c := range registerCommitHostileFieldCases {
		t.Run(c.name, func(t *testing.T) {
			kv := setupTestKVStore(t)
			if _, _, err := GetOrCreateSigningKey(kv); err != nil {
				t.Fatalf("signing key setup failed: %v", err)
			}

			body, _ := json.Marshal(c.req)
			req := httptest.NewRequest(http.MethodPost,
				"/auth/sovereign/register/commit?id=0000-0001-2345-6789", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			HandleRegisterCommit(kv)(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("%s must be refused with 400, got %d: %s", c.name, rec.Code, rec.Body.String())
			}
		})
	}
}

// TestIngressValidationRegisterBeginRejectsHostileDeviceId - begin stores a
// pending key too, so it validates the same field.
func TestIngressValidationRegisterBeginRejectsHostileDeviceId(t *testing.T) {
	kv := setupTestKVStore(t)
	keyID, privKey, err := GetOrCreateSigningKey(kv)
	if err != nil {
		t.Fatalf("signing key setup failed: %v", err)
	}
	orcid := "0000-0001-2345-6789"
	_, pubPEM := testGenerateRSAKeyPair(t)
	tok, err := signJWT(orcid, []string{"orcid"}, privKey, keyID)
	if err != nil {
		t.Fatalf("signJWT failed: %v", err)
	}

	body, _ := json.Marshal(RegisterBeginRequest{
		PublicKeyPEM: pubPEM,
		DeviceId:     "../victim/pub/keys/evil",
		DeviceName:   "hostile",
	})
	req := httptest.NewRequest(http.MethodPost,
		"/auth/sovereign/register/begin?id="+orcid, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()

	HandleRegisterBegin(kv)(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("hostile deviceId at begin must be refused with 400, got %d: %s", rec.Code, rec.Body.String())
	}
}
