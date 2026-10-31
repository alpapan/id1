package id1

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// purgeTestOrcid and purgeOtherOrcid are iDs in the reserved test range.
const purgeTestOrcid = "0000-0000-0009-0027"
const purgeOtherOrcid = "0000-0000-0009-0035"
const purgeTestSecret = "purge-test-internal-secret-0123456789abcdef"

// withPurgeTestStore points the package store at a fresh temporary directory
// for one test, restores the previous one when the test ends, and sets the
// internal secret the handler compares against.
func withPurgeTestStore(t *testing.T) {
	t.Helper()
	originalDbpath := dbpath
	dbpath = t.TempDir()
	t.Cleanup(func() { dbpath = originalDbpath })
	t.Setenv("ID1_INTERNAL_SECRET", purgeTestSecret)
}

// purgeSeedAccount stores the three record kinds an account holds in id1:
// the account key, one device key and the private salt.
func purgeSeedAccount(t *testing.T, id string) {
	t.Helper()
	pem := []byte(genTestRSAPubPEM(t))
	args := map[string]string{"x-id": id}
	if _, err := CmdSet(mustKK(t, id, "pub", "key"), args, pem).execUnauthorised(); err != nil {
		t.Fatalf("seed account key: %v", err)
	}
	if _, err := CmdSet(mustKK(t, id, "pub", "keys", "cur-a"), args, pem).execUnauthorised(); err != nil {
		t.Fatalf("seed device key: %v", err)
	}
	if _, err := CmdSet(mustKK(t, id, "priv", "salt"), args, []byte("salt-bytes")).execUnauthorised(); err != nil {
		t.Fatalf("seed salt: %v", err)
	}
}

// purgeRecordStored reports whether the key made of segments holds a value.
func purgeRecordStored(t *testing.T, segments ...any) bool {
	t.Helper()
	data, err := CmdGet(mustKK(t, segments...)).execUnauthorised()
	return err == nil && len(data) > 0
}

func postPurge(t *testing.T, method, secret, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "/internal/account/purge", bytes.NewReader([]byte(body)))
	if secret != "" {
		req.Header.Set("X-ID1-Internal-Secret", secret)
	}
	rr := httptest.NewRecorder()
	HandleInternalAccountPurge()(rr, req)
	return rr
}

func TestInternalAccountPurge_RemovesEveryRecordOfTheAccountOnly(t *testing.T) {
	withPurgeTestStore(t)
	purgeSeedAccount(t, purgeTestOrcid)
	purgeSeedAccount(t, purgeOtherOrcid)

	rr := postPurge(t, http.MethodPost, purgeTestSecret, `{"id":"`+purgeTestOrcid+`"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("purge: want 200, got %d (%s)", rr.Code, rr.Body.String())
	}
	want := `{"status":"purged","id":"0000-0000-0009-0027"}`
	if rr.Body.String() != want {
		t.Fatalf("purge body: want %s, got %s", want, rr.Body.String())
	}
	if purgeRecordStored(t, purgeTestOrcid, "pub", "key") {
		t.Fatal("account key still stored after purge")
	}
	if purgeRecordStored(t, purgeTestOrcid, "pub", "keys", "cur-a") {
		t.Fatal("device key still stored after purge")
	}
	if purgeRecordStored(t, purgeTestOrcid, "priv", "salt") {
		t.Fatal("salt still stored after purge")
	}
	if !purgeRecordStored(t, purgeOtherOrcid, "pub", "key") ||
		!purgeRecordStored(t, purgeOtherOrcid, "pub", "keys", "cur-a") ||
		!purgeRecordStored(t, purgeOtherOrcid, "priv", "salt") {
		t.Fatal("another account's records are missing after the purge")
	}
}

func TestInternalAccountPurge_AbsentAccountAnswersPurged(t *testing.T) {
	withPurgeTestStore(t)

	rr := postPurge(t, http.MethodPost, purgeTestSecret, `{"id":"`+purgeTestOrcid+`"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("purge of an absent account: want 200, got %d (%s)", rr.Code, rr.Body.String())
	}
	want := `{"status":"purged","id":"0000-0000-0009-0027"}`
	if rr.Body.String() != want {
		t.Fatalf("purge body: want %s, got %s", want, rr.Body.String())
	}
}

func TestInternalAccountPurge_RefusesWithoutTheSecret(t *testing.T) {
	cases := []struct {
		name      string
		envSecret string
		header    string
	}{
		{"no header", purgeTestSecret, ""},
		{"wrong header", purgeTestSecret, "not-the-secret"},
		{"secret not configured", "", purgeTestSecret},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withPurgeTestStore(t)
			purgeSeedAccount(t, purgeTestOrcid)
			t.Setenv("ID1_INTERNAL_SECRET", tc.envSecret)

			rr := postPurge(t, http.MethodPost, tc.header, `{"id":"`+purgeTestOrcid+`"}`)
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("want 401, got %d (%s)", rr.Code, rr.Body.String())
			}
			if !purgeRecordStored(t, purgeTestOrcid, "pub", "key") {
				t.Fatal("a refused call removed the account key")
			}
		})
	}
}

func TestInternalAccountPurge_RefusesAnyMethodButPost(t *testing.T) {
	withPurgeTestStore(t)
	purgeSeedAccount(t, purgeTestOrcid)

	rr := postPurge(t, http.MethodDelete, purgeTestSecret, `{"id":"`+purgeTestOrcid+`"}`)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d (%s)", rr.Code, rr.Body.String())
	}
	if !purgeRecordStored(t, purgeTestOrcid, "pub", "key") {
		t.Fatal("a refused call removed the account key")
	}
}

func TestInternalAccountPurge_RefusesAnIdThatIsNotAnOrcid(t *testing.T) {
	cases := []struct {
		name string
		body string
		code int
	}{
		{"reserved top-level id", `{"id":"_system"}`, http.StatusBadRequest},
		{"path traversal", `{"id":"../0000-0000-0009-0027"}`, http.StatusBadRequest},
		{"empty id", `{"id":""}`, http.StatusBadRequest},
		{"not json", `not json`, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withPurgeTestStore(t)
			purgeSeedAccount(t, purgeTestOrcid)
			if _, err := CmdSet(mustKK(t, "_system", "marker"), map[string]string{}, []byte("kept")).execUnauthorised(); err != nil {
				t.Fatalf("seed _system marker: %v", err)
			}

			rr := postPurge(t, http.MethodPost, purgeTestSecret, tc.body)
			if rr.Code != tc.code {
				t.Fatalf("want %d, got %d (%s)", tc.code, rr.Code, rr.Body.String())
			}
			if !purgeRecordStored(t, purgeTestOrcid, "pub", "key") {
				t.Fatal("a refused call removed the account key")
			}
			if !purgeRecordStored(t, "_system", "marker") {
				t.Fatal("a refused call removed the _system record")
			}
		})
	}
}
