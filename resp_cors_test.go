// apps/id1/resp_cors_test.go
//
// group: server
// tags: http, cors, origin, testing
// summary: Tests that id1 answers CORS only for the one configured browser origin.
//
//

package id1

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

const testBrowserOrigin = "https://curatorium.example"

// corsOriginCases are the request Origin values the rule is held to: only the
// first is the configured origin, every other must get no allow-origin header.
var corsOriginCases = []struct {
	name   string
	origin string
	want   string
}{
	{"exact match", testBrowserOrigin, testBrowserOrigin},
	{"no origin header", "", ""},
	{"another site", "https://evil.example", ""},
	{"configured origin as a prefix of another host", "https://curatorium.example.evil.example", ""},
	{"different scheme", "http://curatorium.example", ""},
	{"trailing slash", "https://curatorium.example/", ""},
	{"upper case", "HTTPS://CURATORIUM.EXAMPLE", ""},
	{"null origin", "null", ""},
	{"wildcard", "*", ""},
}

func corsRequest(origin string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/some/key", nil)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	return req
}

func TestCORSAllowsOnlyTheConfiguredOrigin(t *testing.T) {
	t.Setenv("CURATORIUM_BROWSER_ORIGIN", testBrowserOrigin)
	for _, c := range corsOriginCases {
		t.Run(c.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			cors(rec, corsRequest(c.origin))
			values := rec.Header().Values("Access-Control-Allow-Origin")
			if c.want == "" {
				if len(values) != 0 {
					t.Fatalf("Origin %q must get no Access-Control-Allow-Origin header, got %v", c.origin, values)
				}
				return
			}
			if len(values) != 1 || values[0] != c.want {
				t.Fatalf("Origin %q must get exactly Access-Control-Allow-Origin %q, got %v", c.origin, c.want, values)
			}
		})
	}
}

func TestCORSKeepsTheOtherHeadersForEveryOrigin(t *testing.T) {
	t.Setenv("CURATORIUM_BROWSER_ORIGIN", testBrowserOrigin)
	want := map[string]string{
		"Access-Control-Allow-Methods": "GET, PUT, PATCH, POST, DELETE, OPTIONS",
		"Access-Control-Allow-Headers": "*, Authorization",
		"Access-Control-Max-Age":       "0",
		"Vary":                         "Origin",
	}
	for _, c := range corsOriginCases {
		rec := httptest.NewRecorder()
		cors(rec, corsRequest(c.origin))
		for header, value := range want {
			if got := rec.Header().Get(header); got != value {
				t.Errorf("Origin %q: %s = %q, want %q", c.origin, header, got, value)
			}
		}
	}
}

func TestResponseHelpersApplyTheOriginRule(t *testing.T) {
	t.Setenv("CURATORIUM_BROWSER_ORIGIN", testBrowserOrigin)
	helpers := []struct {
		name   string
		status int
		call   func(w http.ResponseWriter, r *http.Request)
	}{
		{"ok200", http.StatusOK, func(w http.ResponseWriter, r *http.Request) { ok200(w, r, []byte("x")) }},
		{"err400", http.StatusBadRequest, func(w http.ResponseWriter, r *http.Request) { err400(w, r, "x") }},
		{"err401", http.StatusUnauthorized, func(w http.ResponseWriter, r *http.Request) { err401(w, r, "x") }},
		{"err403", http.StatusForbidden, func(w http.ResponseWriter, r *http.Request) { err403(w, r, "x") }},
		{"err404", http.StatusNotFound, func(w http.ResponseWriter, r *http.Request) { err404(w, r, "x") }},
		{"err413", http.StatusRequestEntityTooLarge, func(w http.ResponseWriter, r *http.Request) { err413(w, r, "x") }},
		{"err500", http.StatusInternalServerError, func(w http.ResponseWriter, r *http.Request) { err500(w, r, "x") }},
	}
	for _, h := range helpers {
		for _, c := range corsOriginCases {
			rec := httptest.NewRecorder()
			h.call(rec, corsRequest(c.origin))
			if rec.Code != h.status {
				t.Errorf("%s: status = %d, want %d", h.name, rec.Code, h.status)
			}
			if got := rec.Header().Get("Access-Control-Allow-Origin"); got != c.want {
				t.Errorf("%s with Origin %q: Access-Control-Allow-Origin = %q, want %q", h.name, c.origin, got, c.want)
			}
		}
	}
}

func TestBrowserOriginPanicsWhenUnset(t *testing.T) {
	t.Setenv("CURATORIUM_BROWSER_ORIGIN", "")
	defer func() {
		if recover() == nil {
			t.Fatal("expected browserOrigin() to panic when CURATORIUM_BROWSER_ORIGIN is unset")
		}
	}()
	browserOrigin()
}

func TestBrowserOriginReturnsTheConfiguredValueVerbatim(t *testing.T) {
	t.Setenv("CURATORIUM_BROWSER_ORIGIN", testBrowserOrigin)
	if got := BrowserOrigin(); got != testBrowserOrigin {
		t.Fatalf("BrowserOrigin() = %q, want %q", got, testBrowserOrigin)
	}
}
