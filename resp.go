// apps/id1/resp.go
//
// group: models
// tags: http, responses, serialization
// summary: HTTP response type definitions and JSON serialization for operation results.
//
//

package id1

import (
	"net/http"
	"os"
)

// browserOrigin returns the one browser origin id1 answers CORS for, set via
// CURATORIUM_BROWSER_ORIGIN. There is no default: an unset value panics, since
// a guessed origin would let the wrong site read id1's responses. This panic is
// process-level fail-fast, not per-request: main's startup path resolves the
// origin before the HTTP server starts listening, so a missing value stops the
// process at boot.
func browserOrigin() string {
	v := os.Getenv("CURATORIUM_BROWSER_ORIGIN")
	if v == "" {
		panic("CURATORIUM_BROWSER_ORIGIN is required and has no default; set it to the origin browsers load Curatorium from")
	}
	return v
}

// BrowserOrigin exposes the resolved origin so main can resolve it at boot and
// log it, as JWTIssuer does for the issuer.
func BrowserOrigin() string { return browserOrigin() }

// cors writes the CORS headers. Access-Control-Allow-Origin is written only
// when the request's Origin equals the configured browser origin exactly; any
// other Origin, or none, gets no such header, so a page on another site cannot
// read the response. Vary: Origin is always written, because the answer
// depends on the request's Origin.
func cors(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" && origin == browserOrigin() {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
	w.Header().Add("Access-Control-Allow-Methods", "GET, PUT, PATCH, POST, DELETE, OPTIONS")
	w.Header().Add("Access-Control-Allow-Headers", "*, Authorization")
	w.Header().Add("Access-Control-Max-Age", "0")
	w.Header().Add("Vary", "Origin")
}

func ok200(w http.ResponseWriter, r *http.Request, data []byte) {
	cors(w, r)
	w.Write(data)
}

func err404(w http.ResponseWriter, r *http.Request, s string) {
	cors(w, r)
	http.Error(w, s, http.StatusNotFound)
}

func err401(w http.ResponseWriter, r *http.Request, s string) {
	cors(w, r)
	http.Error(w, s, http.StatusUnauthorized)
}

func err403(w http.ResponseWriter, r *http.Request, s string) {
	cors(w, r)
	http.Error(w, s, http.StatusForbidden)
}

func err413(w http.ResponseWriter, r *http.Request, s string) {
	cors(w, r)
	http.Error(w, s, http.StatusRequestEntityTooLarge)
}

func err400(w http.ResponseWriter, r *http.Request, s string) {
	cors(w, r)
	http.Error(w, s, http.StatusBadRequest)
}

func err500(w http.ResponseWriter, r *http.Request, s string) {
	cors(w, r)
	http.Error(w, s, http.StatusInternalServerError)
}
