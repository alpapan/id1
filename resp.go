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

// HostDaemon reports whether this process is the shared host daemon: the one
// standalone id1 a host runs for every curatorium on it (annot8r_id1). It is true
// only when ID1_HOST_DAEMON is the literal "true". A host daemon runs in no
// cluster and serves no browser page, so it needs no namespace and no browser
// origin, and no curatorium's value configures it. Every other id1, the cluster
// id1 included, keeps requiring both.
func HostDaemon() bool { return os.Getenv("ID1_HOST_DAEMON") == "true" }

// browserOrigin returns the one browser origin id1 answers CORS for, set via
// CURATORIUM_BROWSER_ORIGIN. There is no default: an unset value panics, since
// a guessed origin would let the wrong site read id1's responses. This panic is
// process-level fail-fast, not per-request: main's startup path resolves the
// origin before the HTTP server starts listening, so a missing value stops the
// process at boot.
//
// The host daemon (HostDaemon) has no browser origin: it returns "" and never
// reads the variable, so a value left in its environment is not honoured. An
// empty origin allows no cross-origin request (see cors and checkBrowserOrigin).
func browserOrigin() string {
	if HostDaemon() {
		return ""
	}
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
	if origin, allowed := r.Header.Get("Origin"), browserOrigin(); origin != "" && allowed != "" && origin == allowed {
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
