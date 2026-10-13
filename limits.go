// apps/id1/limits.go
//
// group: server
// tags: http, limits, request-body, security
// summary: Request body caps for the whole router, with a per-route raise table.
//
//

package id1

import "net/http"

const (
	// DefaultBodyLimitBytes caps the request body of every route the raise table
	// does not name: 64 KiB.
	DefaultBodyLimitBytes int64 = 64 << 10
	// KVBodyLimitBytes caps the request body of the key/value storage route,
	// which stores caller-supplied values: 10 MiB.
	KVBodyLimitBytes int64 = 10 << 20
	// BodyUncapped, as a raise-table value, removes the cap for that pattern.
	BodyUncapped int64 = -1
)

// kvCatchAllPattern is the pattern main registers for the key/value handler.
const kvCatchAllPattern = "/{key...}"

// IngressBodyLimits is the raise table main passes to LimitBody. Every route
// not named here keeps DefaultBodyLimitBytes; the key/value catch-all is raised
// to KVBodyLimitBytes, and the Nextcloud proxy patterns carry no cap here.
func IngressBodyLimits() map[string]int64 {
	return map[string]int64{
		kvCatchAllPattern: KVBodyLimitBytes,
		"/nextcloud/":     BodyUncapped,
		"/nextcloud":      BodyUncapped,
	}
}

// LimitBody wraps a mux so that every request body is capped. The cap is
// DefaultBodyLimitBytes unless the pattern the mux would serve the request
// with is a key of raised, in which case the table value applies;
// BodyUncapped removes the cap. A request that declares a length over its cap
// is answered 413 before any handler runs; a request with no declared length
// is wrapped in http.MaxBytesReader, so the handler's read fails with
// *http.MaxBytesError once the cap is passed.
func LimitBody(mux *http.ServeMux, raised map[string]int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, pattern := mux.Handler(r)
		limit := DefaultBodyLimitBytes
		if raisedLimit, found := raised[pattern]; found {
			limit = raisedLimit
		}
		if limit != BodyUncapped {
			if r.ContentLength > limit {
				err413(w, r, "")
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
		mux.ServeHTTP(w, r)
	})
}
