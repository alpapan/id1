//go:build !curatoriumdemo

package id1

import "net/http"

// RegisterDemoRoutes is the no-op variant. Without the `curatoriumdemo` build
// tag neither the demo-identity mint handler nor its route exists in the
// binary. Curatorium's own build always requests this tag - a Curatorium
// production image without it would silently break the four demo pages that
// depend on it - but annot8r_id1 builds separately and never requests it: it
// has no ORCID login, no browser, no Traefik route list, and no rate-limited
// proxy in front of it, so an unauthenticated caller reaching it would
// otherwise get a free, permanent device-key registration under
// demoUserORCID with nothing gating it.
func RegisterDemoRoutes(_ *http.ServeMux, _ KeyValueStore) {}
