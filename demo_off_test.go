//go:build !curatoriumdemo

package id1

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Without the `curatoriumdemo` build tag - the annot8r_id1 shape - the
// demo-identity mint must be absent from the mux entirely: that deployment
// has no Traefik route list and no rate-limited proxy in front of it, so an
// unauthenticated caller reaching it would otherwise get a free, permanent
// device-key registration under demoUserORCID with nothing gating it.
func TestRegisterDemoRoutes_NoRouteWithoutBuildTag(t *testing.T) {
	mux := http.NewServeMux()
	RegisterDemoRoutes(mux, ID1KeyValueStore{})

	_, pattern := mux.Handler(httptest.NewRequest(http.MethodGet, "/auth/unauth_demo", nil))
	if pattern != "" {
		t.Fatalf("build without curatoriumdemo registered /auth/unauth_demo (pattern %q); the handler must not be compiled in", pattern)
	}
}
