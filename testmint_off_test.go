//go:build !testmint

package id1

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The production build shape carries no arbitrary-ORCID mint. RegisterTestMintRoutes
// must leave the mux without a /auth/test_user pattern even when ENV says dev.
func TestRegisterTestMintRoutes_NoRouteWithoutBuildTag(t *testing.T) {
	t.Setenv("ENV", "dev")
	mux := http.NewServeMux()
	RegisterTestMintRoutes(mux, ID1KeyValueStore{})

	_, pattern := mux.Handler(httptest.NewRequest(http.MethodGet, "/auth/test_user", nil))
	if pattern != "" {
		t.Fatalf("untagged build registered /auth/test_user (pattern %q); the handler must not be compiled in", pattern)
	}
}
