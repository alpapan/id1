//go:build !testmint

package id1

import "net/http"

// RegisterTestMintRoutes is the no-op variant. Without the `testmint` build tag
// neither the arbitrary-ORCID mint handler nor its route exists in the binary.
func RegisterTestMintRoutes(_ *http.ServeMux, _ KeyValueStore) {}
