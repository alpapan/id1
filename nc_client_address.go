// apps/id1/nc_client_address.go
//
// group: nextcloud
// tags: nextcloud, proxy, client-address, brute-force
// summary: Decides the caller address id1 states to Nextcloud on its id1-only port.
//
//

package id1

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
)

// ClientAddressHeader carries the caller address id1 states to Nextcloud. Nextcloud's
// id1-only port reads it (Apache RemoteIPHeader); id1 removes every incoming copy first.
const ClientAddressHeader = "X-Curatorium-Client-Address"

// EdgeSecretHeader carries the edge secret the Cloudflare edge adds under the
// edge-secret method. id1 removes it before forwarding, so Nextcloud never sees it.
const EdgeSecretHeader = "X-Curatorium-Edge"

// edgeAddressHeader is the header the Cloudflare edge sets to the caller's address.
const edgeAddressHeader = "CF-Connecting-IP"

// traefikPeerHeader is the header Traefik sets to the address of its own peer: a
// tunnel connector pod for public traffic, 127.0.0.1 for a caller on the server itself.
const traefikPeerHeader = "X-Real-Ip"

// loopbackAddress is the address stated for a caller on the server itself.
var loopbackAddress = netip.MustParseAddr("127.0.0.1")

// EdgeProofMethod names how id1 proves a request came through the Cloudflare edge.
// The deployment declares it in EDGE_PROOF_METHOD; it has no default.
type EdgeProofMethod string

// EdgeProofConnectorAddress proves the edge by Traefik's peer being a tunnel connector pod.
const EdgeProofConnectorAddress EdgeProofMethod = "connector-address"

// EdgeProofEdgeSecret proves the edge by a secret header the Cloudflare edge adds.
const EdgeProofEdgeSecret EdgeProofMethod = "edge-secret"

// ParseEdgeProofMethod returns the method named by v, or an error naming both values.
func ParseEdgeProofMethod(v string) (EdgeProofMethod, error) {
	switch EdgeProofMethod(v) {
	case EdgeProofConnectorAddress, EdgeProofEdgeSecret:
		return EdgeProofMethod(v), nil
	}
	return "", fmt.Errorf("id1: EDGE_PROOF_METHOD must be %q or %q, got %q", EdgeProofConnectorAddress, EdgeProofEdgeSecret, v)
}

// ConnectorChecker answers whether an address is a tunnel connector pod.
type ConnectorChecker interface {
	Contains(ctx context.Context, addr netip.Addr) bool
}

// ClientAddressRule decides the caller address id1 states to Nextcloud.
type ClientAddressRule struct {
	Method     EdgeProofMethod
	PodRange   netip.Prefix
	Connectors ConnectorChecker
	EdgeSecret string
}

// ClientAddressDecision is either an Address to state (Status 0) or a refusal: an
// HTTP Status and a Reason for the log.
type ClientAddressDecision struct {
	Address netip.Addr
	Status  int
	Reason  string
}

// Decide applies the rule to the incoming request headers.
func (r ClientAddressRule) Decide(ctx context.Context, h http.Header) ClientAddressDecision {
	peerText := strings.TrimSpace(h.Get(traefikPeerHeader))
	peer, peerErr := netip.ParseAddr(peerText)
	if peerErr == nil {
		peer = peer.Unmap()
	}
	var proved bool
	switch r.Method {
	case EdgeProofConnectorAddress:
		proved = peerErr == nil && r.Connectors != nil && r.Connectors.Contains(ctx, peer)
	case EdgeProofEdgeSecret:
		presented := h.Get(EdgeSecretHeader)
		proved = r.EdgeSecret != "" && subtle.ConstantTimeCompare([]byte(presented), []byte(r.EdgeSecret)) == 1
	default:
		return ClientAddressDecision{Status: http.StatusInternalServerError, Reason: fmt.Sprintf("edge proof method %q is not %q or %q", r.Method, EdgeProofConnectorAddress, EdgeProofEdgeSecret)}
	}
	if proved {
		return r.edgeAddress(h)
	}
	if peerErr == nil && peer == loopbackAddress {
		return ClientAddressDecision{Address: loopbackAddress}
	}
	if r.Method == EdgeProofEdgeSecret {
		return ClientAddressDecision{Status: http.StatusForbidden, Reason: fmt.Sprintf("edge header missing (X-Real-Ip %q)", peerText)}
	}
	return ClientAddressDecision{Status: http.StatusForbidden, Reason: fmt.Sprintf("X-Real-Ip %q is not a tunnel connector", peerText)}
}

// edgeAddress reads CF-Connecting-IP once the edge is proved.
func (r ClientAddressRule) edgeAddress(h http.Header) ClientAddressDecision {
	values := h.Values(edgeAddressHeader)
	if len(values) == 0 || strings.TrimSpace(values[0]) == "" {
		return ClientAddressDecision{Status: http.StatusBadRequest, Reason: "CF-Connecting-IP missing"}
	}
	if len(values) != 1 {
		return ClientAddressDecision{Status: http.StatusBadRequest, Reason: fmt.Sprintf("CF-Connecting-IP given %d times", len(values))}
	}
	text := strings.TrimSpace(values[0])
	addr, err := netip.ParseAddr(text)
	if err != nil || addr.Zone() != "" {
		return ClientAddressDecision{Status: http.StatusBadRequest, Reason: fmt.Sprintf("CF-Connecting-IP %q is not an address", text)}
	}
	addr = addr.Unmap()
	if r.PodRange.Contains(addr) {
		return ClientAddressDecision{Status: http.StatusBadRequest, Reason: fmt.Sprintf("CF-Connecting-IP %q is inside the pod range %s", text, r.PodRange)}
	}
	return ClientAddressDecision{Address: addr}
}

// ApplyClientAddress removes every incoming copy of the address and edge-secret
// headers, and every Connection token naming either (the reverse proxy drops every
// header a Connection token names after its director runs, which would remove the
// stated address), then states addr.
func ApplyClientAddress(h http.Header, addr netip.Addr) {
	h.Del(ClientAddressHeader)
	h.Del(EdgeSecretHeader)
	var kept []string
	for _, value := range h.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			token = strings.TrimSpace(token)
			if token == "" || strings.EqualFold(token, ClientAddressHeader) || strings.EqualFold(token, EdgeSecretHeader) {
				continue
			}
			kept = append(kept, token)
		}
	}
	h.Del("Connection")
	if len(kept) > 0 {
		h.Set("Connection", strings.Join(kept, ", "))
	}
	h.Set(ClientAddressHeader, addr.String())
}
