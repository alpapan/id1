// apps/id1/nc_client_address_test.go
//
// group: nextcloud
// tags: nextcloud, proxy, client-address, brute-force, testing
// summary: Tests for ClientAddressRule.Decide and ApplyClientAddress.
//
//

package id1

import (
	"context"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

const testEdgeSecret = "0123456789abcdef0123456789abcdef"

func connectorTestRule() ClientAddressRule {
	stub := &connectorLookupStub{addrs: []netip.Addr{netip.MustParseAddr("10.42.1.10"), netip.MustParseAddr("10.42.2.20")}}
	clock := &connectorClock{now: time.Unix(1000, 0)}
	return ClientAddressRule{
		Method:     EdgeProofConnectorAddress,
		PodRange:   netip.MustParsePrefix("10.42.0.0/16"),
		Connectors: newConnectorTestSet(stub, clock),
	}
}

func secretTestRule() ClientAddressRule {
	return ClientAddressRule{
		Method:     EdgeProofEdgeSecret,
		PodRange:   netip.MustParsePrefix("10.42.0.0/16"),
		EdgeSecret: testEdgeSecret,
	}
}

func headerWith(pairs ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(pairs); i += 2 {
		h.Add(pairs[i], pairs[i+1])
	}
	return h
}

func TestClientAddressRuleDecide(t *testing.T) {
	cases := []struct {
		name       string
		rule       ClientAddressRule
		header     http.Header
		wantAddr   string
		wantStatus int
		wantReason string
	}{
		{"connector peer, IPv4 edge address", connectorTestRule(), headerWith("X-Real-Ip", "10.42.1.10", "CF-Connecting-IP", "203.0.113.7"), "203.0.113.7", 0, ""},
		{"connector peer, IPv6 edge address", connectorTestRule(), headerWith("X-Real-Ip", "10.42.2.20", "CF-Connecting-IP", "2001:db8::7"), "2001:db8::7", 0, ""},
		{"connector peer, IPv4-mapped edge address", connectorTestRule(), headerWith("X-Real-Ip", "10.42.1.10", "CF-Connecting-IP", "::ffff:203.0.113.7"), "203.0.113.7", 0, ""},
		{"connector peer, edge address missing", connectorTestRule(), headerWith("X-Real-Ip", "10.42.1.10"), "", http.StatusBadRequest, "CF-Connecting-IP missing"},
		{"connector peer, edge address given twice", connectorTestRule(), headerWith("X-Real-Ip", "10.42.1.10", "CF-Connecting-IP", "203.0.113.7", "CF-Connecting-IP", "198.51.100.9"), "", http.StatusBadRequest, "CF-Connecting-IP given 2 times"},
		{"connector peer, edge address not an address", connectorTestRule(), headerWith("X-Real-Ip", "10.42.1.10", "CF-Connecting-IP", "not-an-address"), "", http.StatusBadRequest, "is not an address"},
		{"connector peer, edge address with IPv6 zone", connectorTestRule(), headerWith("X-Real-Ip", "10.42.1.10", "CF-Connecting-IP", "fe80::1%eth0"), "", http.StatusBadRequest, "is not an address"},
		{"connector peer, edge address inside the pod range", connectorTestRule(), headerWith("X-Real-Ip", "10.42.1.10", "CF-Connecting-IP", "10.42.3.4"), "", http.StatusBadRequest, "inside the pod range"},
		{"peer not a connector", connectorTestRule(), headerWith("X-Real-Ip", "10.42.9.9", "CF-Connecting-IP", "203.0.113.7"), "", http.StatusForbidden, `X-Real-Ip "10.42.9.9" is not a tunnel connector`},
		{"peer missing", connectorTestRule(), headerWith("CF-Connecting-IP", "203.0.113.7"), "", http.StatusForbidden, `X-Real-Ip "" is not a tunnel connector`},
		{"connector method, on-server caller", connectorTestRule(), headerWith("X-Real-Ip", "127.0.0.1", "CF-Connecting-IP", "203.0.113.7"), "127.0.0.1", 0, ""},
		{"edge secret matches", secretTestRule(), headerWith("X-Real-Ip", "10.42.9.9", "X-Curatorium-Edge", testEdgeSecret, "CF-Connecting-IP", "203.0.113.7"), "203.0.113.7", 0, ""},
		{"edge secret matches, edge address inside the pod range", secretTestRule(), headerWith("X-Real-Ip", "10.42.9.9", "X-Curatorium-Edge", testEdgeSecret, "CF-Connecting-IP", "10.42.0.1"), "", http.StatusBadRequest, "inside the pod range"},
		{"edge secret wrong", secretTestRule(), headerWith("X-Real-Ip", "10.42.9.9", "X-Curatorium-Edge", "wrong", "CF-Connecting-IP", "203.0.113.7"), "", http.StatusForbidden, `edge header missing (X-Real-Ip "10.42.9.9")`},
		{"edge secret absent", secretTestRule(), headerWith("X-Real-Ip", "10.42.9.9", "CF-Connecting-IP", "203.0.113.7"), "", http.StatusForbidden, `edge header missing (X-Real-Ip "10.42.9.9")`},
		{"edge secret method, on-server caller", secretTestRule(), headerWith("X-Real-Ip", "127.0.0.1"), "127.0.0.1", 0, ""},
		{"edge secret method with no secret configured never proves the edge", ClientAddressRule{Method: EdgeProofEdgeSecret, PodRange: netip.MustParsePrefix("10.42.0.0/16")}, headerWith("X-Real-Ip", "10.42.9.9", "X-Curatorium-Edge", "", "CF-Connecting-IP", "203.0.113.7"), "", http.StatusForbidden, "edge header missing"},
		{"method not set", ClientAddressRule{PodRange: netip.MustParsePrefix("10.42.0.0/16")}, headerWith("X-Real-Ip", "127.0.0.1"), "", http.StatusInternalServerError, "edge proof method"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.rule.Decide(context.Background(), tc.header)
			if got.Status != tc.wantStatus {
				t.Fatalf("Status = %d, want %d (reason %q)", got.Status, tc.wantStatus, got.Reason)
			}
			if tc.wantStatus != 0 {
				if !strings.Contains(got.Reason, tc.wantReason) {
					t.Fatalf("Reason = %q, want it to contain %q", got.Reason, tc.wantReason)
				}
				return
			}
			if got.Address.String() != tc.wantAddr {
				t.Fatalf("Address = %q, want %q", got.Address.String(), tc.wantAddr)
			}
		})
	}
}

func TestApplyClientAddressReplacesIncomingCopies(t *testing.T) {
	h := headerWith(
		"X-Curatorium-Client-Address", "198.51.100.1",
		"X-Curatorium-Client-Address", "198.51.100.2",
		"X-Curatorium-Edge", testEdgeSecret,
	)
	ApplyClientAddress(h, netip.MustParseAddr("203.0.113.7"))
	if got := h.Values("X-Curatorium-Client-Address"); len(got) != 1 || got[0] != "203.0.113.7" {
		t.Fatalf("X-Curatorium-Client-Address = %q, want exactly [203.0.113.7]", got)
	}
	if got := h.Values("X-Curatorium-Edge"); len(got) != 0 {
		t.Fatalf("X-Curatorium-Edge = %q, want it removed", got)
	}
}

func TestApplyClientAddressRemovesConnectionTokensNamingItsHeaders(t *testing.T) {
	h := headerWith("Connection", "keep-alive, X-Curatorium-Client-Address", "Connection", "x-curatorium-edge")
	ApplyClientAddress(h, netip.MustParseAddr("2001:db8::7"))
	if got := h.Get("Connection"); got != "keep-alive" {
		t.Fatalf("Connection = %q, want %q", got, "keep-alive")
	}
	if got := h.Get("X-Curatorium-Client-Address"); got != "2001:db8::7" {
		t.Fatalf("X-Curatorium-Client-Address = %q, want %q", got, "2001:db8::7")
	}
}

func TestApplyClientAddressDropsConnectionWhenOnlyItsTokensWereNamed(t *testing.T) {
	h := headerWith("Connection", "X-Curatorium-Client-Address")
	ApplyClientAddress(h, netip.MustParseAddr("203.0.113.7"))
	if got := h.Values("Connection"); len(got) != 0 {
		t.Fatalf("Connection = %q, want it removed", got)
	}
}
