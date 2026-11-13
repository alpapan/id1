// apps/id1/nc_compute_address_test.go
//
// group: nextcloud
// tags: nextcloud, proxy, client-address, compute
// summary: tests for the per-account stated address on id1's compute port.
//
//

package id1

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestComputeAccountAddressIsInTheBlockAndNeverTheServerCaller(t *testing.T) {
	for _, account := range []string{
		"0000-0002-1825-0097",
		"0000-0001-5109-3700",
		"0000-0002-1694-233X",
		"9999-0000-0000-000X",
	} {
		addr := ComputeAccountAddress(account)
		if !ComputeAddressBlock.Contains(addr) {
			t.Fatalf("ComputeAccountAddress(%q) = %s, outside %s", account, addr, ComputeAddressBlock)
		}
		if addr == netip.MustParseAddr("127.0.0.1") {
			t.Fatalf("ComputeAccountAddress(%q) = 127.0.0.1, the address stated for a caller on the server", account)
		}
		if again := ComputeAccountAddress(account); again != addr {
			t.Fatalf("ComputeAccountAddress(%q) gave %s then %s; the same account must map to one address", account, addr, again)
		}
	}
}

func TestComputeAccountAddressSeparatesAccounts(t *testing.T) {
	first := ComputeAccountAddress("0000-0002-1825-0097")
	second := ComputeAccountAddress("0000-0001-5109-3700")
	if first == second {
		t.Fatalf("two accounts share the stated address %s, so they would share one brute-force bucket", first)
	}
}

func TestDecideComputeAddress(t *testing.T) {
	cases := []struct {
		name       string
		user       string
		withAuth   bool
		wantStatus int
	}{
		{name: "no Basic auth", withAuth: false, wantStatus: http.StatusBadRequest},
		{name: "empty user name", user: "", withAuth: true, wantStatus: http.StatusBadRequest},
		{name: "not an ORCID iD", user: "alice", withAuth: true, wantStatus: http.StatusBadRequest},
		{name: "lower-case check character", user: "0000-0002-1694-233x", withAuth: true, wantStatus: http.StatusBadRequest},
		{name: "missing a group", user: "0000-0002-1825", withAuth: true, wantStatus: http.StatusBadRequest},
		{name: "canonical ORCID iD", user: "0000-0002-1825-0097", withAuth: true, wantStatus: 0},
		{name: "canonical ORCID iD with X", user: "0000-0002-1694-233X", withAuth: true, wantStatus: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("PROPFIND", "/nextcloud/remote.php/dav/files/x/", nil)
			if tc.withAuth {
				req.SetBasicAuth(tc.user, "app-password")
			}
			decision := DecideComputeAddress(req)
			if decision.Status != tc.wantStatus {
				t.Fatalf("status = %d, want %d (reason %q)", decision.Status, tc.wantStatus, decision.Reason)
			}
			if tc.wantStatus == 0 && decision.Address != ComputeAccountAddress(tc.user) {
				t.Fatalf("address = %s, want %s", decision.Address, ComputeAccountAddress(tc.user))
			}
			if tc.wantStatus != 0 && decision.Reason == "" {
				t.Fatalf("a refusal must carry a reason for the log")
			}
		})
	}
}
