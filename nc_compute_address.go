// apps/id1/nc_compute_address.go
//
// group: nextcloud
// tags: nextcloud, proxy, client-address, compute
// summary: the stated address for a request on id1's compute port, one per account.
//
//

package id1

import (
	"encoding/binary"
	"hash/fnv"
	"net"
	"net/http"
	"net/netip"
	"strconv"
)

// ComputeProxyPort is the port id1's compute listener binds. Traefik's compute
// entrypoint routes compute-<domain> WebDAV requests to it. A request that arrives
// on it is attributed to its account, not to its caller's address: every job on a
// site partition reaches Nextcloud through one relay, so the caller address would
// put every account in one brute-force bucket.
const ComputeProxyPort = "8081"

// ComputeAddressBlock is the reserved loopback block a compute-port request's
// stated address is drawn from. It excludes 127.0.0.1, the address stated for a
// caller on the server, and lies outside the pod range, so a compute account never
// shares a bucket with either.
var ComputeAddressBlock = netip.MustParsePrefix("127.128.0.0/9")

// computeAddressHostBits is the number of host bits in ComputeAddressBlock.
const computeAddressHostBits = 23

// ComputeAccountAddress returns the address in ComputeAddressBlock that stands for
// account: the FNV-1a 32-bit hash of the account name, reduced to the block's 23
// host bits and added to the block's base address. The same account always maps to
// the same address.
func ComputeAccountAddress(account string) netip.Addr {
	h := fnv.New32a()
	_, _ = h.Write([]byte(account))
	base := ComputeAddressBlock.Addr().As4()
	value := binary.BigEndian.Uint32(base[:]) + (h.Sum32() & (1<<computeAddressHostBits - 1))
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], value)
	return netip.AddrFrom4(out)
}

// DecideComputeAddress decides the stated address for a request that arrived on
// ComputeProxyPort. The Basic-auth user name must be a canonical ORCID iD
// (orcidPattern); a missing or other user name is refused with 400 before Nextcloud
// sees the request. The reason never carries the user name.
func DecideComputeAddress(r *http.Request) ClientAddressDecision {
	user, _, ok := r.BasicAuth()
	if !ok || user == "" {
		return ClientAddressDecision{Status: http.StatusBadRequest, Reason: "compute port: no Basic-auth user name"}
	}
	if !orcidPattern.MatchString(user) {
		return ClientAddressDecision{Status: http.StatusBadRequest, Reason: "compute port: the Basic-auth user name is not a canonical ORCID iD"}
	}
	return ClientAddressDecision{Address: ComputeAccountAddress(user)}
}

// arrivedOnComputePort reports whether net/http accepted r on ComputeProxyPort.
func arrivedOnComputePort(r *http.Request) bool {
	addr, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok {
		return false
	}
	tcp, ok := addr.(*net.TCPAddr)
	if !ok {
		return false
	}
	return strconv.Itoa(tcp.Port) == ComputeProxyPort
}
