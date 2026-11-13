// apps/id1/connector_set.go
//
// group: nextcloud
// tags: nextcloud, proxy, client-address, dns
// summary: The set of Cloudflare tunnel connector pod addresses, read from a headless Service.
//
//

package id1

import (
	"context"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"
)

// CloudflaredConnectorsName is the DNS name of the headless Service selecting every
// cloudflared pod (publishNotReadyAddresses: true), so its A records are the tunnel
// connector pod addresses Traefik reports in X-Real-Ip for public traffic.
const CloudflaredConnectorsName = "cloudflared-connectors.kube-system.svc.cluster.local"

// ConnectorSetTTL is how long a successful lookup is used before the next one.
const ConnectorSetTTL = 5 * time.Second

// connectorRefreshMinInterval bounds lookups on a miss: an address not in the cached
// set triggers a fresh lookup (a connector pod may have just restarted with a new
// address) only when the last lookup is at least this old.
const connectorRefreshMinInterval = 1 * time.Second

// connectorLookupTimeout bounds one DNS lookup.
const connectorLookupTimeout = 2 * time.Second

// ConnectorSet answers whether an address is one of the tunnel connector pods. A
// failed lookup is an empty set and is not cached, so the next request looks up again.
type ConnectorSet struct {
	name    string
	ttl     time.Duration
	lookup  func(ctx context.Context, name string) ([]netip.Addr, error)
	now     func() time.Time
	mu      sync.Mutex
	cached  map[netip.Addr]struct{}
	fetched time.Time
}

// NewConnectorSet returns a ConnectorSet reading name through the system resolver.
func NewConnectorSet(name string) *ConnectorSet {
	return newConnectorSetWith(name, ConnectorSetTTL, func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}, time.Now)
}

func newConnectorSetWith(name string, ttl time.Duration, lookup func(ctx context.Context, name string) ([]netip.Addr, error), now func() time.Time) *ConnectorSet {
	return &ConnectorSet{name: name, ttl: ttl, lookup: lookup, now: now}
}

// Contains reports whether addr is a tunnel connector address.
func (s *ConnectorSet) Contains(ctx context.Context, addr netip.Addr) bool {
	addr = addr.Unmap()
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if s.cached != nil && now.Sub(s.fetched) < s.ttl {
		if _, ok := s.cached[addr]; ok {
			return true
		}
		if now.Sub(s.fetched) < connectorRefreshMinInterval {
			return false
		}
	}
	lookupCtx, cancel := context.WithTimeout(ctx, connectorLookupTimeout)
	addrs, err := s.lookup(lookupCtx, s.name)
	cancel()
	if err != nil {
		log.Printf("[nextcloud-proxy] connector lookup of %s failed, treating the connector set as empty: %v", s.name, err)
		s.cached = nil
		return false
	}
	set := make(map[netip.Addr]struct{}, len(addrs))
	for _, a := range addrs {
		set[a.Unmap()] = struct{}{}
	}
	s.cached = set
	s.fetched = now
	_, ok := s.cached[addr]
	return ok
}
