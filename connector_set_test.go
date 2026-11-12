// apps/id1/connector_set_test.go
//
// group: nextcloud
// tags: nextcloud, proxy, client-address, dns, testing
// summary: Tests for ConnectorSet - DNS-backed membership with a short cache.
//
//

package id1

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

type connectorLookupStub struct {
	calls int
	addrs []netip.Addr
	err   error
}

func (s *connectorLookupStub) lookup(ctx context.Context, name string) ([]netip.Addr, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return s.addrs, nil
}

type connectorClock struct {
	now time.Time
}

func (c *connectorClock) read() time.Time {
	return c.now
}

func newConnectorTestSet(stub *connectorLookupStub, clock *connectorClock) *ConnectorSet {
	return newConnectorSetWith("cloudflared-connectors.test", 5*time.Second, stub.lookup, clock.read)
}

func TestConnectorSetContainsListedAddress(t *testing.T) {
	stub := &connectorLookupStub{addrs: []netip.Addr{netip.MustParseAddr("10.42.1.10"), netip.MustParseAddr("10.42.2.20")}}
	clock := &connectorClock{now: time.Unix(1000, 0)}
	set := newConnectorTestSet(stub, clock)
	if !set.Contains(context.Background(), netip.MustParseAddr("10.42.2.20")) {
		t.Fatal("listed connector address 10.42.2.20 was not in the set")
	}
	if set.Contains(context.Background(), netip.MustParseAddr("10.42.9.9")) {
		t.Fatal("unlisted address 10.42.9.9 was in the set")
	}
}

func TestConnectorSetMatchesIPv4MappedAddress(t *testing.T) {
	stub := &connectorLookupStub{addrs: []netip.Addr{netip.MustParseAddr("10.42.1.10")}}
	clock := &connectorClock{now: time.Unix(1000, 0)}
	set := newConnectorTestSet(stub, clock)
	if !set.Contains(context.Background(), netip.MustParseAddr("::ffff:10.42.1.10")) {
		t.Fatal("IPv4-mapped form of a listed connector address was not in the set")
	}
}

func TestConnectorSetCachesWithinTTL(t *testing.T) {
	stub := &connectorLookupStub{addrs: []netip.Addr{netip.MustParseAddr("10.42.1.10")}}
	clock := &connectorClock{now: time.Unix(1000, 0)}
	set := newConnectorTestSet(stub, clock)
	set.Contains(context.Background(), netip.MustParseAddr("10.42.1.10"))
	clock.now = clock.now.Add(3 * time.Second)
	set.Contains(context.Background(), netip.MustParseAddr("10.42.1.10"))
	if stub.calls != 1 {
		t.Fatalf("lookup calls = %d, want 1 (second hit inside the TTL must use the cache)", stub.calls)
	}
}

func TestConnectorSetLooksUpAgainAfterTTL(t *testing.T) {
	stub := &connectorLookupStub{addrs: []netip.Addr{netip.MustParseAddr("10.42.1.10")}}
	clock := &connectorClock{now: time.Unix(1000, 0)}
	set := newConnectorTestSet(stub, clock)
	set.Contains(context.Background(), netip.MustParseAddr("10.42.1.10"))
	clock.now = clock.now.Add(6 * time.Second)
	set.Contains(context.Background(), netip.MustParseAddr("10.42.1.10"))
	if stub.calls != 2 {
		t.Fatalf("lookup calls = %d, want 2 (the cache expires after the TTL)", stub.calls)
	}
}

func TestConnectorSetRefreshesOnMissAtMostOncePerSecond(t *testing.T) {
	stub := &connectorLookupStub{addrs: []netip.Addr{netip.MustParseAddr("10.42.1.10")}}
	clock := &connectorClock{now: time.Unix(1000, 0)}
	set := newConnectorTestSet(stub, clock)
	set.Contains(context.Background(), netip.MustParseAddr("10.42.1.10"))
	clock.now = clock.now.Add(500 * time.Millisecond)
	if set.Contains(context.Background(), netip.MustParseAddr("10.42.3.30")) {
		t.Fatal("unlisted address was in the set")
	}
	if stub.calls != 1 {
		t.Fatalf("lookup calls = %d, want 1 (a miss within one second of the last lookup must not look up again)", stub.calls)
	}
	stub.addrs = append(stub.addrs, netip.MustParseAddr("10.42.3.30"))
	clock.now = clock.now.Add(1 * time.Second)
	if !set.Contains(context.Background(), netip.MustParseAddr("10.42.3.30")) {
		t.Fatal("a connector added since the last lookup was not found by the refresh on miss")
	}
	if stub.calls != 2 {
		t.Fatalf("lookup calls = %d, want 2 (a miss more than one second after the last lookup looks up again)", stub.calls)
	}
}

func TestConnectorSetLookupFailureIsEmptyAndNotCached(t *testing.T) {
	stub := &connectorLookupStub{err: errors.New("no such host")}
	clock := &connectorClock{now: time.Unix(1000, 0)}
	set := newConnectorTestSet(stub, clock)
	if set.Contains(context.Background(), netip.MustParseAddr("10.42.1.10")) {
		t.Fatal("a failed lookup must give an empty set")
	}
	stub.err = nil
	stub.addrs = []netip.Addr{netip.MustParseAddr("10.42.1.10")}
	if !set.Contains(context.Background(), netip.MustParseAddr("10.42.1.10")) {
		t.Fatal("a failed lookup was cached: the next call must look up again")
	}
	if stub.calls != 2 {
		t.Fatalf("lookup calls = %d, want 2", stub.calls)
	}
}
