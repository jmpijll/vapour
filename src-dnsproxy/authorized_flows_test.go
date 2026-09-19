package main

import (
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type authorizedFlowTestUpstream struct {
	address string
	closed  atomic.Bool
}

func (u *authorizedFlowTestUpstream) Exchange(*dns.Msg) (*dns.Msg, error) { return nil, nil }
func (u *authorizedFlowTestUpstream) Address() string                     { return u.address }
func (u *authorizedFlowTestUpstream) Close() error {
	u.closed.Store(true)
	return nil
}

func TestAuthorizedFlowsLifetimeCapacityAndNoRouteClose(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	flows := newAuthorizedFlows(2)
	route := &authorizedFlowTestUpstream{address: "route-1"}
	key := authorizedTestFlowKey("udp", 53000, 53)

	if err := flows.Register(key, route, time.Minute, now); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if got, ok := flows.Lookup(key, now.Add(59*time.Second)); !ok || got != route {
		t.Fatalf("Lookup before expiry = (%v, %v), want route and true", got, ok)
	}
	if got, ok := flows.Lookup(key, now.Add(time.Minute)); ok || got != nil {
		t.Fatalf("Lookup at expiry = (%v, %v), want nil and false", got, ok)
	}
	if route.closed.Load() {
		t.Fatal("expiry closed the supplied upstream")
	}
	if err := flows.Register(key, route, time.Minute, now.Add(time.Minute)); !errors.Is(err, errAuthorizedFlowQuarantined) {
		t.Fatalf("Register expired key error = %v, want quarantine", err)
	}

	secondKey := authorizedTestFlowKey("tcp", 53001, 853)
	secondRoute := &authorizedFlowTestUpstream{address: "route-2"}
	if err := flows.Register(secondKey, secondRoute, 2*time.Minute, now); err != nil {
		t.Fatalf("Register second key: %v", err)
	}
	if !flows.Release(secondKey) {
		t.Fatal("Release returned false for active key")
	}
	if secondRoute.closed.Load() {
		t.Fatal("Release closed the supplied upstream")
	}
	if flows.Release(secondKey) {
		t.Fatal("Release returned true for an already released key")
	}
	if err := flows.Register(secondKey, secondRoute, time.Minute, now); !errors.Is(err, errAuthorizedFlowQuarantined) {
		t.Fatalf("Register released key error = %v, want quarantine", err)
	}

	thirdKey := authorizedTestFlowKey("udp", 53002, 54)
	if err := flows.Register(thirdKey, &authorizedFlowTestUpstream{address: "route-3"}, time.Minute, now); !errors.Is(err, errAuthorizedFlowCapacity) {
		t.Fatalf("Register at lifetime capacity error = %v, want capacity", err)
	}
}

func TestAuthorizedFlowsRequireExactProtocolEndpointsAndZones(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	flows := newAuthorizedFlows(8)
	route := &authorizedFlowTestUpstream{address: "route"}
	key := flowKey{
		Protocol: "udp",
		Peer:     netip.AddrPortFrom(netip.MustParseAddr("fe80::53").WithZone("resolver0"), 53),
		Local:    netip.AddrPortFrom(netip.MustParseAddr("fe80::1").WithZone("resolver0"), 53000),
	}
	if err := flows.Register(key, route, time.Minute, now); err != nil {
		t.Fatalf("Register: %v", err)
	}
	for name, changed := range map[string]flowKey{
		"protocol":      {Protocol: "tcp", Peer: key.Peer, Local: key.Local},
		"peer address":  {Protocol: key.Protocol, Peer: netip.AddrPortFrom(netip.MustParseAddr("fe80::54").WithZone("resolver0"), 53), Local: key.Local},
		"peer port":     {Protocol: key.Protocol, Peer: netip.AddrPortFrom(key.Peer.Addr(), 54), Local: key.Local},
		"local address": {Protocol: key.Protocol, Peer: key.Peer, Local: netip.AddrPortFrom(netip.MustParseAddr("fe80::2").WithZone("resolver0"), 53000)},
		"local port":    {Protocol: key.Protocol, Peer: key.Peer, Local: netip.AddrPortFrom(key.Local.Addr(), 53001)},
		"IPv6 zone":     {Protocol: key.Protocol, Peer: netip.AddrPortFrom(key.Peer.Addr().WithZone("resolver1"), 53), Local: key.Local},
	} {
		if route, ok := flows.Lookup(changed, now); ok || route != nil {
			t.Errorf("Lookup changed %s = (%v, %v), want nil and false", name, route, ok)
		}
	}
	if got, ok := flows.Lookup(key, now); !ok || got != route {
		t.Fatalf("Lookup exact key = (%v, %v), want route and true", got, ok)
	}
}

func TestAuthorizedFlowsRejectInvalidKeysLifetimesAndRoutes(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	route := &authorizedFlowTestUpstream{address: "route"}
	valid := authorizedTestFlowKey("udp", 53000, 53)

	tests := []struct {
		name     string
		key      flowKey
		lifetime time.Duration
	}{
		{name: "uppercase protocol", key: flowKey{Protocol: "UDP", Peer: valid.Peer, Local: valid.Local}, lifetime: time.Minute},
		{name: "mixed protocol", key: flowKey{Protocol: "Udp", Peer: valid.Peer, Local: valid.Local}, lifetime: time.Minute},
		{name: "empty protocol", key: flowKey{Peer: valid.Peer, Local: valid.Local}, lifetime: time.Minute},
		{name: "zero peer port", key: flowKey{Protocol: "udp", Peer: netip.AddrPortFrom(valid.Peer.Addr(), 0), Local: valid.Local}, lifetime: time.Minute},
		{name: "zero local port", key: flowKey{Protocol: "udp", Peer: valid.Peer, Local: netip.AddrPortFrom(valid.Local.Addr(), 0)}, lifetime: time.Minute},
		{name: "unspecified peer", key: flowKey{Protocol: "udp", Peer: netip.MustParseAddrPort("0.0.0.0:53"), Local: valid.Local}, lifetime: time.Minute},
		{name: "multicast peer", key: flowKey{Protocol: "udp", Peer: netip.MustParseAddrPort("224.0.0.1:53"), Local: valid.Local}, lifetime: time.Minute},
		{name: "invalid peer", key: flowKey{Protocol: "udp", Local: valid.Local}, lifetime: time.Minute},
		{name: "family mismatch", key: flowKey{Protocol: "udp", Peer: netip.MustParseAddrPort("[::1]:53"), Local: valid.Local}, lifetime: time.Minute},
		{name: "zero lifetime", key: valid, lifetime: 0},
		{name: "negative lifetime", key: valid, lifetime: -time.Nanosecond},
		{name: "lifetime over two minutes", key: valid, lifetime: 2*time.Minute + time.Nanosecond},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			flows := newAuthorizedFlows(2)
			if err := flows.Register(test.key, route, test.lifetime, now); err == nil {
				t.Fatal("Register accepted invalid input")
			}
		})
	}

	flows := newAuthorizedFlows(1)
	var typedNil *authorizedFlowTestUpstream
	if err := flows.Register(valid, typedNil, time.Minute, now); !errors.Is(err, errAuthorizedFlowInvalidRoute) {
		t.Fatalf("Register typed nil route error = %v, want invalid route", err)
	}
	if err := flows.Register(valid, nil, time.Minute, now); !errors.Is(err, errAuthorizedFlowInvalidRoute) {
		t.Fatalf("Register nil route error = %v, want invalid route", err)
	}
}

func TestAuthorizedFlowsConcurrentLookupAndRegister(t *testing.T) {
	const writers = 32
	now := time.Unix(1_700_000_000, 0)
	flows := newAuthorizedFlows(writers + 1)
	seedKey := authorizedTestFlowKey("udp", 53000, 53)
	seedRoute := &authorizedFlowTestUpstream{address: "seed"}
	if err := flows.Register(seedKey, seedRoute, time.Minute, now); err != nil {
		t.Fatalf("Register seed: %v", err)
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		i := i
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			key := authorizedTestFlowKey("tcp", uint16(54000+i), uint16(860+i))
			route := &authorizedFlowTestUpstream{address: key.Protocol}
			if err := flows.Register(key, route, time.Minute, now); err != nil {
				t.Errorf("Register writer %d: %v", i, err)
			}
		}()
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 100; j++ {
				if got, ok := flows.Lookup(seedKey, now); !ok || got != seedRoute {
					t.Errorf("Lookup seed = (%v, %v), want seed and true", got, ok)
					return
				}
			}
		}()
	}
	close(start)
	wg.Wait()
}

func authorizedTestFlowKey(protocol string, localPort, peerPort uint16) flowKey {
	return flowKey{
		Protocol: protocol,
		Peer:     netip.AddrPortFrom(netip.MustParseAddr("192.0.2.53"), peerPort),
		Local:    netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), localPort),
	}
}
