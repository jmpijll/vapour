package main

import (
	"errors"
	"net/netip"
	"reflect"
	"sync"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
)

const maxAuthorizedFlowLifetime = 2 * time.Minute

var (
	errAuthorizedFlowInvalidKey      = errors.New("invalid authorized flow key")
	errAuthorizedFlowInvalidRoute    = errors.New("authorized flow route is nil")
	errAuthorizedFlowInvalidLifetime = errors.New("invalid authorized flow lifetime")
	errAuthorizedFlowCapacity        = errors.New("authorized flow capacity exhausted")
	errAuthorizedFlowDuplicate       = errors.New("authorized flow already registered")
	errAuthorizedFlowQuarantined     = errors.New("authorized flow is released or expired")
)

// flowKey is the exact packet tuple used to authorize a reflected DNS flow.
// The address values are intentionally retained without normalization: an
// IPv6 zone is part of netip.Addr's identity and therefore part of this key.
type flowKey struct {
	Protocol string
	Peer     netip.AddrPort
	Local    netip.AddrPort
}

type authorizedFlow struct {
	route     upstream.Upstream
	expiresAt time.Time
}

// authorizedFlows is a bounded, session-scoped flow table.  Every successful
// registration consumes one lifetime slot.  Released and expired keys remain
// quarantined until the table is dropped, so a delayed packet can never be
// accepted by a later registration that happens to use the same tuple.
type authorizedFlows struct {
	mu sync.Mutex

	capacity  int
	allocated int
	active    map[flowKey]authorizedFlow
	// quarantined includes both explicitly released keys and expired keys.
	quarantined map[flowKey]struct{}
}

func newAuthorizedFlows(capacity int) *authorizedFlows {
	if capacity < 0 {
		capacity = 0
	}

	return &authorizedFlows{
		capacity:    capacity,
		active:      make(map[flowKey]authorizedFlow),
		quarantined: make(map[flowKey]struct{}),
	}
}

// Register adds an exact flow key and its caller-owned upstream route.
// Registrations never replace an active row or reclaim a released/expired
// row.  A lifetime is fixed at registration time and is not extended by
// lookups or retries.
func (f *authorizedFlows) Register(
	key flowKey,
	route upstream.Upstream,
	lifetime time.Duration,
	now time.Time,
) error {
	return f.registerPrepared(key, route, lifetime, now, nil)
}

// prepare runs only after admission checks pass, under the registration lock.
// It must not call back into this table. A rejected key never consumes a slot.
func (f *authorizedFlows) registerPrepared(key flowKey, route upstream.Upstream, lifetime time.Duration, now time.Time, prepare func() error) error {
	if f == nil {
		return errAuthorizedFlowCapacity
	}
	if err := validateAuthorizedFlowKey(key); err != nil {
		return err
	}
	if isNilUpstream(route) {
		return errAuthorizedFlowInvalidRoute
	}
	if lifetime <= 0 || lifetime > maxAuthorizedFlowLifetime {
		return errAuthorizedFlowInvalidLifetime
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if active, ok := f.active[key]; ok {
		if !now.Before(active.expiresAt) {
			f.quarantineLocked(key)
			return errAuthorizedFlowQuarantined
		}
		return errAuthorizedFlowDuplicate
	}
	if _, ok := f.quarantined[key]; ok {
		return errAuthorizedFlowQuarantined
	}
	if f.allocated >= f.capacity {
		return errAuthorizedFlowCapacity
	}
	if prepare != nil {
		if err := prepare(); err != nil {
			return err
		}
	}

	f.active[key] = authorizedFlow{
		route:     route,
		expiresAt: now.Add(lifetime),
	}
	f.allocated++
	return nil
}

// Lookup returns the caller-owned route for an exact live key.  Expired rows
// are moved to permanent quarantine before returning false.
func (f *authorizedFlows) Lookup(key flowKey, now time.Time) (upstream.Upstream, bool) {
	if f == nil {
		return nil, false
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	active, ok := f.active[key]
	if !ok {
		return nil, false
	}
	if !now.Before(active.expiresAt) {
		f.quarantineLocked(key)
		return nil, false
	}
	return active.route, true
}

// Release removes an active row and permanently quarantines its exact key.
// It never closes the supplied upstream; the controller owns route lifetime.
func (f *authorizedFlows) Release(key flowKey) bool {
	if f == nil {
		return false
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if _, ok := f.active[key]; !ok {
		return false
	}
	f.quarantineLocked(key)
	return true
}

func (f *authorizedFlows) quarantineLocked(key flowKey) {
	delete(f.active, key)
	f.quarantined[key] = struct{}{}
}

func validateAuthorizedFlowKey(key flowKey) error {
	if key.Protocol != "udp" && key.Protocol != "tcp" {
		return errAuthorizedFlowInvalidKey
	}
	if !validAuthorizedEndpoint(key.Peer) || !validAuthorizedEndpoint(key.Local) {
		return errAuthorizedFlowInvalidKey
	}
	if key.Peer.Addr().Is4() != key.Local.Addr().Is4() {
		return errAuthorizedFlowInvalidKey
	}
	return nil
}

func validAuthorizedEndpoint(endpoint netip.AddrPort) bool {
	if !endpoint.IsValid() || endpoint.Port() == 0 {
		return false
	}

	address := endpoint.Addr()
	if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() {
		return false
	}

	// IsGlobalUnicast excludes loopback and link-local addresses.  Both are
	// valid for the local proxy and test flows, so include those explicitly.
	return address.IsGlobalUnicast() || address.IsLoopback() || address.IsLinkLocalUnicast()
}

// Upstream is an interface, so a typed nil pointer can otherwise pass a
// direct route == nil check.  Treat all nil-able dynamic values as nil while
// leaving ordinary value implementations valid.
func isNilUpstream(route upstream.Upstream) bool {
	if route == nil {
		return true
	}

	value := reflect.ValueOf(route)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
