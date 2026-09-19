package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
)

type flowRegistration struct {
	Protocol   string `json:"protocol"`
	Peer       string `json:"peer"`
	Local      string `json:"local"`
	Resolver   string `json:"resolver,omitempty"`
	Slot       int    `json:"slot"`
	LifetimeMS int    `json:"lifetime_ms,omitempty"`
}
type upstreamSlotStatus struct {
	ID      int    `json:"id"`
	UDPAddr string `json:"udp_addr"`
	TCPAddr string `json:"tcp_addr"`
}

func validateTransparentReady(cfg config, udp, tcp []string, slots []upstreamSlotStatus) error {
	expected := make(map[netip.Addr]bool)
	for _, text := range cfg.ListenAddresses {
		ip, err := netip.ParseAddr(text)
		if err != nil {
			return err
		}
		expected[ip] = true
	}
	owned := map[string]map[netip.AddrPort]bool{"udp": {}, "tcp": {}}
	for protocol, addresses := range map[string][]string{"udp": udp, "tcp": tcp} {
		seen := make(map[netip.Addr]bool)
		for _, text := range addresses {
			endpoint, err := netip.ParseAddrPort(text)
			if err == nil {
				endpoint, err = canonicalEndpoint(endpoint)
			}
			if err != nil || endpoint.Port() == 0 || endpoint.Port() == 53 || !expected[endpoint.Addr()] || seen[endpoint.Addr()] || (cfg.ListenPort != 0 && endpoint.Port() != uint16(cfg.ListenPort)) {
				return errors.New("transparent listener readiness mismatch")
			}
			seen[endpoint.Addr()] = true
			owned[protocol][endpoint] = true
		}
		if len(seen) != len(expected) {
			return errors.New("transparent listener missing requested address")
		}
	}
	counts := make(map[netip.Addr]int)
	for index, slot := range slots {
		u, err := netip.ParseAddrPort(slot.UDPAddr)
		if err == nil {
			u, err = canonicalEndpoint(u)
		}
		if err != nil {
			return err
		}
		t, err := netip.ParseAddrPort(slot.TCPAddr)
		if err == nil {
			t, err = canonicalEndpoint(t)
		}
		if err != nil {
			return err
		}
		if slot.ID != index || u.Addr() != t.Addr() || !expected[u.Addr()] || u.Port() == 0 || t.Port() == 0 || u.Port() == 53 || t.Port() == 53 || owned["udp"][u] || owned["tcp"][t] {
			return errors.New("transparent upstream slot readiness mismatch")
		}
		owned["udp"][u] = true
		owned["tcp"][t] = true
		counts[u.Addr()]++
	}
	for ip := range expected {
		if counts[ip] != 8 {
			return errors.New("transparent upstream slot count mismatch")
		}
	}
	return nil
}

func validateTransparentConfig(cfg config) (config, error) {
	if cfg.Upstream != "" || cfg.ListenAddress != "" || cfg.DualStack {
		return config{}, errors.New("transparent mode requires explicit listen_addresses only")
	}
	if len(cfg.ListenAddresses) == 0 || len(cfg.ListenAddresses) > 16 {
		return config{}, errors.New("transparent mode requires 1..16 local addresses")
	}
	if cfg.ListenPort < 0 || cfg.ListenPort > 65535 || cfg.ListenPort == 53 {
		return config{}, errors.New("transparent listen_port must be 0..65535 excluding 53")
	}
	seen := make(map[netip.Addr]bool)
	for i, text := range cfg.ListenAddresses {
		ip, err := netip.ParseAddr(text)
		if err == nil {
			ip, err = canonicalZone(ip)
		}
		if err != nil || ip.IsUnspecified() || ip.IsMulticast() || ip.Is4In6() || seen[ip] {
			return config{}, errors.New("invalid or duplicate transparent listener address")
		}
		if ip.IsLinkLocalUnicast() && ip.Is6() && ip.Zone() == "" {
			return config{}, errors.New("link-local listener requires an interface zone")
		}
		cfg.ListenAddresses[i] = ip.String()
		seen[ip] = true
	}
	if len(cfg.Rules) > maxRuleTextBytes {
		return config{}, errors.New("rules exceed input limit")
	}
	if err := validateRules(cfg.Rules); err != nil {
		return config{}, err
	}
	return cfg, nil
}
func (r flowRegistration) key() (flowKey, error) {
	peer, err := netip.ParseAddrPort(r.Peer)
	if err != nil {
		return flowKey{}, err
	}
	local, err := netip.ParseAddrPort(r.Local)
	if err != nil {
		return flowKey{}, err
	}
	peer, err = canonicalEndpoint(peer)
	if err != nil {
		return flowKey{}, err
	}
	local, err = canonicalEndpoint(local)
	if err != nil {
		return flowKey{}, err
	}
	return flowKey{Protocol: r.Protocol, Peer: peer, Local: local}, nil
}
func (s *dnsService) registerFlow(r flowRegistration) error {
	if s.flows == nil {
		return errors.New("service is not in transparent mode")
	}
	key, err := r.key()
	if err != nil {
		return err
	}
	if err = validateAuthorizedFlowKey(key); err != nil {
		return err
	}
	if key.Peer.Port() == key.Local.Port() {
		return errors.New("flow client port overlaps proxy listener")
	}
	if r.Protocol != "udp" && r.Protocol != "tcp" {
		return errors.New("unsupported flow protocol")
	}
	if r.Slot < 0 || r.Slot >= len(s.slots) || r.LifetimeMS <= 0 || r.LifetimeMS > 120000 {
		return errors.New("invalid flow slot or lifetime")
	}
	resolver, err := netip.ParseAddrPort(r.Resolver)
	if err == nil {
		resolver, err = canonicalEndpoint(resolver)
	}
	if err != nil || resolver.Port() != 53 || resolver.Addr() != key.Peer.Addr() {
		return errors.New("flow resolver must match the reflected peer at port 53")
	}
	listeners := s.udpAddrs()
	if r.Protocol == "tcp" {
		listeners = s.tcpAddrs()
	}
	known := false
	for _, listener := range listeners {
		if listener == key.Local.String() {
			known = true
			break
		}
	}
	if !known || s.slots[r.Slot].UDPAddr().Addr() != key.Local.Addr() {
		return errors.New("flow does not belong to the selected listener and upstream slot")
	}
	// Reserved source ports must never also identify an intercepted client flow.
	// The driver controller applies the same check before reflecting a packet.
	for _, slot := range s.slots {
		owned := slot.UDPAddr()
		if r.Protocol == "tcp" {
			owned = slot.TCPAddr()
		}
		if key.Peer.Port() == owned.Port() && key.Local.Addr() == owned.Addr() {
			return errors.New("flow overlaps an owned upstream source port")
		}
	}
	return s.flows.registerPrepared(key, s.slots[r.Slot], time.Duration(r.LifetimeMS)*time.Millisecond, time.Now(), func() error { return s.slots[r.Slot].Assign(resolver, r.Protocol == "tcp") })
}

// Winsock may report a named IPv6 zone while the parent supplies its numeric
// interface index. Canonicalize both before exact flow/response comparison.
func canonicalZone(ip netip.Addr) (netip.Addr, error) {
	if ip.Zone() == "" {
		return ip, nil
	}
	if !ip.Is6() || !ip.IsLinkLocalUnicast() {
		return netip.Addr{}, errors.New("zone requires a link-local IPv6 address")
	}
	if index, err := strconv.ParseUint(ip.Zone(), 10, 32); err == nil && index > 0 {
		return ip.WithZone(strconv.FormatUint(index, 10)), nil
	}
	iface, err := net.InterfaceByName(ip.Zone())
	if err != nil {
		return netip.Addr{}, err
	}
	return ip.WithZone(strconv.Itoa(iface.Index)), nil
}
func canonicalEndpoint(endpoint netip.AddrPort) (netip.AddrPort, error) {
	ip, err := canonicalZone(endpoint.Addr())
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(ip, endpoint.Port()), nil
}
func (s *dnsService) releaseFlow(r flowRegistration) error {
	if s.flows == nil {
		return errors.New("service is not in transparent mode")
	}
	key, err := r.key()
	if err != nil {
		return err
	}
	if !s.flows.Release(key) {
		return errors.New("flow is not registered")
	}
	return nil
}
func (s *dnsService) slotStatus() []upstreamSlotStatus {
	result := make([]upstreamSlotStatus, 0, len(s.slots))
	for id, slot := range s.slots {
		result = append(result, upstreamSlotStatus{ID: id, UDPAddr: slot.UDPAddr().String(), TCPAddr: slot.TCPAddr().String()})
	}
	return result
}
func (s *dnsService) closeSlots() error {
	var result error
	for _, slot := range s.slots {
		result = errors.Join(result, slot.Close())
	}
	return result
}

// dnsproxy requires a default upstream even when every admitted request has a
// custom upstream. This sentinel cannot consult the network or system DNS.
type rejectingUpstream struct{}

func (rejectingUpstream) Address() string { return "unregistered" }
func (rejectingUpstream) Close() error    { return nil }
func (rejectingUpstream) Exchange(*dns.Msg) (*dns.Msg, error) {
	return nil, fmt.Errorf("no authorized upstream")
}

// A request borrows a slot. Only session shutdown may release its exempt port.
type borrowedUpstream struct{ upstream.Upstream }

func (borrowedUpstream) Close() error { return nil }
