package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// A slot owns both source ports for the entire interception session. Neither
// expiry nor a failed exchange may release an exempt port for another process.
type flowUpstream struct {
	mu                 sync.Mutex
	exchangeGate       chan struct{}
	udp                *net.UDPConn
	tcp                *reservedTCP
	tcpConn            net.Conn
	tcpFailed          bool
	localUDP, localTCP netip.AddrPort
	resolver           netip.AddrPort
	forceTCP, closed   bool
	timeout            time.Duration
}

func reserveFlowUpstream(local netip.Addr, timeout time.Duration) (*flowUpstream, error) {
	if !local.IsValid() || local.IsUnspecified() || local.IsMulticast() || local.Is4In6() || timeout <= 0 || timeout > 5*time.Second {
		return nil, errors.New("invalid upstream reservation")
	}
	tcp, err := reserveTCP(local)
	if err != nil {
		return nil, err
	}
	network := "udp4"
	if local.Is6() {
		network = "udp6"
	}
	listener := net.ListenConfig{Control: exclusiveSocketControl}
	packet, err := listener.ListenPacket(context.Background(), network, netip.AddrPortFrom(local, 0).String())
	if err != nil {
		_ = tcp.Close()
		return nil, err
	}
	udp, ok := packet.(*net.UDPConn)
	if !ok {
		_ = packet.Close()
		_ = tcp.Close()
		return nil, errors.New("unexpected UDP socket type")
	}
	return &flowUpstream{udp: udp, tcp: tcp, localUDP: udp.LocalAddr().(*net.UDPAddr).AddrPort(), localTCP: tcp.LocalAddr(), timeout: timeout, exchangeGate: make(chan struct{}, 1)}, nil
}
func (s *flowUpstream) UDPAddr() netip.AddrPort { return s.localUDP }
func (s *flowUpstream) TCPAddr() netip.AddrPort { return s.localTCP }
func (s *flowUpstream) Assign(resolver netip.AddrPort, forceTCP bool) error {
	var err error
	resolver, err = canonicalEndpoint(resolver)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || !resolver.IsValid() || resolver.Port() == 0 || resolver == s.localUDP || resolver == s.localTCP || resolver.Addr().IsUnspecified() || resolver.Addr().IsMulticast() || resolver.Addr().Is4In6() || resolver.Addr().Is4() != s.localUDP.Addr().Is4() {
		return errors.New("invalid upstream assignment")
	}
	if s.resolver.IsValid() && (s.resolver != resolver || s.forceTCP != forceTCP) {
		return errors.New("upstream slot is already assigned")
	}
	s.resolver = resolver
	s.forceTCP = forceTCP
	return nil
}
func (s *flowUpstream) Address() string { s.mu.Lock(); defer s.mu.Unlock(); return s.resolver.String() }
func (s *flowUpstream) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	conn := s.tcpConn
	s.mu.Unlock()
	err := s.udp.Close()
	if conn != nil {
		err = errors.Join(err, conn.Close())
	}
	return errors.Join(err, s.tcp.Close())
}
func (s *flowUpstream) Exchange(request *dns.Msg) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	select {
	case s.exchangeGate <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-s.exchangeGate }()
	s.mu.Lock()
	resolver, tcp, closed := s.resolver, s.forceTCP, s.closed
	s.mu.Unlock()
	if closed || !resolver.IsValid() || request == nil || request.Response || len(request.Question) != 1 {
		return nil, errors.New("invalid upstream query")
	}
	query := request.Copy()
	query.Id = dns.Id()
	var response *dns.Msg
	var err error
	if !tcp {
		response, err = s.exchangeUDP(ctx, query, resolver)
		if err != nil {
			return nil, err
		}
		tcp = response.Truncated
	}
	if tcp {
		response, err = s.exchangeTCP(ctx, query, resolver)
	}
	if err != nil {
		return nil, err
	}
	if !matchesResponse(query, response) {
		return nil, errors.New("upstream response does not match query")
	}
	response.Id = request.Id
	return response, nil
}
func (s *flowUpstream) exchangeUDP(ctx context.Context, query *dns.Msg, resolver netip.AddrPort) (*dns.Msg, error) {
	wire, err := query.Pack()
	if err != nil {
		return nil, err
	}
	deadline, _ := ctx.Deadline()
	if err = s.udp.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if _, err = s.udp.WriteToUDPAddrPort(wire, resolver); err != nil {
		return nil, err
	}
	buffer := make([]byte, 65535)
	// Bound parsing of unrelated or malformed datagrams, as well as wall time.
	for attempts := 0; attempts < 64; attempts++ {
		n, peer, readErr := s.udp.ReadFromUDPAddrPort(buffer)
		if readErr != nil {
			return nil, readErr
		}
		peer, peerErr := canonicalEndpoint(peer)
		if peerErr != nil || peer != resolver {
			continue
		}
		response := new(dns.Msg)
		if response.Unpack(buffer[:n]) != nil || !matchesResponse(query, response) {
			continue
		}
		return response, nil
	}
	return nil, errors.New("too many unrelated upstream responses")
}
func (s *flowUpstream) exchangeTCP(ctx context.Context, query *dns.Msg, resolver netip.AddrPort) (*dns.Msg, error) {
	s.mu.Lock()
	conn, failed := s.tcpConn, s.tcpFailed
	s.mu.Unlock()
	if failed {
		return nil, errors.New("reserved TCP upstream is unavailable")
	}
	if conn == nil {
		var err error
		conn, err = s.tcp.Connect(ctx, resolver)
		s.mu.Lock()
		if err != nil {
			s.tcpFailed = true
			s.mu.Unlock()
			return nil, err
		}
		if s.closed {
			s.mu.Unlock()
			_ = conn.Close()
			return nil, net.ErrClosed
		}
		s.tcpConn = conn
		s.mu.Unlock()
	}
	response, _, err := (&dns.Client{Net: "tcp", Timeout: s.timeout}).ExchangeWithConnContext(ctx, query, &dns.Conn{Conn: conn})
	if err != nil || !matchesResponse(query, response) {
		s.mu.Lock()
		s.tcpFailed = true
		s.mu.Unlock()
		// Keep the failed connection's bound socket owned until interception stops.
		if err == nil {
			err = fmt.Errorf("TCP upstream response does not match query")
		}
	}
	return response, err
}
func matchesResponse(query, response *dns.Msg) bool {
	if response == nil || !response.Response || response.Id != query.Id || response.Opcode != query.Opcode || len(response.Question) != len(query.Question) {
		return false
	}
	for i, q := range query.Question {
		r := response.Question[i]
		if q.Qtype != r.Qtype || q.Qclass != r.Qclass || !strings.EqualFold(q.Name, r.Name) {
			return false
		}
	}
	return true
}
