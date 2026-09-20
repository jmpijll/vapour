package main

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	dnsproxy "github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
)

func TestTransparentListenersAuthorizeRawUDPBeforeDNSValidation(t *testing.T) {
	service := newTransparentListenerTestService(t)
	listeners := newStartedTransparentListeners(t, service)
	defer listeners.Shutdown(context.Background())

	serverAddr := listeners.UDPAddrs()[0]
	remote, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	anyRequest := (&dns.Msg{}).SetQuestion("unknown.example.", dns.TypeANY)
	if err := assertTransparentUDPNoResponse(t, conn, anyRequest); err != nil {
		t.Fatal(err)
	}
	if err := assertTransparentUDPNoResponse(t, conn, &dns.Msg{}); err != nil {
		t.Fatal(err)
	}

	registerTransparentTestFlow(t, service.flows, "udp", conn.LocalAddr(), remote)
	blocked := (&dns.Msg{}).SetQuestion("blocked.example.test.", dns.TypeA)
	response := transparentUDPExchange(t, conn, blocked)
	if response.Rcode != dns.RcodeNameError {
		t.Fatalf("blocked response rcode = %d, want NXDOMAIN", response.Rcode)
	}
	response = transparentUDPExchange(t, conn, (&dns.Msg{}).SetQuestion("allowed.example.test.", dns.TypeA))
	assertA(t, response, "192.0.2.1")
	large := (&dns.Msg{}).SetQuestion("blocked.example.test.", dns.TypeA).SetEdns0(4096, false)
	large.IsEdns0().Option = append(large.IsEdns0().Option, &dns.EDNS0_PADDING{Padding: make([]byte, 600)})
	if packed, err := large.Pack(); err != nil || len(packed) <= dns.MinMsgSize {
		t.Fatalf("large EDNS request length = %d, pack error = %v", len(packed), err)
	}
	response = transparentUDPExchange(t, conn, large)
	if response.Rcode != dns.RcodeNameError {
		t.Fatalf("large blocked response rcode = %d, want NXDOMAIN", response.Rcode)
	}
}

func TestTransparentListenersAuthorizeTCPAfterReadAndDropUnknownPackets(t *testing.T) {
	service := newTransparentListenerTestService(t)
	listeners := newStartedTransparentListeners(t, service)
	defer listeners.Shutdown(context.Background())

	for _, request := range []*dns.Msg{(&dns.Msg{}).SetQuestion("unknown.example.", dns.TypeANY), &dns.Msg{}} {
		conn, err := net.DialTimeout("tcp", listeners.TCPAddrs()[0], time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if err := writeTransparentTCPMessage(conn, request); err != nil {
			conn.Close()
			t.Fatal(err)
		}
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		var response [2]byte
		n, readErr := conn.Read(response[:])
		_ = conn.Close()
		if readErr == nil && n != 0 {
			t.Fatalf("unauthorized TCP request received %d response bytes", n)
		}
	}

	// The TCP authorization check runs after ReadTCP.  Registering after Dial
	// and before writing the first query must therefore admit this connection.
	conn, err := net.DialTimeout("tcp", listeners.TCPAddrs()[0], time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	serverEndpoint, err := transparentEndpoint(conn.RemoteAddr())
	if err != nil {
		t.Fatal(err)
	}
	registerTransparentTestFlow(t, service.flows, "tcp", conn.LocalAddr(), conn.RemoteAddr())
	if err := writeTransparentTCPMessage(conn, (&dns.Msg{}).SetQuestion("blocked.example.test.", dns.TypeA)); err != nil {
		t.Fatal(err)
	}
	response := readTransparentTCPMessage(t, conn)
	if response.Rcode != dns.RcodeNameError {
		t.Fatalf("blocked TCP response rcode = %d, want NXDOMAIN (listener %s)", response.Rcode, serverEndpoint)
	}
}

func TestTransparentListenersShutdownReleasesSockets(t *testing.T) {
	service := newTransparentListenerTestService(t)
	listeners := newStartedTransparentListeners(t, service)
	udpAddr, tcpAddr := listeners.UDPAddrs()[0], listeners.TCPAddrs()[0]

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := listeners.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if err := listeners.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}

	udpConn, err := net.ListenPacket("udp4", udpAddr)
	if err != nil {
		t.Fatalf("rebind UDP %s: %v", udpAddr, err)
	}
	udpConn.Close()
	tcpListener, err := net.Listen("tcp4", tcpAddr)
	if err != nil {
		t.Fatalf("rebind TCP %s: %v", tcpAddr, err)
	}
	tcpListener.Close()
}

func TestTransparentListenersBindFailureCleansEarlierSockets(t *testing.T) {
	service := newTransparentListenerTestService(t)
	udpProbe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	udpPort := udpProbe.LocalAddr().(*net.UDPAddr).Port
	if err := udpProbe.Close(); err != nil {
		t.Fatal(err)
	}
	tcpBlocker, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	tcpPort := tcpBlocker.Addr().(*net.TCPAddr).Port
	defer tcpBlocker.Close()

	listeners, err := newTransparentListeners(service,
		[]*net.UDPAddr{{IP: net.ParseIP("127.0.0.1"), Port: udpPort}},
		[]*net.TCPAddr{{IP: net.ParseIP("127.0.0.1"), Port: tcpPort}},
	)
	if err != nil && strings.Contains(err.Error(), "requires Windows") {
		t.Skip(err)
	}
	if err == nil {
		listeners.Shutdown(context.Background())
		t.Fatal("bind failure accepted")
	}

	if err := tcpBlocker.Close(); err != nil {
		t.Fatal(err)
	}
	rebound, err := net.ListenPacket("udp4", netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(udpPort)).String())
	if err != nil {
		t.Fatalf("earlier UDP bind was not cleaned up: %v", err)
	}
	rebound.Close()
}

func newTransparentListenerTestService(t *testing.T) *dnsService {
	t.Helper()
	engine, err := newDomainEngine("||blocked.example.test^")
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := dnsproxy.New(&dnsproxy.Config{
		UDPListenAddr:  []*net.UDPAddr{},
		TCPListenAddr:  []*net.TCPAddr{},
		UpstreamConfig: &dnsproxy.UpstreamConfig{Upstreams: []upstream.Upstream{rejectingUpstream{}}},
		RequestHandler: filteringHandler{engine: nil},
		CacheEnabled:   false,
		DNSSECEnabled:  false,
		RefuseAny:      true,
		MaxGoroutines:  64,
	})
	if err != nil {
		t.Fatal(err)
	}
	service := &dnsService{proxy: proxy, flows: newAuthorizedFlows(128)}
	service.engine.Store(engine)
	return service
}

func newStartedTransparentListeners(t *testing.T, service *dnsService) *transparentListeners {
	t.Helper()
	listeners, err := newTransparentListeners(service,
		[]*net.UDPAddr{{IP: net.ParseIP("127.0.0.1"), Port: 0}},
		[]*net.TCPAddr{{IP: net.ParseIP("127.0.0.1"), Port: 0}},
	)
	if err != nil && strings.Contains(err.Error(), "requires Windows") {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := listeners.Start(); err != nil {
		t.Fatal(err)
	}
	return listeners
}

func registerTransparentTestFlow(t *testing.T, flows *authorizedFlows, protocol string, peerAddr, localAddr net.Addr) {
	t.Helper()
	peer, err := transparentEndpoint(peerAddr)
	if err != nil {
		t.Fatal(err)
	}
	local, err := transparentEndpoint(localAddr)
	if err != nil {
		t.Fatal(err)
	}
	if err := flows.Register(flowKey{Protocol: protocol, Peer: peer, Local: local}, &answerRoute{address: "192.0.2.1"}, time.Minute, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func assertTransparentUDPNoResponse(t *testing.T, conn *net.UDPConn, request *dns.Msg) error {
	t.Helper()
	packet, err := request.Pack()
	if err != nil {
		return err
	}
	if _, err = conn.Write(packet); err != nil {
		return err
	}
	conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	var response [dns.MaxMsgSize]byte
	if _, _, err = conn.ReadFromUDP(response[:]); err == nil {
		return errors.New("unauthorized UDP request received a response")
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		return err
	}
	return nil
}

func transparentUDPExchange(t *testing.T, conn *net.UDPConn, request *dns.Msg) *dns.Msg {
	t.Helper()
	packet, err := request.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(packet); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var response [dns.MaxMsgSize]byte
	n, _, err := conn.ReadFromUDP(response[:])
	if err != nil {
		t.Fatal(err)
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(response[:n]); err != nil {
		t.Fatal(err)
	}
	return msg
}

func writeTransparentTCPMessage(conn net.Conn, request *dns.Msg) error {
	packet, err := request.Pack()
	if err != nil {
		return err
	}
	if len(packet) > 65535 {
		return errors.New("test DNS packet is too large")
	}
	var prefix [2]byte
	binary.BigEndian.PutUint16(prefix[:], uint16(len(packet)))
	if _, err = conn.Write(prefix[:]); err != nil {
		return err
	}
	_, err = conn.Write(packet)
	return err
}

func readTransparentTCPMessage(t *testing.T, conn net.Conn) *dns.Msg {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var prefix [2]byte
	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, int(binary.BigEndian.Uint16(prefix[:])))
	if _, err := io.ReadFull(conn, packet); err != nil {
		t.Fatal(err)
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(packet); err != nil {
		t.Fatal(err)
	}
	return msg
}
