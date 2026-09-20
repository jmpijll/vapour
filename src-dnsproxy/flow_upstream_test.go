//go:build windows

package main

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestFlowUpstreamKeepsReservedPortsAndResolver(t *testing.T) {
	server := startSyntheticUpstream(t)
	for _, tcp := range []bool{false, true} {
		route, err := reserveFlowUpstream(netip.MustParseAddr("127.0.0.1"), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = route.Close() })
		udp, tcpAddr := route.UDPAddr(), route.TCPAddr()
		if socket, err := net.ListenPacket("udp4", udp.String()); err == nil {
			socket.Close()
			t.Fatal("UDP reservation was not exclusive")
		}
		if socket, err := net.Listen("tcp4", tcpAddr.String()); err == nil {
			socket.Close()
			t.Fatal("TCP reservation was not exclusive")
		}
		endpoint := netip.MustParseAddrPort(server.address())
		if err := route.Assign(endpoint, tcp); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 2; i++ {
			request := (&dns.Msg{}).SetQuestion("owned.example.test.", dns.TypeA)
			response, err := route.Exchange(request)
			if err != nil {
				t.Fatal(err)
			}
			assertA(t, response, "192.0.2.42")
			if response.Id != request.Id {
				t.Fatal("client transaction ID changed")
			}
		}
		if route.UDPAddr() != udp || route.TCPAddr() != tcpAddr {
			t.Fatal("reserved source port changed")
		}
		if err := route.Assign(netip.MustParseAddrPort("127.0.0.2:53"), tcp); err == nil {
			t.Fatal("live slot retargeted")
		}
		_ = route.Close()
		if _, err := route.Exchange((&dns.Msg{}).SetQuestion("closed.test.", dns.TypeA)); err == nil {
			t.Fatal("closed route accepted query")
		}
	}
}

func TestFlowUpstreamTruncationUsesReservedTCPAndChecksResponses(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "::1"} {
		t.Run(ip, func(t *testing.T) { testFlowUpstreamFallback(t, ip) })
	}
}
func testFlowUpstreamFallback(t *testing.T, ip string) {
	t.Helper()
	tcpNetwork, udpNetwork := "tcp4", "udp4"
	if netip.MustParseAddr(ip).Is6() {
		tcpNetwork, udpNetwork = "tcp6", "udp6"
	}
	tcp, udp, err := bindSyntheticUpstreamPair(
		func(_ string, addr *net.TCPAddr) (net.Listener, error) {
			addr.IP = net.ParseIP(ip)
			return net.ListenTCP(tcpNetwork, addr)
		},
		func(_ string, addr *net.UDPAddr) (net.PacketConn, error) {
			addr.IP = net.ParseIP(ip)
			return net.ListenUDP(udpNetwork, addr)
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	observed := make(chan net.Addr, 4)
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		observed <- w.RemoteAddr()
		response := (&dns.Msg{}).SetReply(q)
		if _, ok := w.RemoteAddr().(*net.UDPAddr); ok {
			response.Truncated = true
			wrong := response.Copy()
			wrong.Id ^= 1
			_ = w.WriteMsg(wrong)
		} else {
			response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}, A: net.ParseIP("192.0.2.99")}}
		}
		_ = w.WriteMsg(response)
	})
	udpServer := &dns.Server{PacketConn: udp, Handler: handler}
	tcpServer := &dns.Server{Listener: tcp, Handler: handler}
	go func() { _ = udpServer.ActivateAndServe() }()
	go func() { _ = tcpServer.ActivateAndServe() }()
	t.Cleanup(func() { _ = udpServer.Shutdown(); _ = tcpServer.Shutdown() })
	route, err := reserveFlowUpstream(netip.MustParseAddr(ip), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	if err = route.Assign(netip.MustParseAddrPort(tcp.Addr().String()), false); err != nil {
		t.Fatal(err)
	}
	query := (&dns.Msg{}).SetQuestion("fallback.example.test.", dns.TypeA)
	response, err := route.Exchange(query)
	if err != nil {
		t.Fatal(err)
	}
	assertA(t, response, "192.0.2.99")
	first, second := <-observed, <-observed
	if first.String() != route.UDPAddr().String() || second.String() != route.TCPAddr().String() {
		t.Fatalf("source ports changed: %s %s", first, second)
	}
	wrong := response.Copy()
	wrong.Question[0].Name = "other.example.test."
	if matchesResponse(query, wrong) {
		t.Fatal("wrong question accepted")
	}
	wrong = response.Copy()
	wrong.Response = false
	if matchesResponse(query, wrong) {
		t.Fatal("query accepted as response")
	}
}

func TestFlowUpstreamDeadlineIncludesQueueTime(t *testing.T) {
	route, err := reserveFlowUpstream(netip.MustParseAddr("127.0.0.1"), 30*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	if err = route.Assign(netip.MustParseAddrPort("127.0.0.1:9"), false); err != nil {
		t.Fatal(err)
	}
	route.exchangeGate <- struct{}{}
	defer func() { <-route.exchangeGate }()
	started := time.Now()
	if _, err = route.Exchange((&dns.Msg{}).SetQuestion("queue.test.", dns.TypeA)); err == nil {
		t.Fatal("busy slot accepted query")
	}
	if time.Since(started) > time.Second {
		t.Fatal("queue did not respect query deadline")
	}
}
