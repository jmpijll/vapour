package main

import (
	"net"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
)

func TestProcessDualStackServesBothLoopbackFamilies(t *testing.T) {
	requireIPv6Loopback(t)

	binary := buildBinary(t)
	upstream := startSyntheticUpstream(t)
	child := startChild(t, binary)

	sendCommand(t, child.stdin, command{
		Op: "start",
		Config: &config{
			Upstream:   upstream.address(),
			ListenPort: 0,
			DualStack:  true,
			Rules:      "||ads.example.test^",
		},
	})
	ready := child.readStatus(t)
	if ready.Status != "ready" {
		t.Fatalf("ready status = %#v", ready)
	}
	assertDualStackReady(t, ready)

	for _, listener := range []struct {
		name    string
		network string
		address string
	}{
		{name: "udp4", network: "udp", address: ready.UDPAddrs[0]},
		{name: "udp6", network: "udp", address: ready.UDPAddrs[1]},
		{name: "tcp4", network: "tcp", address: ready.TCPAddrs[0]},
		{name: "tcp6", network: "tcp", address: ready.TCPAddrs[1]},
	} {
		t.Run(listener.name, func(t *testing.T) {
			blocked := exchangeDNS(t, listener.network, listener.address, "ads.example.test.", dns.TypeA)
			if blocked.Rcode != dns.RcodeNameError || len(blocked.Answer) != 0 {
				t.Fatalf("blocked response: rcode=%d answers=%v", blocked.Rcode, blocked.Answer)
			}

			allowed := exchangeDNS(t, listener.network, listener.address, "allowed.example.test.", dns.TypeAAAA)
			assertAAAA(t, allowed, "2001:db8::42")
		})
	}
	if got := atomic.LoadInt32(&upstream.queries); got != 4 {
		t.Fatalf("allowed query count = %d, want 4", got)
	}

	sendCommand(t, child.stdin, command{Op: "stop"})
	if stopped := child.readStatus(t); stopped.Status != "stopped" {
		t.Fatalf("stop status = %#v", stopped)
	}
	child.wait(t)
}

func TestProcessDualStackBindFailureClosesEarlierIPv4Listener(t *testing.T) {
	conflict, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.ParseIP("::1"), Port: 0})
	if err != nil {
		t.Skipf("IPv6 loopback is unavailable: %v", err)
	}
	defer conflict.Close()
	port := conflict.LocalAddr().(*net.UDPAddr).Port

	probeUDP := func() *net.UDPConn {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		if err != nil {
			t.Fatalf("IPv4 UDP probe on port %d: %v", port, err)
		}
		return conn
	}
	probeTCP := func() *net.TCPListener {
		listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		if err != nil {
			t.Fatalf("IPv4 TCP probe on port %d: %v", port, err)
		}
		return listener
	}
	probeUDP().Close()
	probeTCP().Close()

	binary := buildBinary(t)
	upstream := startSyntheticUpstream(t)
	child := startChild(t, binary)
	sendCommand(t, child.stdin, command{
		Op: "start",
		Config: &config{
			Upstream:   upstream.address(),
			ListenPort: port,
			DualStack:  true,
			Rules:      "||ads.example.test^",
		},
	})
	errorStatus := child.readStatus(t)
	if errorStatus.Status != "error" {
		t.Fatalf("bind conflict status = %#v", errorStatus)
	}

	probeUDP().Close()
	probeTCP().Close()

	sendCommand(t, child.stdin, command{Op: "stop"})
	if stopped := child.readStatus(t); stopped.Status != "stopped" {
		t.Fatalf("stop status = %#v", stopped)
	}
	child.wait(t)
}

func requireIPv6Loopback(t *testing.T) {
	t.Helper()
	conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.ParseIP("::1"), Port: 0})
	if err != nil {
		t.Skipf("IPv6 loopback is unavailable: %v", err)
	}
	_ = conn.Close()
}

func assertDualStackReady(t *testing.T, ready statusMessage) {
	t.Helper()
	if len(ready.UDPAddrs) != 2 || len(ready.TCPAddrs) != 2 {
		t.Fatalf("dual-stack listener arrays = udp %v tcp %v", ready.UDPAddrs, ready.TCPAddrs)
	}
	if ready.UDPAddr != ready.UDPAddrs[0] || ready.TCPAddr != ready.TCPAddrs[0] {
		t.Fatalf("legacy listener addresses do not name first listener: %#v", ready)
	}
	assertLoopbackFamilyHighPort(t, ready.UDPAddrs[0], false)
	assertLoopbackFamilyHighPort(t, ready.UDPAddrs[1], true)
	assertLoopbackFamilyHighPort(t, ready.TCPAddrs[0], false)
	assertLoopbackFamilyHighPort(t, ready.TCPAddrs[1], true)
}

func assertLoopbackFamilyHighPort(t *testing.T, address string, wantIPv6 bool) {
	t.Helper()
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", address, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		t.Fatalf("listener %q is not a loopback IP", address)
	}
	if (ip.To4() == nil) != wantIPv6 {
		t.Fatalf("listener %q has wrong address family", address)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 1024 {
		t.Fatalf("listener %q is not an ephemeral high port", address)
	}
}
