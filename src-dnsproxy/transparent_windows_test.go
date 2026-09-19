package main

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestTransparentServiceReadyRegistrationBlockReleaseAndCleanup(t *testing.T) {
	runtime := &serviceRuntime{}
	ready, err := runtime.start(config{Transparent: true, ListenAddresses: []string{"127.0.0.1", "::1"}, Rules: "||blocked.example.test^"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.stop() })
	if len(ready.Slots) != 16 || len(ready.UDPAddrs) != 2 || len(ready.TCPAddrs) != 2 {
		t.Fatalf("incomplete ready: %#v", ready)
	}
	for _, protocol := range []string{"udp", "tcp"} {
		addresses := ready.UDPAddrs
		if protocol == "tcp" {
			addresses = ready.TCPAddrs
		}
		for _, address := range addresses {
			conn, err := net.DialTimeout(protocol, address, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			local := netip.MustParseAddrPort(address)
			peer := netip.MustParseAddrPort(conn.LocalAddr().String())
			slot := -1
			for _, candidate := range ready.Slots {
				endpoint := netip.MustParseAddrPort(candidate.UDPAddr)
				if endpoint.Addr() == local.Addr() {
					candidateID := candidate.ID
					if protocol == "tcp" {
						candidateID++
					}
					slot = candidateID
					break
				}
			}
			if slot < 0 {
				t.Fatal("matching upstream slot missing")
			}
			registration := flowRegistration{Protocol: protocol, Peer: peer.String(), Local: address, Resolver: netip.AddrPortFrom(peer.Addr(), 53).String(), Slot: slot, LifetimeMS: 10000}
			if err = runtime.service.registerFlow(registration); err != nil {
				conn.Close()
				t.Fatal(err)
			}
			query := (&dns.Msg{}).SetQuestion("blocked.example.test.", dns.TypeA)
			client := &dns.Client{Net: protocol, Timeout: time.Second}
			response, _, err := client.ExchangeWithConn(query, &dns.Conn{Conn: conn})
			if err != nil || response.Rcode != dns.RcodeNameError {
				conn.Close()
				t.Fatalf("%s %s: response=%v err=%v", protocol, address, response, err)
			}
			if err = runtime.service.releaseFlow(registration); err != nil {
				conn.Close()
				t.Fatal(err)
			}
			client.Timeout = 100 * time.Millisecond
			if response, _, err = client.ExchangeWithConn(query, &dns.Conn{Conn: conn}); err == nil {
				conn.Close()
				t.Fatalf("released flow got response: %v", response)
			}
			conn.Close()
		}
	}
	if err = runtime.stop(); err != nil {
		t.Fatal(err)
	}
	for _, slot := range ready.Slots {
		udp, err := net.ListenPacket("udp", slot.UDPAddr)
		if err != nil {
			t.Fatalf("UDP slot leaked: %v", err)
		}
		udp.Close()
		tcp, err := net.Listen("tcp", slot.TCPAddr)
		if err != nil {
			t.Fatalf("TCP slot leaked: %v", err)
		}
		tcp.Close()
	}
}

func TestTransparentProcessRegistrationProtocol(t *testing.T) {
	child := startChild(t, buildBinary(t))
	sendCommand(t, child.stdin, command{Op: "start", Config: &config{Transparent: true, ListenAddresses: []string{"127.0.0.1"}, Rules: "||blocked.example.test^"}})
	ready := child.readStatus(t)
	if ready.Status != "ready" || len(ready.Slots) != 8 {
		t.Fatalf("unexpected ready: %#v", ready)
	}
	conn, err := net.Dial("udp", ready.UDPAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	peer := netip.MustParseAddrPort(conn.LocalAddr().String())
	flow := &flowRegistration{Protocol: "udp", Peer: peer.String(), Local: ready.UDPAddr, Resolver: netip.AddrPortFrom(peer.Addr(), 53).String(), Slot: 0, LifetimeMS: 10000}
	sendCommand(t, child.stdin, command{Op: "register", Flow: flow})
	if status := child.readStatus(t); status.Status != "registered" {
		t.Fatalf("registration: %#v", status)
	}
	request := (&dns.Msg{}).SetQuestion("blocked.example.test.", dns.TypeA)
	response, _, err := (&dns.Client{Net: "udp", Timeout: time.Second}).ExchangeWithConn(request, &dns.Conn{Conn: conn})
	if err != nil || response.Rcode != dns.RcodeNameError {
		t.Fatalf("blocked response=%v err=%v", response, err)
	}
	sendCommand(t, child.stdin, command{Op: "release", Flow: flow})
	if status := child.readStatus(t); status.Status != "released" {
		t.Fatalf("release: %#v", status)
	}
	sendCommand(t, child.stdin, command{Op: "register", Flow: flow})
	if status := child.readStatus(t); status.Status != "error" {
		t.Fatalf("quarantined registration accepted: %#v", status)
	}
	sendCommand(t, child.stdin, command{Op: "stop"})
	if status := child.readStatus(t); status.Status != "stopped" {
		t.Fatalf("stop: %#v", status)
	}
	child.wait(t)
}
