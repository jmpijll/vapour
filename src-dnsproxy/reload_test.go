package main

import (
	"github.com/miekg/dns"
	"testing"
)

func TestProcessReloadKeepsListenersAndRejectsInvalidReplacement(t *testing.T) {
	child := startChild(t, buildBinary(t))
	upstream := startSyntheticUpstream(t)
	sendCommand(t, child.stdin, command{Op: "start", Config: &config{Upstream: upstream.address(), Rules: "||old.example.test^"}})
	ready := child.readStatus(t)
	if ready.Status != "ready" {
		t.Fatalf("start: %#v", ready)
	}
	// Use raw JSON so this test fails on the unsupported operation before the
	// new command field exists.
	if _, err := child.stdin.Write([]byte("{\"op\":\"reload\",\"rules\":\"||new.example.test^\"}\n")); err != nil {
		t.Fatal(err)
	}
	updated := child.readStatus(t)
	if updated.Status != "updated" || updated.RulesCount != 1 {
		t.Fatalf("reload: %#v", updated)
	}
	for _, network := range []string{"udp", "tcp"} {
		address := ready.UDPAddr
		if network == "tcp" {
			address = ready.TCPAddr
		}
		assertA(t, exchangeDNS(t, network, address, "old.example.test.", dns.TypeA), "192.0.2.42")
		if reply := exchangeDNS(t, network, address, "new.example.test.", dns.TypeAAAA); reply.Rcode != dns.RcodeNameError {
			t.Fatalf("replacement did not block: %v", reply)
		}
	}
	if _, err := child.stdin.Write([]byte("{\"op\":\"reload\",\"rules\":\"192.0.2.1 arbitrary.example.test\"}\n")); err != nil {
		t.Fatal(err)
	}
	if rejected := child.readStatus(t); rejected.Status != "error" {
		t.Fatalf("bad update: %#v", rejected)
	}
	if reply := exchangeDNS(t, "udp", ready.UDPAddr, "new.example.test.", dns.TypeA); reply.Rcode != dns.RcodeNameError {
		t.Fatalf("invalid update replaced active filter: %v", reply)
	}
	sendCommand(t, child.stdin, command{Op: "stop"})
	if stopped := child.readStatus(t); stopped.Status != "stopped" {
		t.Fatalf("stop: %#v", stopped)
	}
	child.wait(t)
}
