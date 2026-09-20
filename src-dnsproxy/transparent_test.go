package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	dnsproxy "github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/miekg/dns"
)

func TestTransparentConfigFileRequiresCommandProtocol(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"transparent":true,"listen_addresses":["127.0.0.1"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err := runConfigFile(path, strings.NewReader(""), &output)
	if err == nil || !strings.Contains(err.Error(), "command protocol") || strings.Contains(output.String(), `"status":"ready"`) {
		t.Fatalf("config-file mode must reject transparent routing before readiness: %v, %s", err, output.String())
	}
}

type localAddressConn struct {
	net.Conn
	address net.Addr
}

func (c localAddressConn) LocalAddr() net.Addr { return c.address }

type answerRoute struct {
	address string
	calls   int
	closed  bool
}

func (r *answerRoute) Address() string { return r.address }
func (r *answerRoute) Close() error    { r.closed = true; return nil }
func (r *answerRoute) Exchange(q *dns.Msg) (*dns.Msg, error) {
	r.calls++
	response := (&dns.Msg{}).SetReply(q)
	response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}, A: net.ParseIP(r.address)}}
	return response, nil
}
func TestTransparentHandlerAuthorizesBeforeFilteringAndSelectsExactRoute(t *testing.T) {
	engine, err := newDomainEngine("||blocked.example.test^")
	if err != nil {
		t.Fatal(err)
	}
	service, err := newDNSService(config{Upstream: "127.0.0.1:9", ListenAddress: "127.0.0.1"}, engine)
	if err != nil {
		t.Fatal(err)
	}
	if err = service.start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.shutdown() })
	flows := newAuthorizedFlows(4)
	handler := filteringHandler{engine: &service.engine, flows: flows}
	local := netip.MustParseAddrPort("127.0.0.1:42000")
	first := flowKey{Protocol: "udp", Peer: netip.MustParseAddrPort("127.0.0.2:53000"), Local: local}
	second := flowKey{Protocol: "udp", Peer: netip.MustParseAddrPort("127.0.0.3:53000"), Local: local}
	routes := []*answerRoute{{address: "192.0.2.1"}, {address: "192.0.2.2"}}
	for i, key := range []flowKey{first, second} {
		if err = flows.Register(key, routes[i], time.Minute, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	query := func(key flowKey, name string) (*dnsproxy.DNSContext, error) {
		dctx := &dnsproxy.DNSContext{Proto: dnsproxy.Proto(key.Protocol), Addr: key.Peer, Conn: localAddressConn{address: net.UDPAddrFromAddrPort(key.Local)}, Req: (&dns.Msg{}).SetQuestion(name, dns.TypeA)}
		return dctx, handler.ServeDNS(context.Background(), service.proxy, dctx)
	}
	for i, key := range []flowKey{first, second} {
		dctx, err := query(key, "allowed.example.test.")
		if err != nil {
			t.Fatal(err)
		}
		assertA(t, dctx.Res, routes[i].address)
	}
	blocked, err := query(first, "blocked.example.test.")
	if err != nil || blocked.Res.Rcode != dns.RcodeNameError {
		t.Fatalf("blocked: %v %#v", err, blocked.Res)
	}
	if routes[0].calls != 1 || routes[1].calls != 1 {
		t.Fatal("blocked query reached upstream")
	}
	unknown := first
	unknown.Local = netip.MustParseAddrPort("127.0.0.1:42001")
	if _, err = query(unknown, "blocked.example.test."); !errors.Is(err, dnsproxy.ErrDrop) {
		t.Fatalf("unknown blocked flow accepted: %v", err)
	}
	flows.Release(first)
	if _, err = query(first, "allowed.example.test."); !errors.Is(err, dnsproxy.ErrDrop) {
		t.Fatal("released flow accepted")
	}
	borrowed := borrowedUpstream{routes[1]}
	_ = borrowed.Close()
	if routes[1].closed {
		t.Fatal("borrower released owned socket")
	}
}
func TestTransparentConfigurationRejectsAmbiguousListeners(t *testing.T) {
	for _, cfg := range []config{
		{Transparent: true},
		{Transparent: true, ListenAddresses: []string{"0.0.0.0"}},
		{Transparent: true, ListenAddresses: []string{"::"}},
		{Transparent: true, ListenAddresses: []string{"fe80::1"}},
		{Transparent: true, ListenAddresses: []string{"127.0.0.1", "127.0.0.1"}},
		{Transparent: true, ListenAddresses: []string{"127.0.0.1"}, Upstream: "1.1.1.1:53"},
		{Transparent: true, ListenAddresses: []string{"127.0.0.1"}, ListenPort: 53},
	} {
		if _, err := validateConfig(cfg); err == nil {
			t.Fatalf("accepted %#v", cfg)
		}
	}
	if _, err := validateConfig(config{Transparent: true, ListenAddresses: []string{"127.0.0.1", "::1"}}); err != nil {
		t.Fatal(err)
	}
}

func TestRejectedFlowDoesNotAssignAnotherUpstreamSlot(t *testing.T) {
	flows := newAuthorizedFlows(1)
	key := flowKey{Protocol: "udp", Peer: netip.MustParseAddrPort("127.0.0.2:53000"), Local: netip.MustParseAddrPort("127.0.0.1:42000")}
	route := &answerRoute{address: "192.0.2.1"}
	now := time.Now()
	prepared := 0
	prepare := func() error { prepared++; return nil }
	if err := flows.registerPrepared(key, route, time.Minute, now, prepare); err != nil {
		t.Fatal(err)
	}
	if err := flows.registerPrepared(key, route, time.Minute, now, prepare); err == nil {
		t.Fatal("duplicate accepted")
	}
	flows.Release(key)
	if err := flows.registerPrepared(key, route, time.Minute, now, prepare); err == nil {
		t.Fatal("quarantined key accepted")
	}
	other := key
	other.Peer = netip.MustParseAddrPort("127.0.0.3:53000")
	if err := flows.registerPrepared(other, route, time.Minute, now, prepare); err == nil {
		t.Fatal("exhausted table accepted key")
	}
	if prepared != 1 {
		t.Fatalf("slot assignment called %d times", prepared)
	}
}

func TestTransparentReadinessValidatesExactAddressesAndOwnedPorts(t *testing.T) {
	cfg := config{Transparent: true, ListenAddresses: []string{"127.0.0.1"}}
	udp, tcp := []string{"127.0.0.1:42000"}, []string{"127.0.0.1:42001"}
	slots := make([]upstreamSlotStatus, 8)
	for i := range slots {
		slots[i] = upstreamSlotStatus{ID: i, UDPAddr: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(43000+i)).String(), TCPAddr: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(44000+i)).String()}
	}
	if err := validateTransparentReady(cfg, udp, tcp, slots); err != nil {
		t.Fatal(err)
	}
	if err := validateTransparentReady(cfg, []string{"127.0.0.2:42000"}, tcp, slots); err == nil {
		t.Fatal("wrong local address accepted")
	}
	if err := validateTransparentReady(cfg, udp, nil, slots); err == nil {
		t.Fatal("missing listener accepted")
	}
	slots[0].UDPAddr = udp[0]
	if err := validateTransparentReady(cfg, udp, tcp, slots); err == nil {
		t.Fatal("overlapping upstream port accepted")
	}
}
