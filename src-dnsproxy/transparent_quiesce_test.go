package main

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type quiesceProtocolHarness struct {
	input  *io.PipeWriter
	output *bufio.Scanner
	done   chan error
}

func newQuiesceProtocolHarness(t *testing.T) *quiesceProtocolHarness {
	t.Helper()
	inputReader, inputWriter := io.Pipe()
	outputReader, outputWriter := io.Pipe()
	done := make(chan error, 1)
	go func() {
		err := runProtocol(inputReader, outputWriter)
		_ = outputWriter.Close()
		done <- err
	}()
	return &quiesceProtocolHarness{
		input:  inputWriter,
		output: bufio.NewScanner(outputReader),
		done:   done,
	}
}

func (h *quiesceProtocolHarness) send(t *testing.T, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if _, err = h.input.Write(data); err != nil {
		t.Fatal(err)
	}
}

func (h *quiesceProtocolHarness) status(t *testing.T) statusMessage {
	t.Helper()
	if !h.output.Scan() {
		t.Fatalf("read protocol status: %v", h.output.Err())
	}
	var status statusMessage
	if err := json.Unmarshal(h.output.Bytes(), &status); err != nil {
		t.Fatalf("decode protocol status %q: %v", h.output.Text(), err)
	}
	return status
}

func (h *quiesceProtocolHarness) cleanup(t *testing.T) {
	t.Helper()
	_ = h.input.Close()
	for h.output.Scan() {
	}
	select {
	case <-h.done:
	case <-time.After(10 * time.Second):
		t.Error("protocol did not stop after input close")
	}
}

func TestTransparentQuiesceRetainsOwnedSocketsAndRejectsWork(t *testing.T) {
	harness := newQuiesceProtocolHarness(t)
	defer harness.cleanup(t)

	config := &config{
		Transparent:     true,
		ListenAddresses: []string{"127.0.0.1"},
		Rules:           "||blocked.example.test^",
	}
	harness.send(t, command{Op: "start", Config: config})
	ready := harness.status(t)
	if ready.Status == "error" && strings.Contains(ready.Error, "requires Windows") {
		t.Skip(ready.Error)
	}
	if ready.Status != "ready" || len(ready.UDPAddrs) != 1 || len(ready.TCPAddrs) != 1 || len(ready.Slots) != 8 {
		t.Fatalf("unexpected transparent readiness: %#v", ready)
	}

	remote, err := net.ResolveUDPAddr("udp4", ready.UDPAddr)
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.DialUDP("udp4", nil, remote)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	peer, err := transparentEndpoint(client.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	local, err := transparentEndpoint(client.RemoteAddr())
	if err != nil {
		t.Fatal(err)
	}
	flow := &flowRegistration{
		Protocol:   "udp",
		Peer:       peer.String(),
		Local:      local.String(),
		Resolver:   netip.AddrPortFrom(peer.Addr(), 53).String(),
		Slot:       ready.Slots[0].ID,
		LifetimeMS: 120000,
	}
	harness.send(t, command{Op: "register", Flow: flow})
	if status := harness.status(t); status.Status != "registered" {
		t.Fatalf("register status = %#v", status)
	}

	blocked := (&dns.Msg{}).SetQuestion("blocked.example.test.", dns.TypeA)
	response := transparentUDPExchange(t, client, blocked)
	if response.Rcode != dns.RcodeNameError {
		t.Fatalf("before quiesce rcode = %d, want NXDOMAIN", response.Rcode)
	}

	harness.send(t, command{Op: "quiesce"})
	if status := harness.status(t); status.Status != "quiesced" || status.Error != "" || status.UDPAddr != "" || status.TCPAddr != "" || len(status.Slots) != 0 {
		t.Fatalf("quiesce status = %#v, want exactly status=quiesced", status)
	}

	assertTransparentUDPSilent(t, client, blocked)
	harness.send(t, command{Op: "register", Flow: flow})
	if status := harness.status(t); status.Status != "error" || !strings.Contains(status.Error, "quiesced") {
		t.Fatalf("register after quiesce = %#v", status)
	}
	rules := "||other.example.test^"
	harness.send(t, command{Op: "reload", Rules: &rules})
	if status := harness.status(t); status.Status != "error" || !strings.Contains(status.Error, "quiesced") {
		t.Fatalf("reload after quiesce = %#v", status)
	}
	harness.send(t, command{Op: "quiesce"})
	if status := harness.status(t); status.Status != "quiesced" {
		t.Fatalf("repeated quiesce = %#v", status)
	}

	ownedUDP := append([]string{ready.UDPAddr}, readySlotUDPAddrs(ready.Slots)...)
	ownedTCP := append([]string{ready.TCPAddr}, readySlotTCPAddrs(ready.Slots)...)
	for _, address := range ownedUDP {
		assertTransparentUDPUnavailable(t, address)
	}
	for _, address := range ownedTCP {
		assertTransparentTCPUnavailable(t, address)
	}

	harness.send(t, command{Op: "stop"})
	if status := harness.status(t); status.Status != "stopped" {
		t.Fatalf("stop status = %#v", status)
	}
	for _, address := range ownedUDP {
		assertTransparentUDPAvailable(t, address)
	}
	for _, address := range ownedTCP {
		assertTransparentTCPAvailable(t, address)
	}
}

func readySlotUDPAddrs(slots []upstreamSlotStatus) []string {
	addresses := make([]string, 0, len(slots))
	for _, slot := range slots {
		addresses = append(addresses, slot.UDPAddr)
	}
	return addresses
}

func readySlotTCPAddrs(slots []upstreamSlotStatus) []string {
	addresses := make([]string, 0, len(slots))
	for _, slot := range slots {
		addresses = append(addresses, slot.TCPAddr)
	}
	return addresses
}

func assertTransparentUDPSilent(t *testing.T, client *net.UDPConn, request *dns.Msg) {
	t.Helper()
	packet, err := request.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Write(packet); err != nil {
		t.Fatal(err)
	}
	if err = client.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var response [dns.MaxMsgSize]byte
	if n, err := client.Read(response[:]); err == nil {
		t.Fatalf("quiesced UDP request received %d response bytes", n)
	}
	if err = client.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
}

func assertTransparentUDPUnavailable(t *testing.T, address string) {
	t.Helper()
	conn, err := net.ListenPacket("udp4", address)
	if err == nil {
		_ = conn.Close()
		t.Fatalf("quiesced UDP endpoint %s accepted a competing bind", address)
	}
}

func assertTransparentTCPUnavailable(t *testing.T, address string) {
	t.Helper()
	listener, err := net.Listen("tcp4", address)
	if err == nil {
		_ = listener.Close()
		t.Fatalf("quiesced TCP endpoint %s accepted a competing bind", address)
	}
}

func assertTransparentUDPAvailable(t *testing.T, address string) {
	t.Helper()
	conn, err := net.ListenPacket("udp4", address)
	if err != nil {
		t.Fatalf("stopped UDP endpoint %s did not clean up: %v", address, err)
	}
	_ = conn.Close()
}

func assertTransparentTCPAvailable(t *testing.T, address string) {
	t.Helper()
	listener, err := net.Listen("tcp4", address)
	if err != nil {
		t.Fatalf("stopped TCP endpoint %s did not clean up: %v", address, err)
	}
	_ = listener.Close()
}
