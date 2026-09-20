//go:build windows

package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestReserveTCPIPv4OwnsEphemeralPort(t *testing.T) {
	local := netip.MustParseAddr("127.0.0.1")
	reserved, err := reserveTCP(local)
	if err != nil {
		t.Fatalf("reserveTCP(%v): %v", local, err)
	}
	defer reserved.Close()

	addr := reserved.LocalAddr()
	if !addr.IsValid() || addr.Addr() != local || addr.Port() == 0 {
		t.Fatalf("LocalAddr() = %v, want %v:ephemeral", addr, local)
	}
	assertTCPPortUnavailable(t, "tcp4", local, addr.Port())
}

func TestReserveTCPIPv6OwnsEphemeralPort(t *testing.T) {
	local := netip.MustParseAddr("::1")
	if !ipv6LoopbackAvailable() {
		t.Skip("IPv6 loopback is unavailable")
	}

	reserved, err := reserveTCP(local)
	if err != nil {
		t.Fatalf("reserveTCP(%v): %v", local, err)
	}
	defer reserved.Close()

	addr := reserved.LocalAddr()
	if !addr.IsValid() || addr.Addr() != local || addr.Port() == 0 {
		t.Fatalf("LocalAddr() = %v, want %v:ephemeral", addr, local)
	}
	assertTCPPortUnavailable(t, "tcp6", local, addr.Port())
}

func TestReservedTCPConnectUsesOwnedSourcePort(t *testing.T) {
	for _, test := range []struct {
		name   string
		net    string
		local  netip.Addr
		remote netip.Addr
	}{
		{name: "ipv4", net: "tcp4", local: netip.MustParseAddr("127.0.0.1"), remote: netip.MustParseAddr("127.0.0.1")},
		{name: "ipv6", net: "tcp6", local: netip.MustParseAddr("::1"), remote: netip.MustParseAddr("::1")},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.remote.Is6() && !ipv6LoopbackAvailable() {
				t.Skip("IPv6 loopback is unavailable")
			}

			listener, err := net.ListenTCP(test.net, &net.TCPAddr{IP: net.IP(test.local.AsSlice()), Port: 0})
			if err != nil {
				t.Fatalf("ListenTCP: %v", err)
			}
			defer listener.Close()
			accepted := make(chan struct{})
			go func() {
				conn, acceptErr := listener.AcceptTCP()
				if acceptErr == nil {
					_ = conn.Close()
				}
				close(accepted)
			}()

			reserved, err := reserveTCP(test.local)
			if err != nil {
				t.Fatalf("reserveTCP: %v", err)
			}
			defer reserved.Close()

			remote := netip.AddrPortFrom(test.remote, uint16(listener.Addr().(*net.TCPAddr).Port))
			conn, err := reserved.Connect(context.Background(), remote)
			if err != nil {
				t.Fatalf("Connect(%v): %v", remote, err)
			}
			got, ok := conn.LocalAddr().(*net.TCPAddr)
			if !ok {
				_ = conn.Close()
				t.Fatalf("LocalAddr type = %T, want *net.TCPAddr", conn.LocalAddr())
			}
			if got.Port != int(reserved.LocalAddr().Port()) {
				_ = conn.Close()
				t.Fatalf("connected source port = %d, reserved port = %d", got.Port, reserved.LocalAddr().Port())
			}
			if !got.IP.Equal(net.IP(test.local.AsSlice())) {
				_ = conn.Close()
				t.Fatalf("connected source address = %v", got.IP)
			}
			if err := conn.Close(); err != nil {
				t.Fatalf("conn.Close: %v", err)
			}
			assertTCPPortUnavailable(t, test.net, test.local, reserved.LocalAddr().Port())
			<-accepted
		})
	}
}

func TestReservedTCPConnReadWriteUsesOwnedSocket(t *testing.T) {
	local := netip.MustParseAddr("127.0.0.1")
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IP(local.AsSlice()), Port: 0})
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		server, acceptErr := listener.AcceptTCP()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer server.Close()
		var request [4]byte
		if _, err := io.ReadFull(server, request[:]); err != nil {
			serverDone <- err
			return
		}
		if string(request[:]) != "ping" {
			serverDone <- errors.New("unexpected request")
			return
		}
		_, err := server.Write([]byte("pong"))
		serverDone <- err
	}()

	reserved, err := reserveTCP(local)
	if err != nil {
		t.Fatalf("reserveTCP: %v", err)
	}
	defer reserved.Close()
	remote := netip.AddrPortFrom(local, uint16(listener.Addr().(*net.TCPAddr).Port))
	conn, err := reserved.Connect(context.Background(), remote)
	if err != nil {
		t.Fatalf("Connect(%v): %v", remote, err)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		conn.Close()
		t.Fatalf("Write: %v", err)
	}
	var response [4]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil {
		conn.Close()
		t.Fatalf("Read: %v", err)
	}
	if string(response[:]) != "pong" {
		t.Fatalf("response = %q, want pong", response[:])
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("conn.Close: %v", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func TestReservedTCPConnReadDeadlineAndClose(t *testing.T) {
	local := netip.MustParseAddr("127.0.0.1")
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IP(local.AsSlice()), Port: 0})
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer listener.Close()
	accepted := make(chan *net.TCPConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptTCP()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	reserved, err := reserveTCP(local)
	if err != nil {
		t.Fatalf("reserveTCP: %v", err)
	}
	defer reserved.Close()
	remote := netip.AddrPortFrom(local, uint16(listener.Addr().(*net.TCPAddr).Port))
	conn, err := reserved.Connect(context.Background(), remote)
	if err != nil {
		t.Fatalf("Connect(%v): %v", remote, err)
	}
	defer conn.Close()
	var server *net.TCPConn
	select {
	case server = <-accepted:
		defer server.Close()
	case err := <-acceptErr:
		t.Fatalf("AcceptTCP: %v", err)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for accepted connection")
	}

	var one [1]byte
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	readDeadlineDone := make(chan error, 1)
	go func() {
		_, readErr := conn.Read(one[:])
		readDeadlineDone <- readErr
	}()
	time.Sleep(20 * time.Millisecond)
	if err := conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("shorten ReadDeadline: %v", err)
	}
	select {
	case err := <-readDeadlineDone:
		if timeoutErr, ok := err.(net.Error); !ok || !timeoutErr.Timeout() {
			t.Fatalf("Read deadline error = %v, want timeout", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Read did not observe shortened deadline")
	}

	if err := conn.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("expired ReadDeadline: %v", err)
	}
	started := time.Now()
	if _, err := conn.Read(one[:]); err == nil {
		t.Fatal("Read unexpectedly succeeded with expired deadline")
	} else if timeoutErr, ok := err.(net.Error); !ok || !timeoutErr.Timeout() {
		t.Fatalf("expired ReadDeadline error = %v, want timeout", err)
	}
	if elapsed := time.Since(started); elapsed > 50*time.Millisecond {
		t.Fatalf("expired ReadDeadline took %v", elapsed)
	}

	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clear ReadDeadline: %v", err)
	}
	readDone := make(chan error, 1)
	go func() {
		_, readErr := conn.Read(one[:])
		readDone <- readErr
	}()
	time.Sleep(20 * time.Millisecond)
	if err := conn.Close(); err != nil {
		t.Fatalf("conn.Close: %v", err)
	}
	select {
	case readErr := <-readDone:
		if readErr == nil {
			t.Fatal("Read after conn.Close unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("Read did not return after conn.Close")
	}
}

func TestReservedTCPConnectFailureKeepsPortUntilClose(t *testing.T) {
	local := netip.MustParseAddr("127.0.0.1")
	target, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IP(local.AsSlice()), Port: 0})
	if err != nil {
		t.Fatalf("target ListenTCP: %v", err)
	}
	remotePort := target.Addr().(*net.TCPAddr).Port
	_ = target.Close()

	reserved, err := reserveTCP(local)
	if err != nil {
		t.Fatalf("reserveTCP: %v", err)
	}
	defer reserved.Close()
	port := reserved.LocalAddr().Port()
	remote := netip.AddrPortFrom(local, uint16(remotePort))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := reserved.Connect(ctx, remote); err == nil {
		t.Fatal("Connect to closed target unexpectedly succeeded")
	}
	assertTCPPortUnavailable(t, "tcp4", local, port)
	if err := reserved.Close(); err != nil {
		t.Fatalf("reserved.Close after failed connect: %v", err)
	}
	assertTCPPortAvailable(t, "tcp4", local, port)
}

func TestReservedTCPConnectCanceledBeforeAttemptKeepsPortUntilClose(t *testing.T) {
	local := netip.MustParseAddr("127.0.0.1")
	reserved, err := reserveTCP(local)
	if err != nil {
		t.Fatalf("reserveTCP: %v", err)
	}
	defer reserved.Close()
	port := reserved.LocalAddr().Port()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := reserved.Connect(ctx, netip.MustParseAddrPort("127.0.0.1:1")); !errors.Is(err, context.Canceled) {
		t.Fatalf("Connect canceled error = %v, want context.Canceled", err)
	}
	assertTCPPortUnavailable(t, "tcp4", local, port)

	if err := reserved.Close(); err != nil {
		t.Fatalf("reserved.Close: %v", err)
	}
	assertTCPPortAvailable(t, "tcp4", local, port)
}

func TestReservedTCPConnectCanceledPendingKeepsPortUntilClose(t *testing.T) {
	local := netip.MustParseAddr("127.0.0.1")
	reserved, err := reserveTCP(local)
	if err != nil {
		t.Fatalf("reserveTCP: %v", err)
	}
	t.Cleanup(func() { _ = reserved.Close() })
	port := reserved.LocalAddr().Port()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, connectErr := reserved.Connect(ctx, netip.MustParseAddrPort("192.0.2.1:9"))
	if connectErr == nil {
		t.Fatal("Connect unexpectedly succeeded")
	}
	assertTCPPortUnavailable(t, "tcp4", local, port)
	closeDone := make(chan error, 1)
	go func() { closeDone <- reserved.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("reserved.Close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reserved.Close did not finish after canceled Connect")
	}
	assertTCPPortAvailable(t, "tcp4", local, port)
}

func TestReservedTCPCloseInterruptsConnect(t *testing.T) {
	local := netip.MustParseAddr("127.0.0.1")
	reserved, err := reserveTCP(local)
	if err != nil {
		t.Fatalf("reserveTCP: %v", err)
	}

	connectDone := make(chan error, 1)
	go func() {
		_, connectErr := reserved.Connect(context.Background(), netip.MustParseAddrPort("192.0.2.1:9"))
		connectDone <- connectErr
	}()
	time.Sleep(50 * time.Millisecond)
	if err := reserved.Close(); err != nil {
		t.Fatalf("reserved.Close: %v", err)
	}
	select {
	case <-connectDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Connect did not return after reservedTCP.Close")
	}
}

func TestReservedTCPConnectCloseSubmissionRace(t *testing.T) {
	local := netip.MustParseAddr("127.0.0.1")
	remote := netip.MustParseAddrPort("192.0.2.1:9")
	for i := 0; i < 64; i++ {
		reserved, err := reserveTCP(local)
		if err != nil {
			t.Fatalf("reserveTCP iteration %d: %v", i, err)
		}
		connectDone := make(chan error, 1)
		go func() {
			_, connectErr := reserved.Connect(context.Background(), remote)
			connectDone <- connectErr
		}()
		time.Sleep(time.Millisecond)
		closeDone := make(chan error, 1)
		go func() { closeDone <- reserved.Close() }()
		select {
		case <-connectDone:
		case <-time.After(time.Second):
			t.Fatalf("Connect iteration %d did not return after Close", i)
		}
		select {
		case err := <-closeDone:
			if err != nil {
				t.Fatalf("Close iteration %d: %v", i, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("Close iteration %d did not return", i)
		}
	}
}

func assertTCPPortUnavailable(t *testing.T, network string, local netip.Addr, port uint16) {
	t.Helper()
	listener, err := net.ListenTCP(network, &net.TCPAddr{IP: net.IP(local.AsSlice()), Port: int(port)})
	if err == nil {
		_ = listener.Close()
		t.Fatalf("competing %s bind unexpectedly succeeded on %v", network, netip.AddrPortFrom(local, port))
	}
}

func assertTCPPortAvailable(t *testing.T, network string, local netip.Addr, port uint16) {
	t.Helper()
	listener, err := net.ListenTCP(network, &net.TCPAddr{IP: net.IP(local.AsSlice()), Port: int(port)})
	if err != nil {
		t.Fatalf("competing %s bind after Close: %v", network, err)
	}
	_ = listener.Close()
}

func ipv6LoopbackAvailable() bool {
	listener, err := net.ListenTCP("tcp6", &net.TCPAddr{IP: net.ParseIP("::1"), Port: 0})
	if err != nil {
		return false
	}
	_ = listener.Close()
	return true
}
