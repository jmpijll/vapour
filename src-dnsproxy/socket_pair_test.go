package main

import (
	"errors"
	"net"
	"testing"
)

func TestBindSyntheticUpstreamPairRetriesUDPConflict(t *testing.T) {
	var tcpAttempts int
	var udpAttempts int
	var firstTCPClosed bool

	listenTCP := func(network string, address *net.TCPAddr) (net.Listener, error) {
		tcpAttempts++
		listener, err := net.ListenTCP(network, address)
		if err != nil {
			return nil, err
		}
		if tcpAttempts == 1 {
			return &trackedListener{
				Listener: listener,
				closed:   &firstTCPClosed,
			}, nil
		}
		return listener, nil
	}
	listenUDP := func(network string, address *net.UDPAddr) (net.PacketConn, error) {
		udpAttempts++
		if udpAttempts == 1 {
			return nil, errors.New("occupied UDP port")
		}
		return net.ListenUDP(network, address)
	}

	tcpListener, udpConn, err := bindSyntheticUpstreamPair(listenTCP, listenUDP)
	if err != nil {
		t.Fatalf("bindSyntheticUpstreamPair: %v", err)
	}
	t.Cleanup(func() {
		_ = tcpListener.Close()
		_ = udpConn.Close()
	})

	if tcpAttempts != 2 || udpAttempts != 2 {
		t.Fatalf("listener attempts = tcp %d, udp %d; want one retry", tcpAttempts, udpAttempts)
	}
	if !firstTCPClosed {
		t.Fatal("closed the UDP-conflicting TCP candidate only after abandoning it")
	}

	tcpPort := tcpListener.Addr().(*net.TCPAddr).Port
	udpPort := udpConn.LocalAddr().(*net.UDPAddr).Port
	if tcpPort != udpPort {
		t.Fatalf("listener ports = tcp %d, udp %d; want same port", tcpPort, udpPort)
	}
}

type trackedListener struct {
	net.Listener
	closed *bool
}

func (l *trackedListener) Close() error {
	*l.closed = true
	return l.Listener.Close()
}
