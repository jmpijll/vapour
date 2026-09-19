//go:build !windows

package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
)

type reservedTCP struct{}

func reserveTCP(netip.Addr) (*reservedTCP, error) {
	return nil, errors.New("transparent DNS transport requires Windows")
}
func (*reservedTCP) LocalAddr() netip.AddrPort { return netip.AddrPort{} }
func (*reservedTCP) Connect(context.Context, netip.AddrPort) (net.Conn, error) {
	return nil, errors.New("transparent DNS transport requires Windows")
}
func (*reservedTCP) Close() error { return nil }
func exclusiveSocketControl(string, string, syscall.RawConn) error {
	return errors.New("transparent DNS transport requires Windows")
}
