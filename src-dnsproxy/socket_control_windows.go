package main

import (
	"golang.org/x/sys/windows"
	"syscall"
)

func exclusiveSocketControl(network, address string, raw syscall.RawConn) error {
	var socketErr error
	err := raw.Control(func(fd uintptr) {
		socketErr = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, -5, 1) // SO_EXCLUSIVEADDRUSE
		if socketErr == nil && (network == "udp6" || network == "tcp6") {
			socketErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, windows.IPV6_V6ONLY, 1)
		}
	})
	if err != nil {
		return err
	}
	return socketErr
}
