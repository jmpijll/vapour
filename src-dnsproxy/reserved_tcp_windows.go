//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// SO_EXCLUSIVEADDRUSE is defined by Winsock as ^SO_REUSEADDR.  It is not
	// exported by x/sys/windows, whose SO_REUSEADDR value is 4.
	soExclusiveAddrUse = -5
	// x/sys/windows exports SO_RCVTIMEO but omits the corresponding Winsock
	// send timeout constant.
	soSndRcvTimeout = 0x1005

	connectWaitPoll = 50 * time.Millisecond
)

var (
	errReservedTCPAttempted = errors.New("reserved TCP socket has already attempted a connection")
	errReservedTCPInvalid   = errors.New("reserved TCP socket is invalid")
)

// reservedTCP owns one bound TCP socket for a single interception session.
// The socket is deliberately retained after a failed or canceled Connect so
// that its source port remains exclusively owned until Close.
type reservedTCP struct {
	mu sync.Mutex
	// nativeMu serializes the reservation's direct use of the socket handle
	// with the final closesocket. It is held across ConnectEx submission and
	// connected-socket finalization so Close cannot invalidate or reuse the
	// native handle between the state check and the syscall.
	nativeMu sync.Mutex

	handle windows.Handle
	local  netip.AddrPort

	attempted bool
	closed    bool

	// ConnectEx's operation is retained here when Connect returns because its
	// context was canceled.  Close cancels the operation, waits for completion,
	// and only then releases the event handles and source socket.
	operationPending bool
	operation        *windows.Overlapped
	operationEvent   windows.Handle
	closeEvent       windows.Handle

	connectDone       chan struct{}
	connectDoneClosed bool
	closeDone         chan struct{}
	closeErr          error

	conn *reservedTCPConn
}

// reserveTCP creates and binds an exclusive ephemeral TCP source socket.
// The returned reservation must be closed by its owner, including after a
// failed or canceled connection attempt.
func reserveTCP(local netip.Addr) (*reservedTCP, error) {
	if !local.IsValid() || local.Is4In6() {
		return nil, fmt.Errorf("reserve TCP: %w", errReservedTCPInvalid)
	}
	zoneID, err := sockaddrZoneID(local)
	if err != nil {
		return nil, fmt.Errorf("reserve TCP %v: %w", local, err)
	}

	family := windows.AF_INET
	if local.Is6() {
		family = windows.AF_INET6
	}
	handle, err := windows.WSASocket(
		int32(family),
		int32(windows.SOCK_STREAM),
		int32(windows.IPPROTO_TCP),
		nil,
		0,
		windows.WSA_FLAG_OVERLAPPED|windows.WSA_FLAG_NO_HANDLE_INHERIT,
	)
	if err != nil {
		return nil, fmt.Errorf("create TCP socket: %w", err)
	}
	closeSocket := true
	defer func() {
		if closeSocket {
			_ = windows.Closesocket(handle)
		}
	}()

	if err := windows.SetsockoptInt(handle, windows.SOL_SOCKET, soExclusiveAddrUse, 1); err != nil {
		return nil, fmt.Errorf("set SO_EXCLUSIVEADDRUSE: %w", err)
	}
	if local.Is6() {
		if err := windows.SetsockoptInt(handle, windows.IPPROTO_IPV6, windows.IPV6_V6ONLY, 1); err != nil {
			return nil, fmt.Errorf("set IPV6_V6ONLY: %w", err)
		}
	}
	if err := windows.Bind(handle, sockaddrForAddrPort(netip.AddrPortFrom(local, 0), zoneID)); err != nil {
		return nil, fmt.Errorf("bind TCP source %v: %w", local, err)
	}

	bound, err := windows.Getsockname(handle)
	if err != nil {
		return nil, fmt.Errorf("get TCP source address: %w", err)
	}
	localAddr, err := addrPortFromSockaddr(bound, local.Zone())
	if err != nil {
		return nil, fmt.Errorf("decode TCP source address: %w", err)
	}
	if localAddr.Port() == 0 {
		return nil, errors.New("bind TCP source returned port 0")
	}

	closeSocket = false
	return &reservedTCP{handle: handle, local: localAddr}, nil
}

// LocalAddr returns the address and ephemeral source port owned by the
// reservation. It remains stable until Close, including after failed Connect.
func (r *reservedTCP) LocalAddr() netip.AddrPort {
	if r == nil {
		return netip.AddrPort{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.local
}

// Connect performs the one permitted ConnectEx attempt. A context cancellation
// returns to the caller without releasing the source socket; Close owns the
// final cancellation and cleanup of a still-pending operation.
func (r *reservedTCP) Connect(ctx context.Context, remote netip.AddrPort) (net.Conn, error) {
	if r == nil {
		return nil, errReservedTCPInvalid
	}
	if ctx == nil {
		return nil, errors.New("reserved TCP connect: nil context")
	}
	if !remote.IsValid() || remote.Port() == 0 || remote.Addr().Is4In6() {
		return nil, fmt.Errorf("reserved TCP connect: invalid remote %v", remote)
	}

	r.mu.Lock()
	if r.closed || r.handle == 0 || r.handle == windows.InvalidHandle {
		r.mu.Unlock()
		return nil, net.ErrClosed
	}
	if r.attempted {
		r.mu.Unlock()
		return nil, errReservedTCPAttempted
	}
	if (r.local.Addr().Is4()) != remote.Addr().Is4() {
		r.mu.Unlock()
		return nil, fmt.Errorf("reserved TCP connect: address family mismatch: local %v remote %v", r.local, remote)
	}
	r.attempted = true
	r.connectDone = make(chan struct{})
	handle := r.handle
	connectDone := r.connectDone
	r.mu.Unlock()

	if err := ctx.Err(); err != nil {
		r.finishCanceled(connectDone)
		return nil, err
	}
	remoteZoneID, err := sockaddrZoneID(remote.Addr())
	if err != nil {
		r.finishCanceled(connectDone)
		return nil, fmt.Errorf("resolve remote IPv6 zone: %w", err)
	}
	remoteSockaddr := sockaddrForAddrPort(remote, remoteZoneID)

	opEvent, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		r.finishCanceled(connectDone)
		return nil, fmt.Errorf("create ConnectEx event: %w", err)
	}
	closeEvent, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		_ = windows.CloseHandle(opEvent)
		r.finishCanceled(connectDone)
		return nil, fmt.Errorf("create connect cancellation event: %w", err)
	}
	overlapped := new(windows.Overlapped)
	overlapped.HEvent = opEvent

	r.mu.Lock()
	if r.closed || r.handle != handle {
		r.mu.Unlock()
		_ = windows.CloseHandle(closeEvent)
		_ = windows.CloseHandle(opEvent)
		r.finishCanceled(connectDone)
		return nil, net.ErrClosed
	}
	r.operation = overlapped
	r.operationEvent = opEvent
	r.closeEvent = closeEvent
	r.operationPending = true
	r.mu.Unlock()

	var sent uint32
	// Keep the native handle stable from the final state check through the
	// ConnectEx submission. Close may mark the reservation closed concurrently,
	// but it cannot call closesocket until this syscall returns.
	r.nativeMu.Lock()
	r.mu.Lock()
	closedBeforeSubmit := r.closed || r.handle != handle
	r.mu.Unlock()
	if closedBeforeSubmit {
		_ = windows.SetEvent(opEvent)
		err := r.finishClosed(connectDone)
		r.nativeMu.Unlock()
		return nil, err
	}
	err = windows.ConnectEx(handle, remoteSockaddr, nil, 0, &sent, overlapped)
	if err == nil {
		// Keep nativeMu held through synchronous completion, including
		// SO_UPDATE_CONNECT_CONTEXT and getsockname, so Close cannot release
		// the socket between ConnectEx and finalization.
		conn, finishErr := r.finishConnectedLocked(connectDone, handle, opEvent, closeEvent, nil, remote, ctx)
		r.nativeMu.Unlock()
		return conn, finishErr
	}
	if err != nil && !errors.Is(err, windows.ERROR_IO_PENDING) {
		finishErr := r.finishImmediateFailure(connectDone, opEvent, closeEvent, err, ctx)
		r.nativeMu.Unlock()
		return nil, finishErr
	}
	r.nativeMu.Unlock()

	for {
		waitFor := connectWaitDuration(ctx)
		waitMS := uint32(waitFor / time.Millisecond)
		if waitMS == 0 {
			waitMS = 1
		}
		if waitFor == 0 {
			waitMS = 0
		}
		waitResult, waitErr := windows.WaitForMultipleObjects(
			[]windows.Handle{opEvent, closeEvent},
			false,
			waitMS,
		)
		if waitErr != nil {
			return nil, r.finishWaitFailure(connectDone, waitErr, ctx)
		}
		switch waitResult {
		case windows.WAIT_OBJECT_0:
			return r.finishConnected(connectDone, handle, opEvent, closeEvent, overlapped, remote, ctx)
		case windows.WAIT_OBJECT_0 + 1:
			return nil, r.finishClosed(connectDone)
		case uint32(windows.WAIT_TIMEOUT):
			if err := ctx.Err(); err != nil {
				// Leave the overlapped operation and bound socket owned by r.
				// Close will cancel/await the operation before releasing them.
				r.cancelPendingOperation()
				r.finishCanceledPending(connectDone)
				return nil, err
			}
		default:
			return nil, r.finishWaitFailure(connectDone, fmt.Errorf("unexpected wait result %d", waitResult), ctx)
		}
	}
}

// Close cancels any pending ConnectEx operation and releases the original
// bound socket. A connected net.Conn is only a view over that same socket;
// closing the reservation is its sole final handle release.
func (r *reservedTCP) Close() error {
	if r == nil {
		return nil
	}

	r.mu.Lock()
	if r.closed {
		closeDone := r.closeDone
		r.mu.Unlock()
		if closeDone != nil {
			<-closeDone
		}
		return r.closeErr
	}
	r.closed = true
	closeDone := make(chan struct{})
	r.closeDone = closeDone
	handle := r.handle
	r.handle = 0
	closeEvent := r.closeEvent
	opEvent := r.operationEvent
	overlapped := r.operation
	operationPending := r.operationPending
	connectDone := r.connectDone
	conn := r.conn
	r.conn = nil
	r.mu.Unlock()

	if closeEvent != 0 {
		_ = windows.SetEvent(closeEvent)
	}
	if conn != nil {
		// Shutdown wakes a synchronous WSARecv/WSASend without releasing the
		// bound source port. closeByReservation waits for those operations to
		// stop before the owning socket handle is closed below.
		conn.closeByReservation()
	}
	r.nativeMu.Lock()
	if operationPending && handle != 0 && handle != windows.InvalidHandle && overlapped != nil {
		// CancelIoEx is best effort. closesocket below is required as the final
		// Winsock cancellation path and preserves the reservation until here.
		_ = windows.CancelIoEx(handle, overlapped)
	}
	var closeErr error
	if handle != 0 && handle != windows.InvalidHandle {
		closeErr = windows.Closesocket(handle)
	}
	r.nativeMu.Unlock()
	if connectDone != nil {
		<-connectDone
	}
	if operationPending && opEvent != 0 {
		_, _ = windows.WaitForSingleObject(opEvent, windows.INFINITE)
	}
	if closeEvent != 0 {
		_ = windows.CloseHandle(closeEvent)
	}
	if opEvent != 0 {
		_ = windows.CloseHandle(opEvent)
	}
	r.mu.Lock()
	r.closeErr = closeErr
	close(closeDone)
	r.mu.Unlock()
	return closeErr
}

func (r *reservedTCP) finishCanceled(done chan struct{}) {
	r.mu.Lock()
	if r.connectDone == done {
		r.closeConnectDoneLocked()
	}
	r.mu.Unlock()
}

func (r *reservedTCP) finishCanceledPending(done chan struct{}) {
	r.mu.Lock()
	if r.connectDone == done {
		// Keep operation, event, and close event for Close. The source socket
		// remains bound even though this Connect call has returned.
		r.closeConnectDoneLocked()
	}
	r.mu.Unlock()
}

func (r *reservedTCP) finishImmediateFailure(done chan struct{}, opEvent, closeEvent windows.Handle, connectErr error, ctx context.Context) error {
	// An immediate ConnectEx failure has no pending operation. Signal the
	// operation event first so a concurrent Close that observed the optimistic
	// pending state cannot wait forever for completion.
	_ = windows.SetEvent(opEvent)
	r.finishNoPending(done, opEvent, closeEvent)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return fmt.Errorf("ConnectEx: %w", connectErr)
}

func (r *reservedTCP) finishWaitFailure(done chan struct{}, waitErr error, ctx context.Context) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		r.cancelPendingOperation()
		r.finishCanceledPending(done)
		return ctxErr
	}
	r.finishCanceledPending(done)
	return fmt.Errorf("wait for ConnectEx: %w", waitErr)
}

func (r *reservedTCP) finishClosed(done chan struct{}) error {
	// Close owns event and socket cleanup. Connect only reports the close and
	// lets Close wait for the pending overlapped operation before closing them.
	r.mu.Lock()
	if r.connectDone == done {
		r.closeConnectDoneLocked()
	}
	r.mu.Unlock()
	return net.ErrClosed
}

func (r *reservedTCP) finishConnected(done chan struct{}, handle, opEvent, closeEvent windows.Handle, overlapped *windows.Overlapped, remote netip.AddrPort, ctx context.Context) (net.Conn, error) {
	r.nativeMu.Lock()
	defer r.nativeMu.Unlock()
	return r.finishConnectedLocked(done, handle, opEvent, closeEvent, overlapped, remote, ctx)
}

func (r *reservedTCP) finishConnectedLocked(done chan struct{}, handle, opEvent, closeEvent windows.Handle, overlapped *windows.Overlapped, remote netip.AddrPort, ctx context.Context) (net.Conn, error) {
	// Close may have completed before this waiter acquired nativeMu. Reject
	// the stale handle before any syscall; once this check passes, Close cannot
	// close or allow the numeric handle to be reused until nativeMu is released.
	r.mu.Lock()
	validHandle := !r.closed && r.handle == handle
	r.mu.Unlock()
	if !validHandle {
		_ = windows.SetEvent(opEvent)
		return nil, r.finishClosed(done)
	}
	if err := ctx.Err(); err != nil {
		if overlapped == nil {
			// ConnectEx completed synchronously, so there is no overlapped
			// request left for Close to cancel or await.
			_ = windows.SetEvent(opEvent)
			r.finishNoPending(done, opEvent, closeEvent)
		} else {
			r.cancelPendingOperationLocked()
			r.finishCanceledPending(done)
		}
		return nil, err
	}
	var flags uint32
	if overlapped != nil {
		var bytes uint32
		if err := windows.WSAGetOverlappedResult(handle, overlapped, &bytes, false, &flags); err != nil {
			return nil, r.finishConnectedFailure(done, opEvent, closeEvent, fmt.Errorf("ConnectEx result: %w", err))
		}
	}
	if err := windows.Setsockopt(handle, windows.SOL_SOCKET, windows.SO_UPDATE_CONNECT_CONTEXT, (*byte)(unsafe.Pointer(&handle)), int32(unsafe.Sizeof(handle))); err != nil {
		return nil, r.finishConnectedFailure(done, opEvent, closeEvent, fmt.Errorf("update ConnectEx context: %w", err))
	}
	local := r.LocalAddr()
	bound, err := windows.Getsockname(handle)
	if err != nil {
		return nil, r.finishConnectedFailure(done, opEvent, closeEvent, fmt.Errorf("get connected TCP source address: %w", err))
	}
	local, err = addrPortFromSockaddr(bound, local.Addr().Zone())
	if err != nil {
		return nil, r.finishConnectedFailure(done, opEvent, closeEvent, fmt.Errorf("decode connected TCP source address: %w", err))
	}
	localAddr := tcpAddrFromAddrPort(local)
	remoteAddr := tcpAddrFromAddrPort(remote)

	r.mu.Lock()
	if r.closed || r.handle != handle {
		r.mu.Unlock()
		_ = windows.SetEvent(opEvent)
		return nil, r.finishClosed(done)
	}
	owned := &reservedTCPConn{
		owner:      r,
		handle:     handle,
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}
	r.conn = owned
	r.operationPending = false
	r.operation = nil
	r.operationEvent = 0
	r.closeEvent = 0
	r.closeConnectDoneLocked()
	r.mu.Unlock()

	_ = windows.CloseHandle(opEvent)
	_ = windows.CloseHandle(closeEvent)
	return owned, nil
}

func (r *reservedTCP) finishConnectedFailure(done chan struct{}, opEvent, closeEvent windows.Handle, err error) error {
	_ = windows.SetEvent(opEvent)
	r.finishNoPending(done, opEvent, closeEvent)
	return err
}

func (r *reservedTCP) cancelPendingOperation() {
	r.nativeMu.Lock()
	defer r.nativeMu.Unlock()
	r.cancelPendingOperationLocked()
}

func (r *reservedTCP) cancelPendingOperationLocked() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.operationPending || r.handle == 0 || r.handle == windows.InvalidHandle || r.operation == nil {
		return
	}
	// CancelIoEx cancels the overlapped ConnectEx request without closing the
	// bound socket. Close still performs the final closesocket and waits for
	// the operation event before releasing the reservation. Keep the state lock
	// while issuing it so Close cannot close and race reuse of this handle.
	_ = windows.CancelIoEx(r.handle, r.operation)
}

func (r *reservedTCP) finishNoPending(done chan struct{}, opEvent, closeEvent windows.Handle) {
	r.mu.Lock()
	if r.connectDone != done {
		r.mu.Unlock()
		return
	}
	r.operationPending = false
	r.operation = nil
	r.operationEvent = 0
	r.closeEvent = 0
	r.closeConnectDoneLocked()
	closed := r.closed
	r.mu.Unlock()
	if !closed {
		_ = windows.CloseHandle(opEvent)
		_ = windows.CloseHandle(closeEvent)
	}
}

func (r *reservedTCP) closeConnectDoneLocked() {
	if !r.connectDoneClosed && r.connectDone != nil {
		r.connectDoneClosed = true
		close(r.connectDone)
	}
}

type reservedTCPConn struct {
	owner      *reservedTCP
	handle     windows.Handle
	localAddr  *net.TCPAddr
	remoteAddr *net.TCPAddr

	mu            sync.Mutex
	readMu        sync.Mutex
	writeMu       sync.Mutex
	closed        bool
	readDeadline  time.Time
	writeDeadline time.Time
}

func (c *reservedTCPConn) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	handle := c.handle
	// This is deliberately shutdown rather than closesocket. The reservation
	// remains the sole owner of the socket and must keep its source port until
	// reservedTCP.Close.
	if handle != 0 && handle != windows.InvalidHandle {
		_ = windows.Shutdown(handle, sdBoth)
	}
	c.mu.Unlock()
	return nil
}

// closeByReservation marks the view closed, wakes synchronous I/O, and waits
// for operations using the raw handle before the reservation closes it.
func (c *reservedTCPConn) closeByReservation() {
	if c == nil {
		return
	}
	_ = c.Close()
	c.readMu.Lock()
	c.readMu.Unlock()
	c.writeMu.Lock()
	c.writeMu.Unlock()
}

func (c *reservedTCPConn) Read(p []byte) (int, error) {
	if c == nil {
		return 0, net.ErrClosed
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if uint64(len(p)) > uint64(^uint32(0)) {
		return 0, c.opError("read", errors.New("read buffer is too large"))
	}
	if len(p) == 0 {
		if _, _, err := c.prepareIO(true); err != nil {
			return 0, c.prepareError("read", err)
		}
		return 0, nil
	}
	for {
		handle, _, err := c.prepareIO(true)
		if err != nil {
			return 0, c.prepareError("read", err)
		}
		buf := windows.WSABuf{Len: uint32(len(p)), Buf: &p[0]}
		var received uint32
		flags := uint32(0)
		err = windows.WSARecv(handle, &buf, 1, &received, &flags, nil, nil)
		if err == nil {
			if received == 0 {
				return 0, io.EOF
			}
			return int(received), nil
		}
		if errors.Is(err, windows.WSAETIMEDOUT) {
			if c.isClosed() {
				return int(received), net.ErrClosed
			}
			if c.ioDeadlineExpired(true) {
				return int(received), c.opTimeoutError("read", err)
			}
			continue
		}
		if c.isClosed() {
			return int(received), net.ErrClosed
		}
		return int(received), c.opError("read", err)
	}
}

func (c *reservedTCPConn) Write(p []byte) (int, error) {
	if c == nil {
		return 0, net.ErrClosed
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if uint64(len(p)) > uint64(^uint32(0)) {
		return 0, c.opError("write", errors.New("write buffer is too large"))
	}
	if len(p) == 0 {
		if _, _, err := c.prepareIO(false); err != nil {
			return 0, c.prepareError("write", err)
		}
		return 0, nil
	}
	total := 0
	for total < len(p) {
		handle, _, err := c.prepareIO(false)
		if err != nil {
			return total, c.prepareError("write", err)
		}
		buf := windows.WSABuf{Len: uint32(len(p) - total), Buf: &p[total]}
		var sent uint32
		err = windows.WSASend(handle, &buf, 1, &sent, 0, nil, nil)
		if err == nil {
			if sent == 0 {
				return total, io.ErrShortWrite
			}
			total += int(sent)
			continue
		}
		if errors.Is(err, windows.WSAETIMEDOUT) {
			if c.isClosed() {
				return total + int(sent), net.ErrClosed
			}
			if c.ioDeadlineExpired(false) {
				return total + int(sent), c.opTimeoutError("write", err)
			}
			total += int(sent)
			continue
		}
		if c.isClosed() {
			return total + int(sent), net.ErrClosed
		}
		return total + int(sent), c.opError("write", err)
	}
	return total, nil
}

func (c *reservedTCPConn) LocalAddr() net.Addr {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return cloneTCPAddr(c.localAddr)
}

func (c *reservedTCPConn) RemoteAddr() net.Addr {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return cloneTCPAddr(c.remoteAddr)
}

func (c *reservedTCPConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *reservedTCPConn) SetReadDeadline(t time.Time) error {
	if c == nil {
		return net.ErrClosed
	}
	c.mu.Lock()
	if c.closed || c.handle == 0 || c.handle == windows.InvalidHandle {
		c.mu.Unlock()
		return net.ErrClosed
	}
	c.readDeadline = t
	err := setSocketTimeout(c.handle, windows.SO_RCVTIMEO, socketPollTimeoutMillis(t))
	c.mu.Unlock()
	if err != nil {
		return c.opError("set read deadline", err)
	}
	return nil
}

func (c *reservedTCPConn) SetWriteDeadline(t time.Time) error {
	if c == nil {
		return net.ErrClosed
	}
	c.mu.Lock()
	if c.closed || c.handle == 0 || c.handle == windows.InvalidHandle {
		c.mu.Unlock()
		return net.ErrClosed
	}
	c.writeDeadline = t
	err := setSocketTimeout(c.handle, soSndRcvTimeout, socketPollTimeoutMillis(t))
	c.mu.Unlock()
	if err != nil {
		return c.opError("set write deadline", err)
	}
	return nil
}

// prepareIO snapshots a valid handle and applies a short timeout while the
// state lock is held. The read/write mutex held by the caller keeps the raw
// handle valid until the synchronous Winsock operation returns; the timeout
// lets the loop observe deadline changes and logical Close promptly.
func (c *reservedTCPConn) prepareIO(read bool) (windows.Handle, time.Time, error) {
	c.mu.Lock()
	if c.closed || c.handle == 0 || c.handle == windows.InvalidHandle {
		c.mu.Unlock()
		return 0, time.Time{}, net.ErrClosed
	}
	deadline := c.writeDeadline
	if read {
		deadline = c.readDeadline
	}
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		c.mu.Unlock()
		return 0, deadline, reservedTCPTimeoutError{err: windows.WSAETIMEDOUT}
	}
	option := soSndRcvTimeout
	if read {
		option = windows.SO_RCVTIMEO
	}
	err := setSocketTimeout(c.handle, option, socketPollTimeoutMillis(deadline))
	handle := c.handle
	c.mu.Unlock()
	if err != nil {
		return 0, time.Time{}, err
	}
	return handle, deadline, nil
}

func (c *reservedTCPConn) prepareError(op string, err error) error {
	if errors.Is(err, net.ErrClosed) {
		return err
	}
	if errors.Is(err, windows.WSAETIMEDOUT) {
		return c.opTimeoutError(op, err)
	}
	return c.opError("set socket timeout", err)
}

func (c *reservedTCPConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed || c.handle == 0 || c.handle == windows.InvalidHandle
}

func (c *reservedTCPConn) ioDeadlineExpired(read bool) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.handle == 0 || c.handle == windows.InvalidHandle {
		return true
	}
	deadline := c.writeDeadline
	if read {
		deadline = c.readDeadline
	}
	if deadline.IsZero() {
		return false
	}
	// Use current metadata, so SetDeadline can shorten or extend an operation
	// while it is polling.
	return !time.Now().Before(deadline)
}

func (c *reservedTCPConn) opError(op string, err error) error {
	return &net.OpError{Op: op, Net: "tcp", Source: c.LocalAddr(), Addr: c.RemoteAddr(), Err: err}
}

func (c *reservedTCPConn) opTimeoutError(op string, err error) error {
	return &net.OpError{Op: op, Net: "tcp", Source: c.LocalAddr(), Addr: c.RemoteAddr(), Err: reservedTCPTimeoutError{err: err}}
}

type reservedTCPTimeoutError struct {
	err error
}

func (e reservedTCPTimeoutError) Error() string { return e.err.Error() }

func (e reservedTCPTimeoutError) Unwrap() error { return e.err }

func (e reservedTCPTimeoutError) Timeout() bool { return true }

func (e reservedTCPTimeoutError) Temporary() bool { return true }

const sdBoth = 2

func setSocketTimeout(handle windows.Handle, option int, timeout int) error {
	return windows.SetsockoptInt(handle, windows.SOL_SOCKET, option, timeout)
}

func socketPollTimeoutMillis(deadline time.Time) int {
	const maxPollMillis = int64(connectWaitPoll / time.Millisecond)
	if deadline.IsZero() {
		return int(maxPollMillis)
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return 1
	}
	millis := remaining / time.Millisecond
	if remaining%time.Millisecond != 0 {
		millis++
	}
	if int64(millis) > maxPollMillis {
		return int(maxPollMillis)
	}
	max := int64(^uint32(0) >> 1)
	if millis > time.Duration(max) {
		return int(max)
	}
	if millis < 1 {
		return 1
	}
	return int(millis)
}

func tcpAddrFromAddrPort(addr netip.AddrPort) *net.TCPAddr {
	if !addr.IsValid() {
		return nil
	}
	return &net.TCPAddr{
		IP:   net.IP(addr.Addr().AsSlice()),
		Port: int(addr.Port()),
		Zone: addr.Addr().Zone(),
	}
}

func cloneTCPAddr(addr *net.TCPAddr) *net.TCPAddr {
	if addr == nil {
		return nil
	}
	clone := *addr
	clone.IP = append(net.IP(nil), addr.IP...)
	return &clone
}

func connectWaitDuration(ctx context.Context) time.Duration {
	if _, ok := ctx.Deadline(); !ok && ctx.Done() == nil {
		return time.Duration(windows.INFINITE) * time.Millisecond
	}
	waitFor := connectWaitPoll
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0
		}
		if remaining < waitFor {
			waitFor = remaining
		}
	}
	return waitFor
}

func sockaddrForAddrPort(addr netip.AddrPort, zoneID uint32) windows.Sockaddr {
	if addr.Addr().Is4() {
		return &windows.SockaddrInet4{Port: int(addr.Port()), Addr: addr.Addr().As4()}
	}
	return &windows.SockaddrInet6{Port: int(addr.Port()), ZoneId: zoneID, Addr: addr.Addr().As16()}
}

func sockaddrZoneID(addr netip.Addr) (uint32, error) {
	zone := addr.Zone()
	if zone == "" {
		return 0, nil
	}
	if numeric, err := strconv.ParseUint(zone, 10, 32); err == nil {
		if numeric == 0 {
			return 0, errors.New("IPv6 zone index is zero")
		}
		return uint32(numeric), nil
	}
	iface, err := net.InterfaceByName(zone)
	if err != nil {
		return 0, fmt.Errorf("resolve IPv6 zone %q: %w", zone, err)
	}
	if iface.Index <= 0 {
		return 0, fmt.Errorf("IPv6 zone %q has invalid interface index %d", zone, iface.Index)
	}
	return uint32(iface.Index), nil
}

func addrPortFromSockaddr(addr windows.Sockaddr, zone string) (netip.AddrPort, error) {
	switch addr := addr.(type) {
	case *windows.SockaddrInet4:
		return netip.AddrPortFrom(netip.AddrFrom4(addr.Addr), uint16(addr.Port)), nil
	case *windows.SockaddrInet6:
		return netip.AddrPortFrom(netip.AddrFrom16(addr.Addr).WithZone(zone), uint16(addr.Port)), nil
	default:
		return netip.AddrPort{}, fmt.Errorf("unsupported socket address %T", addr)
	}
}
