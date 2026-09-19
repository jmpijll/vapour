package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	dnsproxy "github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/miekg/dns"
)

const (
	transparentListenerTimeout = 2 * time.Second
	transparentStartupTimeout  = 5 * time.Second
	transparentQuiesceTimeout  = 5 * time.Second
	transparentMaxTCPConns     = 64
	transparentMaxHandlers     = 64
)

var (
	errTransparentUnauthorized = errors.New("transparent DNS flow is not authorized")
	errTransparentStopped      = errors.New("transparent DNS listeners are stopped")
	errTransparentQuiesced     = errors.New("transparent DNS listeners are quiesced")
)

// transparentListeners owns the sockets used in transparent mode.  The
// dnsproxy instance remains the resolver engine; these servers only perform
// the transport-level admission check before miekg/dns parses a packet.
type transparentListeners struct {
	service *dnsService

	udpConns      []*net.UDPConn
	tcpListeners  []*transparentTCPListener
	udpServers    []*dns.Server
	tcpServers    []*dns.Server
	serverRunners []*transparentServerRunner
	udpAddrs      []string
	tcpAddrs      []string

	startedNotify chan struct{}
	serveErrors   chan error
	serveWG       sync.WaitGroup

	handlerMu       sync.Mutex
	handlerGate     chan struct{}
	handlerWG       sync.WaitGroup
	handlerStopping bool
	quiescing       bool
	quiesced        bool

	stateMu  sync.Mutex
	starting bool
	started  bool
	closed   bool

	shutdownOnce sync.Once
	shutdownDone chan struct{}
	shutdownErr  error

	boundCloseOnce sync.Once
	boundCloseErr  error
}

type transparentServerRunner struct {
	server  *dns.Server
	started atomic.Bool
	proto   dnsproxy.Proto
}

// newTransparentListeners binds every requested endpoint before returning.
// This makes construction transactional: a failure at any point releases all
// sockets acquired by earlier binds.
func newTransparentListeners(
	service *dnsService,
	udpAddrs []*net.UDPAddr,
	tcpAddrs []*net.TCPAddr,
) (*transparentListeners, error) {
	if service == nil || service.proxy == nil {
		return nil, errors.New("transparent DNS service is nil")
	}
	if service.flows == nil {
		return nil, errors.New("transparent DNS flow table is nil")
	}
	if len(udpAddrs) == 0 && len(tcpAddrs) == 0 {
		return nil, errors.New("no transparent DNS listeners configured")
	}

	l := &transparentListeners{
		service:       service,
		startedNotify: make(chan struct{}, len(udpAddrs)+len(tcpAddrs)),
		serveErrors:   make(chan error, len(udpAddrs)+len(tcpAddrs)),
		handlerGate:   make(chan struct{}, transparentMaxHandlers),
		shutdownDone:  make(chan struct{}),
	}

	for index, requested := range udpAddrs {
		network, address, err := transparentUDPBinding(requested)
		if err != nil {
			return nil, errors.Join(fmt.Errorf("validate UDP listener %d: %w", index, err), l.closeBound())
		}
		listenConfig := net.ListenConfig{Control: exclusiveSocketControl}
		packetConn, err := listenConfig.ListenPacket(context.Background(), network, address)
		if err != nil {
			return nil, errors.Join(fmt.Errorf("bind UDP listener %s: %w", address, err), l.closeBound())
		}
		udpConn, ok := packetConn.(*net.UDPConn)
		if !ok || udpConn == nil {
			_ = packetConn.Close()
			return nil, errors.Join(fmt.Errorf("bind UDP listener %s: unexpected packet connection", address), l.closeBound())
		}
		l.udpConns = append(l.udpConns, udpConn)
		bound, err := transparentEndpoint(udpConn.LocalAddr())
		if err != nil {
			return nil, errors.Join(err, l.closeBound())
		}
		l.udpAddrs = append(l.udpAddrs, bound.String())
	}

	for index, requested := range tcpAddrs {
		network, address, err := transparentTCPBinding(requested)
		if err != nil {
			return nil, errors.Join(fmt.Errorf("validate TCP listener %d: %w", index, err), l.closeBound())
		}
		listenConfig := net.ListenConfig{Control: exclusiveSocketControl}
		listener, err := listenConfig.Listen(context.Background(), network, address)
		if err != nil {
			return nil, errors.Join(fmt.Errorf("bind TCP listener %s: %w", address, err), l.closeBound())
		}
		limited := newTransparentTCPListener(listener)
		l.tcpListeners = append(l.tcpListeners, limited)
		bound, err := transparentEndpoint(listener.Addr())
		if err != nil {
			return nil, errors.Join(err, l.closeBound())
		}
		l.tcpAddrs = append(l.tcpAddrs, bound.String())
	}

	for _, packetConn := range l.udpConns {
		runner := &transparentServerRunner{proto: dnsproxy.ProtoUDP}
		runner.server = &dns.Server{
			PacketConn:   &transparentPacketConn{UDPConn: packetConn},
			Handler:      transparentDNSHandler{listeners: l, service: service, proto: dnsproxy.ProtoUDP},
			UDPSize:      dns.MaxMsgSize,
			ReadTimeout:  transparentListenerTimeout,
			WriteTimeout: transparentListenerTimeout,
			DecorateReader: func(reader dns.Reader) dns.Reader {
				return &transparentReader{listeners: l, Reader: reader, flows: service.flows, proto: dnsproxy.ProtoUDP, buffer: make([]byte, dns.MaxMsgSize)}
			},
		}
		l.installRunnerNotify(runner)
		l.udpServers = append(l.udpServers, runner.server)
		l.serverRunners = append(l.serverRunners, runner)
	}
	for _, listener := range l.tcpListeners {
		runner := &transparentServerRunner{proto: dnsproxy.ProtoTCP}
		runner.server = &dns.Server{
			Listener:     listener,
			Handler:      transparentDNSHandler{listeners: l, service: service, proto: dnsproxy.ProtoTCP},
			ReadTimeout:  transparentListenerTimeout,
			WriteTimeout: transparentListenerTimeout,
			DecorateReader: func(reader dns.Reader) dns.Reader {
				return &transparentReader{listeners: l, Reader: reader, flows: service.flows, proto: dnsproxy.ProtoTCP}
			},
		}
		l.installRunnerNotify(runner)
		l.tcpServers = append(l.tcpServers, runner.server)
		l.serverRunners = append(l.serverRunners, runner)
	}

	return l, nil
}

func (l *transparentListeners) installRunnerNotify(runner *transparentServerRunner) {
	runner.server.NotifyStartedFunc = func() {
		runner.started.Store(true)
		l.startedNotify <- struct{}{}
	}
}

// Start starts all prebound servers and only returns successfully after every
// server has entered its serving loop.
func (l *transparentListeners) Start() error {
	if l == nil {
		return errors.New("transparent DNS listeners are nil")
	}

	l.stateMu.Lock()
	if l.closed {
		l.stateMu.Unlock()
		return errTransparentStopped
	}
	if l.started || l.starting {
		l.stateMu.Unlock()
		return errors.New("transparent DNS listeners already started")
	}
	l.starting = true
	l.stateMu.Unlock()

	for _, runner := range l.serverRunners {
		l.serveWG.Add(1)
		go func(runner *transparentServerRunner) {
			defer l.serveWG.Done()
			if err := runner.server.ActivateAndServe(); err != nil {
				select {
				case l.serveErrors <- fmt.Errorf("serve %s listener: %w", runner.proto, err):
				default:
				}
			}
		}(runner)
	}

	timer := time.NewTimer(transparentStartupTimeout)
	defer timer.Stop()
	for started := 0; started < len(l.serverRunners); started++ {
		select {
		case <-l.startedNotify:
		case err := <-l.serveErrors:
			return l.failStart(err)
		case <-timer.C:
			return l.failStart(errors.New("transparent DNS listener startup timed out"))
		}
	}

	select {
	case err := <-l.serveErrors:
		return l.failStart(err)
	default:
	}

	l.stateMu.Lock()
	if l.closed {
		l.stateMu.Unlock()
		return errTransparentStopped
	}
	l.starting = false
	l.started = true
	l.stateMu.Unlock()
	return nil
}

func (l *transparentListeners) failStart(startErr error) error {
	l.stateMu.Lock()
	l.starting = false
	l.stateMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), transparentStartupTimeout)
	defer cancel()
	return errors.Join(startErr, l.Shutdown(ctx))
}

// Quiesce stops admitting new transparent DNS work and waits for handlers
// already admitted at the barrier to finish. It deliberately leaves every
// listener and upstream reservation open; Shutdown remains the sole owner of
// those sockets. The barrier covers user-space handlers and aborts accepted
// TCP views with SetLinger(0) where the connection supports it, but cannot by
// itself prove that a kernel has delivered no final TCP packet. Native
// end-to-end quiescence is a later controller concern.
func (l *transparentListeners) Quiesce(ctx context.Context) error {
	if l == nil {
		return errors.New("transparent DNS listeners are nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	l.stateMu.Lock()
	closed := l.closed
	started := l.started
	l.stateMu.Unlock()
	if closed {
		return errTransparentStopped
	}
	if !started {
		return errors.New("transparent DNS listeners are not started")
	}

	l.handlerMu.Lock()
	if l.quiesced {
		l.handlerMu.Unlock()
		return nil
	}
	// Keep handlerStopping set even when the caller's deadline expires. This
	// fails closed while preserving the sockets for a later retry or stop.
	l.quiescing = true
	l.handlerStopping = true
	l.handlerMu.Unlock()

	var closeErr error
	for _, listener := range l.tcpListeners {
		closeErr = errors.Join(closeErr, listener.quiesceConnections())
	}
	waitErr := l.waitForHandlers(ctx)
	if closeErr != nil || waitErr != nil {
		return errors.Join(closeErr, waitErr)
	}

	l.stateMu.Lock()
	closed = l.closed
	l.stateMu.Unlock()
	if closed {
		return errTransparentStopped
	}
	l.handlerMu.Lock()
	l.quiesced = true
	l.handlerMu.Unlock()
	return nil
}

func (l *transparentListeners) isQuiescing() bool {
	if l == nil {
		return false
	}
	l.handlerMu.Lock()
	defer l.handlerMu.Unlock()
	return l.quiescing || l.handlerStopping
}

func (l *transparentListeners) rejectWhenQuiescing() error {
	if l != nil && l.isQuiescing() {
		return errTransparentQuiesced
	}
	return nil
}

// Shutdown stops all servers, closes active TCP connections, and releases the
// original sockets.  It is idempotent and safe to call before Start.
func (l *transparentListeners) Shutdown(ctx context.Context) error {
	if l == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	l.stateMu.Lock()
	if !l.closed {
		l.closed = true
	}
	l.started = false
	l.starting = false
	l.stateMu.Unlock()

	// Only the first caller runs the teardown.  A later caller can still bound
	// its wait with its own context.
	l.shutdownOnce.Do(func() {
		l.shutdownErr = l.shutdownAll(ctx)
		close(l.shutdownDone)
	})

	select {
	case <-l.shutdownDone:
		return l.shutdownErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *transparentListeners) shutdownAll(ctx context.Context) error {
	l.handlerMu.Lock()
	// Prevent new handlers from being admitted before listeners are stopped.
	// Existing handlers are waited for below.
	l.handlerStopping = true
	l.handlerMu.Unlock()

	shutdownErrors := make(chan error, len(l.serverRunners))
	for _, runner := range l.serverRunners {
		go func(runner *transparentServerRunner) {
			err := runner.server.ShutdownContext(ctx)
			if err != nil && !strings.Contains(err.Error(), "server not started") {
				shutdownErrors <- fmt.Errorf("shutdown %s listener: %w", runner.proto, err)
				return
			}
			shutdownErrors <- nil
		}(runner)
	}

	var result error
	for range l.serverRunners {
		select {
		case err := <-shutdownErrors:
			result = errors.Join(result, err)
		case <-ctx.Done():
			result = errors.Join(result, ctx.Err())
			goto stopped
		}
	}

stopped:
	result = errors.Join(result, l.closeBound())
	result = errors.Join(result, l.waitForServeAndHandlers(ctx))
	return result
}

func (l *transparentListeners) waitForServeAndHandlers(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		l.serveWG.Wait()
		l.handlerWG.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *transparentListeners) waitForHandlers(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	done := make(chan struct{})
	go func() {
		l.handlerWG.Wait()
		close(done)
	}()
	select {
	case <-done:
		if err := ctx.Err(); err != nil {
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *transparentListeners) closeBound() error {
	l.boundCloseOnce.Do(func() {
		var err error
		for _, listener := range l.tcpListeners {
			err = errors.Join(err, transparentCloseError(listener.Close()))
		}
		for _, conn := range l.udpConns {
			err = errors.Join(err, transparentCloseError(conn.Close()))
		}
		l.boundCloseErr = err
	})
	return l.boundCloseErr
}

func transparentCloseError(err error) error {
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (l *transparentListeners) UDPAddrs() []string {
	if l == nil {
		return nil
	}
	return append([]string(nil), l.udpAddrs...)
}

func (l *transparentListeners) TCPAddrs() []string {
	if l == nil {
		return nil
	}
	return append([]string(nil), l.tcpAddrs...)
}

// transparentReader authenticates the transport tuple while the packet is
// still raw.  In particular, unknown UDP packets are consumed and skipped
// before miekg/dns can generate FORMERR or validate a question.
type transparentReader struct {
	listeners *transparentListeners
	dns.Reader
	flows  *authorizedFlows
	proto  dnsproxy.Proto
	buffer []byte
}

func (r *transparentReader) ReadUDP(conn *net.UDPConn, timeout time.Duration) ([]byte, *dns.SessionUDP, error) {
	for {
		packet, session, err := r.Reader.ReadUDP(conn, timeout)
		if err != nil {
			return nil, nil, err
		}
		if r.isQuiescing() {
			continue
		}
		key, err := transparentFlowKey(string(r.proto), conn.LocalAddr(), session.RemoteAddr())
		if err == nil {
			if _, ok := r.flows.Lookup(key, time.Now()); ok {
				return packet, session, nil
			}
		}
	}
}

func (r *transparentReader) ReadPacketConn(conn net.PacketConn, timeout time.Duration) ([]byte, net.Addr, error) {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, nil, err
	}
	for {
		n, peerAddr, err := conn.ReadFrom(r.buffer)
		if err != nil {
			return nil, nil, err
		}
		if r.isQuiescing() {
			continue
		}
		key, err := transparentFlowKey(string(r.proto), conn.LocalAddr(), peerAddr)
		if err != nil {
			continue
		}
		if _, ok := r.flows.Lookup(key, time.Now()); !ok {
			continue
		}
		packet := make([]byte, n)
		copy(packet, r.buffer[:n])
		return packet, peerAddr, nil
	}
}

func (r *transparentReader) ReadTCP(conn net.Conn, timeout time.Duration) ([]byte, error) {
	if r.isQuiescing() {
		return nil, errTransparentQuiesced
	}
	packet, err := r.Reader.ReadTCP(conn, timeout)
	if err != nil {
		return nil, err
	}
	if r.isQuiescing() {
		return nil, errTransparentQuiesced
	}
	key, keyErr := transparentFlowKey(string(r.proto), conn.LocalAddr(), conn.RemoteAddr())
	if keyErr != nil {
		return nil, errTransparentUnauthorized
	}
	if _, ok := r.flows.Lookup(key, time.Now()); !ok {
		return nil, errTransparentUnauthorized
	}
	return packet, nil
}

func (r *transparentReader) isQuiescing() bool {
	return r.listeners != nil && r.listeners.isQuiescing()
}

// transparentPacketConn deliberately has a distinct dynamic type from
// *net.UDPConn.  That makes miekg/dns use PacketConnReader, allowing the
// authorization reader to reuse one bounded scratch buffer for dropped UDP
// packets while still writing responses through net.PacketConn.WriteTo.
type transparentPacketConn struct {
	*net.UDPConn
}

func transparentFlowKey(protocol string, localAddr, peerAddr net.Addr) (flowKey, error) {
	local, err := transparentEndpoint(localAddr)
	if err != nil {
		return flowKey{}, err
	}
	peer, err := transparentEndpoint(peerAddr)
	if err != nil {
		return flowKey{}, err
	}
	key := flowKey{Protocol: protocol, Local: local, Peer: peer}
	if err := validateAuthorizedFlowKey(key); err != nil {
		return flowKey{}, err
	}
	return key, nil
}

func transparentEndpoint(addr net.Addr) (netip.AddrPort, error) {
	if addr == nil {
		return netip.AddrPort{}, errors.New("missing transport address")
	}
	var endpoint netip.AddrPort
	switch typed := addr.(type) {
	case *net.UDPAddr:
		ip, ok := transparentNetIP(typed.IP)
		if !ok {
			return netip.AddrPort{}, fmt.Errorf("invalid UDP address %q", typed)
		}
		if typed.Zone != "" {
			ip = ip.WithZone(typed.Zone)
		}
		endpoint = netip.AddrPortFrom(ip, uint16(typed.Port))
	case *net.TCPAddr:
		ip, ok := transparentNetIP(typed.IP)
		if !ok {
			return netip.AddrPort{}, fmt.Errorf("invalid TCP address %q", typed)
		}
		if typed.Zone != "" {
			ip = ip.WithZone(typed.Zone)
		}
		endpoint = netip.AddrPortFrom(ip, uint16(typed.Port))
	default:
		parsed, err := netip.ParseAddrPort(addr.String())
		if err != nil {
			return netip.AddrPort{}, err
		}
		endpoint = parsed
	}
	return canonicalEndpoint(endpoint)
}

func transparentNetIP(ip net.IP) (netip.Addr, bool) {
	if ip4 := ip.To4(); ip4 != nil {
		return netip.AddrFrom4([4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}), true
	}
	return netip.AddrFromSlice(ip)
}

// transparentDNSHandler runs after raw authorization and miekg/dns packet
// framing.  It calls the existing filtering handler only to resolve the
// request, then writes its response through miekg's transport writer.
type transparentDNSHandler struct {
	listeners *transparentListeners
	service   *dnsService
	proto     dnsproxy.Proto
}

func (h transparentDNSHandler) ServeDNS(writer dns.ResponseWriter, request *dns.Msg) {
	if !h.listeners.acquireHandler() {
		_ = writer.Close()
		return
	}
	defer h.listeners.releaseHandler()

	peer, err := transparentEndpoint(writer.RemoteAddr())
	if err != nil {
		return
	}
	local := writer.LocalAddr()
	if _, err = transparentEndpoint(local); err != nil {
		return
	}

	dctx := &dnsproxy.DNSContext{
		Proto: h.proto,
		Addr:  peer,
		Req:   request,
		Conn: transparentContextConn{
			local:  local,
			remote: writer.RemoteAddr(),
		},
	}
	filter := filteringHandler{engine: &h.service.engine, flows: h.service.flows}
	err = filter.ServeDNS(context.Background(), h.service.proxy, dctx)
	if errors.Is(err, dnsproxy.ErrDrop) {
		return
	}
	if dctx.Res != nil {
		_ = writer.WriteMsg(dctx.Res)
	}
}

func (l *transparentListeners) acquireHandler() bool {
	l.handlerMu.Lock()
	defer l.handlerMu.Unlock()
	if l.handlerStopping {
		return false
	}
	select {
	case l.handlerGate <- struct{}{}:
		l.handlerWG.Add(1)
		return true
	default:
		return false
	}
}

func (l *transparentListeners) releaseHandler() {
	<-l.handlerGate
	l.handlerWG.Done()
}

type transparentContextConn struct {
	local  net.Addr
	remote net.Addr
}

func (transparentContextConn) Read([]byte) (int, error)    { return 0, io.EOF }
func (transparentContextConn) Write([]byte) (int, error)   { return 0, net.ErrClosed }
func (transparentContextConn) Close() error                { return nil }
func (c transparentContextConn) LocalAddr() net.Addr       { return c.local }
func (c transparentContextConn) RemoteAddr() net.Addr      { return c.remote }
func (transparentContextConn) SetDeadline(time.Time) error { return nil }
func (transparentContextConn) SetReadDeadline(time.Time) error {
	return nil
}
func (transparentContextConn) SetWriteDeadline(time.Time) error {
	return nil
}

type transparentTCPListener struct {
	net.Listener

	mu        sync.Mutex
	slots     chan struct{}
	conns     map[*transparentTCPConn]struct{}
	closed    bool
	quiescing bool
}

func newTransparentTCPListener(listener net.Listener) *transparentTCPListener {
	return &transparentTCPListener{
		Listener: listener,
		slots:    make(chan struct{}, transparentMaxTCPConns),
		conns:    make(map[*transparentTCPConn]struct{}),
	}
}

func (l *transparentTCPListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}

		l.mu.Lock()
		if l.closed {
			l.mu.Unlock()
			_ = conn.Close()
			return nil, net.ErrClosed
		}
		if l.quiescing {
			l.mu.Unlock()
			_ = transparentCloseError(transparentAbortiveClose(conn))
			continue
		}
		select {
		case l.slots <- struct{}{}:
			wrapped := &transparentTCPConn{Conn: conn, owner: l}
			l.conns[wrapped] = struct{}{}
			l.mu.Unlock()
			return wrapped, nil
		default:
			l.mu.Unlock()
			_ = conn.Close()
		}
	}
}

func (l *transparentTCPListener) quiesceConnections() error {
	l.mu.Lock()
	l.quiescing = true
	connections := make([]*transparentTCPConn, 0, len(l.conns))
	for conn := range l.conns {
		connections = append(connections, conn)
	}
	l.mu.Unlock()

	var err error
	for _, conn := range connections {
		err = errors.Join(err, transparentCloseError(conn.abortiveClose()))
	}
	return err
}

func (l *transparentTCPListener) release(conn *transparentTCPConn) {
	l.mu.Lock()
	if _, ok := l.conns[conn]; ok {
		delete(l.conns, conn)
		<-l.slots
	}
	l.mu.Unlock()
}

func (l *transparentTCPListener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	connections := make([]*transparentTCPConn, 0, len(l.conns))
	for conn := range l.conns {
		connections = append(connections, conn)
	}
	l.mu.Unlock()

	err := transparentCloseError(l.Listener.Close())
	for _, conn := range connections {
		err = errors.Join(err, transparentCloseError(conn.Close()))
	}
	return err
}

type transparentTCPConn struct {
	net.Conn
	owner *transparentTCPListener
	once  sync.Once
}

func (c *transparentTCPConn) Close() error {
	var err error
	c.once.Do(func() {
		err = c.Conn.Close()
		c.owner.release(c)
	})
	return err
}

func (c *transparentTCPConn) abortiveClose() error {
	var err error
	c.once.Do(func() {
		if linger, ok := c.Conn.(interface{ SetLinger(int) error }); ok {
			err = errors.Join(err, linger.SetLinger(0))
		}
		err = errors.Join(err, c.Conn.Close())
		c.owner.release(c)
	})
	return err
}

func transparentAbortiveClose(conn net.Conn) error {
	var err error
	if linger, ok := conn.(interface{ SetLinger(int) error }); ok {
		err = errors.Join(err, linger.SetLinger(0))
	}
	return errors.Join(err, conn.Close())
}

func transparentUDPBinding(addr *net.UDPAddr) (network, address string, err error) {
	if addr == nil {
		return "", "", errors.New("address is nil")
	}
	endpoint, err := transparentListenerEndpoint(addr.IP, addr.Zone, addr.Port)
	if err != nil {
		return "", "", err
	}
	if endpoint.Addr().Is4() {
		network = "udp4"
	} else {
		network = "udp6"
	}
	return network, endpoint.String(), nil
}

func transparentTCPBinding(addr *net.TCPAddr) (network, address string, err error) {
	if addr == nil {
		return "", "", errors.New("address is nil")
	}
	endpoint, err := transparentListenerEndpoint(addr.IP, addr.Zone, addr.Port)
	if err != nil {
		return "", "", err
	}
	if endpoint.Addr().Is4() {
		network = "tcp4"
	} else {
		network = "tcp6"
	}
	return network, endpoint.String(), nil
}

func transparentListenerEndpoint(ip net.IP, zone string, port int) (netip.AddrPort, error) {
	if ip == nil {
		return netip.AddrPort{}, errors.New("IP address is nil")
	}
	if port < 0 || port > 65535 {
		return netip.AddrPort{}, fmt.Errorf("invalid port %d", port)
	}
	parsed, ok := transparentNetIP(ip)
	if !ok {
		return netip.AddrPort{}, errors.New("invalid or mapped IP address")
	}
	if zone != "" {
		parsed = parsed.WithZone(zone)
	}
	if parsed.IsUnspecified() || parsed.IsMulticast() {
		return netip.AddrPort{}, errors.New("listener IP must be an explicit unicast address")
	}
	if !parsed.IsGlobalUnicast() && !parsed.IsLoopback() && !parsed.IsLinkLocalUnicast() {
		return netip.AddrPort{}, errors.New("listener IP must be unicast")
	}
	if parsed.Is4() && parsed.Zone() != "" {
		return netip.AddrPort{}, errors.New("IPv4 listener cannot have a zone")
	}
	if parsed.Is6() && parsed.IsLinkLocalUnicast() && parsed.Zone() == "" {
		return netip.AddrPort{}, errors.New("link-local listener requires a zone")
	}
	endpoint, err := canonicalEndpoint(netip.AddrPortFrom(parsed, uint16(port)))
	if err != nil {
		return netip.AddrPort{}, err
	}
	return endpoint, nil
}
