// The src-dnsproxy companion is intentionally self-contained.  The Tauri
// application can build and supervise it without changing this directory's
// dependency graph or touching Windows DNS and firewall state.
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	dnsproxy "github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/urlfilter"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/miekg/dns"
)

const (
	// maxRuleTextBytes is the maximum decoded feed text accepted by a start
	// command or config file.  It bounds both parser work and retained input.
	maxRuleTextBytes = 8 * 1024 * 1024

	// JSON escaping can double a decoded rules string (for example, newlines
	// become two bytes).  Keep a separate finite bound for one line and for a
	// config file while still accepting any list at the decoded limit.
	maxCommandBytes = 2*maxRuleTextBytes + 64*1024

	shutdownTimeout = 5 * time.Second
)

// config is the validated service configuration.  A zero listen port asks
// the OS for an ephemeral port, which is useful for tests.  Production may
// set 53; the process does not elevate itself or change system DNS settings.
type config struct {
	Upstream      string `json:"upstream"`
	ListenAddress string `json:"listen_address,omitempty"`
	ListenPort    int    `json:"listen_port,omitempty"`
	Rules         string `json:"rules,omitempty"`
}

type command struct {
	Op     string  `json:"op"`
	Config *config `json:"config,omitempty"`
}

type statusMessage struct {
	Status     string `json:"status"`
	Error      string `json:"error,omitempty"`
	UDPAddr    string `json:"udp_addr,omitempty"`
	TCPAddr    string `json:"tcp_addr,omitempty"`
	RulesCount uint64 `json:"rules_count,omitempty"`
}

// domainDecision is intentionally small because the command protocol only
// needs a block/allow decision and source text for future app diagnostics.
type domainDecision struct {
	Blocked   bool
	Exception bool
	Rule      string
}

type domainEngine struct {
	dns *urlfilter.DNSEngine
}

// newDomainEngine parses AdGuard network and host syntax before constructing
// urlfilter's indexes.  The caller can therefore reject an update without
// replacing a running service.
func newDomainEngine(rulesText string) (*domainEngine, error) {
	if len([]byte(rulesText)) > maxRuleTextBytes {
		return nil, fmt.Errorf("rules exceed %d bytes", maxRuleTextBytes)
	}
	if err := validateRules(rulesText); err != nil {
		return nil, err
	}

	list := filterlist.NewString(&filterlist.StringConfig{
		RulesText:      rulesText,
		ID:             rules.ListID(1),
		IgnoreCosmetic: true,
	})
	storage, err := filterlist.NewRuleStorage([]filterlist.Interface{list})
	if err != nil {
		return nil, fmt.Errorf("build rule storage: %w", err)
	}

	return &domainEngine{dns: urlfilter.NewDNSEngine(storage)}, nil
}

func (e *domainEngine) rulesCount() uint64 {
	if e == nil || e.dns == nil {
		return 0
	}
	return e.dns.RulesCount()
}

func (e *domainEngine) decideQuestion(hostname string, qtype uint16) domainDecision {
	if e == nil || e.dns == nil {
		return domainDecision{}
	}

	hostname = normalizeHostname(hostname)
	if hostname == "" {
		return domainDecision{}
	}

	result, matched := e.dns.MatchRequest(&urlfilter.DNSRequest{
		Hostname: hostname,
		DNSType:  rules.RRType(qtype),
	})
	if !matched || result == nil {
		return domainDecision{}
	}
	if result.NetworkRule != nil {
		decision := domainDecision{Rule: result.NetworkRule.Text()}
		if result.NetworkRule.Whitelist {
			decision.Exception = true
			return decision
		}
		decision.Blocked = true
		return decision
	}

	// Only conventional sink targets are blocking host entries.  Arbitrary
	// host mappings are rejected by validateRules rather than guessed to be
	// blocks.  Host entries apply only to their address-family query.
	if qtype == dns.TypeA {
		for _, hostRule := range result.HostRulesV4 {
			if isBlockingHostTarget(hostRule.IP) {
				return domainDecision{Blocked: true, Rule: hostRule.Text()}
			}
		}
	}
	if qtype == dns.TypeAAAA {
		for _, hostRule := range result.HostRulesV6 {
			if isBlockingHostTarget(hostRule.IP) {
				return domainDecision{Blocked: true, Rule: hostRule.Text()}
			}
		}
	}

	return domainDecision{}
}

func normalizeHostname(hostname string) string {
	hostname = strings.TrimSpace(hostname)
	hostname = strings.TrimSuffix(hostname, ".")
	return strings.ToLower(hostname)
}

var ipv4LoopbackSink = netip.MustParseAddr("127.0.0.1")

func isBlockingHostTarget(address netip.Addr) bool {
	return address.IsUnspecified() || address == ipv4LoopbackSink
}

func validateRules(rulesText string) error {
	for lineNumber, line := range strings.Split(rulesText, "\n") {
		line = strings.TrimSuffix(line, "\r")
		parsed, err := rules.NewRule(line, rules.ListID(1))
		if err != nil {
			return fmt.Errorf("parse AdGuard rule at line %d: %w", lineNumber+1, err)
		}

		switch rule := parsed.(type) {
		case *rules.HostRule:
			if !isBlockingHostTarget(rule.IP) {
				return fmt.Errorf(
					"unsupported hosts-file target at line %d (%q); only 0.0.0.0, ::, or 127.0.0.1 are blocking targets",
					lineNumber+1,
					line,
				)
			}
		case *rules.NetworkRule:
			if rule.DNSRewrite != nil {
				return fmt.Errorf(
					"unsupported DNS rewrite at line %d (%q); use a basic domain rule or implement rewrite handling explicitly",
					lineNumber+1,
					line,
				)
			}
		}
	}

	return nil
}

func validateUpstreamAddress(address string) error {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("upstream must be an explicit IP:port: %w", err)
	}
	if net.ParseIP(host) == nil {
		return fmt.Errorf("upstream host must be an IP address: %q", host)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("upstream port must be 1..65535: %q", portText)
	}
	return nil
}

func validateConfig(input config) (config, error) {
	input.Upstream = strings.TrimSpace(input.Upstream)
	if err := validateUpstreamAddress(input.Upstream); err != nil {
		return config{}, err
	}

	input.ListenAddress = strings.TrimSpace(input.ListenAddress)
	if input.ListenAddress == "" {
		input.ListenAddress = "127.0.0.1"
	}
	listenIP := net.ParseIP(input.ListenAddress)
	if listenIP == nil || !listenIP.IsLoopback() {
		return config{}, fmt.Errorf("listen_address must be a loopback IP address")
	}
	if input.ListenPort < 0 || input.ListenPort > 65535 {
		return config{}, fmt.Errorf("listen_port must be 0..65535: %d", input.ListenPort)
	}
	if len([]byte(input.Rules)) > maxRuleTextBytes {
		return config{}, fmt.Errorf("rules exceed %d bytes", maxRuleTextBytes)
	}
	if _, err := newDomainEngine(input.Rules); err != nil {
		return config{}, err
	}

	return input, nil
}

type dnsService struct {
	proxy *dnsproxy.Proxy
}

func newDNSService(cfg config, engine *domainEngine) (*dnsService, error) {
	if engine == nil || engine.dns == nil {
		return nil, fmt.Errorf("domain engine is required")
	}
	if err := validateUpstreamAddress(cfg.Upstream); err != nil {
		return nil, err
	}

	upstreams, err := dnsproxy.ParseUpstreamsConfig(
		[]string{"udp://" + cfg.Upstream},
		&upstream.Options{Timeout: 2 * time.Second},
	)
	if err != nil {
		return nil, fmt.Errorf("parse explicit DNS upstream: %w", err)
	}
	listenIP := net.ParseIP(cfg.ListenAddress)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := dnsproxy.New(&dnsproxy.Config{
		Logger: logger,
		UDPListenAddr: []*net.UDPAddr{{
			IP:   listenIP,
			Port: cfg.ListenPort,
		}},
		TCPListenAddr: []*net.TCPAddr{{
			IP:   listenIP,
			Port: cfg.ListenPort,
		}},
		UpstreamConfig: upstreams,
		RequestHandler: filteringHandler{engine: engine},
		CacheEnabled:   false,
		DNSSECEnabled:  false,
		RefuseAny:      true,
		MaxGoroutines:  64,
		UDPBufferSize:  2048,
	})
	if err != nil {
		return nil, fmt.Errorf("create DNS proxy: %w", err)
	}

	return &dnsService{proxy: server}, nil
}

func (s *dnsService) start() error {
	if s == nil || s.proxy == nil {
		return fmt.Errorf("DNS service is nil")
	}
	if err := s.proxy.Start(context.Background()); err != nil {
		return fmt.Errorf("start DNS proxy: %w", err)
	}
	return nil
}

func (s *dnsService) shutdown() error {
	if s == nil || s.proxy == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	return s.proxy.Shutdown(ctx)
}

func (s *dnsService) udpAddr() string {
	if s == nil || s.proxy == nil {
		return ""
	}
	if address := s.proxy.Addr(dnsproxy.ProtoUDP); address != nil {
		return address.String()
	}
	return ""
}

func (s *dnsService) tcpAddr() string {
	if s == nil || s.proxy == nil {
		return ""
	}
	if address := s.proxy.Addr(dnsproxy.ProtoTCP); address != nil {
		return address.String()
	}
	return ""
}

type filteringHandler struct {
	engine *domainEngine
}

func (h filteringHandler) ServeDNS(
	ctx context.Context,
	server *dnsproxy.Proxy,
	dctx *dnsproxy.DNSContext,
) error {
	for _, question := range dctx.Req.Question {
		if h.engine.decideQuestion(question.Name, question.Qtype).Blocked {
			response := (&dns.Msg{}).SetReply(dctx.Req)
			response.Authoritative = true
			response.Rcode = dns.RcodeNameError
			dctx.Res = response
			return nil
		}
	}
	return server.Resolve(ctx, dctx)
}
