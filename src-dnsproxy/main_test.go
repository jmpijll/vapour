package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const processTestTimeout = 10 * time.Second

func TestProtocolReportsInvalidStartAndStops(t *testing.T) {
	input := strings.NewReader(strings.Join([]string{
		`{"op":"start","config":{"upstream":"resolver.example.test:53","listen_port":0,"rules":"||ads.example.test^"}}`,
		`{"op":"stop"}`,
		"",
	}, "\n"))

	var output bytes.Buffer
	if err := runProtocol(input, &output); err != nil {
		t.Fatalf("runProtocol: %v", err)
	}

	statuses := decodeStatuses(t, output.Bytes())
	if len(statuses) != 2 {
		t.Fatalf("statuses = %#v, want error and stopped", statuses)
	}
	if statuses[0].Status != "error" || statuses[0].Error == "" {
		t.Fatalf("error status = %#v", statuses[0])
	}
	if statuses[1].Status != "stopped" {
		t.Fatalf("stopped status = %#v", statuses[1])
	}
}

func TestConfigValidationRejectsUnknownAndOversize(t *testing.T) {
	if _, err := decodeConfig([]byte(`{"upstream":"127.0.0.1:53","unexpected":true}`)); err == nil {
		t.Fatal("unknown config field was accepted")
	}
	if _, err := validateConfig(config{
		Upstream: "127.0.0.1:53",
		Rules:    strings.Repeat("x", maxRuleTextBytes+1),
	}); err == nil || !strings.Contains(err.Error(), "rules exceed") {
		t.Fatalf("oversize rules error = %v", err)
	}
}

func TestProcessStartStopOverPipesAndUDPAndTCP(t *testing.T) {
	binary := buildBinary(t)
	upstream := startSyntheticUpstream(t)
	child := startChild(t, binary)

	sendCommand(t, child.stdin, command{
		Op: "start",
		Config: &config{
			Upstream:      upstream.address(),
			ListenAddress: "127.0.0.1",
			ListenPort:    0,
			Rules: strings.Join([]string{
				"||ads.example.test^",
				"@@||allowed.ads.example.test^",
			}, "\n"),
		},
	})
	ready := child.readStatus(t)
	if ready.Status != "ready" || ready.UDPAddr == "" || ready.TCPAddr == "" || ready.RulesCount != 2 {
		t.Fatalf("ready status = %#v", ready)
	}
	assertLoopbackHighPort(t, ready.UDPAddr)
	assertLoopbackHighPort(t, ready.TCPAddr)

	blockedUDP := exchangeDNS(t, "udp", ready.UDPAddr, "ADS.EXAMPLE.TEST.", dns.TypeA)
	if blockedUDP.Rcode != dns.RcodeNameError || len(blockedUDP.Answer) != 0 {
		t.Fatalf("blocked UDP response: rcode=%d answers=%v", blockedUDP.Rcode, blockedUDP.Answer)
	}
	if got := atomic.LoadInt32(&upstream.queries); got != 0 {
		t.Fatalf("blocked UDP reached upstream %d times", got)
	}

	allowedUDP := exchangeDNS(t, "udp", ready.UDPAddr, "allowed.ads.example.test.", dns.TypeAAAA)
	assertAAAA(t, allowedUDP, "2001:db8::42")
	if got := atomic.LoadInt32(&upstream.queries); got != 1 {
		t.Fatalf("allowed UDP upstream count = %d, want 1", got)
	}

	blockedTCP := exchangeDNS(t, "tcp", ready.TCPAddr, "ads.example.test.", dns.TypeAAAA)
	if blockedTCP.Rcode != dns.RcodeNameError || len(blockedTCP.Answer) != 0 {
		t.Fatalf("blocked TCP response: rcode=%d answers=%v", blockedTCP.Rcode, blockedTCP.Answer)
	}
	if got := atomic.LoadInt32(&upstream.queries); got != 1 {
		t.Fatalf("blocked TCP reached upstream; count = %d", got)
	}

	allowedTCP := exchangeDNS(t, "tcp", ready.TCPAddr, "allowed.ads.example.test.", dns.TypeAAAA)
	assertAAAA(t, allowedTCP, "2001:db8::42")
	if got := atomic.LoadInt32(&upstream.queries); got != 2 {
		t.Fatalf("allowed TCP upstream count = %d, want 2", got)
	}

	controlTCP := exchangeDNS(t, "tcp", ready.TCPAddr, "control.example.test.", dns.TypeA)
	assertA(t, controlTCP, "192.0.2.42")
	if got := atomic.LoadInt32(&upstream.queries); got != 3 {
		t.Fatalf("control TCP upstream count = %d, want 3", got)
	}

	sendCommand(t, child.stdin, command{Op: "stop"})
	stopped := child.readStatus(t)
	if stopped.Status != "stopped" {
		t.Fatalf("stop status = %#v", stopped)
	}
	child.wait(t)
	if got := child.stderr.String(); got != "" {
		t.Fatalf("child wrote unexpected stderr (query logging would be a regression): %q", got)
	}
}

func TestProcessEOFGracefullyStops(t *testing.T) {
	binary := buildBinary(t)
	upstream := startSyntheticUpstream(t)
	child := startChild(t, binary)

	sendCommand(t, child.stdin, command{
		Op: "start",
		Config: &config{
			Upstream:   upstream.address(),
			ListenPort: 0,
			Rules:      "||ads.example.test^",
		},
	})
	ready := child.readStatus(t)
	if ready.Status != "ready" {
		t.Fatalf("ready status = %#v", ready)
	}
	if err := child.stdin.Close(); err != nil {
		t.Fatalf("close stdin: %v", err)
	}

	stopped := child.readStatus(t)
	if stopped.Status != "stopped" {
		t.Fatalf("EOF status = %#v", stopped)
	}
	child.wait(t)
	if got := child.stderr.String(); got != "" {
		t.Fatalf("child wrote unexpected stderr: %q", got)
	}
}

func TestConfigFileFlagStartsAndStopsOnEOF(t *testing.T) {
	binary := buildBinary(t)
	upstream := startSyntheticUpstream(t)
	configPath := filepath.Join(t.TempDir(), "dnsproxy.json")
	data, err := json.Marshal(config{
		Upstream:      upstream.address(),
		ListenAddress: "127.0.0.1",
		ListenPort:    0,
		Rules:         "||ads.example.test^",
	})
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	child := startChildWithArgs(t, binary, "--config-file", configPath)
	ready := child.readStatus(t)
	if ready.Status != "ready" || ready.UDPAddr == "" || ready.TCPAddr == "" {
		t.Fatalf("config-file ready status = %#v", ready)
	}
	if err := child.stdin.Close(); err != nil {
		t.Fatalf("close stdin: %v", err)
	}
	stopped := child.readStatus(t)
	if stopped.Status != "stopped" {
		t.Fatalf("config-file stopped status = %#v", stopped)
	}
	child.wait(t)
}

func buildBinary(t *testing.T) string {
	t.Helper()
	goTool := os.Getenv("GO_BIN")
	if goTool == "" {
		goTool = "go"
	}
	extension := ""
	if runtime.GOOS == "windows" {
		extension = ".exe"
	}
	binary := filepath.Join(t.TempDir(), "vapour-dnsproxy"+extension)
	build := exec.Command(goTool, "build", "-o", binary, ".")
	build.Dir, _ = os.Getwd()
	output, err := build.CombinedOutput()
	if err != nil {
		t.Fatalf("go build: %v\n%s", err, output)
	}
	return binary
}

type childProcess struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	stderr *bytes.Buffer
	waited bool
}

func startChild(t *testing.T, binary string) *childProcess {
	t.Helper()
	return startChildWithArgs(t, binary)
}

func startChildWithArgs(t *testing.T, binary string, args ...string) *childProcess {
	t.Helper()
	cmd := exec.Command(binary, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	child := &childProcess{cmd: cmd, stdin: stdin, stdout: bufio.NewReader(stdout), stderr: stderr}
	t.Cleanup(func() {
		if child.waited {
			return
		}
		_ = child.stdin.Close()
		_ = child.cmd.Process.Kill()
		_ = child.cmd.Wait()
		child.waited = true
	})
	return child
}

func sendCommand(t *testing.T, writer io.Writer, cmd command) {
	t.Helper()
	if err := json.NewEncoder(writer).Encode(cmd); err != nil {
		t.Fatalf("encode command: %v", err)
	}
}

func (c *childProcess) readStatus(t *testing.T) statusMessage {
	t.Helper()
	type result struct {
		line []byte
		err  error
	}
	resultCh := make(chan result, 1)
	go func() {
		line, err := c.stdout.ReadBytes('\n')
		resultCh <- result{line: line, err: err}
	}()
	timer := time.NewTimer(processTestTimeout)
	defer timer.Stop()
	select {
	case result := <-resultCh:
		if result.err != nil {
			t.Fatalf("read status: %v", result.err)
		}
		var status statusMessage
		if err := json.Unmarshal(result.line, &status); err != nil {
			t.Fatalf("decode status %q: %v", result.line, err)
		}
		return status
	case <-timer.C:
		t.Fatalf("timed out waiting for status")
		return statusMessage{}
	}
}

func (c *childProcess) wait(t *testing.T) {
	t.Helper()
	if c.waited {
		return
	}
	done := make(chan error, 1)
	go func() { done <- c.cmd.Wait() }()
	timer := time.NewTimer(processTestTimeout)
	defer timer.Stop()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("child exit: %v", err)
		}
		c.waited = true
	case <-timer.C:
		_ = c.cmd.Process.Kill()
		t.Fatalf("timed out waiting for child exit")
	}
}

func decodeStatuses(t *testing.T, data []byte) []statusMessage {
	t.Helper()
	var statuses []statusMessage
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		var status statusMessage
		if err := json.Unmarshal(scanner.Bytes(), &status); err != nil {
			t.Fatalf("decode status %q: %v", scanner.Bytes(), err)
		}
		statuses = append(statuses, status)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan statuses: %v", err)
	}
	return statuses
}

func assertLoopbackHighPort(t *testing.T, address string) {
	t.Helper()
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", address, err)
	}
	if !net.ParseIP(host).IsLoopback() {
		t.Fatalf("listener %q is not loopback", address)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 1024 {
		t.Fatalf("listener %q is not an ephemeral high port", address)
	}
}

func exchangeDNS(t *testing.T, network, address, name string, qtype uint16) *dns.Msg {
	t.Helper()
	client := &dns.Client{Net: network, Timeout: processTestTimeout}
	request := (&dns.Msg{}).SetQuestion(name, qtype)
	response, _, err := client.Exchange(request, address)
	if err != nil {
		t.Fatalf("DNS %s %s: %v", network, name, err)
	}
	return response
}

func assertA(t *testing.T, response *dns.Msg, want string) {
	t.Helper()
	if response.Rcode != dns.RcodeSuccess || len(response.Answer) != 1 {
		t.Fatalf("A response: rcode=%d answers=%v", response.Rcode, response.Answer)
	}
	a, ok := response.Answer[0].(*dns.A)
	if !ok || a.A.String() != want {
		t.Fatalf("A answer = %v, want %s", response.Answer[0], want)
	}
}

func assertAAAA(t *testing.T, response *dns.Msg, want string) {
	t.Helper()
	if response.Rcode != dns.RcodeSuccess || len(response.Answer) != 1 {
		t.Fatalf("AAAA response: rcode=%d answers=%v", response.Rcode, response.Answer)
	}
	aaaa, ok := response.Answer[0].(*dns.AAAA)
	if !ok || aaaa.AAAA.String() != want {
		t.Fatalf("AAAA answer = %v, want %s", response.Answer[0], want)
	}
}

type syntheticUpstream struct {
	udpServer *dns.Server
	tcpServer *dns.Server
	udpConn   *net.UDPConn
	tcpConn   *net.TCPListener
	queries   int32
}

func startSyntheticUpstream(t *testing.T) *syntheticUpstream {
	t.Helper()
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	port := udpConn.LocalAddr().(*net.UDPAddr).Port
	tcpConn, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		_ = udpConn.Close()
		t.Fatalf("ListenTCP: %v", err)
	}

	upstream := &syntheticUpstream{udpConn: udpConn, tcpConn: tcpConn}
	handler := dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		atomic.AddInt32(&upstream.queries, 1)
		response := (&dns.Msg{}).SetReply(request)
		response.Authoritative = true
		if len(request.Question) > 0 {
			question := request.Question[0]
			switch question.Qtype {
			case dns.TypeA:
				response.Answer = append(response.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
					A:   net.ParseIP("192.0.2.42"),
				})
			case dns.TypeAAAA:
				response.Answer = append(response.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: question.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 30},
					AAAA: net.ParseIP("2001:db8::42"),
				})
			}
		}
		_ = writer.WriteMsg(response)
	})
	upstream.udpServer = &dns.Server{PacketConn: udpConn, Handler: handler}
	upstream.tcpServer = &dns.Server{Listener: tcpConn, Handler: handler}
	go func() { _ = upstream.udpServer.ActivateAndServe() }()
	go func() { _ = upstream.tcpServer.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = upstream.udpServer.Shutdown()
		_ = upstream.tcpServer.Shutdown()
	})
	return upstream
}

func (s *syntheticUpstream) address() string {
	return fmt.Sprintf("127.0.0.1:%d", s.udpConn.LocalAddr().(*net.UDPAddr).Port)
}
