package strategylab

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const strategyQueueNumber = 64610

// ProbeTarget is deliberately resolved from the trusted service catalog by the
// API. The browser cannot supply an arbitrary URL to the router.
type ProbeTarget struct {
	ServiceID string
	ProbeURL  string
	Protocol  string
	IPFamily  string
}

type ProbeExecutor interface {
	Execute(context.Context, Candidate, ProbeTarget) (Evidence, error)
}

// SystemProbeExecutor runs one serialized, narrowly scoped NFQUEUE probe. It
// never edits an engine config or the default route. Its temporary OUTPUT rule
// is limited to one destination IP, destination port and reserved source port.
type SystemProbeExecutor struct {
	mu sync.Mutex
}

func (x *SystemProbeExecutor) Execute(ctx context.Context, candidate Candidate, target ProbeTarget) (evidence Evidence, returnErr error) {
	x.mu.Lock()
	defer x.mu.Unlock()

	started := time.Now()
	evidence = Evidence{CandidateID: candidate.ID, ServiceID: target.ServiceID, Protocol: target.Protocol, IPFamily: target.IPFamily, CheckedAt: started.UTC().Format(time.RFC3339)}
	stage := func(name, status, detail string, began time.Time) {
		evidence.Stages = append(evidence.Stages, StageEvidence{Stage: name, Status: status, Detail: shortProbeText(detail), Elapsed: time.Since(began).Milliseconds()})
	}
	if runtime.GOOS != "linux" {
		return evidence, errors.New("изолированный NFQUEUE-тест доступен только на Linux/Entware")
	}
	if target.Protocol != "tcp" && target.Protocol != "quic" {
		return evidence, errors.New("обычный UDP требует сервисного протокола; доступен отдельный настоящий HTTP/3/QUIC-тест")
	}
	if target.IPFamily == "" {
		target.IPFamily = "ipv4"
		evidence.IPFamily = target.IPFamily
	}
	if !validFamily(target.IPFamily) {
		return evidence, errors.New("IP family must be ipv4 or ipv6")
	}
	u, err := validateStrategyProbeURL(target.ProbeURL)
	if err != nil {
		return evidence, err
	}
	arguments, err := parseArguments(candidate.Arguments)
	if err != nil {
		return evidence, err
	}
	preflightStarted := time.Now()
	nfqwsBinary := findNFQWS2()
	iptablesBinary := findProbeBinary(map[bool][]string{
		true:  {"/opt/sbin/ip6tables", "/opt/bin/ip6tables", "/usr/sbin/ip6tables", "ip6tables"},
		false: {"/opt/sbin/iptables", "/opt/bin/iptables", "/usr/sbin/iptables", "iptables"},
	}[target.IPFamily == "ipv6"])
	if nfqwsBinary == "" || iptablesBinary == "" {
		stage("preflight", "fail", "нужны NFQWS2 и iptables/ip6tables", preflightStarted)
		return evidence, nil
	}
	if externalZ2KActive() {
		stage("preflight", "fail", "обнаружен активный внешний z2k; второй NFQWS2 запрещён до передачи ownership", preflightStarted)
		return evidence, nil
	}
	if queueInUse(strategyQueueNumber) {
		stage("preflight", "fail", fmt.Sprintf("NFQUEUE %d уже занята", strategyQueueNumber), preflightStarted)
		return evidence, nil
	}
	stage("preflight", "pass", fmt.Sprintf("%s + %s; отдельная очередь %d", nfqwsBinary, iptablesBinary, strategyQueueNumber), preflightStarted)

	dnsStarted := time.Now()
	address, err := resolvePublicAddress(ctx, u.Hostname(), target.IPFamily)
	if err != nil {
		stage("dns", "fail", err.Error(), dnsStarted)
		return evidence, nil
	}
	stage("dns", "pass", address.String(), dnsStarted)

	port, err := reserveProbePort(target.Protocol, target.IPFamily)
	if err != nil {
		stage("socket", "fail", err.Error(), time.Now())
		return evidence, nil
	}
	chain, err := randomProbeChain()
	if err != nil {
		return evidence, err
	}
	destinationPort := 443
	transportProtocol := "tcp"
	if target.Protocol == "quic" {
		transportProtocol = "udp"
	}
	jumpArgs := []string{"-t", "mangle", "-D", "OUTPUT", "-p", transportProtocol, "-d", address.String(), "--dport", strconv.Itoa(destinationPort), "--sport", strconv.Itoa(port), "-j", chain}
	chainCreated, jumpCreated := false, false
	var process *exec.Cmd
	var processDone chan error
	var processOutput boundedBuffer
	defer func() {
		cleanupStarted := time.Now()
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cleanupCancel()
		cleanupErrors := make([]string, 0, 3)
		if jumpCreated {
			if _, err := runProbeCommand(cleanupContext, iptablesBinary, jumpArgs...); err != nil {
				cleanupErrors = append(cleanupErrors, "jump: "+err.Error())
			}
		}
		if chainCreated {
			if _, err := runProbeCommand(cleanupContext, iptablesBinary, "-t", "mangle", "-F", chain); err != nil {
				cleanupErrors = append(cleanupErrors, "flush: "+err.Error())
			}
			if _, err := runProbeCommand(cleanupContext, iptablesBinary, "-t", "mangle", "-X", chain); err != nil {
				cleanupErrors = append(cleanupErrors, "chain: "+err.Error())
			}
		}
		if process != nil && process.Process != nil {
			_ = process.Process.Kill()
			select {
			case <-processDone:
			case <-time.After(2 * time.Second):
				cleanupErrors = append(cleanupErrors, "NFQWS2 process did not exit")
			}
		}
		if len(cleanupErrors) > 0 {
			evidence.Success = false
			stage("cleanup", "fail", strings.Join(cleanupErrors, "; "), cleanupStarted)
		} else {
			stage("cleanup", "pass", "временная цепочка и процесс удалены", cleanupStarted)
		}
		evidence.LatencyMS = time.Since(started).Milliseconds()
	}()

	processStarted := time.Now()
	processArgs := []string{"--qnum=" + strconv.Itoa(strategyQueueNumber)}
	processArgs = append(processArgs, installedBaseArguments()...)
	processArgs = append(processArgs, arguments...)
	process = exec.CommandContext(ctx, nfqwsBinary, processArgs...)
	process.Stdout, process.Stderr = &processOutput, &processOutput
	if err := process.Start(); err != nil {
		stage("nfqws2", "fail", err.Error(), processStarted)
		return evidence, nil
	}
	processDone = make(chan error, 1)
	go func() { processDone <- process.Wait() }()
	select {
	case err := <-processDone:
		process = nil
		detail := processOutput.String()
		if detail == "" && err != nil {
			detail = err.Error()
		}
		stage("nfqws2", "fail", detail, processStarted)
		return evidence, nil
	case <-time.After(180 * time.Millisecond):
		stage("nfqws2", "pass", fmt.Sprintf("временный процесс слушает очередь %d", strategyQueueNumber), processStarted)
	case <-ctx.Done():
		stage("nfqws2", "fail", ctx.Err().Error(), processStarted)
		return evidence, nil
	}

	firewallStarted := time.Now()
	if output, err := runProbeCommand(ctx, iptablesBinary, "-t", "mangle", "-N", chain); err != nil {
		stage("firewall", "fail", output, firewallStarted)
		return evidence, nil
	}
	chainCreated = true
	if output, err := runProbeCommand(ctx, iptablesBinary, "-t", "mangle", "-A", chain, "-j", "NFQUEUE", "--queue-num", strconv.Itoa(strategyQueueNumber)); err != nil {
		stage("firewall", "fail", output, firewallStarted)
		return evidence, nil
	}
	insertArgs := append([]string(nil), jumpArgs...)
	insertArgs[2] = "-I"
	insertArgs = append(insertArgs[:4], append([]string{"1"}, insertArgs[4:]...)...)
	if output, err := runProbeCommand(ctx, iptablesBinary, insertArgs...); err != nil {
		stage("firewall", "fail", output, firewallStarted)
		return evidence, nil
	}
	jumpCreated = true
	stage("firewall", "pass", fmt.Sprintf("только %s:%d, source-port %d", address, destinationPort, port), firewallStarted)

	var httpStatus int
	var traceStages []StageEvidence
	var requestErr error
	if target.Protocol == "quic" {
		httpStatus, traceStages, requestErr = executePinnedHTTP3(ctx, u, address, port, target.IPFamily)
	} else {
		httpStatus, traceStages, requestErr = executePinnedHTTPS(ctx, u, address, port, target.IPFamily)
	}
	evidence.Stages = append(evidence.Stages, traceStages...)
	processAlive := true
	select {
	case err := <-processDone:
		processAlive = false
		process = nil
		stage("nfqws2-exit", "fail", fmt.Sprintf("%v: %s", err, processOutput.String()), time.Now())
	default:
	}
	counterOutput, counterErr := runProbeCommand(ctx, iptablesBinary, "-t", "mangle", "-L", chain, "-v", "-n", "-x")
	packets := parseNFQueuePackets(counterOutput)
	evidence.RouteConfirmed = processAlive && counterErr == nil && packets > 0
	if evidence.RouteConfirmed {
		stage("route", "pass", fmt.Sprintf("NFQUEUE получила %d пакетов", packets), time.Now())
	} else {
		stage("route", "fail", fmt.Sprintf("маршрут не подтверждён: packets=%d process_alive=%t", packets, processAlive), time.Now())
	}
	if requestErr != nil {
		stage("result", "fail", requestErr.Error(), time.Now())
		return evidence, nil
	}
	evidence.Success = evidence.RouteConfirmed && httpStatus >= 200 && httpStatus < 400
	if evidence.Success {
		stage("result", "pass", fmt.Sprintf("HTTP %d через изолированную очередь", httpStatus), time.Now())
	} else {
		stage("result", "fail", fmt.Sprintf("HTTP %d не считается доступным сервисом", httpStatus), time.Now())
	}
	return evidence, nil
}

func validateStrategyProbeURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Port() != "" && u.Port() != "443" {
		return nil, errors.New("сервису нужен публичный HTTPS probe URL на порту 443")
	}
	return u, nil
}

func resolvePublicAddress(ctx context.Context, host, family string) (netip.Addr, error) {
	network := "ip4"
	if family == "ipv6" {
		network = "ip6"
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, network, host)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, address := range addresses {
		address = address.Unmap()
		if address.IsValid() && address.IsGlobalUnicast() && !address.IsPrivate() && !address.IsLoopback() && !address.IsLinkLocalUnicast() {
			return address, nil
		}
	}
	return netip.Addr{}, errors.New("DNS не вернул публичный адрес нужного семейства")
}

func reserveProbePort(protocol, family string) (int, error) {
	if protocol == "quic" {
		address := &net.UDPAddr{IP: net.IPv4zero}
		network := "udp4"
		if family == "ipv6" {
			address, network = &net.UDPAddr{IP: net.IPv6unspecified}, "udp6"
		}
		connection, err := net.ListenUDP(network, address)
		if err != nil {
			return 0, err
		}
		port := connection.LocalAddr().(*net.UDPAddr).Port
		if err := connection.Close(); err != nil {
			return 0, err
		}
		return port, nil
	}
	address := "0.0.0.0:0"
	network := "tcp4"
	if family == "ipv6" {
		address, network = "[::]:0", "tcp6"
	}
	listener, err := net.Listen(network, address)
	if err != nil {
		return 0, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		return 0, err
	}
	return port, nil
}

func executePinnedHTTPS(ctx context.Context, u *url.URL, address netip.Addr, sourcePort int, family string) (int, []StageEvidence, error) {
	started := time.Now()
	localIP := net.IPv4zero
	network := "tcp4"
	if family == "ipv6" {
		localIP, network = net.IPv6unspecified, "tcp6"
	}
	dialer := &net.Dialer{Timeout: 6 * time.Second, LocalAddr: &net.TCPAddr{IP: localIP, Port: sourcePort}}
	transport := &http.Transport{
		Proxy: nil, DisableKeepAlives: true, ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, net.JoinHostPort(address.String(), "443"))
		},
	}
	defer transport.CloseIdleConnections()
	var mu sync.Mutex
	tcpAt, tlsAt, firstByteAt := time.Time{}, time.Time{}, time.Time{}
	trace := &httptrace.ClientTrace{
		ConnectDone: func(_, _ string, err error) {
			if err == nil {
				mu.Lock()
				tcpAt = time.Now()
				mu.Unlock()
			}
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			if err == nil {
				mu.Lock()
				tlsAt = time.Now()
				mu.Unlock()
			}
		},
		GotFirstResponseByte: func() { mu.Lock(); firstByteAt = time.Now(); mu.Unlock() },
	}
	request, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, u.String(), nil)
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("User-Agent", "RAZVILKA-Strategy-Lab/0.11")
	request.Header.Set("Accept", "text/html,application/json;q=0.9,*/*;q=0.1")
	request.Header.Set("Range", "bytes=0-4095")
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, requestErr := client.Do(request)
	mu.Lock()
	tcpCopy, tlsCopy, firstByteCopy := tcpAt, tlsAt, firstByteAt
	mu.Unlock()
	stages := make([]StageEvidence, 0, 3)
	traceStage := func(name string, at time.Time) {
		status, detail, elapsed := "fail", "этап не подтверждён", int64(0)
		if !at.IsZero() {
			status, detail, elapsed = "pass", "подтверждено сетевым trace", at.Sub(started).Milliseconds()
		}
		stages = append(stages, StageEvidence{Stage: name, Status: status, Detail: detail, Elapsed: elapsed})
	}
	traceStage("tcp", tcpCopy)
	traceStage("tls", tlsCopy)
	traceStage("first-byte", firstByteCopy)
	if requestErr != nil {
		return 0, stages, requestErr
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	return response.StatusCode, stages, nil
}

func executePinnedHTTP3(ctx context.Context, u *url.URL, address netip.Addr, sourcePort int, family string) (int, []StageEvidence, error) {
	started := time.Now()
	localAddress := &net.UDPAddr{IP: net.IPv4zero, Port: sourcePort}
	network := "udp4"
	if family == "ipv6" {
		localAddress, network = &net.UDPAddr{IP: net.IPv6unspecified, Port: sourcePort}, "udp6"
	}
	udpConnection, err := net.ListenUDP(network, localAddress)
	if err != nil {
		return 0, []StageEvidence{{Stage: "udp", Status: "fail", Detail: shortProbeText(err.Error())}}, err
	}
	defer udpConnection.Close()
	quicTransport := &quic.Transport{Conn: udpConnection}
	defer quicTransport.Close()
	remoteAddress := &net.UDPAddr{IP: net.IP(address.AsSlice()), Port: 443}
	var mu sync.Mutex
	handshakeAt, firstByteAt := time.Time{}, time.Time{}
	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS13, NextProtos: []string{http3.NextProtoH3}},
		QUICConfig:      &quic.Config{HandshakeIdleTimeout: 6 * time.Second, MaxIdleTimeout: 8 * time.Second},
		Dial: func(dialContext context.Context, _ string, tlsConfig *tls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
			connection, dialErr := quicTransport.Dial(dialContext, remoteAddress, tlsConfig, quicConfig)
			if dialErr == nil {
				mu.Lock()
				handshakeAt = time.Now()
				mu.Unlock()
			}
			return connection, dialErr
		},
	}
	defer transport.Close()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("User-Agent", "RAZVILKA-Strategy-Lab/0.11")
	request.Header.Set("Accept", "text/html,application/json;q=0.9,*/*;q=0.1")
	request.Header.Set("Range", "bytes=0-4095")
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, requestErr := client.Do(request)
	if requestErr == nil {
		firstByteAt = time.Now()
	}
	mu.Lock()
	handshakeCopy := handshakeAt
	mu.Unlock()
	stages := []StageEvidence{{Stage: "udp", Status: "pass", Detail: fmt.Sprintf("source-port %d", sourcePort)}}
	traceStage := func(name string, at time.Time) {
		status, detail, elapsed := "fail", "этап не подтверждён", int64(0)
		if !at.IsZero() {
			status, detail, elapsed = "pass", "подтверждено HTTP/3 transport", at.Sub(started).Milliseconds()
		}
		stages = append(stages, StageEvidence{Stage: name, Status: status, Detail: detail, Elapsed: elapsed})
	}
	traceStage("quic-handshake", handshakeCopy)
	traceStage("h3-first-byte", firstByteAt)
	if requestErr != nil {
		return 0, stages, requestErr
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	return response.StatusCode, stages, nil
}

func findProbeBinary(candidates []string) string {
	for _, candidate := range candidates {
		if strings.Contains(candidate, "/") {
			if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
				return candidate
			}
			continue
		}
		if found, err := exec.LookPath(candidate); err == nil {
			return found
		}
	}
	return ""
}

func installedBaseArguments() []string {
	for _, path := range []string{"/opt/etc/nfqws2/nfqws2.conf", "/etc/nfqws2/nfqws2.conf"} {
		data, err := os.ReadFile(path)
		if err != nil || len(data) > 2<<20 {
			continue
		}
		value, ok := shellAssignment(string(data), "NFQWS_BASE_ARGS")
		if !ok {
			continue
		}
		arguments, err := parseArguments(value)
		if err == nil {
			return arguments
		}
	}
	return nil
}

func shellAssignment(content, key string) (string, bool) {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	offset := 0
	for offset < len(content) {
		end := strings.IndexByte(content[offset:], '\n')
		if end < 0 {
			end = len(content) - offset
		}
		lineStart, lineEnd := offset, offset+end
		line := strings.TrimSpace(content[lineStart:lineEnd])
		line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		name, raw, found := strings.Cut(line, "=")
		if found && strings.TrimSpace(name) == key {
			rawOffset := strings.Index(content[lineStart:lineEnd], "=") + lineStart + 1
			for rawOffset < len(content) && (content[rawOffset] == ' ' || content[rawOffset] == '\t') {
				rawOffset++
			}
			if rawOffset >= len(content) {
				return "", true
			}
			quote := content[rawOffset]
			if quote != '\'' && quote != '"' {
				value := strings.TrimSpace(raw)
				if index := strings.IndexByte(value, '#'); index >= 0 {
					value = strings.TrimSpace(value[:index])
				}
				return value, true
			}
			var value strings.Builder
			escaped := false
			for i := rawOffset + 1; i < len(content); i++ {
				char := content[i]
				if escaped {
					value.WriteByte(char)
					escaped = false
					continue
				}
				if char == '\\' && quote == '"' {
					escaped = true
					value.WriteByte(char)
					continue
				}
				if char == quote {
					return value.String(), true
				}
				value.WriteByte(char)
			}
			return "", false
		}
		offset = lineEnd + 1
	}
	return "", false
}

func externalZ2KActive() bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		data, err := os.ReadFile("/proc/" + entry.Name() + "/cmdline")
		if err == nil && strings.Contains(strings.ToLower(string(data)), "/opt/zapret2/") {
			return true
		}
	}
	return false
}

func queueInUse(number int) bool {
	data, err := os.ReadFile("/proc/net/netfilter/nfnetlink_queue")
	if err != nil {
		return false
	}
	want := strconv.Itoa(number)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == want {
			return true
		}
	}
	return false
}

func randomProbeChain() (string, error) {
	random := make([]byte, 4)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return "RZST" + strings.ToUpper(hex.EncodeToString(random)), nil
}

func runProbeCommand(ctx context.Context, binary string, arguments ...string) (string, error) {
	var output boundedBuffer
	command := exec.CommandContext(ctx, binary, arguments...)
	command.Stdout, command.Stderr = &output, &output
	err := command.Run()
	return output.String(), err
}

func parseNFQueuePackets(output string) int64 {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || !strings.EqualFold(fields[2], "NFQUEUE") {
			continue
		}
		packets, err := strconv.ParseInt(fields[0], 10, 64)
		if err == nil {
			return packets
		}
	}
	return 0
}

type boundedBuffer struct {
	bytes.Buffer
}

func (b *boundedBuffer) Write(data []byte) (int, error) {
	const limit = 8192
	written := len(data)
	if len(data) >= limit {
		b.Buffer.Reset()
		_, _ = b.Buffer.Write(data[len(data)-limit:])
		return written, nil
	}
	if b.Len()+len(data) > limit {
		current := append([]byte(nil), b.Bytes()...)
		keep := limit - len(data)
		b.Buffer.Reset()
		_, _ = b.Buffer.Write(current[len(current)-keep:])
	}
	_, _ = b.Buffer.Write(data)
	return written, nil
}

func shortProbeText(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 600 {
		return value[:600] + "…"
	}
	return value
}
