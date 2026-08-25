package routeprobe

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/engine"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/systemprobe"
	"github.com/ArtixSx/razvilka/internal/testlab"
)

type Manager struct {
	Configs       *engineconfig.Manager
	DataplaneRoot string
	Statuses      func() []engine.Status
	System        func() systemprobe.Snapshot
	Timeout       time.Duration
	nfqwsMu       sync.Mutex
}

func New(configs *engineconfig.Manager) *Manager {
	return &Manager{
		Configs:       configs,
		DataplaneRoot: "/opt/var/lib/razvilka/dataplane",
		Statuses:      func() []engine.Status { return (engine.Detector{}).All() },
		System:        systemprobe.Probe,
		Timeout:       12 * time.Second,
	}
}

func (m *Manager) Probe(ctx context.Context, service catalog.Service, route string) testlab.Result {
	result := testlab.Result{ServiceID: service.ID, ServiceName: service.Name, ProbeURL: service.ProbeURL, Route: route, Status: "not-ready", CheckedAt: time.Now().UTC().Format(time.RFC3339)}
	if err := validateProbeURL(service.ProbeURL); err != nil {
		result.Detail = err.Error()
		return result
	}
	if route != "direct" {
		status, ok := m.engineStatus(route)
		if !ok || !status.Installed {
			result.Detail = "engine is not installed"
			return result
		}
		if !status.Running && route != "warp-wg" && route != "amneziawg" {
			result.Detail = "engine is installed but not running"
			return result
		}
	}

	var client *http.Client
	var evidence string
	var confirmed bool
	var err error
	switch route {
	case "direct":
		client, evidence, confirmed, err = m.directClient(service.ProbeURL)
	case "usque", "sing-box", "xray":
		client, evidence, confirmed, err = m.socksClient(route)
	case "warp-wg", "amneziawg":
		client, evidence, confirmed, err = m.interfaceClient(route, service.ProbeURL)
	case "nfqws2":
		return m.probeNFQWS(ctx, service)
	default:
		err = errors.New("route has no isolated probe adapter")
	}
	if err != nil {
		result.Detail = err.Error()
		return result
	}
	result = probeHTTP(ctx, client, service, route, evidence, confirmed)
	if confirmed && (result.Status == "pass" || result.Status == "partial") {
		result.EgressIP = probeEgress(ctx, client)
	}
	return result
}

func (m *Manager) probeNFQWS(ctx context.Context, service catalog.Service) (result testlab.Result) {
	m.nfqwsMu.Lock()
	defer m.nfqwsMu.Unlock()

	result = testlab.Result{ServiceID: service.ID, ServiceName: service.Name, ProbeURL: service.ProbeURL, Route: "nfqws2", Status: "not-ready", CheckedAt: time.Now().UTC().Format(time.RFC3339)}
	u, err := url.Parse(service.ProbeURL)
	if err != nil || u.Port() != "" && u.Port() != "443" {
		result.Detail = "NFQWS2 probe requires a public HTTPS endpoint on port 443"
		return result
	}
	address, err := resolvePublicIPv4(ctx, u.Hostname())
	if err != nil {
		result.Detail = err.Error()
		return result
	}
	iptablesBinary := findSystemBinary([]string{"/opt/sbin/iptables", "/opt/bin/iptables", "/usr/sbin/iptables", "iptables"})
	if iptablesBinary == "" {
		result.Detail = "iptables was not found"
		return result
	}
	queueNumber, processEvidence, err := activeNFQWSQueue()
	if err != nil {
		result.Detail = err.Error()
		return result
	}
	if !kernelQueueActive(queueNumber) {
		result.Detail = fmt.Sprintf("NFQWS2 queue %d is not registered in the kernel", queueNumber)
		return result
	}
	port, err := reserveTCPPort()
	if err != nil {
		result.Detail = "reserve probe source port: " + err.Error()
		return result
	}
	chain, err := randomNFQWSProbeChain()
	if err != nil {
		result.Detail = "create probe identifier: " + err.Error()
		return result
	}

	jumpArgs := []string{"-t", "mangle", "-D", "OUTPUT", "-p", "tcp", "-d", address.String(), "--dport", "443", "--sport", strconv.Itoa(port), "-j", chain}
	chainCreated, jumpCreated := false, false
	cleanupErrors := []string{}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		if jumpCreated {
			if output, cleanupErr := runSystemCommand(cleanupCtx, iptablesBinary, jumpArgs...); cleanupErr != nil {
				cleanupErrors = append(cleanupErrors, "delete jump: "+commandError(output, cleanupErr))
			}
		}
		if chainCreated {
			if output, cleanupErr := runSystemCommand(cleanupCtx, iptablesBinary, "-t", "mangle", "-F", chain); cleanupErr != nil {
				cleanupErrors = append(cleanupErrors, "flush chain: "+commandError(output, cleanupErr))
			}
			if output, cleanupErr := runSystemCommand(cleanupCtx, iptablesBinary, "-t", "mangle", "-X", chain); cleanupErr != nil {
				cleanupErrors = append(cleanupErrors, "delete chain: "+commandError(output, cleanupErr))
			}
		}
		if len(cleanupErrors) > 0 {
			result.RouteConfirmed = false
			result.Status = "fail"
			result.Detail = strings.TrimSpace(result.Detail + "; cleanup failed: " + strings.Join(cleanupErrors, "; "))
		}
	}()

	if output, createErr := runSystemCommand(ctx, iptablesBinary, "-t", "mangle", "-N", chain); createErr != nil {
		result.Detail = "create isolated NFQUEUE chain: " + commandError(output, createErr)
		return result
	}
	chainCreated = true
	if output, appendErr := runSystemCommand(ctx, iptablesBinary, "-t", "mangle", "-A", chain, "-j", "NFQUEUE", "--queue-num", strconv.Itoa(queueNumber)); appendErr != nil {
		result.Detail = "attach NFQUEUE target: " + commandError(output, appendErr)
		return result
	}
	insertArgs := []string{"-t", "mangle", "-I", "OUTPUT", "1", "-p", "tcp", "-d", address.String(), "--dport", "443", "--sport", strconv.Itoa(port), "-j", chain}
	if output, insertErr := runSystemCommand(ctx, iptablesBinary, insertArgs...); insertErr != nil {
		result.Detail = "attach isolated OUTPUT jump: " + commandError(output, insertErr)
		return result
	}
	jumpCreated = true

	client := pinnedHTTPSClient(address, port, m.timeout())
	result = probeHTTP(ctx, client, service, "nfqws2", "isolated NFQUEUE request awaiting exact-chain counter", false)
	counterOutput, counterErr := runSystemCommand(ctx, iptablesBinary, "-t", "mangle", "-L", chain, "-v", "-n", "-x")
	packets := parseScopedNFQueuePackets(counterOutput)
	queueStillActive := kernelQueueActive(queueNumber)
	result.RouteConfirmed = counterErr == nil && packets > 0 && queueStillActive
	if result.RouteConfirmed {
		result.EvidenceSource = fmt.Sprintf("scoped-nfqueue-chain:%s;queue=%d;packets=%d;destination=%s:443;source-port=%d;process=%s", chain, queueNumber, packets, address, port, processEvidence)
	} else {
		result.EvidenceSource = fmt.Sprintf("scoped-nfqueue-unconfirmed:queue=%d;packets=%d;kernel-active=%t", queueNumber, packets, queueStillActive)
		if result.Status == "pass" || result.Status == "partial" {
			result.Status = "fail"
			result.Detail = "service replied, but the exact request was not proven to pass through NFQWS2"
		}
	}
	return result
}

func resolvePublicIPv4(ctx context.Context, host string) (netip.Addr, error) {
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("resolve NFQWS2 probe destination: %w", err)
	}
	for _, address := range addresses {
		address = address.Unmap()
		if publicAddress(address) {
			return address, nil
		}
	}
	return netip.Addr{}, errors.New("NFQWS2 probe destination resolved only to private or local addresses")
}

func activeNFQWSQueue() (int, string, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, "", fmt.Errorf("inspect NFQWS2 processes: %w", err)
	}
	queues := map[int]string{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		cmdline, readErr := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if readErr != nil || len(cmdline) == 0 {
			continue
		}
		args := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
		if len(args) == 0 {
			continue
		}
		binary := filepathBase(args[0])
		if binary != "nfqws2" && binary != "nfqws" {
			continue
		}
		pathText := strings.ToLower(strings.Join(args, " "))
		if strings.Contains(pathText, "/opt/zapret2/") || strings.Contains(pathText, "/z2k/") {
			continue
		}
		queue, ok := parseNFQWSQueueArgs(args[1:])
		if ok {
			queues[queue] = entry.Name() + ":" + args[0]
		}
	}
	if len(queues) == 0 {
		return 0, "", errors.New("running NFQWS2 process with an explicit --qnum was not found")
	}
	if len(queues) > 1 {
		values := make([]string, 0, len(queues))
		for queue := range queues {
			values = append(values, strconv.Itoa(queue))
		}
		return 0, "", fmt.Errorf("multiple NFQWS2 queues are active (%s); isolated ownership is ambiguous", strings.Join(values, ", "))
	}
	for queue, evidence := range queues {
		return queue, evidence, nil
	}
	return 0, "", errors.New("NFQWS2 queue discovery failed")
}

func parseNFQWSQueueArgs(args []string) (int, bool) {
	for index := 0; index < len(args); index++ {
		value := ""
		if suffix, ok := strings.CutPrefix(args[index], "--qnum="); ok {
			value = suffix
		} else if args[index] == "--qnum" && index+1 < len(args) {
			index++
			value = args[index]
		}
		if value == "" {
			continue
		}
		queue, err := strconv.Atoi(value)
		if err == nil && queue >= 0 && queue <= 65535 {
			return queue, true
		}
		return 0, false
	}
	return 0, false
}

func kernelQueueActive(want int) bool {
	data, err := os.ReadFile("/proc/net/netfilter/nfnetlink_queue")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		queue, parseErr := strconv.Atoi(fields[0])
		if parseErr == nil && queue == want {
			return true
		}
	}
	return false
}

func reserveTCPPort() (int, error) {
	listener, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		return 0, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		return 0, err
	}
	return port, nil
}

func randomNFQWSProbeChain() (string, error) {
	buffer := make([]byte, 4)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return "RZRP" + strings.ToUpper(hex.EncodeToString(buffer)), nil
}

func findSystemBinary(candidates []string) string {
	for _, candidate := range candidates {
		if strings.Contains(candidate, "/") {
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
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

func runSystemCommand(ctx context.Context, binary string, args ...string) (string, error) {
	output, err := exec.CommandContext(ctx, binary, args...).CombinedOutput()
	return shortened(strings.TrimSpace(string(output))), err
}

func commandError(output string, err error) string {
	if strings.TrimSpace(output) != "" {
		return output
	}
	return err.Error()
}

func pinnedHTTPSClient(address netip.Addr, sourcePort int, timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: 6 * time.Second, KeepAlive: -1, LocalAddr: &net.TCPAddr{IP: net.IPv4zero, Port: sourcePort}}
	transport := &http.Transport{
		Proxy: nil, ForceAttemptHTTP2: true, DisableKeepAlives: true,
		TLSHandshakeTimeout: 7 * time.Second, ResponseHeaderTimeout: 8 * time.Second,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", net.JoinHostPort(address.String(), "443"))
		},
	}
	return &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

func parseScopedNFQueuePackets(output string) uint64 {
	var packets uint64
	for _, line := range strings.Split(output, "\n") {
		if !strings.Contains(strings.ToUpper(line), "NFQUEUE") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if value, err := strconv.ParseUint(fields[0], 10, 64); err == nil {
			packets += value
		}
	}
	return packets
}

func (m *Manager) engineStatus(route string) (engine.Status, bool) {
	base, _, _ := strings.Cut(route, ":")
	for _, status := range m.Statuses() {
		if status.ID == base {
			return status, true
		}
	}
	return engine.Status{}, false
}

func (m *Manager) directClient(rawURL string) (*http.Client, string, bool, error) {
	system := m.System()
	if system.WANInterface == "" {
		return nil, "", false, errors.New("WAN interface was not detected")
	}
	if system.RouteContamination {
		return nil, "", false, fmt.Errorf("DIRECT isolation refused while external tunnels are present: %s", strings.Join(system.ExternalTunnels, ", "))
	}
	ip, err := firstInterfaceIP(system.WANInterface)
	if err != nil {
		return nil, "", false, err
	}
	confirmed := routeUsesDevice(ip, rawURL, system.WANInterface)
	dialer := &net.Dialer{Timeout: 6 * time.Second, KeepAlive: -1, LocalAddr: &net.TCPAddr{IP: ip}}
	return hardenedClient(dialer.DialContext, m.timeout()), "source-address-bound:" + system.WANInterface, confirmed, nil
}

func (m *Manager) socksClient(route string) (*http.Client, string, bool, error) {
	endpoint, username, password, err := m.socksEndpoint(route)
	if err != nil {
		return nil, "", false, err
	}
	dialer := socksDialer{ProxyAddress: endpoint, Username: username, Password: password, Timeout: 6 * time.Second}
	return hardenedClient(dialer.DialContext, m.timeout()), "explicit-socks5:" + route + "@" + endpoint, true, nil
}

func (m *Manager) socksEndpoint(route string) (string, string, string, error) {
	if endpoint := m.managedSOCKSEndpoint(route); endpoint != "" {
		return endpoint, "", "", nil
	}
	if m.Configs != nil {
		if content, err := m.Configs.ReadExpert(route, "main"); err == nil && content.Content != "" {
			if endpoint, username, password := endpointFromJSON(route, []byte(content.Content)); endpoint != "" {
				return endpoint, username, password, nil
			}
		}
	}
	if route == "usque" {
		if endpoint := endpointFromProcess("usque"); endpoint != "" {
			return endpoint, "", "", nil
		}
		// Official usque SOCKS mode defaults to 0.0.0.0:1080. The probe uses
		// loopback and still requires a successful SOCKS handshake.
		return "127.0.0.1:1080", "", "", nil
	}
	return "", "", "", errors.New("no loopback SOCKS inbound found in the active configuration")
}

func (m *Manager) managedSOCKSEndpoint(route string) string {
	if m.DataplaneRoot == "" {
		return ""
	}
	runtimeRoot := filepath.Join(m.DataplaneRoot, route, "runtime")
	configPath := filepath.Join(runtimeRoot, "engine.json")
	if data, err := os.ReadFile(configPath); err == nil {
		if endpoint, _, _ := endpointFromJSON(route, data); endpoint != "" {
			return endpoint
		}
	}
	if route == "usque" {
		if _, configErr := os.Stat(configPath); configErr == nil {
			if _, pidErr := os.Stat(filepath.Join(runtimeRoot, "engine.pid")); pidErr == nil {
				return "127.0.0.1:18080"
			}
		}
	}
	return ""
}

func (m *Manager) interfaceClient(route, rawURL string) (*http.Client, string, bool, error) {
	if m.Configs == nil {
		return nil, "", false, errors.New("configuration manager is unavailable")
	}
	content, err := m.Configs.ReadExpert(route, "main")
	if err != nil || content.Content == "" {
		return nil, "", false, errors.New("tunnel profile is missing")
	}
	ip, err := profileAddress(content.Content)
	if err != nil {
		return nil, "", false, err
	}
	interfaceName, err := interfaceForIP(ip)
	if err != nil {
		return nil, "", false, err
	}
	confirmed := routeUsesDevice(ip, rawURL, interfaceName)
	if !confirmed {
		return nil, "", false, fmt.Errorf("source address %s exists on %s, but kernel route evidence does not confirm that destination uses this interface", ip, interfaceName)
	}
	dialer := &net.Dialer{Timeout: 6 * time.Second, KeepAlive: -1, LocalAddr: &net.TCPAddr{IP: ip}}
	return hardenedClient(dialer.DialContext, m.timeout()), "source-address-and-kernel-route:" + interfaceName, true, nil
}

func (m *Manager) timeout() time.Duration {
	if m.Timeout <= 0 {
		return 12 * time.Second
	}
	return m.Timeout
}

func hardenedClient(dial func(context.Context, string, string) (net.Conn, error), timeout time.Duration) *http.Client {
	transport := &http.Transport{
		Proxy: nil, DialContext: safeDial(dial), ForceAttemptHTTP2: true, DisableKeepAlives: true,
		TLSHandshakeTimeout: 7 * time.Second, ResponseHeaderTimeout: 8 * time.Second,
	}
	return &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(request *http.Request, via []*http.Request) error {
		if len(via) >= 4 {
			return errors.New("too many redirects")
		}
		return validateProbeURL(request.URL.String())
	}}
}

func safeDial(dial func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		resolved, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("resolve probe destination: %w", err)
		}
		var lastErr error
		for _, candidate := range resolved {
			candidate = candidate.Unmap()
			if !publicAddress(candidate) {
				continue
			}
			connection, dialErr := dial(ctx, network, net.JoinHostPort(candidate.String(), port))
			if dialErr == nil {
				return connection, nil
			}
			lastErr = dialErr
		}
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, errors.New("probe destination resolved only to private or local addresses")
	}
}

func probeHTTP(ctx context.Context, client *http.Client, service catalog.Service, route, evidence string, confirmed bool) testlab.Result {
	result := testlab.Result{ServiceID: service.ID, ServiceName: service.Name, ProbeURL: service.ProbeURL, Route: route, Status: "fail", CheckedAt: time.Now().UTC().Format(time.RFC3339), RouteConfirmed: confirmed, EvidenceSource: evidence}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, service.ProbeURL, nil)
	if err != nil {
		result.Detail = err.Error()
		return result
	}
	request.Header.Set("User-Agent", "RAZVILKA-Isolated-Probe/0.15.1")
	request.Header.Set("Accept", "text/html,application/json;q=0.9,*/*;q=0.1")
	request.Header.Set("Range", "bytes=0-32767")
	start := time.Now()
	response, err := client.Do(request)
	result.TTFBMS = time.Since(start).Milliseconds()
	if err != nil {
		result.LatencyMS = time.Since(start).Milliseconds()
		result.Detail = shortened(err.Error())
		return result
	}
	defer response.Body.Close()
	result.HTTPStatus = response.StatusCode
	readStarted := time.Now()
	result.BytesRead, err = io.Copy(io.Discard, io.LimitReader(response.Body, 32768))
	result.ReadMS = time.Since(readStarted).Milliseconds()
	result.LatencyMS = time.Since(start).Milliseconds()
	result.StreamStatus = classifyProbeStream(response, result.BytesRead, err)
	if err != nil {
		result.Detail = fmt.Sprintf("response stream interrupted after %d bytes: %s", result.BytesRead, shortened(err.Error()))
		return result
	}
	switch {
	case response.StatusCode >= 200 && response.StatusCode < 400:
		result.Status = "pass"
		result.Detail = "service endpoint reachable through isolated " + route + " adapter"
	case response.StatusCode == 401 || response.StatusCode == 403 || response.StatusCode == 407 || response.StatusCode == 429 || response.StatusCode == 451:
		result.Status = "partial"
		result.Detail = fmt.Sprintf("route works, but service/policy returned HTTP %d", response.StatusCode)
	case response.StatusCode >= 400 && response.StatusCode < 500:
		result.Status = "partial"
		result.Detail = fmt.Sprintf("route reached service with HTTP %d", response.StatusCode)
	default:
		result.Detail = fmt.Sprintf("service returned HTTP %d", response.StatusCode)
	}
	return result
}

func classifyProbeStream(response *http.Response, bytesRead int64, readErr error) string {
	if readErr != nil {
		return "interrupted"
	}
	if bytesRead == 0 {
		return "empty"
	}
	if bytesRead >= 32768 || response.ContentLength > bytesRead {
		return "sampled"
	}
	return "complete"
}

func probeEgress(ctx context.Context, client *http.Client) string {
	probeContext, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(probeContext, http.MethodGet, "https://1.1.1.1/cdn-cgi/trace", nil)
	if err != nil {
		return ""
	}
	response, err := client.Do(request)
	if err != nil {
		return ""
	}
	defer response.Body.Close()
	scanner := bufio.NewScanner(io.LimitReader(response.Body, 4096))
	for scanner.Scan() {
		if value, ok := strings.CutPrefix(scanner.Text(), "ip="); ok {
			if address, err := netip.ParseAddr(strings.TrimSpace(value)); err == nil && address.IsGlobalUnicast() {
				return address.String()
			}
		}
	}
	return ""
}

type socksDialer struct {
	ProxyAddress string
	Username     string
	Password     string
	Timeout      time.Duration
}

func (d socksDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, errors.New("SOCKS adapter supports TCP only")
	}
	base := &net.Dialer{Timeout: d.Timeout, KeepAlive: -1}
	connection, err := base.DialContext(ctx, "tcp", d.ProxyAddress)
	if err != nil {
		return nil, fmt.Errorf("connect local SOCKS5 proxy: %w", err)
	}
	failed := true
	defer func() {
		if failed {
			_ = connection.Close()
		}
	}()
	methods := []byte{0x00}
	if d.Username != "" || d.Password != "" {
		methods = append(methods, 0x02)
	}
	if _, err := connection.Write(append([]byte{0x05, byte(len(methods))}, methods...)); err != nil {
		return nil, err
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(connection, reply); err != nil || reply[0] != 0x05 || reply[1] == 0xff {
		return nil, errors.New("SOCKS5 method negotiation failed")
	}
	if reply[1] == 0x02 {
		if len(d.Username) > 255 || len(d.Password) > 255 {
			return nil, errors.New("SOCKS5 credentials are too long")
		}
		request := []byte{0x01, byte(len(d.Username))}
		request = append(request, d.Username...)
		request = append(request, byte(len(d.Password)))
		request = append(request, d.Password...)
		if _, err := connection.Write(request); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(connection, reply); err != nil || reply[1] != 0x00 {
			return nil, errors.New("SOCKS5 authentication failed")
		}
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, _ := strconv.Atoi(portText)
	request := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			request = append(request, 0x01)
			request = append(request, ipv4...)
		} else {
			request = append(request, 0x04)
			request = append(request, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, errors.New("invalid SOCKS5 destination host")
		}
		request = append(request, 0x03, byte(len(host)))
		request = append(request, host...)
	}
	var encodedPort [2]byte
	binary.BigEndian.PutUint16(encodedPort[:], uint16(port))
	request = append(request, encodedPort[:]...)
	if _, err := connection.Write(request); err != nil {
		return nil, err
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(connection, header); err != nil || header[0] != 0x05 || header[1] != 0x00 {
		return nil, errors.New("SOCKS5 CONNECT failed")
	}
	addressBytes := 0
	switch header[3] {
	case 0x01:
		addressBytes = 4
	case 0x04:
		addressBytes = 16
	case 0x03:
		length := []byte{0}
		if _, err := io.ReadFull(connection, length); err != nil {
			return nil, err
		}
		addressBytes = int(length[0])
	default:
		return nil, errors.New("SOCKS5 returned invalid address type")
	}
	if _, err := io.CopyN(io.Discard, connection, int64(addressBytes+2)); err != nil {
		return nil, err
	}
	failed = false
	return connection, nil
}

func endpointFromJSON(route string, content []byte) (string, string, string) {
	var document map[string]interface{}
	if json.Unmarshal(content, &document) != nil {
		return "", "", ""
	}
	inbounds, _ := document["inbounds"].([]interface{})
	for _, raw := range inbounds {
		inbound, _ := raw.(map[string]interface{})
		protocol := stringValue(inbound["type"])
		if protocol == "" {
			protocol = stringValue(inbound["protocol"])
		}
		if protocol != "socks" && protocol != "mixed" {
			continue
		}
		port := intValue(inbound["listen_port"])
		if port == 0 {
			port = intValue(inbound["port"])
		}
		host := stringValue(inbound["listen"])
		if host == "" || host == "0.0.0.0" || host == "::" {
			host = "127.0.0.1"
		}
		if port > 0 && loopbackHost(host) {
			username, password := inboundCredentials(inbound)
			return net.JoinHostPort(host, strconv.Itoa(port)), username, password
		}
	}
	if route == "usque" {
		port := intValue(document["socks_port"])
		if port > 0 {
			return net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), stringValue(document["socks_username"]), stringValue(document["socks_password"])
		}
	}
	return "", "", ""
}

func inboundCredentials(inbound map[string]interface{}) (string, string) {
	users, _ := inbound["users"].([]interface{})
	if len(users) == 0 {
		return "", ""
	}
	user, _ := users[0].(map[string]interface{})
	return stringValue(user["username"]), stringValue(user["password"])
}

func endpointFromProcess(name string) string {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		cmdline, err := os.ReadFile("/proc/" + entry.Name() + "/cmdline")
		if err != nil {
			continue
		}
		args := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
		if len(args) < 2 || strings.TrimSuffix(filepathBase(args[0]), ".exe") != name {
			continue
		}
		proxyMode := false
		for _, arg := range args[1:] {
			if arg == "socks" || arg == "l4-socks" {
				proxyMode = true
				break
			}
		}
		if !proxyMode {
			continue
		}
		host, port := "127.0.0.1", 1080
		for i := 1; i < len(args); i++ {
			if (args[i] == "-b" || args[i] == "--bind") && i+1 < len(args) {
				host = args[i+1]
				i++
			} else if (args[i] == "-p" || args[i] == "--port") && i+1 < len(args) {
				port, _ = strconv.Atoi(args[i+1])
				i++
			}
		}
		if host == "0.0.0.0" || host == "::" {
			host = "127.0.0.1"
		}
		if port > 0 && port <= 65535 && loopbackHost(host) {
			return net.JoinHostPort(host, strconv.Itoa(port))
		}
	}
	return ""
}

func profileAddress(content string) (net.IP, error) {
	for _, line := range strings.Split(content, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), "Address") {
			continue
		}
		for _, candidate := range strings.Split(value, ",") {
			candidate = strings.TrimSpace(candidate)
			if ip, _, err := net.ParseCIDR(candidate); err == nil && ip.To4() != nil {
				return ip, nil
			}
		}
	}
	return nil, errors.New("profile has no IPv4 Address")
}

func interfaceForIP(ip net.IP) (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, item := range interfaces {
		addresses, _ := item.Addrs()
		for _, address := range addresses {
			candidate, _, _ := net.ParseCIDR(address.String())
			if candidate != nil && candidate.Equal(ip) {
				return item.Name, nil
			}
		}
	}
	return "", fmt.Errorf("profile address %s is not assigned to an active interface", ip)
}

func firstInterfaceIP(name string) (net.IP, error) {
	item, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("inspect WAN interface %s: %w", name, err)
	}
	addresses, err := item.Addrs()
	if err != nil {
		return nil, err
	}
	for _, address := range addresses {
		ip, _, _ := net.ParseCIDR(address.String())
		if ip != nil && ip.To4() != nil && !ip.IsLoopback() {
			return ip, nil
		}
	}
	return nil, fmt.Errorf("WAN interface %s has no IPv4 address", name)
}

func routeUsesDevice(source net.IP, rawURL, wantDevice string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	resolveContext, resolveCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer resolveCancel()
	addresses, err := net.DefaultResolver.LookupIP(resolveContext, "ip4", u.Hostname())
	if err != nil || len(addresses) == 0 {
		return false
	}
	ipBinary := ""
	for _, candidate := range []string{"ip", "/opt/sbin/ip", "/opt/bin/ip"} {
		if strings.Contains(candidate, "/") {
			if _, err := os.Stat(candidate); err == nil {
				ipBinary = candidate
				break
			}
		} else if found, err := exec.LookPath(candidate); err == nil {
			ipBinary = found
			break
		}
	}
	if ipBinary == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, ipBinary, "route", "get", addresses[0].String(), "from", source.String()).Output()
	if err != nil {
		return false
	}
	fields := strings.Fields(string(output))
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "dev" {
			return fields[i+1] == wantDevice
		}
	}
	return false
}

func validateProbeURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return errors.New("service has no valid HTTPS probe URL")
	}
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil && !publicAddress(ip.Unmap()) {
		return errors.New("private or local probe destination is not allowed")
	}
	return nil
}

func publicAddress(ip netip.Addr) bool {
	return ip.IsValid() && ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast()
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func intValue(value interface{}) int {
	switch typed := value.(type) {
	case float64:
		return int(typed)
	case json.Number:
		parsed, _ := typed.Int64()
		return int(parsed)
	case string:
		parsed, _ := strconv.Atoi(typed)
		return parsed
	}
	return 0
}

func stringValue(value interface{}) string {
	text, _ := value.(string)
	return strings.TrimSpace(text)
}

func filepathBase(value string) string {
	value = strings.ReplaceAll(value, "\\", "/")
	if index := strings.LastIndexByte(value, '/'); index >= 0 {
		value = value[index+1:]
	}
	return strings.ToLower(value)
}

func shortened(value string) string {
	if len(value) > 500 {
		return value[:500] + "…"
	}
	return value
}
