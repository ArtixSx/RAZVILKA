package dataplane

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/probecheck"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

var (
	ErrExactNodeBusy        = errors.New("exact node checker is busy")
	ErrExactNodeUnavailable = errors.New("exact node checker is unavailable")
	ErrExactNodeRuntime     = errors.New("sing-box runtime is unavailable")
)

const exactNodeSchema = 1

type NodeCheckRequest struct {
	NodeID         string
	Outbound       []byte
	Service        catalog.Service
	NetworkProfile string
}

type NodeCheckStage struct {
	ID       string `json:"id"`
	Status   string `json:"status"`
	Message  string `json:"message"`
	Duration int64  `json:"duration_ms,omitempty"`
}

// NodeCheckResult is deliberately safe for persistence and the Web API. Raw
// process output, the remote endpoint and direct egress address are omitted.
type NodeCheckResult struct {
	SchemaVersion  int                    `json:"schema_version"`
	ProbeID        string                 `json:"probe_id"`
	NodeID         string                 `json:"node_id"`
	ServiceID      string                 `json:"service_id"`
	NetworkProfile string                 `json:"network_profile"`
	RoutePathID    string                 `json:"route_path_id"`
	StartedAt      time.Time              `json:"started_at"`
	FinishedAt     time.Time              `json:"finished_at"`
	ExpiresAt      time.Time              `json:"expires_at"`
	TestLevel      string                 `json:"test_level"`
	Stage          string                 `json:"stage"`
	Verdict        evidence.Verdict       `json:"verdict"`
	Available      bool                   `json:"available"`
	EgressIP       string                 `json:"egress_ip,omitempty"`
	HTTPStatus     int                    `json:"http_status,omitempty"`
	LatencyMS      int64                  `json:"latency_ms,omitempty"`
	ErrorCode      string                 `json:"error_code,omitempty"`
	Message        string                 `json:"message"`
	DirectControl  string                 `json:"direct_control"`
	DirectLeak     bool                   `json:"direct_leak"`
	Stages         []NodeCheckStage       `json:"stages"`
	Evidence       evidence.ProbeEvidence `json:"evidence"`
}

type NodeChecker interface {
	Check(context.Context, NodeCheckRequest) (NodeCheckResult, error)
	Recover(context.Context) error
}

type exactNodeEndpoint struct {
	Protocol  string
	Transport string
	Host      string
	Port      int
	Pinned    netip.Addr
}

type exactNodeSession struct {
	Root    string
	Address string
	Spec    ProcessSpec
}

// ExactNodeChecker owns one fixed, loopback-only temporary Sing-box process.
// A non-blocking single-slot gate prevents port/process collisions with itself.
type ExactNodeChecker struct {
	StateRoot     string
	Binary        string
	Port          int
	Timeout       time.Duration
	EvidenceTTL   time.Duration
	Processes     ProcessController
	resolve       func(context.Context, string) ([]netip.Addr, error)
	dialTransport func(context.Context, exactNodeEndpoint, []netip.Addr) (bool, error)
	prepare       func(context.Context, NodeCheckRequest, exactNodeEndpoint) (exactNodeSession, error)
	start         func(context.Context, exactNodeSession) error
	identity      func(exactNodeSession) (routeidentity.Passport, error)
	directEgress  func(context.Context) (string, error)
	proxyEgress   func(context.Context, string) (string, error)
	serviceProbe  func(context.Context, string, string, string, catalog.Service) (evidence.ProbeEvidence, error)
	cleanup       func(context.Context, exactNodeSession) error
	runtimeReady  func() bool
	now           func() time.Time
	gate          chan struct{}
	poisoned      atomic.Bool
}

func NewExactNodeChecker(stateRoot string) *ExactNodeChecker {
	checker := &ExactNodeChecker{
		StateRoot: stateRoot, Port: 19181, Timeout: 45 * time.Second, EvidenceTTL: 30 * time.Minute,
		Processes: OSProcessController{}, now: time.Now, gate: make(chan struct{}, 1),
	}
	checker.resolve = checker.resolveHost
	checker.dialTransport = checker.transportPrefilter
	checker.prepare = checker.prepareSession
	checker.start = checker.startSession
	checker.identity = checker.verifyIdentity
	checker.directEgress = checker.directTrace
	checker.proxyEgress = checker.proxyTrace
	checker.serviceProbe = checker.probeService
	checker.cleanup = checker.cleanupSession
	checker.runtimeReady = func() bool { return checker.binary() != "" }
	return checker
}

func (c *ExactNodeChecker) Check(parent context.Context, request NodeCheckRequest) (result NodeCheckResult, resultErr error) {
	if err := c.validRequest(request); err != nil {
		return NodeCheckResult{}, err
	}
	select {
	case c.gate <- struct{}{}:
		defer func() { <-c.gate }()
	default:
		return NodeCheckResult{}, ErrExactNodeBusy
	}
	ctx, cancel := context.WithTimeout(parent, c.timeout())
	defer cancel()
	started := c.currentTime()
	result = NodeCheckResult{
		SchemaVersion: exactNodeSchema, ProbeID: newNodeProbeID(), NodeID: request.NodeID,
		ServiceID: request.Service.ID, NetworkProfile: request.NetworkProfile,
		RoutePathID: "sing-box:" + request.NodeID, StartedAt: started, TestLevel: "dns",
		Stage: "dns", Verdict: evidence.VerdictError, Message: "Проверка не завершена.",
		DirectControl: "not_run", Stages: []NodeCheckStage{},
	}
	finish := func() {
		result.FinishedAt = c.currentTime()
		result.ExpiresAt = result.FinishedAt.Add(c.evidenceTTL())
		result.LatencyMS = result.FinishedAt.Sub(result.StartedAt).Milliseconds()
		if result.LatencyMS < 0 {
			result.LatencyMS = 0
		}
	}

	endpoint, err := inspectExactNodeOutbound(request.Outbound)
	if err != nil {
		result.fail("dns", "node-config-invalid", "Конфигурация узла не прошла строгую проверку.")
		finish()
		return result, nil
	}
	stageStarted := c.currentTime()
	addresses, err := c.resolve(ctx, endpoint.Host)
	if err != nil || len(addresses) == 0 || !publicNodeAddresses(addresses) {
		result.fail("dns", "node-dns-failed", "Адрес узла не удалось безопасно определить.")
		result.addStage("dns", "failed", "DNS-проверка не пройдена.", stageStarted, c.currentTime())
		finish()
		return result, nil
	}
	result.addStage("dns", "passed", "Адрес узла определён без раскрытия в интерфейсе.", stageStarted, c.currentTime())
	endpoint.Pinned = addresses[0].Unmap()

	stageStarted = c.currentTime()
	checked, err := c.dialTransport(ctx, endpoint, addresses)
	if err != nil {
		result.TestLevel = "transport"
		result.fail("transport", "node-transport-failed", "Транспорт до узла недоступен.")
		result.addStage("transport", "failed", "Предварительное соединение не установлено.", stageStarted, c.currentTime())
		finish()
		return result, nil
	}
	result.TestLevel = "transport"
	if checked {
		result.addStage("transport", "passed", "Предварительное соединение установлено; это ещё не доказывает работу ключа.", stageStarted, c.currentTime())
	} else {
		result.addStage("transport", "skipped", "Для UDP-протокола отдельный TCP-тест неприменим; проверяется реальный обмен.", stageStarted, c.currentTime())
	}

	stageStarted = c.currentTime()
	session, err := c.prepare(ctx, request, endpoint)
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(parent), 8*time.Second)
		defer cleanupCancel()
		if err := c.cleanup(cleanupCtx, session); err != nil {
			c.poisoned.Store(true)
			result.Available = false
			result.Verdict = evidence.VerdictError
			result.Stage = "cleanup"
			result.ErrorCode = "node-cleanup-failed"
			result.Message = "Временный процесс не удалось гарантированно убрать; повторные проверки заблокированы до восстановления."
			result.addStage("cleanup", "failed", "Очистка временного процесса требует внимания.", c.currentTime(), c.currentTime())
			finish()
		}
	}()
	if err != nil {
		result.TestLevel = "protocol"
		result.fail("configuration", "node-runtime-config-rejected", "Sing-box отклонил изолированную конфигурацию узла.")
		result.addStage("configuration", "failed", "Изолированная конфигурация не принята.", stageStarted, c.currentTime())
		finish()
		return result, nil
	}
	result.addStage("configuration", "passed", "Создан временный профиль только для этого узла.", stageStarted, c.currentTime())

	stageStarted = c.currentTime()
	if err := c.start(ctx, session); err != nil {
		result.TestLevel = "protocol"
		result.fail("protocol", "node-protocol-start-failed", "Узел не смог запустить рабочий протокольный сеанс.")
		result.addStage("protocol", "failed", "Временный клиент не открыл локальный проверочный канал.", stageStarted, c.currentTime())
		finish()
		return result, nil
	}

	passport, err := c.identity(session)
	if err != nil || passport.Outbound != endpoint.Protocol {
		result.TestLevel = "protocol"
		result.fail("route_identity", "node-route-identity-failed", "Не удалось доказать принадлежность временного канала выбранному узлу.")
		result.addStage("route_identity", "failed", "Идентичность процесса или конфигурации не подтверждена.", stageStarted, c.currentTime())
		finish()
		return result, nil
	}
	result.addStage("route_identity", "passed", "Процесс, конфигурация и локальный канал принадлежат этой проверке.", stageStarted, c.currentTime())

	directIP, directErr := c.directEgress(ctx)
	directAddress, directAddressErr := netip.ParseAddr(strings.TrimSpace(directIP))
	if directErr == nil && directAddressErr == nil && publicNodeAddresses([]netip.Addr{directAddress}) {
		result.DirectControl = "measured"
	} else {
		result.DirectControl = "unavailable"
	}
	stageStarted = c.currentTime()
	proxyIP, err := c.proxyEgress(ctx, session.Address)
	proxyAddress, proxyAddressErr := netip.ParseAddr(strings.TrimSpace(proxyIP))
	if err != nil || proxyAddressErr != nil || !publicNodeAddresses([]netip.Addr{proxyAddress}) {
		result.TestLevel = "protocol"
		result.fail("egress", "node-egress-failed", "Точный выход через узел не подтвердился.")
		result.addStage("protocol", "failed", "Канал открылся локально, но удалённый протокол или ключ не передал запрос.", stageStarted, c.currentTime())
		result.addStage("egress", "failed", "Внешний IP через узел не получен.", stageStarted, c.currentTime())
		finish()
		return result, nil
	}
	result.TestLevel = "egress"
	proxyIP = proxyAddress.Unmap().String()
	result.EgressIP = proxyIP
	result.addStage("protocol", "passed", "Реальный запрос прошёл через протокол выбранного узла.", stageStarted, c.currentTime())
	if result.DirectControl == "measured" && directAddress.Unmap() == proxyAddress.Unmap() {
		result.DirectLeak = true
		result.fail("egress", "node-direct-leak", "Проксированный IP совпал с прямым: точный выход не доказан.")
		result.Verdict = evidence.VerdictMisrouted
		result.addStage("egress", "failed", "Сработал контроль утечки прямого маршрута.", stageStarted, c.currentTime())
		finish()
		return result, nil
	}
	if result.DirectControl == "unavailable" {
		result.Verdict = evidence.VerdictInconclusive
		result.fail("egress", "node-direct-control-unavailable", "IP через узел получен, но прямой контроль недоступен; точный выход не подтверждён.")
		result.addStage("egress", "failed", "Без прямого контрольного IP нельзя исключить утечку маршрута.", stageStarted, c.currentTime())
		finish()
		return result, nil
	}
	result.addStage("egress", "passed", "Получен внешний IP через точный outbound; прямой контроль не совпал.", stageStarted, c.currentTime())

	stageStarted = c.currentTime()
	proof, err := c.serviceProbe(ctx, session.Address, result.RoutePathID, proxyIP, request.Service)
	proof.NetworkProfile = request.NetworkProfile
	result.Evidence = proof
	result.HTTPStatus = proof.HTTPStatus
	if err != nil || !proof.Valid() {
		result.fail("service", "node-service-probe-failed", "Контрольный запрос сервиса не завершён.")
		result.addStage("service", "failed", "Сервис не дал проверяемый ответ через узел.", stageStarted, c.currentTime())
		finish()
		return result, nil
	}
	result.TestLevel = "service"
	result.Stage = "service"
	result.Verdict = proof.Verdict
	exactRoute := proof.RoutePathID == result.RoutePathID && proof.ExpectedRoutePathID == result.RoutePathID && proof.ObservedRoutePathID == result.RoutePathID
	result.Available = proof.AssuranceLevel().AtLeast(evidence.Service) && exactRoute
	if result.Available {
		result.ErrorCode = ""
		result.Message = "Узел подтвердил точный выход и доступ к выбранному сервису."
		result.addStage("service", "passed", "Контрольный адрес сервиса вернул ожидаемый ответ.", stageStarted, c.currentTime())
	} else {
		result.ErrorCode = proof.ErrorCode
		if !exactRoute {
			result.Verdict = evidence.VerdictMisrouted
			result.ErrorCode = "node-route-mismatch"
		}
		if result.ErrorCode == "" {
			result.ErrorCode = "node-service-not-confirmed"
		}
		result.Message = "Узел передаёт трафик, но выбранный сервис через него не подтверждён."
		result.addStage("service", "failed", "Ответ сервиса не соответствует безопасному критерию.", stageStarted, c.currentTime())
	}
	finish()
	return result, resultErr
}

func (c *ExactNodeChecker) Recover(ctx context.Context) error {
	if c == nil || c.StateRoot == "" {
		return ErrExactNodeUnavailable
	}
	select {
	case c.gate <- struct{}{}:
		defer func() { <-c.gate }()
	default:
		return ErrExactNodeBusy
	}
	if err := c.cleanup(ctx, c.session()); err != nil {
		c.poisoned.Store(true)
		return err
	}
	c.poisoned.Store(false)
	return nil
}

func (c *ExactNodeChecker) validRequest(request NodeCheckRequest) error {
	if c == nil || c.Processes == nil || c.resolve == nil || c.dialTransport == nil || c.prepare == nil || c.start == nil || c.identity == nil || c.directEgress == nil || c.proxyEgress == nil || c.serviceProbe == nil || c.cleanup == nil || c.runtimeReady == nil || c.gate == nil || c.poisoned.Load() {
		return ErrExactNodeUnavailable
	}
	if !c.runtimeReady() {
		return ErrExactNodeRuntime
	}
	if !regexp.MustCompile(`^node-[0-9a-f]{64}$`).MatchString(request.NodeID) || len(request.Outbound) == 0 || request.Service.ID == "" || selectedNodeProbe(request.Service).URL == "" || !regexp.MustCompile(`^(?:network-unknown|wan-[0-9a-f]{12})$`).MatchString(request.NetworkProfile) {
		return ErrExactNodeUnavailable
	}
	if !filepath.IsAbs(c.StateRoot) || filepath.Clean(c.StateRoot) == filepath.VolumeName(c.StateRoot)+string(filepath.Separator) || c.Port < 1024 || c.Port > 65535 {
		return ErrExactNodeUnavailable
	}
	return nil
}

func (r *NodeCheckResult) fail(stage, code, message string) {
	r.Available = false
	r.Stage = stage
	r.ErrorCode = code
	r.Message = message
	if r.Verdict == "" || r.Verdict == evidence.VerdictPass {
		r.Verdict = evidence.VerdictError
	}
}

func (r *NodeCheckResult) addStage(id, status, message string, started, finished time.Time) {
	duration := finished.Sub(started).Milliseconds()
	if duration < 0 {
		duration = 0
	}
	r.Stages = append(r.Stages, NodeCheckStage{ID: id, Status: status, Message: message, Duration: duration})
}

func (c *ExactNodeChecker) currentTime() time.Time {
	if c.now != nil {
		return c.now().UTC()
	}
	return time.Now().UTC()
}

func (c *ExactNodeChecker) timeout() time.Duration {
	if c.Timeout <= 0 || c.Timeout > 2*time.Minute {
		return 45 * time.Second
	}
	return c.Timeout
}

func (c *ExactNodeChecker) evidenceTTL() time.Duration {
	if c.EvidenceTTL <= 0 || c.EvidenceTTL > 24*time.Hour {
		return 30 * time.Minute
	}
	return c.EvidenceTTL
}

func newNodeProbeID() string {
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		digest := routeidentity.Hash([]byte(strconv.FormatInt(time.Now().UnixNano(), 10)))
		return "node-check-" + digest[:24]
	}
	return "node-check-" + hex.EncodeToString(random)
}

func selectedNodeProbe(service catalog.Service) catalog.Probe {
	if service.ProbeURL != "" {
		return probecheck.ServiceProbe(service)
	}
	for _, probe := range service.Probes {
		if probe.Required && probe.URL != "" {
			service.ProbeURL = probe.URL
			return probecheck.ServiceProbe(service)
		}
	}
	return catalog.Probe{}
}

func inspectExactNodeOutbound(raw []byte) (exactNodeEndpoint, error) {
	var outbound map[string]json.RawMessage
	if json.Unmarshal(raw, &outbound) != nil || outbound == nil {
		return exactNodeEndpoint{}, errors.New("invalid outbound")
	}
	for _, forbidden := range []string{"tag", "detour"} {
		if _, exists := outbound[forbidden]; exists {
			return exactNodeEndpoint{}, errors.New("chained outbound is not exact")
		}
	}
	var endpoint exactNodeEndpoint
	_ = json.Unmarshal(outbound["type"], &endpoint.Protocol)
	_ = json.Unmarshal(outbound["server"], &endpoint.Host)
	_ = json.Unmarshal(outbound["server_port"], &endpoint.Port)
	var transport struct {
		Type string `json:"type"`
	}
	_ = json.Unmarshal(outbound["transport"], &transport)
	endpoint.Transport = transport.Type
	switch endpoint.Protocol {
	case "vless", "hysteria2", "tuic", "shadowsocks":
	default:
		return exactNodeEndpoint{}, errors.New("unsupported outbound")
	}
	if endpoint.Host == "" || endpoint.Port < 1 || endpoint.Port > 65535 || strings.ContainsAny(endpoint.Host, "/\\:@ \t\r\n") {
		if net.ParseIP(endpoint.Host) == nil || endpoint.Port < 1 || endpoint.Port > 65535 {
			return exactNodeEndpoint{}, errors.New("invalid endpoint")
		}
	}
	if address, err := netip.ParseAddr(endpoint.Host); err == nil && !publicNodeAddresses([]netip.Addr{address}) {
		return exactNodeEndpoint{}, errors.New("private endpoint")
	}
	host := strings.ToLower(strings.TrimSuffix(endpoint.Host, "."))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") {
		return exactNodeEndpoint{}, errors.New("local endpoint")
	}
	return endpoint, nil
}

func publicNodeAddresses(addresses []netip.Addr) bool {
	if len(addresses) == 0 || len(addresses) > 16 {
		return false
	}
	for _, address := range addresses {
		address = address.Unmap()
		if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsMulticast() {
			return false
		}
	}
	return true
}

func (c *ExactNodeChecker) resolveHost(ctx context.Context, host string) ([]netip.Addr, error) {
	if address, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{address}, nil
	}
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

func (c *ExactNodeChecker) transportPrefilter(ctx context.Context, endpoint exactNodeEndpoint, addresses []netip.Addr) (bool, error) {
	if endpoint.Protocol == "hysteria2" || endpoint.Protocol == "tuic" {
		return false, nil
	}
	var lastErr error
	for _, address := range addresses {
		dialer := net.Dialer{Timeout: 3 * time.Second}
		connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(address.String(), strconv.Itoa(endpoint.Port)))
		if err == nil {
			_ = connection.Close()
			return true, nil
		}
		lastErr = err
	}
	return true, lastErr
}

func (c *ExactNodeChecker) binary() string {
	if c.Binary != "" {
		return c.Binary
	}
	for _, candidate := range []string{"/opt/bin/sing-box", "/opt/usr/bin/sing-box", "sing-box"} {
		if strings.Contains(candidate, "/") {
			if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
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

func (c *ExactNodeChecker) session() exactNodeSession {
	root := c.StateRoot
	config := filepath.Join(root, "engine.json")
	return exactNodeSession{
		Root: root, Address: net.JoinHostPort("127.0.0.1", strconv.Itoa(c.Port)),
		Spec: ProcessSpec{ID: "node-check-sing-box", Binary: c.binary(), Args: []string{"run", "-c", config}, Dir: root, PIDPath: filepath.Join(root, "engine.pid"), LogPath: filepath.Join(root, "engine.log"), MatchArg: config, RouteProof: true},
	}
}

func (c *ExactNodeChecker) prepareSession(ctx context.Context, request NodeCheckRequest, endpoint exactNodeEndpoint) (exactNodeSession, error) {
	session := c.session()
	if session.Spec.Binary == "" {
		return session, errors.New("sing-box missing")
	}
	if err := os.MkdirAll(session.Root, 0o700); err != nil {
		return session, err
	}
	var outbound map[string]any
	if json.Unmarshal(request.Outbound, &outbound) != nil {
		return session, errors.New("invalid outbound")
	}
	if !endpoint.Pinned.IsValid() {
		return session, errors.New("endpoint not pinned")
	}
	preserveNodeHostname(outbound, endpoint.Host)
	outbound["server"] = endpoint.Pinned.String()
	outbound["tag"] = "rz-exact-node"
	document := map[string]any{
		"log":       map[string]any{"level": "warn", "timestamp": true},
		"inbounds":  []any{map[string]any{"type": "socks", "tag": "rz-node-check-in", "listen": "127.0.0.1", "listen_port": c.Port}},
		"outbounds": []any{outbound, map[string]any{"type": "direct", "tag": "direct"}},
		"route":     map[string]any{"final": "rz-exact-node", "auto_detect_interface": true},
	}
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil || writeAtomic(session.Spec.MatchArg, data, 0o600) != nil {
		return session, errors.New("write candidate")
	}
	checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(checkCtx, session.Spec.Binary, "check", "-c", session.Spec.MatchArg).CombinedOutput(); err != nil {
		clear(output)
		return session, errors.New("sing-box check failed")
	}
	return session, nil
}

func preserveNodeHostname(outbound map[string]any, hostname string) {
	if outbound == nil || hostname == "" || net.ParseIP(hostname) != nil {
		return
	}
	if tls, ok := outbound["tls"].(map[string]any); ok {
		enabled, _ := tls["enabled"].(bool)
		serverName, _ := tls["server_name"].(string)
		if enabled && strings.TrimSpace(serverName) == "" {
			tls["server_name"] = hostname
		}
	}
	transport, ok := outbound["transport"].(map[string]any)
	if !ok {
		return
	}
	typeName, _ := transport["type"].(string)
	if typeName != "ws" && typeName != "http" && typeName != "httpupgrade" {
		return
	}
	headers, _ := transport["headers"].(map[string]any)
	if headers == nil {
		headers = map[string]any{}
		transport["headers"] = headers
	}
	if host, _ := headers["Host"].(string); strings.TrimSpace(host) == "" {
		headers["Host"] = hostname
	}
}

func (c *ExactNodeChecker) startSession(ctx context.Context, session exactNodeSession) error {
	if err := c.Processes.Start(ctx, session.Spec); err != nil {
		return err
	}
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if !c.Processes.Running(session.Spec) {
			return errors.New("candidate exited")
		}
		if probeSOCKS5(ctx, session.Address) == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return errors.New("SOCKS readiness timeout")
}

func (c *ExactNodeChecker) verifyIdentity(session exactNodeSession) (routeidentity.Passport, error) {
	return routeidentity.Verify(session.Root, "sing-box", session.Address)
}

func (c *ExactNodeChecker) directTrace(ctx context.Context) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.cloudflare.com/cdn-cgi/trace", nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("User-Agent", "RAZVILKA-Node-Check/1")
	transport := &http.Transport{
		Proxy:             nil,
		DialContext:       (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		ForceAttemptHTTP2: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   8 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", errors.New("trace status")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 16*1024))
	if err != nil {
		return "", err
	}
	trace, err := parseCloudflareTrace(string(body))
	clear(body)
	return trace.EgressIP, err
}

func (c *ExactNodeChecker) proxyTrace(ctx context.Context, address string) (string, error) {
	trace, err := probeCloudflareTraceViaSOCKS(ctx, address)
	return trace.EgressIP, err
}

func (c *ExactNodeChecker) probeService(ctx context.Context, address, routePathID, egressIP string, service catalog.Service) (evidence.ProbeEvidence, error) {
	probe := selectedNodeProbe(service)
	service.ProbeURL = probe.URL
	started := c.currentTime()
	response, cleanup, err := socksHTTPGet(ctx, probe.URL, address)
	if cleanup != nil {
		defer cleanup()
	}
	finished := c.currentTime()
	result := evidence.ProbeEvidence{
		SchemaVersion: evidence.ProbeSchemaVersion, ProbeID: newNodeProbeID(), StartedAt: started, FinishedAt: finished,
		NetworkProfile: "", Service: service.ID, RoutePathID: routePathID, Engine: "sing-box", Outbound: routePathID,
		EgressIP: egressIP, Stage: "service", Outcome: evidence.OutcomeUnknown, Verdict: evidence.VerdictError,
		RequestedURL: probecheck.RedactedURL(probe.URL), ExpectedRoutePathID: routePathID, ObservedRoutePathID: routePathID,
		Source: "exact-node-check",
	}
	if err != nil {
		result.ErrorCode = "request-failed"
		return result, nil
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, probecheck.MaxBodyBytes+1))
	if readErr != nil || len(body) > probecheck.MaxBodyBytes {
		result.ErrorCode = "response-body-invalid"
		return result, nil
	}
	redirects := responseRedirects(response)
	assessment := probecheck.Evaluate(service, probe, probecheck.Observation{
		RequestedURL: probe.URL, FinalURL: probecheck.FinalURL(response, probe.URL), RedirectChain: redirects,
		HTTPStatus: response.StatusCode, ContentType: response.Header.Get("Content-Type"), Body: body,
		BodyTruncated: response.ContentLength > int64(len(body)), ExpectedRoutePathID: routePathID, ObservedRoutePathID: routePathID,
	})
	result.HTTPStatus = response.StatusCode
	result.Outcome, result.Verdict = assessment.Outcome, assessment.Verdict
	result.ErrorCode, result.ContentFingerprint = assessment.ErrorCode, assessment.ContentFingerprint
	result.ContentType = response.Header.Get("Content-Type")
	result.FinalURL = probecheck.RedactedURL(probecheck.FinalURL(response, probe.URL))
	for _, target := range redirects {
		result.RedirectChain = append(result.RedirectChain, probecheck.RedactedURL(target))
	}
	clear(body)
	return result, nil
}

func responseRedirects(response *http.Response) []string {
	chain := []string{}
	if response == nil || response.Request == nil {
		return chain
	}
	for request := response.Request; request != nil && request.Response != nil; request = request.Response.Request {
		chain = append([]string{request.URL.String()}, chain...)
	}
	return chain
}

func (c *ExactNodeChecker) cleanupSession(ctx context.Context, session exactNodeSession) error {
	if session.Spec.Binary == "" {
		if _, err := os.Lstat(session.Spec.PIDPath); err == nil {
			return errors.New("temporary process ownership unavailable")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		for _, path := range []string{session.Spec.MatchArg, session.Spec.PIDPath + routeidentity.ReceiptSuffix, session.Spec.LogPath} {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		return nil
	}
	if err := c.Processes.Stop(ctx, session.Spec); err != nil {
		return err
	}
	for _, path := range []string{session.Spec.MatchArg, session.Spec.PIDPath, session.Spec.PIDPath + routeidentity.ReceiptSuffix, session.Spec.LogPath} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}
