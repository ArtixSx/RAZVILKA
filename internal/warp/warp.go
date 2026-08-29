package warp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

const maxProfileBytes = 256 << 10

var ErrTermsAcceptanceRequired = errors.New("Cloudflare Terms of Service must be accepted before registration")
var ErrRegistrationEndpointUnavailable = errors.New("Cloudflare WARP registration endpoint is temporarily unavailable")

type Status struct {
	GeneratorInstalled bool         `json:"generator_installed"`
	GeneratorPath      string       `json:"generator_path,omitempty"`
	GeneratorVersion   string       `json:"generator_version,omitempty"`
	AccountRegistered  bool         `json:"account_registered"`
	LiveProfile        bool         `json:"live_profile"`
	LivePath           string       `json:"live_path,omitempty"`
	CandidateStaged    bool         `json:"candidate_staged"`
	Valid              bool         `json:"valid"`
	ValidationError    string       `json:"validation_error,omitempty"`
	SHA256             string       `json:"sha256,omitempty"`
	ModifiedAt         string       `json:"modified_at,omitempty"`
	Note               string       `json:"note"`
	Health             HealthStatus `json:"health"`
}

type Result struct {
	OK           bool   `json:"ok"`
	Source       string `json:"source"`
	FreshAccount bool   `json:"fresh_account,omitempty"`
	SHA256       string `json:"sha256,omitempty"`
	Message      string `json:"message"`
}

type ConnectivityCheck struct {
	OK             bool              `json:"ok"`
	Registration   ConnectivityProbe `json:"registration"`
	MASQUEHTTP2    ConnectivityProbe `json:"masque_http2"`
	WireGuardPorts []int             `json:"wireguard_ports"`
	Recommendation string            `json:"recommendation"`
	Note           string            `json:"note"`
}

type ConnectivityProbe struct {
	Ready     bool   `json:"ready"`
	Target    string `json:"target"`
	LatencyMS int64  `json:"latency_ms,omitempty"`
	Message   string `json:"message"`
}

type Manager struct {
	Root          string
	BackupRoot    string
	EngineConfigs *engineconfig.Manager
	BinPaths      []string
	ProfilePaths  []string
	Timeout       time.Duration
	mu            sync.Mutex
	version       string
	versionAt     time.Time
}

func New(root, backupRoot string, configs *engineconfig.Manager) *Manager {
	return &Manager{
		Root: root, BackupRoot: backupRoot, EngineConfigs: configs, Timeout: 90 * time.Second,
		BinPaths:     []string{"/opt/bin/wgcf", "/opt/usr/bin/wgcf", "wgcf"},
		ProfilePaths: []string{"/opt/etc/razvilka/warp/wgcf-profile.conf", "/opt/etc/wireguard/warp.conf"},
	}
}

func (m *Manager) Status(ctx context.Context) Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	status := Status{Note: "Новый профиль сначала сохраняется как черновик. Рабочий профиль заменяется только после проверки, резервной копии и явного применения."}
	doc, _ := m.loadHealthLocked()
	status.Health = m.healthStatusLocked(doc)
	bin := findBinary(m.BinPaths)
	status.GeneratorInstalled = bin != ""
	status.GeneratorPath = bin
	if bin != "" {
		status.GeneratorVersion = m.versionLocked(ctx, bin)
	}
	status.AccountRegistered = regularFile(m.accountPath())
	if m.EngineConfigs != nil {
		for _, engine := range m.EngineConfigs.List() {
			if engine.ID != "warp-wg" {
				continue
			}
			for _, file := range engine.Files {
				if file.ID == "main" {
					status.CandidateStaged = file.Staged
				}
			}
		}
	}
	path := firstFile(m.ProfilePaths)
	if path == "" {
		return status
	}
	status.LiveProfile, status.LivePath = true, path
	if info, err := os.Stat(path); err == nil {
		status.ModifiedAt = info.ModTime().UTC().Format(time.RFC3339)
	}
	b, err := readProfile(path)
	if err != nil {
		status.ValidationError = err.Error()
		return status
	}
	status.SHA256 = digest(b)
	if err := ValidateProfile(b); err != nil {
		status.ValidationError = err.Error()
		return status
	}
	status.Valid = true
	return status
}

func (m *Manager) Generate(ctx context.Context, acceptTOS, fresh bool) (Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.EngineConfigs == nil {
		return Result{}, errors.New("engine config manager is disabled")
	}
	bin := findBinary(m.BinPaths)
	if bin == "" {
		return Result{}, errors.New("wgcf is not installed; install the component first")
	}
	if err := os.MkdirAll(m.Root, 0o700); err != nil {
		return Result{}, err
	}
	account := m.accountPath()
	var restore []byte
	if fresh && regularFile(account) {
		var err error
		restore, err = os.ReadFile(account)
		if err != nil {
			return Result{}, err
		}
		if err := m.backupLocked("wgcf-account", restore, ".toml"); err != nil {
			return Result{}, err
		}
		if err := os.Remove(account); err != nil {
			return Result{}, err
		}
	}
	restoreAccount := func() {
		if len(restore) > 0 && !regularFile(account) {
			_ = writeSecret(account, restore)
		}
	}
	if !regularFile(account) {
		if !acceptTOS {
			restoreAccount()
			return Result{}, ErrTermsAcceptanceRequired
		}
		if err := m.registerLocked(ctx, bin); err != nil {
			restoreAccount()
			return Result{}, err
		}
		if !regularFile(account) {
			restoreAccount()
			return Result{}, errors.New("wgcf did not create an account file")
		}
		_ = os.Chmod(account, 0o600)
	}
	profile := filepath.Join(m.Root, "wgcf-profile.conf")
	_ = os.Remove(profile)
	if _, err := m.runLocked(ctx, bin, "generate"); err != nil {
		restoreAccount()
		return Result{}, fmt.Errorf("wgcf generate: %w", err)
	}
	b, err := readProfile(profile)
	if err != nil {
		restoreAccount()
		return Result{}, err
	}
	defer func() { _ = os.Remove(profile) }()
	if err := ValidateProfile(b); err != nil {
		restoreAccount()
		return Result{}, fmt.Errorf("generated profile is invalid: %w", err)
	}
	if _, err := m.EngineConfigs.Stage("warp-wg", "main", string(b)); err != nil {
		restoreAccount()
		return Result{}, err
	}
	if fresh {
		if err := m.recordRotationLocked(); err != nil {
			return Result{}, err
		}
	}
	return Result{OK: true, Source: "wgcf", FreshAccount: fresh, SHA256: digest(b), Message: "Кандидат создан и проверен структурно. Рабочий WARP не изменён; выполните Validate и Apply."}, nil
}

func (m *Manager) registerLocked(ctx context.Context, bin string) error {
	var last error
	for attempt := 1; attempt <= 3; attempt++ {
		_, last = m.runLocked(ctx, bin, "register", "--accept-tos", "--name", "RAZVILKA")
		if last == nil || regularFile(m.accountPath()) {
			return nil
		}
		if !transientRegistrationError(last) {
			return fmt.Errorf("wgcf register: %w", last)
		}
		if attempt == 3 {
			break
		}
		delay := time.Duration(attempt*2) * time.Second
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("%w: запрос отменён", ErrRegistrationEndpointUnavailable)
		case <-timer.C:
		}
	}
	return fmt.Errorf("%w: три попытки не прошли; проверьте доступ к api.cloudflareclient.com или импортируйте готовый профиль", ErrRegistrationEndpointUnavailable)
}

func transientRegistrationError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	for _, fragment := range []string{
		"tls handshake timeout", "i/o timeout", "connection timed out", "connection reset",
		"temporary failure", "server misbehaving", "network is unreachable", "no route to host",
		"connection refused", "unexpected eof",
	} {
		if strings.Contains(message, fragment) {
			return true
		}
	}
	return false
}

func (m *Manager) Import(content string) (Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b := []byte(content)
	if len(b) == 0 || len(b) > maxProfileBytes {
		return Result{}, errors.New("profile is empty or too large")
	}
	if err := ValidateProfile(b); err != nil {
		return Result{}, err
	}
	if m.EngineConfigs == nil {
		return Result{}, errors.New("engine config manager is disabled")
	}
	if _, err := m.EngineConfigs.Stage("warp-wg", "main", content); err != nil {
		return Result{}, err
	}
	return Result{OK: true, Source: "import", SHA256: digest(b), Message: "Профиль проверен и сохранён как черновик. Рабочий профиль не изменён."}, nil
}

func (m *Manager) CheckCandidate() (Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.EngineConfigs == nil {
		return Result{}, errors.New("engine config manager is disabled")
	}
	content, err := m.EngineConfigs.ReadExpert("warp-wg", "main")
	if err != nil {
		return Result{}, err
	}
	if content.Source == "missing" || content.Content == "" {
		return Result{}, errors.New("WARP profile is missing")
	}
	b := []byte(content.Content)
	if err := ValidateProfile(b); err != nil {
		return Result{}, err
	}
	return Result{OK: true, Source: content.Source, SHA256: digest(b), Message: "Структура, ключи, endpoint и сети корректны. Перед применением запустите безопасную проверку: временный интерфейс подтвердит handshake и доступ к выбранному сервису, а затем будет удалён."}, nil
}

// CheckConnectivity verifies only facts that can be confirmed without changing
// routes. A WireGuard UDP handshake is deliberately left to transactional Apply.
func (m *Manager) CheckConnectivity(ctx context.Context) ConnectivityCheck {
	registration := probeHTTPS(ctx, "https://api.cloudflareclient.com/")
	masque := probeTCP(ctx, "162.159.198.2:443")
	recommendation := "Создайте или загрузите профиль WARP · WireGuard, затем запустите безопасную проверку без применения. Она проверит UDP handshake через временный интерфейс и не изменит рабочие маршруты."
	if !registration.Ready && masque.Ready {
		recommendation = "Регистрация wgcf сейчас недоступна, но TCP/443 до Cloudflare отвечает. Используйте WARP · MASQUE или загрузите готовый WARP-профиль."
	} else if masque.Ready {
		recommendation = "TCP/443 до Cloudflare доступен: WARP · MASQUE — основной запасной маршрут при блокировке WireGuard UDP."
	} else if !registration.Ready {
		recommendation = "Cloudflare недоступен и для регистрации, и по MASQUE TCP/443. Используйте Sing-box/AmneziaWG со своим сервером."
	}
	return ConnectivityCheck{
		OK: registration.Ready || masque.Ready, Registration: registration, MASQUEHTTP2: masque,
		WireGuardPorts: []int{2408, 500, 1701, 4500}, Recommendation: recommendation,
		Note: "TCP/TLS-проверка не подменяет реальный туннель. WireGuard подтверждается безопасной проверкой handshake и выбранного сервиса; MASQUE — изолированным запросом сервиса.",
	}
}

func probeHTTPS(ctx context.Context, target string) ConnectivityProbe {
	started := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, target, nil)
	if err != nil {
		return ConnectivityProbe{Target: target, Message: "не удалось создать TLS-проверку"}
	}
	client := &http.Client{Timeout: 6 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return ConnectivityProbe{Target: target, Message: shortConnectivityError(err)}
	}
	_ = resp.Body.Close()
	return ConnectivityProbe{Ready: true, Target: target, LatencyMS: time.Since(started).Milliseconds(), Message: fmt.Sprintf("TLS отвечает (HTTP %d)", resp.StatusCode)}
}

func probeTCP(ctx context.Context, target string) ConnectivityProbe {
	started := time.Now()
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", target)
	if err != nil {
		return ConnectivityProbe{Target: target, Message: shortConnectivityError(err)}
	}
	_ = conn.Close()
	return ConnectivityProbe{Ready: true, Target: target, LatencyMS: time.Since(started).Milliseconds(), Message: "TCP/443 отвечает"}
}

func shortConnectivityError(err error) string {
	message := strings.ToLower(err.Error())
	for _, item := range []struct{ fragment, text string }{
		{"timeout", "тайм-аут соединения"}, {"no such host", "DNS не разрешил адрес"},
		{"refused", "соединение отклонено"}, {"unreachable", "сеть недоступна"},
	} {
		if strings.Contains(message, item.fragment) {
			return item.text
		}
	}
	return "соединение не установлено"
}

func (m *Manager) DeleteProfile(safeMode bool) (Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if safeMode {
		return Result{}, errors.New("Safe Mode blocks deletion of the live WARP profile")
	}
	path := firstFile(m.ProfilePaths)
	if path == "" {
		if m.EngineConfigs != nil {
			_ = m.EngineConfigs.Discard("warp-wg", "main")
		}
		return Result{OK: true, Source: "missing", Message: "Рабочего профиля не было; draft удалён."}, nil
	}
	b, err := readProfile(path)
	if err != nil {
		return Result{}, err
	}
	if err := m.backupLocked("warp-profile", b, ".conf"); err != nil {
		return Result{}, err
	}
	if err := os.Remove(path); err != nil {
		return Result{}, err
	}
	if m.EngineConfigs != nil {
		_ = m.EngineConfigs.Discard("warp-wg", "main")
	}
	return Result{OK: true, Source: "live", SHA256: digest(b), Message: "Рабочий профиль удалён после создания backup. Аккаунт wgcf сохранён."}, nil
}

func ValidateProfile(b []byte) error {
	if len(b) == 0 || len(b) > maxProfileBytes || strings.IndexByte(string(b), 0) >= 0 {
		return errors.New("invalid profile size or content")
	}
	sections := parseINI(string(b))
	privateKey := sections["Interface.PrivateKey"]
	publicKey := sections["Peer.PublicKey"]
	if err := validateKey(privateKey); err != nil {
		return fmt.Errorf("PrivateKey: %w", err)
	}
	if err := validateKey(publicKey); err != nil {
		return fmt.Errorf("PublicKey: %w", err)
	}
	addresses := splitCSV(sections["Interface.Address"])
	if len(addresses) == 0 {
		return errors.New("Interface.Address is missing")
	}
	for _, item := range addresses {
		if _, _, err := net.ParseCIDR(item); err != nil {
			return fmt.Errorf("invalid Interface.Address %q", item)
		}
	}
	endpoint := sections["Peer.Endpoint"]
	if endpoint == "" || !validEndpoint(endpoint) {
		return errors.New("Peer.Endpoint must be host:port")
	}
	allowed := splitCSV(sections["Peer.AllowedIPs"])
	if len(allowed) == 0 {
		return errors.New("Peer.AllowedIPs is missing")
	}
	for _, item := range allowed {
		if _, _, err := net.ParseCIDR(item); err != nil {
			return fmt.Errorf("invalid AllowedIPs entry %q", item)
		}
	}
	return nil
}

func validEndpoint(value string) bool {
	host, port, err := net.SplitHostPort(strings.TrimSpace(value))
	if err != nil || host == "" || port == "" {
		return false
	}
	for _, r := range port {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func validateKey(value string) error {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil || len(raw) != 32 {
		return errors.New("must be a 32-byte base64 WireGuard key")
	}
	return nil
}
func parseINI(content string) map[string]string {
	out := map[string]string{}
	section := ""
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if ok && section != "" {
			out[section+"."+strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	return out
}
func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func (m *Manager) accountPath() string { return filepath.Join(m.Root, "wgcf-account.toml") }
func (m *Manager) runLocked(parent context.Context, bin string, args ...string) (string, error) {
	timeout := m.Timeout
	if timeout <= 0 {
		timeout = 90 * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = m.Root
	output, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(output))
	if len(text) > 2048 {
		text = text[len(text)-2048:]
	}
	if ctx.Err() == context.DeadlineExceeded {
		return text, errors.New("command timed out")
	}
	if err != nil {
		if text == "" {
			return text, err
		}
		return text, errors.New(text)
	}
	return text, nil
}
func (m *Manager) versionLocked(ctx context.Context, bin string) string {
	if time.Since(m.versionAt) < 10*time.Minute {
		return m.version
	}
	m.version = components.InstalledReleaseVersion(bin)
	if m.version == "" {
		versionCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		output, err := exec.CommandContext(versionCtx, bin, "--version").CombinedOutput()
		cancel()
		if err == nil {
			m.version = strings.TrimSpace(string(output))
		}
	}
	if len(m.version) > 120 {
		m.version = m.version[:120]
	}
	m.versionAt = time.Now()
	return m.version
}
func (m *Manager) backupLocked(prefix string, b []byte, suffix string) error {
	if err := os.MkdirAll(m.BackupRoot, 0o700); err != nil {
		return err
	}
	path := filepath.Join(m.BackupRoot, prefix+"-"+time.Now().UTC().Format("20060102T150405.000000000Z")+suffix)
	return writeSecret(path, b)
}
func writeSecret(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".warp.tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = tmp.Close(); _ = os.Remove(name) }()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
func readProfile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() || info.Size() <= 0 || info.Size() > maxProfileBytes {
		return nil, errors.New("invalid WARP profile size")
	}
	return os.ReadFile(path)
}
func regularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}
func firstFile(paths []string) string {
	for _, path := range paths {
		if regularFile(path) {
			return path
		}
	}
	return ""
}
func findBinary(paths []string) string {
	for _, path := range paths {
		if strings.ContainsAny(path, `/\\`) {
			if regularFile(path) {
				return path
			}
		} else if found, err := exec.LookPath(path); err == nil {
			return found
		}
	}
	return ""
}
func digest(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
