package dnscontrol

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const schema = 1

type Provider struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Servers     []string `json:"servers,omitempty"`
	DoH         string   `json:"doh,omitempty"`
	DoT         string   `json:"dot,omitempty"`
	Filters     []string `json:"filters,omitempty"`
}

type Profile struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	ProviderID  string `json:"provider_id"`
}

type Selection struct {
	ProfileID string `json:"profile_id"`
}

type ProbeResult struct {
	Server    string `json:"server"`
	Transport string `json:"transport"`
	Status    string `json:"status"`
	LatencyMS int64  `json:"latency_ms,omitempty"`
	Addresses int    `json:"addresses,omitempty"`
	Error     string `json:"error,omitempty"`
}

type Snapshot struct {
	Schema         int           `json:"schema"`
	Draft          Selection     `json:"draft"`
	Applied        Selection     `json:"applied"`
	Dirty          bool          `json:"dirty"`
	Providers      []Provider    `json:"providers"`
	Profiles       []Profile     `json:"profiles"`
	Mode           string        `json:"mode"`
	Note           string        `json:"note"`
	LastProbe      []ProbeResult `json:"last_probe,omitempty"`
	ProbedAt       string        `json:"probed_at,omitempty"`
	ProbeProfileID string        `json:"probe_profile_id,omitempty"`
}

type PlanCheck struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

type PlanStep struct {
	Order   int    `json:"order"`
	Name    string `json:"name"`
	Summary string `json:"summary"`
}

type Plan struct {
	Profile        Profile     `json:"profile"`
	Provider       Provider    `json:"provider"`
	Mode           string      `json:"mode"`
	Listener       string      `json:"listener,omitempty"`
	Ready          bool        `json:"ready"`
	Checks         []PlanCheck `json:"checks"`
	Steps          []PlanStep  `json:"steps"`
	Recommendation string      `json:"recommendation"`
}

type document struct {
	Schema         int           `json:"schema"`
	Draft          Selection     `json:"draft"`
	Applied        Selection     `json:"applied"`
	LastProbe      []ProbeResult `json:"last_probe,omitempty"`
	ProbedAt       string        `json:"probed_at,omitempty"`
	ProbeProfileID string        `json:"probe_profile_id,omitempty"`
}

type Manager struct {
	Path string
	mu   sync.RWMutex
	doc  document
}

func New(path string) (*Manager, error) {
	m := &Manager{Path: path, doc: document{Schema: schema, Draft: Selection{ProfileID: "automatic"}, Applied: Selection{ProfileID: "automatic"}}}
	if err := m.load(); err != nil {
		return nil, err
	}
	return m, nil
}

func Providers() []Provider {
	return []Provider{
		{ID: "system", Name: "Системный DNS", Description: "DNS из Keenetic или от провайдера.", Filters: []string{"без изменений"}},
		{ID: "cloudflare", Name: "Cloudflare", Description: "Публичный резолвер без фильтрации.", Servers: []string{"1.1.1.1:53", "1.0.0.1:53"}, DoH: "https://cloudflare-dns.com/dns-query", DoT: "cloudflare-dns.com:853", Filters: []string{"DNSSEC", "без фильтрации"}},
		{ID: "quad9", Name: "Quad9", Description: "Защитный DNS с блокировкой опасных доменов.", Servers: []string{"9.9.9.9:53", "149.112.112.112:53"}, DoH: "https://dns.quad9.net/dns-query", DoT: "dns.quad9.net:853", Filters: []string{"DNSSEC", "вредоносные домены"}},
		{ID: "adguard", Name: "AdGuard DNS", Description: "Блокирует рекламу и трекеры.", Servers: []string{"94.140.14.14:53", "94.140.15.15:53"}, DoH: "https://dns.adguard-dns.com/dns-query", DoT: "dns.adguard-dns.com:853", Filters: []string{"реклама", "трекеры"}},
		{ID: "adguard-family", Name: "AdGuard Family", Description: "Блокирует рекламу, трекеры и взрослый контент.", Servers: []string{"94.140.14.15:53", "94.140.15.16:53"}, DoH: "https://family.adguard-dns.com/dns-query", DoT: "family.adguard-dns.com:853", Filters: []string{"реклама", "трекеры", "семейный"}},
		{ID: "google", Name: "Google Public DNS", Description: "Публичный DNS без контентной фильтрации.", Servers: []string{"8.8.8.8:53", "8.8.4.4:53"}, DoH: "https://dns.google/dns-query", DoT: "dns.google:853", Filters: []string{"DNSSEC", "без фильтрации"}},
	}
}

func Profiles() []Profile {
	return []Profile{
		{ID: "automatic", Name: "Автоматически", Description: "Оставить DNS под управлением Keenetic и провайдера.", ProviderID: "system"},
		{ID: "private", Name: "Приватный", Description: "Cloudflare без фильтрации контента.", ProviderID: "cloudflare"},
		{ID: "security", Name: "Защита", Description: "Блокировать известные вредоносные домены.", ProviderID: "quad9"},
		{ID: "ad-block", Name: "Без рекламы", Description: "Блокировать рекламу и трекеры через AdGuard DNS.", ProviderID: "adguard"},
		{ID: "family", Name: "Семейный", Description: "Фильтровать рекламу, трекеры и взрослый контент.", ProviderID: "adguard-family"},
		{ID: "unfiltered", Name: "Без фильтрации", Description: "Google Public DNS без контентной фильтрации.", ProviderID: "google"},
	}
}

func (m *Manager) Snapshot() Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return Snapshot{Schema: schema, Draft: m.doc.Draft, Applied: m.doc.Applied, Dirty: m.doc.Draft != m.doc.Applied, Providers: Providers(), Profiles: Profiles(), Mode: "preview", Note: "Профиль сохранён как черновик. Рабочий DNS роутера не меняется до появления транзакционного адаптера и проверки конфликтов.", LastProbe: append([]ProbeResult(nil), m.doc.LastProbe...), ProbedAt: m.doc.ProbedAt, ProbeProfileID: m.doc.ProbeProfileID}
}

// Plan describes the safety contract for the selected DNS profile without
// changing the router. listener is supplied by Engine Lab and deliberately
// contains no command that could stop or replace the current resolver.
func (m *Manager) Plan(listener string) Plan {
	m.mu.RLock()
	doc := m.doc
	m.mu.RUnlock()
	profile, _ := profileByID(doc.Draft.ProfileID)
	provider, _ := providerByID(profile.ProviderID)
	plan := Plan{
		Profile: profile, Provider: provider, Mode: "preview", Listener: listener,
		Checks: []PlanCheck{},
		Steps: []PlanStep{
			{Order: 1, Name: "Снимок", Summary: "Сохранить только DNS-объекты RAZVILKA и текущий upstream системного резолвера."},
			{Order: 2, Name: "Проверка", Summary: "Проверить bootstrap, выбранные серверы, DNSSEC и отсутствие циклического маршрута."},
			{Order: 3, Name: "Подготовка", Summary: "Запустить локальный кандидат на отдельном порту, не занимая рабочий :53."},
			{Order: 4, Name: "Canary", Summary: "Отправить тестовые запросы только через кандидата и сравнить ответы с контролем."},
			{Order: 5, Name: "Переключение", Summary: "Изменить upstream штатного DNS атомарно; при ошибке немедленно вернуть снимок."},
			{Order: 6, Name: "Контроль", Summary: "Проверить DNS с роутера и LAN-клиента, затем зафиксировать или откатить."},
		},
		Recommendation: "Live-применение остаётся выключенным, пока не реализован и не проверен адаптер штатного DNS Keenetic/Netcraze.",
	}
	if profile.ID == "automatic" {
		plan.Checks = append(plan.Checks, PlanCheck{ID: "profile", Status: "pass", Message: "Системный DNS остаётся без изменений."})
		plan.Checks = append(plan.Checks, PlanCheck{ID: "ownership", Status: "pass", Message: "RAZVILKA не запрашивает порт 53."})
		plan.Recommendation = "Применение не требуется: DNS остаётся под управлением системы."
		plan.Ready = true
		return plan
	}
	passed := 0
	for _, result := range doc.LastProbe {
		if result.Status == "pass" {
			passed++
		}
	}
	if doc.ProbeProfileID != profile.ID || len(doc.LastProbe) == 0 {
		plan.Checks = append(plan.Checks, PlanCheck{ID: "probe", Status: "fail", Message: "Сначала проверьте выбранный профиль."})
	} else if passed == 0 {
		plan.Checks = append(plan.Checks, PlanCheck{ID: "probe", Status: "fail", Message: "Ни один транспорт выбранного профиля не ответил."})
	} else if passed < len(doc.LastProbe) {
		plan.Checks = append(plan.Checks, PlanCheck{ID: "probe", Status: "warn", Message: fmt.Sprintf("Доступны %d из %d проверенных транспортов; нужен failover.", passed, len(doc.LastProbe))})
	} else {
		plan.Checks = append(plan.Checks, PlanCheck{ID: "probe", Status: "pass", Message: "Все заявленные транспорты выбранного профиля ответили."})
	}
	if strings.TrimSpace(listener) != "" {
		plan.Checks = append(plan.Checks, PlanCheck{ID: "ownership", Status: "fail", Message: "Порт 53 уже обслуживает " + listener + ". Нужна интеграция через upstream, а не второй DNS-сервер."})
	} else {
		plan.Checks = append(plan.Checks, PlanCheck{ID: "ownership", Status: "warn", Message: "Локальный DNS-владелец не определён; live-применение без аппаратной проверки запрещено."})
	}
	plan.Checks = append(plan.Checks, PlanCheck{ID: "adapter", Status: "fail", Message: "Транзакционный DNS-адаптер этой платформы ещё не активирован."})
	return plan
}

func (m *Manager) SetDraft(profileID string) error {
	profileID = strings.TrimSpace(profileID)
	if _, ok := profileByID(profileID); !ok {
		return fmt.Errorf("unknown DNS profile %q", profileID)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	previous := m.doc
	m.doc.Draft = Selection{ProfileID: profileID}
	if err := m.saveLocked(); err != nil {
		m.doc = previous
		return err
	}
	return nil
}

func (m *Manager) Discard() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	previous := m.doc
	m.doc.Draft = m.doc.Applied
	if err := m.saveLocked(); err != nil {
		m.doc = previous
		return err
	}
	return nil
}

func (m *Manager) Probe(ctx context.Context, profileID string) ([]ProbeResult, error) {
	profile, ok := profileByID(strings.TrimSpace(profileID))
	if !ok {
		return nil, fmt.Errorf("unknown DNS profile %q", profileID)
	}
	provider, _ := providerByID(profile.ProviderID)
	if provider.ID == "system" {
		results := []ProbeResult{probeSystem(ctx)}
		m.mu.Lock()
		m.doc.LastProbe = append([]ProbeResult(nil), results...)
		m.doc.ProbedAt = time.Now().UTC().Format(time.RFC3339)
		m.doc.ProbeProfileID = profile.ID
		err := m.saveLocked()
		m.mu.Unlock()
		return results, err
	}
	targets := make([]dnsTarget, 0, len(provider.Servers)*2+2)
	for _, server := range provider.Servers {
		targets = append(targets,
			dnsTarget{"UDP", server, probeDNSOverUDP},
			dnsTarget{"TCP", server, probeDNSOverTCP},
		)
	}
	if provider.DoH != "" {
		targets = append(targets, dnsTarget{"DoH", provider.DoH, probeDNSOverHTTPS})
	}
	if provider.DoT != "" {
		targets = append(targets, dnsTarget{"DoT", provider.DoT, probeDNSOverTLS})
	}
	results := make([]ProbeResult, len(targets))
	var probes sync.WaitGroup
	probes.Add(len(targets))
	for index, target := range targets {
		go func() {
			defer probes.Done()
			results[index] = probeEndpoint(ctx, target.transport, target.endpoint, target.probe)
		}()
	}
	probes.Wait()
	m.mu.Lock()
	m.doc.LastProbe = append([]ProbeResult(nil), results...)
	m.doc.ProbedAt = time.Now().UTC().Format(time.RFC3339)
	m.doc.ProbeProfileID = profile.ID
	err := m.saveLocked()
	m.mu.Unlock()
	return results, err
}

type dnsProbe func(context.Context, string, []byte) ([]byte, error)

type dnsTarget struct {
	transport string
	endpoint  string
	probe     dnsProbe
}

func probeSystem(parent context.Context) ProbeResult {
	ctx, cancel := context.WithTimeout(parent, 4*time.Second)
	defer cancel()
	started := time.Now()
	addresses, err := net.DefaultResolver.LookupHost(ctx, "example.com")
	result := ProbeResult{Server: "system", Transport: "Системный", LatencyMS: time.Since(started).Milliseconds()}
	if err != nil {
		result.Status = "fail"
		result.Error = friendlyProbeError(err)
		return result
	}
	result.Status = "pass"
	result.Addresses = len(addresses)
	return result
}

func probeEndpoint(parent context.Context, transport, endpoint string, probe dnsProbe) ProbeResult {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	started := time.Now()
	query, err := buildDNSQuery(uint16(time.Now().UnixNano()))
	if err == nil {
		var response []byte
		response, err = probe(ctx, endpoint, query)
		if err == nil {
			var addresses int
			addresses, err = validateDNSResponse(query, response)
			if err == nil {
				return ProbeResult{Server: endpoint, Transport: transport, Status: "pass", LatencyMS: time.Since(started).Milliseconds(), Addresses: addresses}
			}
		}
	}
	return ProbeResult{Server: endpoint, Transport: transport, Status: "fail", LatencyMS: time.Since(started).Milliseconds(), Error: friendlyProbeError(err)}
}

func buildDNSQuery(id uint16) ([]byte, error) {
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	builder.EnableCompression()
	if err := builder.StartQuestions(); err != nil {
		return nil, err
	}
	if err := builder.Question(dnsmessage.Question{Name: dnsmessage.MustNewName("example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	return builder.Finish()
}

func validateDNSResponse(query, response []byte) (int, error) {
	var queryParser dnsmessage.Parser
	queryHeader, err := queryParser.Start(query)
	if err != nil {
		return 0, fmt.Errorf("invalid DNS query: %w", err)
	}
	var parser dnsmessage.Parser
	header, err := parser.Start(response)
	if err != nil {
		return 0, fmt.Errorf("invalid DNS response: %w", err)
	}
	if !header.Response || header.ID != queryHeader.ID {
		return 0, errors.New("DNS response does not match the request")
	}
	if header.RCode != dnsmessage.RCodeSuccess {
		return 0, fmt.Errorf("DNS server returned %s", header.RCode)
	}
	if err := parser.SkipAllQuestions(); err != nil {
		return 0, fmt.Errorf("invalid DNS question section: %w", err)
	}
	answers, err := parser.AllAnswers()
	if err != nil {
		return 0, fmt.Errorf("invalid DNS answer section: %w", err)
	}
	addresses := 0
	for _, answer := range answers {
		switch answer.Body.(type) {
		case *dnsmessage.AResource, *dnsmessage.AAAAResource:
			addresses++
		}
	}
	if addresses == 0 {
		return 0, errors.New("DNS response contains no addresses")
	}
	return addresses, nil
}

func probeDNSOverUDP(ctx context.Context, endpoint string, query []byte) ([]byte, error) {
	connection, err := (&net.Dialer{}).DialContext(ctx, "udp", endpoint)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	applyContextDeadline(ctx, connection)
	if _, err := connection.Write(query); err != nil {
		return nil, err
	}
	response := make([]byte, 4096)
	n, err := connection.Read(response)
	return response[:n], err
}

func probeDNSOverTCP(ctx context.Context, endpoint string, query []byte) ([]byte, error) {
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	applyContextDeadline(ctx, connection)
	return exchangeFramedDNS(connection, query)
}

func probeDNSOverTLS(ctx context.Context, endpoint string, query []byte) ([]byte, error) {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid DoT endpoint: %w", err)
	}
	dialer := tls.Dialer{Config: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}}
	connection, err := dialer.DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	applyContextDeadline(ctx, connection)
	return exchangeFramedDNS(connection, query)
}

func probeDNSOverHTTPS(ctx context.Context, endpoint string, query []byte) ([]byte, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return nil, errors.New("invalid DoH HTTPS endpoint")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/dns-message")
	request.Header.Set("Content-Type", "application/dns-message")
	client := &http.Client{
		Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}},
		CheckRedirect: func(request *http.Request, _ []*http.Request) error {
			if request.URL.Scheme != "https" {
				return errors.New("DoH endpoint redirected outside HTTPS")
			}
			return nil
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("DoH endpoint returned HTTP %d", response.StatusCode)
	}
	return io.ReadAll(io.LimitReader(response.Body, 65536))
}

func exchangeFramedDNS(connection net.Conn, query []byte) ([]byte, error) {
	if len(query) > 65535 {
		return nil, errors.New("DNS query is too large")
	}
	frame := make([]byte, len(query)+2)
	binary.BigEndian.PutUint16(frame[:2], uint16(len(query)))
	copy(frame[2:], query)
	if _, err := connection.Write(frame); err != nil {
		return nil, err
	}
	var size [2]byte
	if _, err := io.ReadFull(connection, size[:]); err != nil {
		return nil, err
	}
	response := make([]byte, int(binary.BigEndian.Uint16(size[:])))
	_, err := io.ReadFull(connection, response)
	return response, err
}

func applyContextDeadline(ctx context.Context, connection net.Conn) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
}

func friendlyProbeError(err error) string {
	text := strings.ToLower(err.Error())
	if errors.Is(err, context.DeadlineExceeded) || strings.Contains(text, "timeout") {
		return "DNS-сервер не ответил за 4 секунды"
	}
	if strings.Contains(text, "refused") {
		return "DNS-сервер отклонил соединение"
	}
	if strings.Contains(text, "certificate") || strings.Contains(text, "tls") {
		return "Не удалось подтвердить защищённое TLS-соединение"
	}
	if strings.Contains(text, "no addresses") {
		return "DNS-сервер ответил, но не вернул адрес"
	}
	if strings.Contains(text, "http") {
		return "DoH-сервер вернул неожиданный HTTP-ответ"
	}
	return "Не удалось получить DNS-ответ"
}

func profileByID(id string) (Profile, bool) {
	for _, profile := range Profiles() {
		if profile.ID == id {
			return profile, true
		}
	}
	return Profile{}, false
}

func providerByID(id string) (Provider, bool) {
	for _, provider := range Providers() {
		if provider.ID == id {
			return provider, true
		}
	}
	return Provider{}, false
}

func (m *Manager) load() error {
	if m.Path == "" {
		return nil
	}
	b, err := os.ReadFile(m.Path)
	if errors.Is(err, os.ErrNotExist) {
		return m.saveLocked()
	}
	if err != nil {
		return err
	}
	var loaded document
	if err := json.Unmarshal(b, &loaded); err != nil {
		return fmt.Errorf("decode DNS state: %w", err)
	}
	if loaded.Schema != schema {
		return fmt.Errorf("unsupported DNS state schema %d", loaded.Schema)
	}
	if _, ok := profileByID(loaded.Draft.ProfileID); !ok {
		loaded.Draft.ProfileID = "automatic"
	}
	if _, ok := profileByID(loaded.Applied.ProfileID); !ok {
		loaded.Applied.ProfileID = "automatic"
	}
	m.doc = loaded
	return nil
}

func (m *Manager) saveLocked() error {
	if m.Path == "" {
		return nil
	}
	m.doc.Schema = schema
	b, err := json.MarshalIndent(m.doc, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(m.Path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(dir, ".dns-*.tmp")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(b); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, m.Path); err != nil {
		return err
	}
	return os.Chmod(m.Path, 0600)
}
