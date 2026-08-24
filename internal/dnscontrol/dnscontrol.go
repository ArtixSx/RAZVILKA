package dnscontrol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
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
		plan.Checks = append(plan.Checks, PlanCheck{ID: "probe", Status: "fail", Message: "Ни один сервер выбранного профиля не ответил."})
	} else if passed < len(doc.LastProbe) {
		plan.Checks = append(plan.Checks, PlanCheck{ID: "probe", Status: "warn", Message: fmt.Sprintf("Ответили %d из %d серверов; нужен failover.", passed, len(doc.LastProbe))})
	} else {
		plan.Checks = append(plan.Checks, PlanCheck{ID: "probe", Status: "pass", Message: "Все серверы выбранного профиля ответили."})
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
	servers := append([]string(nil), provider.Servers...)
	if provider.ID == "system" {
		servers = []string{"system"}
	}
	results := make([]ProbeResult, 0, len(servers))
	for _, server := range servers {
		results = append(results, probeServer(ctx, server))
	}
	m.mu.Lock()
	m.doc.LastProbe = append([]ProbeResult(nil), results...)
	m.doc.ProbedAt = time.Now().UTC().Format(time.RFC3339)
	m.doc.ProbeProfileID = profile.ID
	err := m.saveLocked()
	m.mu.Unlock()
	return results, err
}

func probeServer(parent context.Context, server string) ProbeResult {
	ctx, cancel := context.WithTimeout(parent, 4*time.Second)
	defer cancel()
	started := time.Now()
	resolver := net.DefaultResolver
	if server != "system" {
		resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "udp", server)
		}}
	}
	addresses, err := resolver.LookupHost(ctx, "example.com")
	result := ProbeResult{Server: server, LatencyMS: time.Since(started).Milliseconds()}
	if err != nil {
		result.Status = "fail"
		result.Error = friendlyProbeError(err)
		return result
	}
	result.Status = "pass"
	result.Addresses = len(addresses)
	return result
}

func friendlyProbeError(err error) string {
	text := strings.ToLower(err.Error())
	if errors.Is(err, context.DeadlineExceeded) || strings.Contains(text, "timeout") {
		return "DNS-сервер не ответил за 4 секунды"
	}
	if strings.Contains(text, "refused") {
		return "DNS-сервер отклонил соединение"
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
