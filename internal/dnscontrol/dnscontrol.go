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
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const schema = 3

type Provider struct {
	ID                    string   `json:"id"`
	Name                  string   `json:"name"`
	Description           string   `json:"description"`
	Servers               []string `json:"servers,omitempty"`
	DoH                   string   `json:"doh,omitempty"`
	DoT                   string   `json:"dot,omitempty"`
	Filters               []string `json:"filters,omitempty"`
	RequiresConfiguration bool     `json:"requires_configuration,omitempty"`
	Configured            bool     `json:"configured"`
	ConfigurationHint     string   `json:"configuration_hint,omitempty"`
	Warnings              []string `json:"warnings,omitempty"`
	RecommendedFor        []string `json:"recommended_for,omitempty"`
	USQUERegistration     string   `json:"usque_registration,omitempty"`
	Experimental          bool     `json:"experimental,omitempty"`
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
	DNSSEC    string `json:"dnssec,omitempty"`
	LatencyMS int64  `json:"latency_ms,omitempty"`
	Addresses int    `json:"addresses,omitempty"`
	Error     string `json:"error,omitempty"`
}

type Snapshot struct {
	Schema           int               `json:"schema"`
	Draft            Selection         `json:"draft"`
	Applied          Selection         `json:"applied"`
	Dirty            bool              `json:"dirty"`
	Providers        []Provider        `json:"providers"`
	Profiles         []Profile         `json:"profiles"`
	Mode             string            `json:"mode"`
	Note             string            `json:"note"`
	LastProbe        []ProbeResult     `json:"last_probe,omitempty"`
	ProbedAt         string            `json:"probed_at,omitempty"`
	ProbeProfileID   string            `json:"probe_profile_id,omitempty"`
	NextDNSProfileID string            `json:"nextdns_profile_id,omitempty"`
	ServiceDrafts    map[string]string `json:"service_drafts"`
	ServiceApplied   map[string]string `json:"service_applied"`
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
	Schema           int               `json:"schema"`
	Draft            Selection         `json:"draft"`
	Applied          Selection         `json:"applied"`
	LastProbe        []ProbeResult     `json:"last_probe,omitempty"`
	ProbedAt         string            `json:"probed_at,omitempty"`
	ProbeProfileID   string            `json:"probe_profile_id,omitempty"`
	NextDNSProfileID string            `json:"nextdns_profile_id,omitempty"`
	CustomProvider   *Provider         `json:"custom_provider,omitempty"`
	ServiceDrafts    map[string]string `json:"service_drafts,omitempty"`
	ServiceApplied   map[string]string `json:"service_applied,omitempty"`
}

type CustomProviderInput struct {
	Name    string   `json:"name"`
	Servers []string `json:"servers"`
	DoH     string   `json:"doh"`
	DoT     string   `json:"dot"`
}

type Manager struct {
	Path string
	mu   sync.RWMutex
	doc  document
}

func New(path string) (*Manager, error) {
	m := &Manager{Path: path, doc: document{Schema: schema, Draft: Selection{ProfileID: "automatic"}, Applied: Selection{ProfileID: "automatic"}, ServiceDrafts: map[string]string{}, ServiceApplied: map[string]string{}}}
	if err := m.load(); err != nil {
		return nil, err
	}
	return m, nil
}

func Providers() []Provider {
	return []Provider{
		{ID: "system", Name: "Системный DNS", Description: "DNS из Keenetic или от провайдера.", Filters: []string{"без изменений"}, Configured: true},
		{ID: "cloudflare", Name: "Cloudflare", Description: "Публичный резолвер без фильтрации.", Servers: []string{"1.1.1.1:53", "1.0.0.1:53"}, DoH: "https://cloudflare-dns.com/dns-query", DoT: "cloudflare-dns.com:853", Filters: []string{"DNSSEC", "без фильтрации"}, Configured: true},
		{ID: "quad9", Name: "Quad9", Description: "Защитный DNS с блокировкой опасных доменов.", Servers: []string{"9.9.9.9:53", "149.112.112.112:53"}, DoH: "https://dns.quad9.net/dns-query", DoT: "dns.quad9.net:853", Filters: []string{"DNSSEC", "вредоносные домены"}, Configured: true},
		{ID: "controld-unfiltered", Name: "Control D Unfiltered", Description: "Публичный Control D без блокирующих списков.", Servers: []string{"76.76.2.0:53", "76.76.10.0:53"}, DoH: "https://freedns.controld.com/p0", DoT: "p0.freedns.controld.com:853", Filters: []string{"без фильтрации"}, RecommendedFor: []string{"общий DNS", "диагностика"}, Configured: true},
		{ID: "controld-uncensored", Name: "Control D Uncensored", Description: "Профиль Control D для доменов, ограниченных в отдельных странах.", Servers: []string{"76.76.2.5:53", "76.76.10.5:53"}, DoH: "https://freedns.controld.com/uncensored", DoT: "uncensored.freedns.controld.com:853", Filters: []string{"без блок-листов", "доступ к ограниченным доменам"}, Warnings: []string{"Результат зависит от конкретного домена и сети; это не замена VPN или DPI-обходу."}, RecommendedFor: []string{"сервисный DNS", "диагностика блокировки"}, USQUERegistration: "test-first", Configured: true},
		{ID: "xbox-dns", Name: "Xbox DNS", Description: "Публичный DNS проекта Xbox DNS для игр и отдельных сервисов.", Servers: []string{"111.88.96.50:53", "111.88.96.51:53"}, DoH: "https://xbox-dns.ru/dns-query", DoT: "xbox-dns.ru:853", Filters: []string{"Smart DNS", "игры"}, Warnings: []string{"Сервис сторонний: перед назначением обязательно проверьте ответы и TLS нужного сайта."}, RecommendedFor: []string{"Xbox", "игровые сервисы"}, USQUERegistration: "unknown", Experimental: true, Configured: true},
		{ID: "adguard", Name: "AdGuard DNS", Description: "Блокирует рекламу и трекеры.", Servers: []string{"94.140.14.14:53", "94.140.15.15:53"}, DoH: "https://dns.adguard-dns.com/dns-query", DoT: "dns.adguard-dns.com:853", Filters: []string{"реклама", "трекеры"}, Configured: true},
		{ID: "adguard-family", Name: "AdGuard Family", Description: "Блокирует рекламу, трекеры и взрослый контент.", Servers: []string{"94.140.14.15:53", "94.140.15.16:53"}, DoH: "https://family.adguard-dns.com/dns-query", DoT: "family.adguard-dns.com:853", Filters: []string{"реклама", "трекеры", "семейный"}, Configured: true},
		{ID: "google", Name: "Google Public DNS", Description: "Публичный DNS без контентной фильтрации.", Servers: []string{"8.8.8.8:53", "8.8.4.4:53"}, DoH: "https://dns.google/dns-query", DoT: "dns.google:853", Filters: []string{"DNSSEC", "без фильтрации"}, Configured: true},
		{ID: "uncensoreddns", Name: "UncensoredDNS", Description: "Независимый публичный DNS без контентной цензуры.", Servers: []string{"91.239.100.100:53", "89.233.43.71:53"}, DoH: "https://anycast.uncensoreddns.org/dns-query", DoT: "anycast.uncensoreddns.org:853", Filters: []string{"без фильтрации", "DNSSEC"}, Warnings: []string{"Обычный UDP/53 может блокироваться или перехватываться провайдером; при возможности проверяйте DoH/DoT отдельно."}, RecommendedFor: []string{"общий DNS", "диагностика цензуры"}, USQUERegistration: "test-first", Configured: true},
		{ID: "flashstart", Name: "FlashStart", Description: "Фильтрующий Smart DNS для управляемого доступа к веб-ресурсам.", Servers: []string{"185.236.104.104:53", "185.236.105.105:53"}, Filters: []string{"фильтрация", "Smart DNS"}, Warnings: []string{"Не использовать для регистрации USQUE: ответы могут указывать на промежуточный узел, из-за чего API Cloudflare возвращает чужой TLS-сертификат.", "Применяйте только после проверки конкретного сервиса и его HTTPS-сертификата."}, RecommendedFor: []string{"контентная фильтрация"}, USQUERegistration: "blocked", Experimental: true, Configured: true},
		{ID: "nextdns", Name: "NextDNS", Description: "Персональная фильтрация по вашему профилю NextDNS.", Filters: []string{"настраиваемая фильтрация", "аналитика NextDNS"}, RequiresConfiguration: true, ConfigurationHint: "Укажите шестизначный ID профиля из кабинета NextDNS."},
		{ID: "custom", Name: "Свой DNS", Description: "Ваш обычный DNS, DoH или DoT endpoint.", Filters: []string{"пользовательский"}, RequiresConfiguration: true, ConfigurationHint: "Укажите хотя бы один DNS, DoH или DoT endpoint."},
	}
}

func Profiles() []Profile {
	return []Profile{
		{ID: "automatic", Name: "Автоматически", Description: "Оставить DNS под управлением Keenetic и провайдера.", ProviderID: "system"},
		{ID: "private", Name: "Приватный", Description: "Cloudflare без фильтрации контента.", ProviderID: "cloudflare"},
		{ID: "security", Name: "Защита", Description: "Блокировать известные вредоносные домены.", ProviderID: "quad9"},
		{ID: "controld-unfiltered", Name: "Control D · без фильтрации", Description: "Чистое разрешение доменов через Control D.", ProviderID: "controld-unfiltered"},
		{ID: "controld-uncensored", Name: "Control D · Uncensored", Description: "Проверить доступ к ограниченным доменам через Control D.", ProviderID: "controld-uncensored"},
		{ID: "xbox-dns", Name: "Xbox DNS", Description: "Экспериментальный Smart DNS для Xbox и игр.", ProviderID: "xbox-dns"},
		{ID: "ad-block", Name: "Без рекламы", Description: "Блокировать рекламу и трекеры через AdGuard DNS.", ProviderID: "adguard"},
		{ID: "family", Name: "Семейный", Description: "Фильтровать рекламу, трекеры и взрослый контент.", ProviderID: "adguard-family"},
		{ID: "unfiltered", Name: "Без фильтрации", Description: "Google Public DNS без контентной фильтрации.", ProviderID: "google"},
		{ID: "uncensoreddns", Name: "UncensoredDNS", Description: "Независимый DNS; UDP/53 проверяется отдельно.", ProviderID: "uncensoreddns"},
		{ID: "flashstart", Name: "FlashStart", Description: "Smart DNS с ограничениями; запрещён для регистрации USQUE.", ProviderID: "flashstart"},
		{ID: "nextdns", Name: "Мой NextDNS", Description: "Персональные списки, реклама и защита из вашего профиля NextDNS.", ProviderID: "nextdns"},
		{ID: "custom", Name: "Свой провайдер", Description: "Проверяемый DNS-провайдер, заданный вручную.", ProviderID: "custom"},
	}
}

func (m *Manager) Snapshot() Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return Snapshot{Schema: schema, Draft: m.doc.Draft, Applied: m.doc.Applied, Dirty: documentDirty(m.doc), Providers: providersFor(m.doc), Profiles: Profiles(), Mode: "preview", Note: "Профиль и привязки сервисов сохранены как черновик. Рабочий DNS роутера не меняется до появления транзакционного адаптера и проверки конфликтов.", LastProbe: append([]ProbeResult(nil), m.doc.LastProbe...), ProbedAt: m.doc.ProbedAt, ProbeProfileID: m.doc.ProbeProfileID, NextDNSProfileID: m.doc.NextDNSProfileID, ServiceDrafts: cloneStringMap(m.doc.ServiceDrafts), ServiceApplied: cloneStringMap(m.doc.ServiceApplied)}
}

func (m *Manager) Dirty() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return documentDirty(m.doc)
}

func (m *Manager) SetServiceDraft(serviceID, profileID string) error {
	serviceID = strings.ToLower(strings.TrimSpace(serviceID))
	profileID = strings.TrimSpace(profileID)
	if !validServiceID(serviceID) {
		return errors.New("некорректный идентификатор сервиса")
	}
	if profileID != "" && profileID != "inherit" {
		if _, ok := profileByID(profileID); !ok {
			return fmt.Errorf("unknown DNS profile %q", profileID)
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	previous := cloneDocument(m.doc)
	if m.doc.ServiceDrafts == nil {
		m.doc.ServiceDrafts = map[string]string{}
	}
	if profileID == "" || profileID == "inherit" {
		delete(m.doc.ServiceDrafts, serviceID)
	} else {
		m.doc.ServiceDrafts[serviceID] = profileID
	}
	if err := m.saveLocked(); err != nil {
		m.doc = previous
		return err
	}
	return nil
}

// Plan describes the safety contract for the selected DNS profile without
// changing the router. listener is supplied by Engine Lab and deliberately
// contains no command that could stop or replace the current resolver.
func (m *Manager) Plan(listener string) Plan {
	m.mu.RLock()
	doc := m.doc
	m.mu.RUnlock()
	profile, _ := profileByID(doc.Draft.ProfileID)
	provider, _ := providerByIDFor(profile.ProviderID, doc)
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
		if !stringMapsEqual(doc.ServiceDrafts, doc.ServiceApplied) {
			plan.Checks = append(plan.Checks, PlanCheck{ID: "service-bindings", Status: "fail", Message: "Привязки DNS к сервисам сохранены как черновик, но DNS-диспетчер ещё не активирован."})
			plan.Recommendation = "Привязки сервисов сохранены, но применить их можно только после реализации и аппаратной проверки DNS-диспетчера Keenetic."
			return plan
		}
		plan.Recommendation = "Применение не требуется: DNS остаётся под управлением системы."
		plan.Ready = true
		return plan
	}
	if !provider.Configured {
		plan.Checks = append(plan.Checks, PlanCheck{ID: "configuration", Status: "fail", Message: provider.ConfigurationHint})
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
	if providerHasFilter(provider, "DNSSEC") && doc.ProbeProfileID == profile.ID && len(doc.LastProbe) > 0 {
		dnssecConfirmed := 0
		for _, result := range doc.LastProbe {
			if result.Status == "pass" && result.DNSSEC == "confirmed" {
				dnssecConfirmed++
			}
		}
		if dnssecConfirmed > 0 {
			plan.Checks = append(plan.Checks, PlanCheck{ID: "dnssec", Status: "pass", Message: fmt.Sprintf("DNSSEC подтверждён на %d транспорт(ах).", dnssecConfirmed)})
		} else {
			plan.Checks = append(plan.Checks, PlanCheck{ID: "dnssec", Status: "warn", Message: "Сервер отвечает, но AD-флаг DNSSEC не подтверждён."})
		}
	}
	if strings.TrimSpace(listener) != "" {
		plan.Checks = append(plan.Checks, PlanCheck{ID: "ownership", Status: "fail", Message: "Порт 53 уже обслуживает " + listener + ". Нужна интеграция через upstream, а не второй DNS-сервер."})
	} else {
		plan.Checks = append(plan.Checks, PlanCheck{ID: "ownership", Status: "warn", Message: "Локальный DNS-владелец не определён; live-применение без аппаратной проверки запрещено."})
	}
	plan.Checks = append(plan.Checks, PlanCheck{ID: "adapter", Status: "fail", Message: "Транзакционный DNS-адаптер этой платформы ещё не активирован."})
	if len(doc.ServiceDrafts) > 0 {
		plan.Checks = append(plan.Checks, PlanCheck{ID: "service-bindings", Status: "warn", Message: fmt.Sprintf("Сохранены индивидуальные DNS-профили для %d сервис(ов); они не применены в сеть.", len(doc.ServiceDrafts))})
	}
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

func (m *Manager) SetNextDNSProfileID(profileID string) error {
	profileID = strings.ToLower(strings.TrimSpace(profileID))
	if profileID != "" && !validNextDNSProfileID(profileID) {
		return errors.New("ID NextDNS должен состоять ровно из 6 строчных шестнадцатеричных символов")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	previous := m.doc
	m.doc.NextDNSProfileID = profileID
	if m.doc.ProbeProfileID == "nextdns" {
		m.doc.LastProbe = nil
		m.doc.ProbedAt = ""
		m.doc.ProbeProfileID = ""
	}
	if err := m.saveLocked(); err != nil {
		m.doc = previous
		return err
	}
	return nil
}

func (m *Manager) SetCustomProvider(input CustomProviderInput) error {
	provider, err := normalizeCustomProvider(input)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	previous := m.doc
	m.doc.CustomProvider = &provider
	m.clearProbeLocked("custom")
	if err := m.saveLocked(); err != nil {
		m.doc = previous
		return err
	}
	return nil
}

func (m *Manager) ClearCustomProvider() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	previous := m.doc
	m.doc.CustomProvider = nil
	m.clearProbeLocked("custom")
	if err := m.saveLocked(); err != nil {
		m.doc = previous
		return err
	}
	return nil
}

func (m *Manager) clearProbeLocked(profileID string) {
	if m.doc.ProbeProfileID != profileID {
		return
	}
	m.doc.LastProbe = nil
	m.doc.ProbedAt = ""
	m.doc.ProbeProfileID = ""
}

func (m *Manager) Discard() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	previous := m.doc
	m.doc.Draft = m.doc.Applied
	m.doc.ServiceDrafts = cloneStringMap(m.doc.ServiceApplied)
	if err := m.saveLocked(); err != nil {
		m.doc = previous
		return err
	}
	return nil
}

// Apply commits only the no-change system profile. Non-system profiles require
// a platform DNS adapter and must remain drafts until that adapter can perform
// snapshot, canary, health and rollback on real hardware.
func (m *Manager) Apply() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !stringMapsEqual(m.doc.ServiceDrafts, m.doc.ServiceApplied) {
		return errors.New("live per-service DNS adapter is not available; service bindings remain drafts")
	}
	if m.doc.Draft.ProfileID != "automatic" {
		return errors.New("live DNS adapter is not available; the selected profile remains a draft")
	}
	previous := m.doc
	m.doc.Applied = m.doc.Draft
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
	m.mu.RLock()
	doc := m.doc
	m.mu.RUnlock()
	provider, _ := providerByIDFor(profile.ProviderID, doc)
	if !provider.Configured {
		return nil, errors.New(provider.ConfigurationHint)
	}
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
	currentProvider, _ := providerByIDFor(profile.ProviderID, m.doc)
	if providerFingerprint(provider) != providerFingerprint(currentProvider) {
		m.mu.Unlock()
		return results, errors.New("настройки DNS изменились во время проверки; запустите её повторно")
	}
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
			var authenticated bool
			addresses, authenticated, err = validateDNSResponse(query, response)
			if err == nil {
				dnssec := "not-confirmed"
				if authenticated {
					dnssec = "confirmed"
				}
				return ProbeResult{Server: endpoint, Transport: transport, Status: "pass", DNSSEC: dnssec, LatencyMS: time.Since(started).Milliseconds(), Addresses: addresses}
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
	if err := builder.Question(dnsmessage.Question{Name: dnsmessage.MustNewName("cloudflare.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	if err := builder.StartAdditionals(); err != nil {
		return nil, err
	}
	var ednsHeader dnsmessage.ResourceHeader
	if err := ednsHeader.SetEDNS0(1232, dnsmessage.RCodeSuccess, true); err != nil {
		return nil, err
	}
	if err := builder.OPTResource(ednsHeader, dnsmessage.OPTResource{}); err != nil {
		return nil, err
	}
	return builder.Finish()
}

func validateDNSResponse(query, response []byte) (int, bool, error) {
	var queryParser dnsmessage.Parser
	queryHeader, err := queryParser.Start(query)
	if err != nil {
		return 0, false, fmt.Errorf("invalid DNS query: %w", err)
	}
	var parser dnsmessage.Parser
	header, err := parser.Start(response)
	if err != nil {
		return 0, false, fmt.Errorf("invalid DNS response: %w", err)
	}
	if !header.Response || header.ID != queryHeader.ID {
		return 0, false, errors.New("DNS response does not match the request")
	}
	if header.RCode != dnsmessage.RCodeSuccess {
		return 0, false, fmt.Errorf("DNS server returned %s", header.RCode)
	}
	if err := parser.SkipAllQuestions(); err != nil {
		return 0, false, fmt.Errorf("invalid DNS question section: %w", err)
	}
	answers, err := parser.AllAnswers()
	if err != nil {
		return 0, false, fmt.Errorf("invalid DNS answer section: %w", err)
	}
	addresses := 0
	for _, answer := range answers {
		switch answer.Body.(type) {
		case *dnsmessage.AResource, *dnsmessage.AAAAResource:
			addresses++
		}
	}
	if addresses == 0 {
		return 0, false, errors.New("DNS response contains no addresses")
	}
	return addresses, header.AuthenticData, nil
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

func providerByIDFor(id string, doc document) (Provider, bool) {
	for _, provider := range providersFor(doc) {
		if provider.ID == id {
			return provider, true
		}
	}
	return Provider{}, false
}

func providersFor(doc document) []Provider {
	providers := Providers()
	for index := range providers {
		switch providers[index].ID {
		case "nextdns":
			if validNextDNSProfileID(doc.NextDNSProfileID) {
				providers[index].Configured = true
				providers[index].DoH = "https://dns.nextdns.io/" + doc.NextDNSProfileID
				providers[index].DoT = doc.NextDNSProfileID + ".dns.nextdns.io:853"
			}
		case "custom":
			if doc.CustomProvider != nil {
				providers[index] = cloneProvider(*doc.CustomProvider)
			}
		}
	}
	return providers
}

func normalizeCustomProvider(input CustomProviderInput) (Provider, error) {
	name := strings.TrimSpace(input.Name)
	if name == "" {
		name = "Свой DNS"
	}
	if len(name) > 80 || strings.IndexFunc(name, func(character rune) bool { return character < 32 || character == 127 }) >= 0 {
		return Provider{}, errors.New("название DNS должно быть короче 80 символов и не содержать управляющие символы")
	}
	servers := make([]string, 0, len(input.Servers))
	seen := map[string]bool{}
	for _, raw := range input.Servers {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		endpoint, err := normalizeDNSEndpoint(raw, "53")
		if err != nil {
			return Provider{}, fmt.Errorf("обычный DNS: %w", err)
		}
		if !seen[endpoint] {
			servers = append(servers, endpoint)
			seen[endpoint] = true
		}
		if len(servers) > 4 {
			return Provider{}, errors.New("можно указать не больше 4 обычных DNS endpoint")
		}
	}
	doh := strings.TrimSpace(input.DoH)
	if doh != "" {
		parsed, err := url.Parse(doh)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || len(doh) > 512 {
			return Provider{}, errors.New("DoH должен быть HTTPS URL без логина, пароля, query и фрагмента")
		}
		if !validDNSHost(parsed.Hostname()) {
			return Provider{}, errors.New("DoH содержит некорректный IP или DNS-имя")
		}
		if parsed.Port() != "" {
			port, err := strconv.Atoi(parsed.Port())
			if err != nil || port < 1 || port > 65535 {
				return Provider{}, errors.New("порт DoH должен быть числом от 1 до 65535")
			}
		}
		doh = parsed.String()
	}
	dot := strings.TrimSpace(input.DoT)
	if dot != "" {
		var err error
		dot, err = normalizeDNSEndpoint(dot, "853")
		if err != nil {
			return Provider{}, fmt.Errorf("DoT: %w", err)
		}
	}
	if len(servers) == 0 && doh == "" && dot == "" {
		return Provider{}, errors.New("укажите хотя бы один обычный DNS, DoH или DoT endpoint")
	}
	return Provider{ID: "custom", Name: name, Description: "Пользовательский DNS-провайдер, сохранённый локально.", Servers: servers, DoH: doh, DoT: dot, Filters: []string{"пользовательский"}, RequiresConfiguration: true, Configured: true, ConfigurationHint: "Endpoint сохранён локально и должен пройти проверку до применения."}, nil
}

func normalizeDNSEndpoint(raw, defaultPort string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" || len(value) > 255 || strings.ContainsAny(value, "/?#@") {
		return "", errors.New("ожидается IP или имя хоста с необязательным портом")
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		if ip := net.ParseIP(value); ip != nil {
			host, port = ip.String(), defaultPort
		} else if strings.Count(value, ":") == 0 {
			host, port = value, defaultPort
		} else {
			return "", errors.New("IPv6 с портом нужно записать как [адрес]:порт")
		}
	}
	if !validDNSHost(host) {
		return "", errors.New("некорректный IP или DNS-имя")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", errors.New("порт должен быть числом от 1 до 65535")
	}
	return net.JoinHostPort(strings.TrimSuffix(strings.ToLower(host), "."), port), nil
}

func validDNSHost(host string) bool {
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if net.ParseIP(host) != nil {
		return true
	}
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func cloneProvider(provider Provider) Provider {
	provider.Servers = append([]string(nil), provider.Servers...)
	provider.Filters = append([]string(nil), provider.Filters...)
	provider.Warnings = append([]string(nil), provider.Warnings...)
	provider.RecommendedFor = append([]string(nil), provider.RecommendedFor...)
	return provider
}

func cloneStringMap(source map[string]string) map[string]string {
	copy := make(map[string]string, len(source))
	for key, value := range source {
		copy[key] = value
	}
	return copy
}

func cloneDocument(source document) document {
	source.ServiceDrafts = cloneStringMap(source.ServiceDrafts)
	source.ServiceApplied = cloneStringMap(source.ServiceApplied)
	if source.CustomProvider != nil {
		provider := cloneProvider(*source.CustomProvider)
		source.CustomProvider = &provider
	}
	return source
}

func stringMapsEqual(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func documentDirty(doc document) bool {
	return doc.Draft != doc.Applied || !stringMapsEqual(doc.ServiceDrafts, doc.ServiceApplied)
}

func validServiceID(value string) bool {
	if value == "" || len(value) > 64 || ((value[0] < 'a' || value[0] > 'z') && (value[0] < '0' || value[0] > '9')) {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func providerFingerprint(provider Provider) string {
	return strings.Join([]string{provider.ID, provider.Name, strings.Join(provider.Servers, ","), provider.DoH, provider.DoT}, "\x00")
}

func providerHasFilter(provider Provider, filter string) bool {
	for _, candidate := range provider.Filters {
		if strings.EqualFold(candidate, filter) {
			return true
		}
	}
	return false
}

func validNextDNSProfileID(value string) bool {
	if len(value) != 6 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
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
	if loaded.Schema != 1 && loaded.Schema != 2 && loaded.Schema != schema {
		return fmt.Errorf("unsupported DNS state schema %d", loaded.Schema)
	}
	loaded.Schema = schema
	if loaded.ServiceDrafts == nil {
		loaded.ServiceDrafts = map[string]string{}
	}
	if loaded.ServiceApplied == nil {
		loaded.ServiceApplied = map[string]string{}
	}
	for serviceID, profileID := range loaded.ServiceDrafts {
		if !validServiceID(serviceID) {
			delete(loaded.ServiceDrafts, serviceID)
			continue
		}
		if _, ok := profileByID(profileID); !ok {
			delete(loaded.ServiceDrafts, serviceID)
		}
	}
	for serviceID, profileID := range loaded.ServiceApplied {
		if !validServiceID(serviceID) {
			delete(loaded.ServiceApplied, serviceID)
			continue
		}
		if _, ok := profileByID(profileID); !ok {
			delete(loaded.ServiceApplied, serviceID)
		}
	}
	if _, ok := profileByID(loaded.Draft.ProfileID); !ok {
		loaded.Draft.ProfileID = "automatic"
	}
	if _, ok := profileByID(loaded.Applied.ProfileID); !ok {
		loaded.Applied.ProfileID = "automatic"
	}
	if loaded.CustomProvider != nil {
		normalized, err := normalizeCustomProvider(CustomProviderInput{Name: loaded.CustomProvider.Name, Servers: loaded.CustomProvider.Servers, DoH: loaded.CustomProvider.DoH, DoT: loaded.CustomProvider.DoT})
		if err != nil {
			loaded.CustomProvider = nil
		} else {
			loaded.CustomProvider = &normalized
		}
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
