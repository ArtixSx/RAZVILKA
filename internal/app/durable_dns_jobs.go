package app

import (
	"context"
	"slices"
	"strings"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

func validDurableDNSRequest(r serviceControlJobRequest) bool {
	if r.ExpectedRevision == nil || len(r.ServiceIDs) != 1 || len(r.NodeIDs) != 0 || r.DNS == nil || len(r.DNS.ProfileIDs) < 1 || len(r.DNS.ProfileIDs) > 3 || r.DNS.VerifyService && len(r.DNS.ProfileIDs) > 2 {
		return false
	}
	seen := map[string]bool{}
	for _, id := range append(slices.Clone(r.DNS.ProfileIDs), r.ServiceIDs...) {
		if id == "" || len(id) > 128 || strings.Trim(id, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.") != "" {
			return false
		}
	}
	for _, id := range r.DNS.ProfileIDs {
		if seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

// Freeze only chosen profile/provider definitions, not changing last-probe
// telemetry or unrelated diagnostic results. The digest contains no credentials.
func (a *App) durableDNSIntentHash(cfg config.Config, services []catalog.Service, spec *serviceDNSJobSpec) (string, error) {
	if a.DNS == nil || spec == nil || len(services) != 1 {
		return "", errDNSCompareServiceMissing
	}
	if p, ok := cfg.ServicePolicies[services[0].ID]; ok && p.TerminalAction != "direct" {
		return "", errDNSComparePathPolicy
	}
	snapshot := a.DNS.Snapshot()
	profiles := []dnscontrol.Profile{}
	providers := []dnscontrol.Provider{}
	for _, id := range spec.ProfileIDs {
		pIndex := slices.IndexFunc(snapshot.Profiles, func(p dnscontrol.Profile) bool { return p.ID == id })
		if pIndex < 0 {
			return "", dnscontrol.ErrServiceDNSInvalid
		}
		profile := snapshot.Profiles[pIndex]
		vIndex := slices.IndexFunc(snapshot.Providers, func(p dnscontrol.Provider) bool { return p.ID == profile.ProviderID })
		if vIndex < 0 || !snapshot.Providers[vIndex].Configured || snapshot.Providers[vIndex].DoH == "" || snapshot.Providers[vIndex].TrustedLocal || snapshot.Providers[vIndex].Scope == "negative-control" {
			return "", dnscontrol.ErrServiceDNSInvalid
		}
		profiles = append(profiles, profile)
		providers = append(providers, snapshot.Providers[vIndex])
	}
	return applyReviewHash(struct {
		ConfigAndServices string
		Profiles          []dnscontrol.Profile
		Providers         []dnscontrol.Provider
	}{durableServiceIntentHash(cfg, services), profiles, providers}), nil
}

func (a *App) runDurableDNSJob(ctx context.Context, r serviceControlJobRequest) (*serviceDNSCompareOutput, error) {
	release, err := a.Operations.Exclusive(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	guard := func(ctx context.Context) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if a.Store == nil || !validDurableDNSRequest(r) {
			return errServiceControlRequest
		}
		cfg := a.Store.Get()
		if cfg.Revision != *r.ExpectedRevision {
			return config.ErrRevisionChanged
		}
		services := []catalog.Service{}
		for _, s := range a.catalogSnapshot().Services {
			if s.ID == r.ServiceIDs[0] {
				services = append(services, s)
			}
		}
		current, err := a.durableDNSIntentHash(cfg, services, r.DNS)
		if err != nil {
			return err
		}
		if current != r.intentHash {
			return dnscontrol.ErrServiceDNSChanged
		}
		return nil
	}
	if err := guard(ctx); err != nil {
		return nil, err
	}
	return a.executeDNSServiceCompare(ctx, serviceDNSCompareRequest{ServiceID: r.ServiceIDs[0], ConfigRevision: r.ExpectedRevision, ProfileIDs: r.DNS.ProfileIDs, VerifyService: r.DNS.VerifyService}, guard)
}

func validDNSJobCode(code string) bool {
	return slices.Contains([]string{"", "DNS_COMPARE_SERVICE_MISSING", "DNS_PROBE_PATH_POLICY", "DNS_COMPARE_AUTH_REQUIRED", "DNS_COMPARE_CANCELED", "DNS_COMPARE_TIMEOUT", "DNS_COMPARE_CHANGED", "DNS_COMPARE_NETWORK_UNAVAILABLE", "DNS_COMPARE_INVALID", "DNS_COMPARE_UNAVAILABLE"}, code)
}

func dnsJobMessage(j durableServiceJob) string {
	switch j.State {
	case "queued":
		return "DNS-проверка сохранена на роутере. Браузер можно закрыть."
	case "running":
		return "Проверяем DNS и выбранный веб-сценарий с роутера. Маршруты не меняются."
	case "completed":
		return "DNS-проверка завершена. Результат относится к времени проверки и не подтверждает маршрут устройств."
	case "canceling":
		return "Отмена DNS-проверки сохранена; ожидаем завершения соединений."
	case "canceled":
		return "DNS-проверка отменена."
	case "interrupted":
		return "После перезапуска проверим настройки и выполним DNS-пробу заново."
	}
	for _, err := range []error{errDNSCompareServiceMissing, errDNSComparePathPolicy, errDNSCompareUnauthorized, context.Canceled, context.DeadlineExceeded, dnscontrol.ErrServiceDNSChanged, errDNSCompareNetworkUnavailable, dnscontrol.ErrServiceDNSInvalid} {
		_, code, message := dnsCompareFailure(err)
		if code == j.DNSCode {
			return message
		}
	}
	if j.Reason == "settings-changed" {
		return "Настройки изменились. Повторите DNS-проверку для текущего состояния."
	}
	return "DNS-проверка не завершена. Успешный результат не подтверждён; откройте журнал."
}
