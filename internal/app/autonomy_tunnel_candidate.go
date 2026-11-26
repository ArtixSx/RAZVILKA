package app

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/warp"
)

type autonomyWARPCandidateKey struct{}

type autonomyWARPCandidate struct {
	owner     *App
	warp      *warp.Manager
	configs   *engineconfig.Manager
	policy    warp.HealthPolicy
	service   catalog.Service
	sources   []string
	network   string
	prepared  engineconfig.Content
	committed string
}

// The current WARP executor can prove HTTPS over an IP policy. A literal test
// destination inside that policy prevents a successful request to an unrelated
// DNS answer from standing in for the chosen service path.
func autonomyWARPService(service catalog.Service) bool {
	if len(service.Domains) != 0 || len(service.SourceRefs) != 0 || len(service.CIDRs) == 0 {
		return false
	}
	probe, err := url.Parse(service.ProbeURL)
	if err != nil || probe.Scheme != "https" || probe.User != nil {
		return false
	}
	ip, err := netip.ParseAddr(probe.Hostname())
	if err != nil || !slices.ContainsFunc(service.CIDRs, func(raw string) bool {
		prefix, err := netip.ParsePrefix(raw)
		return err == nil && prefix.Contains(ip)
	}) {
		return false
	}
	return !slices.ContainsFunc(service.Probes, func(p catalog.Probe) bool {
		return p.Required && (p.URL != service.ProbeURL || !reflect.DeepEqual(p.Expect, catalog.ProbeExpectation{}))
	})
}

func autonomyWARPRegistrationAllowed(p autonomy.Policy, legacy warp.HealthPolicy) bool {
	if !slices.Contains(p.PreferredRoutes, "warp-wg") {
		return false
	}
	if p.AllowInitialWARPRegistration != nil {
		return *p.AllowInitialWARPRegistration
	}
	return p.SetupComplete && legacy.Enabled && legacy.AutoPrepareInitial && legacy.AcceptTOS
}

// A stopped, already committed tunnel needs a fresh service canary, not another
// account. Never treat an editor's staged draft as an existing live profile.
func (a *App) reusableAutonomyWARPProfile() bool {
	if a.EngineConfigs == nil {
		return false
	}
	profile, err := a.EngineConfigs.ReadExpert("warp-wg", "main")
	return err == nil && profile.Source == "live" && warp.ValidateProfile([]byte(profile.Content)) == nil
}

func (a *App) autonomyInitialWARPPolicy(p autonomy.Policy, cfg config.Config, service catalog.Service) (warp.HealthPolicy, bool) {
	if a.Warp == nil || a.EngineConfigs == nil || a.Dataplane == nil || !a.Dataplane.CanaryCapable("warp-wg") ||
		!autonomyWARPService(service) || a.autonomyCapabilityRefusal(cfg, service.ID, "warp-wg") != nil {
		return warp.HealthPolicy{}, false
	}
	policy := a.Warp.Health().Policy
	if !autonomyWARPRegistrationAllowed(p, policy) && !a.reusableAutonomyWARPProfile() {
		return policy, false
	}
	committedRoutes := a.appliedEffectiveRoutes(cfg)
	for id, applied := range cfg.AppliedServices {
		if applied.Enabled && (selectedRoute(applied) == "warp-wg" || committedRoutes[id] == "warp-wg") {
			return policy, false
		}
	}
	return policy, true
}

func (a *App) tryAutonomyInitialWARP(ctx context.Context, p autonomy.Policy, s autonomy.Service, r autonomy.Runtime, cfg config.Config, service catalog.Service, network string) (autonomy.Runtime, bool) {
	warpOwner, configs := a.Warp, a.EngineConfigs
	policy, permitted := a.autonomyInitialWARPPolicy(p, cfg, service)
	if !permitted {
		return r, false
	}
	check := func(c context.Context) error {
		if a.Warp != warpOwner || a.EngineConfigs != configs || !a.autonomyConsent(p, s) || a.autonomyDiskCurrent(c) != nil ||
			a.Store.Get().Revision != cfg.Revision {
			return dataplane.ErrReviewChanged
		}
		if err := a.autonomyResourceGuard(c, p, s, cfg, service); err != nil {
			return err
		}
		fresh, err := a.freshNetworkProfile(c)
		if err != nil || fresh != network {
			return dataplane.ErrNetworkChanged
		}
		return nil
	}
	progress := r
	progress.State, progress.Message = "checking", "Подготавливаем профиль WARP для проверки сервиса."
	a.autonomyRuntime(p.Revision, s.ID, progress)
	prepare, cancel := context.WithTimeout(ctx, 26*time.Second)
	result, err := warpOwner.PrepareAutopilotInitial(prepare, policy, autonomyWARPRegistrationAllowed(p, policy), check)
	timedOut := errors.Is(prepare.Err(), context.DeadlineExceeded)
	cancel()
	if ctx.Err() != nil {
		r.State, r.Message = "paused", "Подготовка WARP отменена."
		return r, true
	}
	if err != nil {
		decision := "initial-profile-unavailable"
		switch {
		case errors.Is(err, warp.ErrAutomaticInitialChanged), errors.Is(err, warp.ErrAutomaticInitialConsent):
			return r, false
		case errors.Is(err, warp.ErrRegistrationEndpointUnavailable):
			decision = "initial-registration-endpoint-unavailable"
			r.State, r.Message = "warp-registration-unreachable", "Адрес регистрации WARP не ответил по HTTPS. Запрос на создание профиля не отправлен. Автопилот проверит другие разрешённые способы."
			if r.NextCheck.IsZero() {
				r.NextCheck = time.Now().Add(time.Duration(p.CheckSeconds) * time.Second)
			}
		case timedOut:
			decision = "initial-registration-timeout"
			r.State, r.Message = "warp-registration-timeout", "Регистрация WARP не завершилась вовремя. Автопилот проверит сохранённый результат, прежде чем допустить новую регистрацию."
		case errors.Is(err, warp.ErrEnrollmentPending):
			decision = "registration-pending-or-failed"
			r.State, r.Message = "warp-registration-pending", "Результат регистрации WARP требует проверки. Повторный запрос на создание профиля не отправляется."
		case errors.Is(err, warp.ErrAutomaticInitialDraft):
			decision = "initial-profile-conflict"
			r.State, r.Message = "warp-profile-conflict", "Профиль WARP или его черновик изменился. Существующий файл сохранён."
		case errors.Is(err, warp.ErrAutomaticInitialBudget):
			decision = "initial-registration-budget"
			r.State, r.Message = "warp-registration-budget", "Новая регистрация WARP ожидает разрешённого интервала. Автопилот проверит другие способы."
		}
		_ = warpOwner.RecordRecovery(decision)
		return r, false
	}
	prepared, err := configs.ReadExpert("warp-wg", "main")
	if err != nil || prepared.Source != result.Source || prepared.SHA256 != result.SHA256 || result.SHA256 == "" {
		return r, false
	}
	candidate := &autonomyWARPCandidate{owner: a, warp: warpOwner, configs: configs, policy: policy,
		service: service, sources: slices.Clone(s.Sources), network: network, prepared: prepared}
	ctx = context.WithValue(ctx, autonomyWARPCandidateKey{}, candidate)
	if !r.ReserveSwitch(time.Now(), p.MaxSwitchesPerHour) {
		r.State, r.Message = "rate-limited", "Лимит применений исчерпан. Подготовленный WARP сохранён для следующей попытки."
		return r, true
	}
	r.State, r.Message = "checking", "Проверяем сервис через WARP и подтверждаем установленный путь."
	a.autonomyRuntime(p.Revision, s.ID, r)
	err = a.applyAutonomyRoute(ctx, p, s, cfg, network, "warp-wg")
	if err == nil {
		_ = warpOwner.RecordRecovery("initial-profile-activated")
		r.State, r.Message = "applied", "WARP применён. HTTPS сервиса и установленный путь проверены."
		r.CheckedAt = time.Now().UTC()
		return r, true
	}
	if errors.Is(err, dataplane.ErrPolicyAdditionUnknown) {
		a.Operations.FenceJournal()
	}
	if a.Operations.Snapshot().Fenced {
		r.State, r.Message = "requires-review", "Состояние сетевых ресурсов WARP требует восстановления."
		return r, true
	}
	if ctx.Err() != nil || check(ctx) != nil || errors.Is(err, dataplane.ErrReviewChanged) || errors.Is(err, dataplane.ErrNetworkChanged) {
		r.State, r.Message = "paused", "Условия применения WARP изменились."
		return r, true
	}
	var failed *autonomyApplyFailure
	refused := errors.Is(err, errAutonomyPlanNotReady)
	if errors.As(err, &failed) && failed.Execution.PlanID == failed.Plan.PlanID && failed.Execution.Digest == failed.Plan.Digest {
		cleanCanary := failed.Execution.State == "canary-failed" && slices.ContainsFunc(failed.Execution.Steps, func(step dataplane.ExecutionStep) bool {
			return step.Adapter == "warp-wg" && step.Phase == "canary" && step.State == "failed"
		})
		refused = dataplane.ConfirmedPreEffectRefusal(failed.Execution, err) || cleanCanary ||
			failed.Execution.State == "rolled-back" && failed.Execution.RollbackVerified
	}
	if refused {
		r.RefundSwitch()
		_ = warpOwner.RecordRecovery("initial-service-unconfirmed")
		r.State, r.Message = "warp-service-unconfirmed", "Профиль WARP сохранён. Работа выбранного сервиса через него ещё не подтверждена."
		return r, false
	}
	r.State, r.Message = "apply-refused", "Применение WARP не подтверждено. Автопилот проверит состояние перед следующим применением."
	return r, true
}

// Ordinary scoped plans carry no editor drafts. Only a first-start transaction
// bound to this resource, service and WAN may consume its prepared WARP draft.
func (a *App) autonomyWARPPlanInputs(ctx context.Context, cfg config.Config, scope changeScope, routes []dataplane.Route, drafts []string, profile string) ([]string, string, error) {
	x, _ := ctx.Value(autonomyWARPCandidateKey{}).(*autonomyWARPCandidate)
	if x == nil {
		return drafts, profile, nil
	}
	if scope != changeScopeNode || cfg.NetworkPolicy != nil || len(drafts) != 0 || profile != "" && profile != x.network {
		return nil, "", dataplane.ErrReviewChanged
	}
	count := 0
	for _, route := range routes {
		if dataplane.AdapterID(route.Resolved) != "warp-wg" {
			continue
		}
		count++
		if route.ServiceID != x.service.ID || route.Selected != "warp-wg" || route.ProbeURL != x.service.ProbeURL ||
			len(route.Domains) != 0 || len(route.SourceRefs) != 0 || !slices.Equal(route.CIDRs, x.service.CIDRs) || !slices.Equal(route.Sources, x.sources) {
			return nil, "", dataplane.ErrReviewChanged
		}
	}
	if count != 1 {
		return nil, "", dataplane.ErrReviewChanged
	}
	if err := a.guardAutonomyWARP(ctx); err != nil {
		return nil, "", err
	}
	if x.prepared.Source == "staged" {
		drafts = []string{"warp-wg/main"}
	}
	return drafts, x.network, nil
}

func (a *App) guardAutonomyWARP(ctx context.Context) error {
	x, _ := ctx.Value(autonomyWARPCandidateKey{}).(*autonomyWARPCandidate)
	if x == nil {
		return nil
	}
	if x.owner != a || x.warp != a.Warp || x.configs != a.EngineConfigs || x.warp.Health().Policy != x.policy {
		return dataplane.ErrReviewChanged
	}
	current, err := x.configs.ReadExpert("warp-wg", "main")
	if err != nil {
		return dataplane.ErrReviewChanged
	}
	if dataplane.ReviewCommittedAdapter(ctx) == "warp-wg" && x.committed == "" {
		if current.Source != "live" || !sameWARPProfileWithNewPort(x.prepared.Content, current.Content) {
			return dataplane.ErrReviewChanged
		}
		x.committed = current.SHA256
	}
	if x.committed != "" && current.Source == "live" && current.SHA256 == x.committed ||
		x.committed == "" && current.Source == x.prepared.Source && current.SHA256 == x.prepared.SHA256 {
		return nil
	}
	return dataplane.ErrReviewChanged
}

func sameWARPProfileWithNewPort(prepared, current string) bool {
	normalize := func(content string) string {
		lines := strings.Split(content, "\n")
		for i, line := range lines {
			key, endpoint, ok := strings.Cut(line, "=")
			if ok && strings.EqualFold(strings.TrimSpace(key), "Endpoint") {
				host, _, err := net.SplitHostPort(strings.TrimSpace(endpoint))
				if err == nil {
					lines[i] = "Endpoint = " + host
				}
			}
		}
		return strings.TrimSpace(strings.Join(lines, "\n"))
	}
	return warp.ValidateProfile([]byte(current)) == nil && normalize(prepared) == normalize(current)
}
