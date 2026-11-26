package app

import (
	"context"
	"errors"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/defaultconsent"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/installpath"
	"github.com/ArtixSx/razvilka/internal/publicfetch"
	"github.com/ArtixSx/razvilka/internal/usquediag"
	"github.com/ArtixSx/razvilka/internal/usquediag/nativeowner"
)

type autonomyUSQUECandidateKey struct{}

type autonomyUSQUECandidate struct {
	owner     *App
	configs   *engineconfig.Manager
	service   catalog.Service
	sources   []string
	network   string
	sha256    string
	livePath  string
	targets   *defaultconsent.LegacyUSQUEProbeTargetReview
	current   func(context.Context) error
	committed atomic.Bool
}

func autonomyUSQUEService(service catalog.Service) bool {
	// The common TUN executor currently admits a literal HTTPS destination
	// in its own CIDR policy. Domain selectors and source lists stay closed.
	if !autonomyWARPService(service) || publicfetch.ValidateURL(service.ProbeURL) != nil {
		return false
	}
	probe, err := url.Parse(service.ProbeURL)
	if err != nil || probe.RawQuery != "" || probe.ForceQuery || probe.Fragment != "" {
		return false
	}
	ip, err := netip.ParseAddr(probe.Hostname())
	if err != nil || !ip.Is4() || !publicfetch.PublicAddress(ip) || ip.String() != probe.Hostname() {
		return false
	}
	_, err = dataplane.FrozenProbeService(dataplane.Route{ServiceID: service.ID, ProbeURL: service.ProbeURL, ProbeService: &service})
	return err == nil
}

func (a *App) tryAutonomyInitialUSQUE(ctx context.Context, p autonomy.Policy, s autonomy.Service, r autonomy.Runtime, cfg config.Config, service catalog.Service, network string, installed bool) (autonomy.Runtime, bool) {
	if !slices.Contains(p.PreferredRoutes, "usque") || !autonomyUSQUEService(service) || a.autonomyCapabilityRefusal(cfg, service.ID, "usque") != nil ||
		!a.hasUnassignedUSQUE(cfg) {
		return r, false
	}
	manager, configs, files := a.Dataplane, a.EngineConfigs, a.SelfUpdateFiles
	livePath := ""
	if configs != nil {
		slot, err := configs.Read("usque", "main")
		if err == nil && slot.Source == "redacted" {
			livePath = slot.Path
		}
	}
	if livePath == "" && !p.AllowInitialMASQUERegistration {
		return autonomyUSQUEFailure(r, nativeowner.ErrUSQUERegistrationConsent), false
	}
	sourceFailure := func(err error) autonomy.Runtime {
		failed := autonomyUSQUEFailure(r, err)
		if !installed && errors.Is(err, dataplane.ErrUSQUEInitialSource) {
			failed.Message = "Движок USQUE не найден среди установленных компонентов. Пакет usque-keenetic запускает собственный туннель. Для Auto требуется проверенный бинарный пакет без сетевого автозапуска."
		}
		return failed
	}
	if manager == nil || configs == nil || files == nil || files.ControlRoot == "" || !manager.CanaryCapable("usque") {
		return sourceFailure(dataplane.ErrUSQUEInitialSource), false
	}
	host := dataplane.DiscoverHost()
	if a.DataplaneHost != nil {
		host = a.DataplaneHost()
	}
	// Keep the prerequisites of the common proxy plan. None of these local
	// failures is a failed provider registration or asks for replacement rules.
	prerequisite := ""
	prepareSidecar := false
	switch {
	case !host.IPCommand:
		prerequisite = "Команда ip для управляемого маршрута MASQUE недоступна."
	case !host.TUN:
		prerequisite = "Устройство /dev/net/tun для управляемого маршрута MASQUE недоступно."
	case !host.SingBox && config.EffectiveProxySidecar(a.ProxySidecarBoot) == "hev":
		prerequisite = "Текущий план MASQUE требует доступного Sing-box. Настройка исполнителя HEV сохранена."
	case !host.SingBox && !host.MASQUESingBox:
		prepareSidecar = manager.USQUEMissingManagedSidecar(configs)
		if !prepareSidecar {
			prerequisite = "Для MASQUE не найден совместимый управляемый Sing-box. Установка пакета Entware с автозапуском заблокирована."
		}
	}
	if prerequisite != "" {
		r.State, r.Message = "masque-component-unavailable", prerequisite
		return r, false
	}
	controlRoot := files.ControlRoot
	review, cancelReview := context.WithTimeout(ctx, 45*time.Second)
	defer cancelReview()
	definitions := a.catalogSnapshot()
	definitionHash := applyReviewHash(definitions)
	custom, sources := a.CustomServices, a.Sources
	catalogCurrent := func() bool {
		return a.CustomServices == custom && a.Sources == sources && applyReviewHash(a.catalogSnapshot()) == definitionHash
	}
	if sources != nil {
		ids := make([]string, 0, len(definitions.Services))
		for _, definition := range definitions.Services {
			ids = append(ids, definition.ID)
		}
		if !sources.AutomaticUseReady(ids) {
			return autonomyUSQUETargetFailure(r, defaultconsent.ErrProbeTargetUnknown), false
		}
	}
	owner, err := a.defaultConsentOwner(review)
	if err != nil {
		return autonomyUSQUETargetFailure(r, err), false
	}
	// Retain the complete original round, rather than the shorter registration
	// window, for the same exact target admission during Canary and live Health.
	targets, err := owner.ReviewLegacyUSQUEProbeTargets(ctx, cfg, definitions, service.ID)
	if err == nil {
		_, err = usquediag.WithOwnedLegacyUSQUEProbeTargetReview(review, targets, service.ID, service.ProbeURL)
	}
	if err != nil {
		return autonomyUSQUETargetFailure(r, err), false
	}
	store := a.Store
	check := func(c context.Context) error {
		if c.Err() != nil {
			return c.Err()
		}
		if a.SelfUpdateFiles != files || files.ControlRoot != controlRoot || store == nil || a.Store != store ||
			a.Dataplane != manager || a.EngineConfigs != configs || !catalogCurrent() ||
			!a.autonomyConsent(p, s) || a.autonomyDiskCurrent(c) != nil {
			return dataplane.ErrReviewChanged
		}
		current := store.Get()
		if current.Revision != cfg.Revision || !a.hasUnassignedUSQUE(current) || a.autonomyRouteBlockReason(p, current) != "" {
			return dataplane.ErrReviewChanged
		}
		if _, err := usquediag.WithOwnedLegacyUSQUEProbeTargetReview(c, targets, s.ID, service.ProbeURL); err != nil {
			return err
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
	if prepareSidecar {
		cancelReview()
		state, message, retry := a.prepareAutonomyComponent(ctx, p, s, cfg, service, components.MASQUESidecarComponent, "Sing-box для MASQUE", func(c context.Context) bool {
			return check(c) == nil && config.EffectiveProxySidecar(a.ProxySidecarBoot) == "sing-box"
		})
		if state != "" {
			return pendingAutonomyUSQUEComponent(r, p, state, message, retry), state == "paused" || state == "requires-review"
		}
		var cancelSidecarReview context.CancelFunc
		review, cancelSidecarReview = context.WithTimeout(ctx, 45*time.Second)
		defer cancelSidecarReview()
	}
	source, err := manager.ReviewUSQUEInitialSource(review, configs)
	if !installed && errors.Is(err, dataplane.ErrUSQUEInitialSource) && review.Err() == nil {
		if err := check(review); err != nil {
			r.State, r.Message = "paused", "Подготовка USQUE отменена. Разрешения, сеть или область изменились."
			return r, true
		}
		cancelReview()
		state, message, retry := a.prepareAutonomyComponent(ctx, p, s, cfg, service, "usque", "USQUE", func(c context.Context) bool {
			return check(c) == nil
		})
		if state != "" {
			return pendingAutonomyUSQUEComponent(r, p, state, message, retry), state == "paused" || state == "requires-review"
		}
		var cancelInstalledReview context.CancelFunc
		review, cancelInstalledReview = context.WithTimeout(ctx, 45*time.Second)
		defer cancelInstalledReview()
		source, err = manager.ReviewUSQUEInitialSource(review, configs)
		installed = a.autonomyNodeEngineInstalled("usque")
	}
	if err != nil {
		return sourceFailure(err), false
	}
	checkSource := func(c context.Context) error {
		if err := check(c); err != nil {
			return err
		}
		return source.Current(c, manager, configs)
	}
	path, hash := source.RegistrationBinary()
	if path == installpath.ManagedUSQUE {
		if err := checkSource(review); err != nil {
			r.State, r.Message = "paused", "При подготовке MASQUE изменились разрешения или исходный исполнитель."
			return r, true
		}
		installer := a.Components
		if installer == nil || installer.CheckInitialUSQUEPublication(review) != nil {
			if ctx.Err() != nil {
				r.State, r.Message = "paused", "Подготовка MASQUE отменена."
				return r, true
			}
			return pendingAutonomyUSQUEComponent(r, p, "masque-publication-unconfirmed",
				"Не подтверждено сохранение проверенного файла USQUE. Автопилот повторит проверку файла.", time.Now().Add(autonomyInstallRetry)), false
		}
		if a.Components != installer || checkSource(review) != nil {
			r.State, r.Message = "paused", "При подготовке MASQUE изменились разрешения или исходный исполнитель."
			return r, true
		}
	}
	candidate := &autonomyUSQUECandidate{owner: a, configs: configs, service: defaultRouteCloneCatalogService(service),
		sources: slices.Clone(s.Sources), network: network, targets: targets,
		current: func(c context.Context) error {
			if a.SelfUpdateFiles != files || files.ControlRoot != controlRoot || !a.autonomyConsent(p, s) || !catalogCurrent() {
				return dataplane.ErrReviewChanged
			}
			return source.Current(c, a.Dataplane, a.EngineConfigs)
		},
	}
	if livePath != "" {
		if err := checkSource(review); err != nil {
			r.State, r.Message = "paused", "При подготовке MASQUE изменились разрешения или исходный исполнитель."
			return r, true
		}
		live, err := source.ReviewLiveSession(review, livePath)
		if err != nil {
			return autonomyUSQUEFailure(r, err), false
		}
		candidate.livePath, candidate.sha256 = livePath, live.SHA256()
		current := candidate.current
		candidate.current = func(c context.Context) error {
			return errors.Join(current(c), live.Current(c))
		}
		return a.applyPreparedAutonomyUSQUE(ctx, p, s, r, cfg, candidate)
	}
	progress := r
	progress.State, progress.Message = "checking", "Подготавливаем сессию MASQUE для проверки сервиса."
	a.autonomyRuntime(p.Revision, s.ID, progress)
	registration, cancelRegistration := context.WithTimeout(ctx, 45*time.Second)
	defer cancelRegistration()
	result, err := nativeowner.PrepareUSQUEInitial(registration, &a.Operations, nativeowner.USQUERegistrationBinding{
		ControlRoot: controlRoot, Binary: path, BinarySHA256: hash, AcceptTOS: p.AllowInitialMASQUERegistration, Configs: configs, Review: checkSource,
	})
	if ctx.Err() != nil {
		r.State, r.Message = "paused", "Подготовка MASQUE отменена."
		return r, true
	}
	if err != nil {
		return autonomyUSQUEFailure(r, err), false
	}
	if result.SHA256 == "" || checkSource(ctx) != nil {
		return r, false
	}
	candidate.sha256 = result.SHA256
	return a.applyPreparedAutonomyUSQUE(ctx, p, s, r, cfg, candidate)
}

func pendingAutonomyUSQUEComponent(r autonomy.Runtime, p autonomy.Policy, state, message string, retry time.Time) autonomy.Runtime {
	r.State, r.Message = state, message
	if retry.IsZero() {
		return r
	}
	if len(p.SourceIDs) == 0 && len(p.PreferredRoutes) == 1 {
		r.NextCheck = retry
	} else {
		r.NextCheck = minTime(r.NextCheck, retry)
	}
	if state != "masque-publication-unconfirmed" {
		r.Message = autonomyComponentRetryMessage(message, retry, p.Timezone)
	}
	return r
}

func autonomyUSQUETargetFailure(r autonomy.Runtime, err error) autonomy.Runtime {
	if errors.Is(err, defaultconsent.ErrProbeTargetExcluded) {
		r.State, r.Message = "masque-target-excluded", "Сервис или адрес проверки MASQUE исключён настройками."
	} else {
		r.State, r.Message = "masque-target-unavailable", "Не удалось подтвердить разрешённые адреса проверки MASQUE."
	}
	return r
}

func (a *App) hasUnassignedUSQUE(cfg config.Config) bool {
	committed := a.appliedEffectiveRoutes(cfg)
	for id, applied := range cfg.AppliedServices {
		if applied.Enabled && (dataplane.AdapterID(selectedRoute(applied)) == "usque" || dataplane.AdapterID(committed[id]) == "usque") {
			return false
		}
	}
	return true
}

func autonomyUSQUEFailure(r autonomy.Runtime, err error) autonomy.Runtime {
	switch {
	case errors.Is(err, nativeowner.ErrUSQUERegistrationTimeout):
		r.State, r.Message = "masque-registration-timeout", "Регистрация MASQUE не ответила вовремя; результат регистрации не подтверждён."
	case errors.Is(err, nativeowner.ErrUSQUERegistrationPending):
		r.State, r.Message = "masque-registration-pending", "Результат регистрации MASQUE требует проверки. Автоматический повтор приостановлен."
	case errors.Is(err, nativeowner.ErrUSQUERegistrationConsent):
		r.State, r.Message = "masque-consent-required", "Для первичной регистрации MASQUE требуется отдельное согласие."
	case errors.Is(err, nativeowner.ErrUSQUERegistrationSlot):
		r.State, r.Message = "masque-session-conflict", "Слот MASQUE занят другой конфигурацией. Существующая сессия сохранена."
	case errors.Is(err, dataplane.ErrUSQUELiveSession):
		r.State, r.Message = "masque-session-unavailable", "Сохранённая сессия MASQUE недоступна, несовместима или изменилась. Автопилот проверит другие разрешённые способы."
	case errors.Is(err, dataplane.ErrUSQUEInitialSource), errors.Is(err, nativeowner.ErrUSQUERegistrationUnsupported):
		r.State, r.Message = "masque-component-unavailable", "Проверенный USQUE или управляемый TUN-компонент недоступен."
	default:
		r.State, r.Message = "masque-session-unavailable", "Не удалось подготовить сессию MASQUE."
	}
	return r
}

func (a *App) applyPreparedAutonomyUSQUE(ctx context.Context, p autonomy.Policy, s autonomy.Service, r autonomy.Runtime, cfg config.Config, candidate *autonomyUSQUECandidate) (autonomy.Runtime, bool) {
	checked, err := usquediag.WithOwnedLegacyUSQUEProbeTargetReview(ctx, candidate.targets, s.ID, candidate.service.ProbeURL)
	if err != nil {
		if ctx.Err() != nil {
			r.State, r.Message = "paused", "Подготовка MASQUE отменена."
			return r, true
		}
		return autonomyUSQUETargetFailure(r, err), false
	}
	ctx = checked
	ctx = context.WithValue(ctx, autonomyUSQUECandidateKey{}, candidate)
	if !r.ReserveSwitch(time.Now(), p.MaxSwitchesPerHour) {
		r.State, r.Message = "rate-limited", "Лимит применений исчерпан. Подготовленная сессия MASQUE сохранена."
		return r, true
	}
	r.State, r.Message = "checking", "Проверяем сервис через MASQUE и подтверждаем установленный путь."
	a.autonomyRuntime(p.Revision, s.ID, r)
	manager := a.Dataplane
	err = a.applyAutonomyRoute(ctx, p, s, cfg, candidate.network, "usque")
	if err == nil {
		r.State, r.Message = "applied", "MASQUE применён. HTTPS сервиса и установленный путь проверены."
		r.CheckedAt = time.Now().UTC()
		return r, true
	}
	if errors.Is(err, dataplane.ErrPolicyAdditionUnknown) || errors.Is(err, dataplane.ErrOriginalProcessCleanup) || errors.Is(err, dataplane.ErrExecutionJournal) {
		a.Operations.FenceJournal()
	}
	var failed *autonomyApplyFailure
	refused := errors.Is(err, errAutonomyPlanNotReady)
	if errors.As(err, &failed) && failed.Execution.PlanID == failed.Plan.PlanID && failed.Execution.Digest == failed.Plan.Digest {
		// The same original round is still admitted, and its staged draft and
		// WAN guard remain current until the rejection proof has closed.
		joinedCanary := a.Dataplane == manager && dataplane.ConfirmedUSQUECanaryRejection(ctx, manager, failed.Plan, failed.Execution, failed.Cause)
		refused = dataplane.ConfirmedPreEffectRefusal(failed.Execution, err) ||
			joinedCanary ||
			failed.Execution.State == "rolled-back" && failed.Execution.RollbackVerified && !errors.Is(err, dataplane.ErrExecutionJournal)
		if !refused && failed.Execution.State == "canary-failed" && slices.ContainsFunc(failed.Execution.Steps, func(step dataplane.ExecutionStep) bool {
			return step.Phase == "canary" && step.State == "failed"
		}) {
			// This generic result does not attest to joined proxy cleanup.
			// Do not launch a fallback or refund the attempt on that basis.
			a.Operations.FenceJournal()
		}
	}
	if a.Operations.Snapshot().Fenced {
		r.State, r.Message = "requires-review", "Состояние сетевых ресурсов MASQUE требует восстановления."
		return r, true
	}
	if ctx.Err() != nil || errors.Is(err, dataplane.ErrReviewChanged) || errors.Is(err, dataplane.ErrNetworkChanged) {
		r.State, r.Message = "paused", "Условия применения MASQUE изменились."
		return r, true
	}
	if refused {
		r.RefundSwitch()
		r.State, r.Message = "masque-service-unconfirmed", "Сессия MASQUE получена, работа выбранного сервиса не подтверждена."
		return r, false
	}
	r.State, r.Message = "apply-refused", "Применение MASQUE не подтверждено. Автопилот заново проверит состояние."
	return r, true
}

func (a *App) hasAutonomyUSQUECandidate(ctx context.Context) bool {
	x, _ := ctx.Value(autonomyUSQUECandidateKey{}).(*autonomyUSQUECandidate)
	return x != nil && x.owner == a
}

func (a *App) autonomyUSQUEPlanInputs(ctx context.Context, cfg config.Config, scope changeScope, routes []dataplane.Route, drafts []string, profile string) ([]string, string, error) {
	x, _ := ctx.Value(autonomyUSQUECandidateKey{}).(*autonomyUSQUECandidate)
	if x == nil {
		return drafts, profile, nil
	}
	if scope != changeScopeNode || cfg.NetworkPolicy != nil || len(drafts) != 0 || profile != "" && profile != x.network || !autonomyUSQUEService(x.service) {
		return nil, "", dataplane.ErrReviewChanged
	}
	count := 0
	for _, route := range routes {
		if dataplane.AdapterID(route.Resolved) != "usque" {
			continue
		}
		count++
		if route.ServiceID != x.service.ID || route.Selected != "usque" || route.Resolved != "usque" || route.ProbeURL != x.service.ProbeURL ||
			route.ProbeService == nil || autonomyDefinition(*route.ProbeService) != autonomyDefinition(x.service) ||
			len(route.Domains) != 0 || len(route.SourceRefs) != 0 || !slices.Equal(route.CIDRs, x.service.CIDRs) || !slices.Equal(route.Sources, x.sources) {
			return nil, "", dataplane.ErrReviewChanged
		}
	}
	if count != 1 || a.guardAutonomyUSQUE(ctx) != nil {
		return nil, "", dataplane.ErrReviewChanged
	}
	if x.livePath == "" {
		drafts = []string{"usque/main"}
	}
	return drafts, x.network, nil
}

func (a *App) guardAutonomyUSQUE(ctx context.Context) error {
	x, _ := ctx.Value(autonomyUSQUECandidateKey{}).(*autonomyUSQUECandidate)
	if x == nil {
		return nil
	}
	if x.owner != a || x.configs != a.EngineConfigs || !x.targets.MatchesService(x.service.ID, x.service.ProbeURL) || x.current == nil || x.current(ctx) != nil {
		return dataplane.ErrReviewChanged
	}
	current, err := x.configs.ReadExpert("usque", "main")
	if err != nil || current.SHA256 != x.sha256 {
		return dataplane.ErrReviewChanged
	}
	if x.livePath != "" {
		if current.Source != "live" || current.Path != x.livePath {
			return dataplane.ErrReviewChanged
		}
		return nil
	}
	if current.Source == "live" && dataplane.ReviewingPublishedUSQUEDraft(ctx, x.configs, x.sha256) {
		return nil // The adapter is still closing this exact publication.
	}
	if dataplane.ReviewCommittedAdapter(ctx) == "usque" && current.Source == "live" {
		x.committed.Store(true)
	}
	if x.committed.Load() && current.Source == "live" || !x.committed.Load() && current.Source == "staged" {
		return nil
	}
	return dataplane.ErrReviewChanged
}

func autonomyWaitingForTunnel(r autonomy.Runtime) bool {
	return strings.HasPrefix(r.State, "masque-") || strings.HasPrefix(r.State, "warp-")
}
