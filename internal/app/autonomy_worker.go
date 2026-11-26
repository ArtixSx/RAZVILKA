package app

import (
	"context"
	"errors"
	"log"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/testlab"
)

func allowedAutonomyOrigin(p autonomy.Policy, o nodestore.Origin, now time.Time) bool {
	return slices.Contains(p.SourceIDs, o.SourceID) && !now.Before(o.ReceivedAt) && now.Before(o.ExpiresAt)
}

func allowedAutonomyNode(p autonomy.Policy, n nodestore.Node, now time.Time) bool {
	return !allowedAutonomyNodeUntil(p, n, now).IsZero()
}

func allowedAutonomyNodeUntil(p autonomy.Policy, n nodestore.Node, now time.Time) time.Time {
	if n.Disabled || !slices.Contains(p.Protocols, strings.ToLower(strings.TrimSpace(n.Protocol))) {
		return time.Time{}
	}
	var until time.Time
	for _, o := range n.Origins {
		if allowedAutonomyOrigin(p, o, now) && until.Before(o.ExpiresAt) {
			until = o.ExpiresAt
		}
	}
	return until
}
func (a *App) autonomyConsent(p autonomy.Policy, s autonomy.Service) bool {
	a.autonomy.mu.Lock()
	defer a.autonomy.mu.Unlock()
	return a.autonomyConsentLocked(p, s)
}

func (a *App) autonomyConsentLocked(p autonomy.Policy, s autonomy.Service) bool {
	current, ok := a.autonomy.doc.Services[s.ID]
	return !a.autonomy.blocked && a.autonomy.doc.Policy.Revision == p.Revision && a.autonomy.doc.Policy.Enabled && ok && current.Enabled && reflect.DeepEqual(s, current)
}

// One service per coordinator round; all mutations use the same admission as
// manual Apply/restore. No browser timer or second networking daemon is used.
func (a *App) autonomyRound(ctx context.Context, now time.Time) {
	a.autonomyRoundWithWebCheck(ctx, now, a.withAutonomyHomeWebCheck)
}

func (a *App) autonomyRoundWithWebCheck(ctx context.Context, now time.Time, withWebCheck func(context.Context, config.Config, autonomy.Service, func(context.Context)) error) {
	// Presentation follows this exact admitted round. It never reads a Store
	// from HTTP or grants another operation access to the in-flight runtime.
	ctx, progress := operationgate.WithProgress(ctx, "autonomy")
	ctx, release, err := a.scopedRuntimeOperation(ctx)
	if err != nil {
		return
	}
	retained := false
	defer func() {
		if !retained {
			// closeRequest may retain the admission for an unjoined private
			// cleanup. Keep that wait visible until the actual holder releases.
			progress("cleanup", "")
			release()
		}
	}()
	if a.loadAutonomy(ctx) != nil || a.Store == nil {
		return
	}
	p := a.autonomyPolicy()
	cfg := a.Store.Get()
	if !p.SetupComplete {
		return
	}
	progress("maintenance", "")
	a.autonomyMaintenance(ctx, p, now)
	if a.componentMaintenancePending() {
		return
	}
	if a.runAutoInstall(ctx, p) {
		// The installer stops this process; until then nothing else runs.
		progress("update-handoff", "")
		a.SelfUpdate.RetainHandoff(release)
		retained = true
		return
	}
	if !cfg.SafeMode {
		_, _ = a.pruneExpiredFeedNodes(ctx, now)
	}
	if ctx.Err() != nil || a.autonomyRouteBlockReason(p, cfg) != "" {
		return
	}
	progress("subscriptions", "")
	if err = a.autonomyEnsureFeeds(ctx, p); err != nil {
		a.autonomy.mu.Lock()
		a.autonomy.maintenanceMessage = "Не удалось сохранить подписку; рабочие маршруты не менялись."
		a.autonomy.mu.Unlock()
	}
	// Read-only scheduling hint: a failed catalog read leaves ordinary ordering.
	// No traversal or eligibility evidence is changed until the selected worker runs.
	progress("selecting", "")
	available := []string{}
	if a.Nodes != nil {
		if snapshot, err := a.Nodes.Snapshot(ctx, now); err == nil {
			for _, n := range snapshot.Nodes {
				if allowedAutonomyNode(p, n, now) {
					available = append(available, n.ID)
				}
			}
		}
	}
	a.autonomy.mu.Lock()
	ids := []string{}
	disabledChanged := false
	activate := []autonomy.Service{}
	for id, s := range a.autonomy.doc.Services {
		if s.Enabled && !s.Removing {
			if message := autonomyScopeRefusal(cfg, s); message != "" {
				r := a.autonomy.doc.Runtime[id]
				if r.State != "capability-refused" || r.Message != message {
					withdrawHomeReserve(&r)
					r.State, r.Message = "capability-refused", message
					a.autonomy.doc.Runtime[id] = r
					disabledChanged = true
				}
				continue
			}
		}
		if s.Enabled && !s.Removing && !cfg.Services[id].Enabled && handedOverUnassigned(cfg, s) {
			activate = append(activate, s)
			continue
		}
		if s.Enabled && !s.Removing && !cfg.Services[id].Enabled {
			// Keep inactive entries out of the probe queue, but do not leave
			// their last successful runtime presented as current automation.
			r := a.autonomy.doc.Runtime[id]
			const message = "Сервис отключён в настройках. Автоматические проверки и переключения приостановлены."
			if r.State != "manual-change" || r.Message != message {
				withdrawHomeReserve(&r)
				r.State, r.Message = "manual-change", message
				a.autonomy.doc.Runtime[id] = r
				disabledChanged = true
			}
			continue
		}
		if s.Enabled && (s.Removing || cfg.Services[id].Enabled) {
			ids = append(ids, id)
		}
	}
	if disabledChanged && a.persistAutonomyLocked(ctx) != nil {
		a.autonomy.mu.Unlock()
		return
	}
	sort.Strings(ids)
	chosen, firstSearchSlot := selectAutonomyRound(ids, a.autonomy.doc, cfg, now, a.autonomy.ordinaryAfterFirstSearch, available)
	var spec autonomy.Service
	var state autonomy.Runtime
	if chosen != "" && len(activate) == 0 {
		spec = a.autonomy.doc.Services[chosen]
		state = a.autonomy.doc.Runtime[chosen].Clone()
		a.autonomy.ordinaryAfterFirstSearch = firstSearchSlot
	}
	a.autonomy.mu.Unlock()
	if len(activate) > 0 {
		progress("activating", "")
		a.activateHandedOverServices(ctx, p, activate)
		return
	}
	if chosen == "" {
		return
	}
	if prior := withdrawHomeReserve(&state); prior.node != "" {
		ctx = context.WithValue(ctx, homeReserveHintKey{}, prior)
	}
	progress("checking", chosen)
	// Retain one original selected-device Review through checks, ordinary
	// route publication and passive refill. No later guard can reopen it.
	home := !spec.Removing && a.autonomyUsesHomeXray(cfg, p, spec)
	if !spec.Removing && cfg.NetworkPolicy != nil && (cfg.NetworkPolicy.Clients.Mode == "selected_devices" || home) {
		window, cancelWindow := context.WithTimeout(ctx, defaultDataplaneApplyTimeout)
		defer cancelWindow()
		var owned context.Context
		var closeDevices func() error
		if home {
			owned, closeDevices, err = a.autonomyHomeXrayContext(window, cfg, spec, false)
		} else {
			owned, closeDevices, err = a.autonomyDeviceContext(window, cfg)
		}
		if err != nil {
			state.State, state.Message = "paused", "Выбранные устройства или их исходная область не подтверждены. Маршрут не меняется."
			state.NextCheck = now.Add(time.Duration(p.CheckSeconds) * time.Second)
			a.autonomyRuntime(p.Revision, chosen, state)
			return
		}
		ctx = owned
		defer func() {
			progress("cleanup", chosen)
			if err := closeDevices(); err != nil {
				a.Operations.FenceJournal()
				withdrawHomeReserve(&state)
				state.State, state.Message = "paused", "Не удалось завершить наблюдение устройств. Автоматические действия остановлены."
				a.autonomyRuntime(p.Revision, chosen, state)
			}
		}()
	}
	state.NextCheck = now.Add(time.Duration(p.CheckSeconds) * time.Second)
	state.State = "checking"
	state.Message = "Проверяем точный путь сервиса."
	if !a.autonomyRuntime(p.Revision, chosen, state) {
		return
	}
	// Publish only bounded descriptions; raw endpoint/config/transport errors are
	// deliberately never copied into the autonomy journal.
	mayCheckWeb := a.autonomyHomeWebCheck(cfg, p, spec)
	state = a.runAutonomyService(ctx, p, spec, state, now)
	// Preserve the ordinary NFQWS2 phase and its live-route decisions. Only
	// after that phase found no path may this separate isolated search run.
	if (state.State == autonomyStateDomainRouteUnavailable || state.State == "capability-refused" || state.State == "excluded") &&
		mayCheckWeb && reflect.DeepEqual(cfg, a.Store.Get()) && !a.Operations.Snapshot().Fenced {
		err := withWebCheck(ctx, cfg, spec, func(owned context.Context) {
			state = a.runAutonomyService(owned, p, spec, state, now)
			a.autonomyRefill(owned, p, spec, state)
		})
		if err != nil {
			withdrawHomeReserve(&state)
			state.State, state.Message = "paused", "Для отдельной проверки Telegram Web нужно подтвердить домашнюю сеть и её исключения."
		}
	}
	if !state.NextCheck.After(time.Now()) {
		state.NextCheck = time.Now().Add(time.Duration(p.CheckSeconds) * time.Second)
	}
	if !a.autonomyRuntime(p.Revision, chosen, state) {
		return
	}
	// Refill is passive catalogue work, not route selection. A failed current
	// node cannot cause repeated fetches if the permitted pool is already full.
	progress("reserves", chosen)
	a.autonomyRefill(ctx, p, spec, state)
}

// handedOverUnassigned reports a service handed to the autopilot (the
// first-setup starter set, a catalogue hand-over) whose draft is still the
// untouched, disabled one it was enrolled with and that was never applied.
// The list-mode guard checks and routes only enabled services, so such a
// service must join the active list; a later owner change of the draft is a
// manual change instead.
func handedOverUnassigned(cfg config.Config, s autonomy.Service) bool {
	draft := cfg.Services[s.ID]
	return autonomyScopeRefusal(cfg, s) == "" && !draft.Enabled && !cfg.AppliedServices[s.ID].Enabled && autonomyDraftFingerprint(draft) == s.DraftFingerprint
}

// activateHandedOverServices enables the drafts of handed-over services with
// their expected route under the config revision it read, then records the new
// draft fingerprint on the unchanged autopilot record. Checks start next round.
func (a *App) activateHandedOverServices(ctx context.Context, p autonomy.Policy, services []autonomy.Service) {
	sort.Slice(services, func(i, j int) bool { return services[i].ID < services[j].ID })
	for _, s := range services {
		cfg := a.Store.Get()
		if ctx.Err() != nil || !a.autonomyConsent(p, s) || cfg.Services[s.ID].Enabled || !handedOverUnassigned(cfg, s) {
			continue
		}
		route := s.ExpectedRoute
		if route == "" {
			route = "auto"
		}
		// Enabling an enrolled draft is not a new profile selection. Retain
		// its reviewed binding and any other draft fields; route and sources
		// are the explicit choices recorded in the autopilot consent. Store
		// normalization keeps the legacy Mode field equal to this route.
		nextDraft := cfg.Services[s.ID]
		nextDraft.Enabled, nextDraft.Route = true, route
		nextDraft.Sources = append([]string(nil), s.Sources...)
		if a.Store.UpdateServiceIfRevision(s.ID, nextDraft, cfg.Revision) != nil {
			return
		}
		draft := a.Store.Get().Services[s.ID]
		if _, ok := a.updateAutonomyService(ctx, p, s, func(next *autonomy.Service) { next.DraftFingerprint = autonomyDraftFingerprint(draft) }); !ok {
			return
		}
		a.autonomy.mu.Lock()
		r := a.autonomy.doc.Runtime[s.ID].Clone()
		a.autonomy.mu.Unlock()
		r.State, r.Message = "pending", "Сервис добавлен в активный список. Автопилот проверит и назначит путь."
		a.autonomyRuntime(p.Revision, s.ID, r)
	}
}

func (a *App) runAutonomyService(ctx context.Context, p autonomy.Policy, s autonomy.Service, r autonomy.Runtime, now time.Time) autonomy.Runtime {
	return a.runAutonomyServiceWithNFQWS2Review(ctx, p, s, r, now, func() bool {
		service, ok := a.autonomyService(s.ID)
		return ok && a.Dataplane != nil && a.Dataplane.NFQWS2FirstStartNeedsApply(s.ID, service.Domains)
	})
}

func (a *App) runAutonomyServiceWithNFQWS2Review(ctx context.Context, p autonomy.Policy, s autonomy.Service, r autonomy.Runtime, now time.Time, needsNFQWS2Apply func() bool) autonomy.Runtime {
	finish := func(state, message string) autonomy.Runtime { r.State = state; r.Message = message; return r }
	service, known := a.autonomyService(s.ID)
	if s.Removing {
		return a.runAutonomyRemoval(ctx, p, s, r)
	}
	if !known {
		return finish("removed", "Сервис удалён из каталога; автоматические изменения остановлены.")
	}
	if autonomyDefinition(service) != s.Definition {
		adopted := false
		s, adopted = a.adoptReviewedDefinition(ctx, p, s, service)
		if !adopted {
			return finish("definition-changed", "Состав сервиса изменился. Повторно подтвердите его область и проверки.")
		}
	}
	cfg := a.Store.Get()
	home, _ := ctx.Value(autonomyHomeScopeKey{}).(*autonomyXrayHomeRound)
	webCheckOnly := home != nil && home.webCheckOnly
	if webCheckOnly && !a.autonomyHomeWebCheck(cfg, p, s) {
		return finish("paused", "Изменились условия отдельной проверки Telegram Web.")
	}
	if autonomyDraftFingerprint(cfg.Services[s.ID]) != s.DraftFingerprint {
		adopted := false
		if nfqws2StandardDraft(service, s, cfg.Services[s.ID]) {
			s, adopted = a.adoptNFQWS2StandardDraft(ctx, p, s, cfg.Services[s.ID])
		}
		if !adopted {
			return finish("manual-change", "Обнаружено ручное изменение сервиса. Автоматическое применение приостановлено.")
		}
	}
	if !a.autonomyConsent(p, s) || ctx.Err() != nil {
		return finish("paused", "Разрешение отозвано или действие отменено.")
	}
	if err := a.autonomyResourceGuard(ctx, p, s, cfg, service); err != nil {
		if !errors.Is(err, errAutonomyResourceIneligible) {
			return finish("paused", "Условия автоматической проверки изменились или не подтверждены; маршрут не меняется.")
		}
		return finish("excluded", "Автоматическая проверка не разрешена текущим списком или исключениями. Маршрут не меняется.")
	}
	status, e := a.Dataplane.Status()
	if e != nil || status.Execution != nil && status.Execution.State == "rollback-failed" {
		return finish("requires-review", "Журнал применения требует восстановления; сеть не меняется.")
	}
	// Mihomo's manual lane owns its distinct plan, live health and Stop.
	// Neither a saved selection nor finite lab evidence may enter the generic
	// Sing-box fallback or certify that retained route through RouteProber.
	if autonomyMihomoSelection(cfg, s) {
		return finish("capability-refused", "Автопилот пока не умеет автоматически применять, восстанавливать и переключать Mihomo. Сохранённый маршрут не изменён. Проверяйте и останавливайте Mihomo вручную.")
	}
	profile, e := a.freshNetworkProfile(ctx)
	if e != nil {
		return finish("network-unknown", "Текущая сеть не подтверждена. Переключение отложено.")
	}
	if !serviceHasNodeProbe(service) {
		return finish("unsupported-scenario", "Для сервиса нет безопасной веб-проверки. Доступ не объявляется подтверждённым.")
	}
	if catalog.IsNFQWS2Starter(service) && (s.ExpectedRoute == "nfqws2" ||
		s.ExpectedRoute == "auto" && nfqws2FirstStartScope(s, service) && nfqws2StarterApplied(cfg, s.ID)) {
		return a.runNFQWS2Starter(ctx, p, s, r, service, cfg, profile)
	}
	// Preparing the missing component may make the reviewed stock first
	// start available. The starter observes it again after installation, and
	// ordinary Apply still rechecks all authority before configuring routes.
	if s.ExpectedRoute == "auto" && !cfg.AppliedServices[s.ID].Enabled &&
		catalog.IsNFQWS2Starter(service) && nfqws2FirstStartScope(s, service) &&
		slices.Contains(p.PreferredRoutes, "nfqws2") &&
		(!a.autonomyNodeEngineInstalled("nfqws2") || needsNFQWS2Apply != nil && needsNFQWS2Apply()) {
		return a.runNFQWS2StarterWithProfileReview(ctx, p, s, r, service, cfg, profile, needsNFQWS2Apply)
	}
	current := ""
	if applied := cfg.AppliedServices[s.ID]; applied.Enabled {
		current = selectedRoute(applied)
		if current == "auto" || strings.HasPrefix(current, "sing-box:group-") {
			current = a.appliedEffectiveRoutes(cfg)[s.ID]
			if current == "" {
				return finish("requires-review", "Не удалось сопоставить применённый выбор с рабочим маршрутом.")
			}
		}
	}
	healthy, replace := false, current == ""
	engine := autonomyNodeEngine(current)
	if current == "" {
		engine = a.autonomySearchEngine(cfg, p, s)
	}
	currentNode := ""
	isNode := strings.HasPrefix(current, engine+":node-")
	if isNode {
		currentNode = strings.TrimPrefix(current, engine+":")
	}
	if current != "" && !isNode {
		// Only a confirmed failure of the current path may replace an existing
		// non-proxy route. Unsupported probes are not counted as a failure.
		var observation autonomyRouteObservation
		if current == "usque" {
			observation = a.observeAutonomyCommittedUSQUE(ctx, p, s, cfg, service, profile, &r)
		} else {
			observation = a.autonomyProbeRouteObservation(ctx, service, current, profile)
		}
		if observation.pause(&r) {
			return r
		}
		verdict := observation.Verdict
		r.CheckedAt = time.Now().UTC()
		healthy = verdict == "PASS"
		replace = r.Observe(current, profile, verdict, time.Now(), time.Duration(p.FailureConfirmSeconds)*time.Second)
		if current == "usque" {
			switch observation.Reason {
			case "masque-restarted":
				return finish("healthy", "Процесс MASQUE восстановлен, работа применённого пути проверена.")
			case "masque-provider-unconfirmed":
				return finish("unconfirmed", "Транспорт или сервис MASQUE не ответил. Назначение сохранено.")
			case "masque-local-unconfirmed":
				return finish("unconfirmed", "Состояние локального процесса или TUN не подтверждено. Назначение сохранено.")
			case "masque-repair-unconfirmed":
				return finish("unconfirmed", "Восстановление процесса MASQUE не подтверждено. Назначение сохранено.")
			case "masque-restart-retry":
				return finish("unconfirmed", "Работа MASQUE пока не подтверждена. Автопилот повторит восстановление того же подключения.")
			case "masque-repair-cleanup-unconfirmed":
				return finish("requires-review", "Завершение процесса MASQUE не подтверждено. Автоматические изменения приостановлены.")
			case "masque-check-canceled":
				return finish("paused", "Проверка MASQUE отменена.")
			case "masque-restart-rate-limited":
				return finish("rate-limited", "Лимит восстановлений исчерпан. Следующая попытка запланирована.")
			}
		}
		if !healthy && !replace {
			if verdict == "FAIL" {
				r.NextCheck = time.Now().Add(time.Duration(p.FailureConfirmSeconds) * time.Second)
			}
			return finish("unconfirmed", "Отказ действующего обхода пока не подтверждён; маршрут сохранён.")
		}
	}
	var snapshot nodestore.Snapshot
	personalFirst := false
	var personalPriorities map[string]bool
	if current == "" {
		// A limit of the saved mode is named before any probe or node check
		// when no route this round could apply is open.
		if refusal := a.autonomyUnappliedRefusal(cfg, p, s, engine); !webCheckOnly && refusal != nil {
			return autonomyCapabilityRefused(refusal, &r)
		}
		if s.ExpectedRoute == "auto" && (!autonomyDomainService(service) || webCheckOnly) && a.Nodes != nil && len(p.SourceIDs) != 0 {
			snapshot, _ = a.Nodes.SnapshotWithPriority(ctx, time.Now())
			personalPriorities = autonomyPersonalPriorities(p, snapshot, time.Now())
			personalFirst = len(personalPriorities) != 0
		}
		// A new personal-priority search starts with the existing local method
		// when admitted. Only its observation is shortened; Apply uses its full
		// transaction and cleanup budget.
		if !webCheckOnly && personalFirst && (r.Search == nil || !r.Search.Halted && r.Search.Cursor == 0 && !r.Search.StandardRoutesTried) &&
			slices.Contains(p.PreferredRoutes, "nfqws2") && a.autonomyCapabilityRefusal(cfg, s.ID, "nfqws2") == nil {
			var done bool
			r, done = a.tryAutonomyRoutePhase(ctx, p, s, r, cfg, service, profile, []string{"nfqws2"}, 5*time.Second, a.autonomyNFQWS2DomainOnlyProfile)
			if done {
				return r
			}
		}
		// CIDR-only source preferences get their bounded node phase first.
		// Domain services retain their existing NFQWS2-only route boundary.
		if !webCheckOnly && !personalFirst && (len(p.PreferredSourceIDs) == 0 || autonomyDomainService(service)) {
			var done bool
			r, done = a.tryAutonomyPreferredRoutes(ctx, p, s, r, cfg, service, profile)
			if done {
				return r
			}
		}
	}
	// Existing domain routes follow the NFQWS2 owner. Only the isolated
	// web diagnostic may inspect new nodes without changing those routes.
	if !webCheckOnly && autonomyDomainService(service) && !(isNode && nfqws2StandardScope(service, s)) {
		return a.finishAutonomyDomainService(ctx, p, s, r, cfg, profile, current, healthy)
	}
	if !isNode && replace {
		engine = a.autonomySearchEngine(cfg, p, s)
		if current != "" && len(p.PreferredSourceIDs) == 0 {
			var done bool
			r, done = a.tryAutonomyPreferredRoutes(ctx, p, s, r, cfg, service, profile)
			if done {
				return r
			}
		}
	}
	canTryAvailableRoutes := !webCheckOnly && !isNode && replace && (len(p.PreferredSourceIDs) > 0 || personalFirst) && (r.Search == nil || !r.Search.Halted)
	if _, err := a.nodeCheckerForEngine(engine); a.Nodes == nil || err != nil {
		// Before the first search, a missing node checker cannot qualify any
		// preferred source. Independently ready routes still get their normal
		// ordered service probes, without advancing the node traversal.
		if canTryAvailableRoutes {
			var done bool
			r, done = a.tryAutonomyPreferredRoutes(ctx, p, s, r, cfg, service, profile)
			if done {
				return r
			}
		}
		if autonomyWaitingForComponent(r) || autonomyWaitingForTunnel(r) {
			return r
		}
		if a.Nodes == nil {
			return finish("checker-unavailable", "Точная проверка подключений недоступна.")
		}
		return finish("checker-unavailable", "Точная проверка выбранного движка недоступна.")
	}
	if !isNode && replace && len(p.SourceIDs) != 0 && slices.Contains(p.PreferredRoutes, engine) {
		name := "Sing-box"
		if engine == "xray" {
			name = "Xray"
		}
		state, message, retry := a.prepareAutonomyComponent(ctx, p, s, cfg, service, engine, name, nil)
		if state != "" {
			if state != "paused" && canTryAvailableRoutes {
				var done bool
				r, done = a.tryAutonomyPreferredRoutes(ctx, p, s, r, cfg, service, profile)
				if done {
					return r
				}
			}
			if retry.After(time.Now()) {
				// The package owns its night window and retry limit. Continue
				// looking for other usable paths at the normal service pace.
				r.NextCheck = minTime(r.NextCheck, retry)
				message = autonomyComponentRetryMessage(message, retry, p.Timezone)
			}
			return finish(state, message)
		}
	}
	if snapshot.Nodes == nil {
		snapshot, e = a.Nodes.Snapshot(ctx, time.Now())
		if e != nil {
			return finish("catalog-unavailable", "Каталог подключений недоступен.")
		}
	}
	if isNode && nfqws2StandardScope(service, s) && !nodeRecoveryNodePresent(snapshot, currentNode, time.Now()) && a.nfqws2RouteReady() {
		return a.returnToNFQWS2Standard(ctx, p, s, r, service, cfg, profile)
	}
	if !webCheckOnly && autonomyDomainService(service) {
		return a.finishAutonomyDomainService(ctx, p, s, r, cfg, profile, current, healthy)
	}
	eligible := map[string]nodestore.Node{}
	ids := []string{}
	r.PruneCandidateFailures(profile, s.Definition, autonomy.ScopeFingerprint(s.Sources), time.Now())
	held := a.retiredFreeIDs(p, snapshot, profile, time.Now())
	for _, n := range snapshot.Nodes {
		if (n.ID == currentNode || !held[n.ID]) && allowedAutonomyNode(p, n, time.Now()) {
			eligible[n.ID] = n
			if !r.CandidateCoolingDown(n.ID) && !a.autonomyConnectivityCoolingDown(ctx, p, s, engine, n.ID, profile, time.Now()) {
				ids = append(ids, n.ID)
			}
		}
	}
	ids = orderAutonomyCandidates(snapshot, p, ids, engine, s.ID, profile, time.Now())
	if isNode {
		if _, ok := eligible[currentNode]; !ok {
			// No new authority is created for a disabled/revoked/expired node. Search
			// for a permitted replacement, but never renew the old receipt ourselves.
			replace = true
			r.State = "origin-expired"
		} else {
			check, err := a.checkAutonomyCurrentNode(ctx, p, s, cfg, engine, currentNode, service, profile)
			if err == nil && (autonomyRouteObservation{RetryAfterSeconds: nodeServiceRateLimitSeconds(check, time.Now())}).pause(&r) {
				return r
			}
			verdict := "INCONCLUSIVE"
			if err == nil {
				verdict = autonomyNodeObservation(check, time.Now())
				healthy = verdict == "PASS"
				if healthy {
					_, resolveErr := a.Nodes.ResolveRouteForEngine(ctx, engine, currentNode, service.ID, profile, "", time.Time{}, time.Now())
					if resolveErr != nil {
						healthy = false
						verdict = "INCONCLUSIVE"
					}
				}
			}
			r.CheckedAt = time.Now().UTC()
			replace = r.Observe(currentNode, profile, verdict, time.Now(), time.Duration(p.FailureConfirmSeconds)*time.Second)
			if !healthy && !replace {
				if verdict == "FAIL" {
					r.NextCheck = time.Now().Add(time.Duration(p.FailureConfirmSeconds) * time.Second)
					return finish("unconfirmed", "Требуется повторная проверка текущего узла; маршрут сохранён.")
				}
				if err != nil || !canExploreUnconfirmedNode(check) {
					return finish("unconfirmed", "Проверка текущего узла не завершена. Требуется восстановление проверяющего механизма; маршрут сохранён.")
				}
				// Preparing an alternative is not permission to switch to it.
			}
		}
	}
	if healthy && isNode {
		// The isolated checker proves the remote node, not our live TUN/process.
		// Autonomy owns this service, so legacy fallback deliberately skips it.
		// Reuse its committed-runtime check before publishing healthy; repair the
		// same proven node through the existing transaction if local runtime died.
		committed, exists, err := a.Dataplane.Committed()
		if err != nil || !exists || committed.Revision != cfg.AppliedRevision {
			return finish("requires-review", "Применённый маршрут не подтверждён журналом. Автоматическое восстановление остановлено.")
		}
		matched, outdated := false, false
		if autonomyManagedXraySelected(cfg, committed, current) {
			matched = a.autonomyManagedXrayCommittedMatches(cfg, committed, s.ID, current)
		} else {
			for _, route := range committed.Routes {
				if route.ServiceID == s.ID && route.Resolved == current && route.Selected == selectedRoute(cfg.AppliedServices[s.ID]) && sameNodeRecoveryStrings(route.Sources, cfg.AppliedServices[s.ID].Sources) {
					matched = nodeRecoveryServiceMatches(route, service)
					outdated = !matched
				}
			}
		}
		if outdated {
			// The consented definition changed after this route was applied (the
			// record's definition equals the current one). Apply the same node,
			// proven in this round, to the current definition.
			if !r.ReserveSwitch(time.Now(), p.MaxSwitchesPerHour) {
				return finish("rate-limited", "Состав сервиса обновился. Лимит применений исчерпан; прежний маршрут сохранён.")
			}
			r.State, r.Message = "applying", "Состав сервиса обновился. Применяем тот же проверенный узел к новому составу."
			a.autonomyRuntime(p.Revision, s.ID, r)
			if err := a.applyAutonomyRoute(ctx, p, s, cfg, profile, current); err != nil {
				if state, message, blocked := autonomyRouteDependency(err, &r); blocked {
					return finish(state, message)
				}
				return finish("apply-refused", "Обновлённый состав сервиса не подтверждён после применения; использована защита и откат.")
			}
			return finish("applied", "Состав сервиса обновился: тот же проверенный узел применён к новому составу.")
		}
		if !matched {
			return finish("requires-review", "Область или состав применённого маршрута изменились. Требуется просмотр.")
		}
		guard := func(c context.Context) error {
			if c.Err() != nil {
				return c.Err()
			}
			if !reflect.DeepEqual(a.Store.Get(), cfg) || !a.autonomyConsent(p, s) || a.autonomyDiskCurrent(c) != nil {
				return dataplane.ErrReviewChanged
			}
			if err := a.autonomyResourceGuard(c, p, s, cfg, service); err != nil {
				return err
			}
			latest, ok := a.autonomyService(s.ID)
			if !ok || autonomyDefinition(latest) != s.Definition {
				return dataplane.ErrReviewChanged
			}
			observed, e := a.freshNetworkProfile(c)
			if e != nil || observed != profile {
				return dataplane.ErrNetworkChanged
			}
			return nil
		}
		if a.checkAutonomyCommittedNodeHealth(ctx, cfg, committed, s.ID, current, guard) != nil {
			if guard(ctx) != nil {
				return finish("paused", "Проверка маршрута отменена: сеть или разрешения изменились.")
			}
			if !r.ReserveSwitch(time.Now(), p.MaxSwitchesPerHour) {
				return finish("rate-limited", "Работа локального маршрута не подтверждена. Лимит восстановлений исчерпан.")
			}
			r.State, r.Message = "applying", "Восстанавливаем прежний проверенный узел без замены подключения."
			a.autonomyRuntime(p.Revision, s.ID, r)
			if err := a.applyAutonomyRoute(ctx, p, s, cfg, profile, current); err != nil {
				if state, message, blocked := autonomyRouteDependency(err, &r); blocked {
					return finish(state, message)
				}
				return finish("apply-refused", "Восстановление прежнего маршрута не подтверждено; использована защита и откат.")
			}
			return finish("applied", "Прежний проверенный узел и его область восстановлены через общую транзакцию.")
		}
	}
	if !healthy && replace {
		return a.runAutonomyFirstUsable(ctx, p, s, r, cfg, service, engine, profile, currentNode, ids, snapshot.Nodes, personalPriorities)
	}
	ready := []string{}
	if healthy && isNode {
		ready = append(ready, currentNode)
	}
	for _, id := range ids {
		if slices.Contains(ready, id) {
			continue
		}
		if _, err := a.Nodes.ResolveRouteForEngine(ctx, engine, id, s.ID, profile, "", time.Time{}, time.Now()); err == nil {
			ready = append(ready, id)
		}
	}
	keep := ""
	if healthy && isNode {
		keep = currentNode
	}
	if engine == "sing-box" {
		ready = rankAutonomyNodes(snapshot, ready, keep, s.ID, profile, time.Now(), a.nodeMeasurements()...)
	} else {
		ready = orderAutonomyExactReserves(ready, keep)
	}
	ready, e = a.Nodes.SelectReserveIDs(ctx, ready, p.ReserveTarget)
	if e != nil {
		return finish("catalog-unavailable", "Не удалось сопоставить резервные подключения. Маршрут сохранён.")
	}
	// Revisit reserves at their own interval, even when their proof has not yet
	// expired. Walk through all candidates, not only the first rows of a feed.
	needRefresh := !time.Now().Before(r.ReserveCheckedAt.Add(time.Duration(p.ReserveSeconds) * time.Second))
	shortlist, next := autonomy.CandidateBatch(ids, currentNode, r.Cursor, p.CandidatesPerRound)
	if refillBeforeApply(healthy, replace, len(ready), p.ReserveTarget, needRefresh) {
		previousCursor := r.Cursor
		r.Cursor = next
		for _, id := range shortlist {
			if ctx.Err() != nil {
				break
			}
			check, err := a.checkAutonomyReserveForEngine(ctx, p, s, cfg, engine, id, service, profile)
			if err == nil && (autonomyRouteObservation{RetryAfterSeconds: nodeServiceRateLimitSeconds(check, time.Now())}).pause(&r) {
				r.Cursor = previousCursor
				return r
			}
			if state, message := autonomyReserveCheckStop(ctx, check, err); state != "" {
				return finish(state, message)
			}
			ready = slices.DeleteFunc(ready, func(v string) bool { return v == id })
			if autonomyNodeObservation(check, time.Now()) == "PASS" {
				ready = append(ready, id)
			}
		}
		r.ReserveCheckedAt = time.Now().UTC()
		// Rank again with the checks recorded in this round.
		if fresh, err := a.Nodes.Snapshot(ctx, time.Now()); err == nil {
			snapshot = fresh
		}
	}
	if engine == "sing-box" {
		ready = rankAutonomyNodes(snapshot, ready, keep, s.ID, profile, time.Now(), a.nodeMeasurements()...)
	} else {
		ready = orderAutonomyExactReserves(ready, keep)
	}
	ready, e = a.Nodes.SelectReserveIDs(ctx, ready, p.ReserveTarget)
	if e != nil {
		return finish("catalog-unavailable", "Не удалось сопоставить резервные подключения. Маршрут сохранён.")
	}
	r.Reserves = slices.Clone(ready)
	if ctx.Err() != nil {
		return finish("paused", "Проверка отменена; рабочий маршрут не меняется.")
	}
	if healthy {
		sources, err := autonomyEffectiveServiceSources(ctx, cfg, s)
		if err != nil {
			return finish("scope-pending", "Область устройств изменилась и требует новой проверки. Маршрут сохранён.")
		}
		if !sameNodeRecoveryStrings(cfg.AppliedServices[s.ID].Sources, sources) {
			if err := a.applyAutonomyRoute(ctx, p, s, cfg, profile, current); err != nil {
				return finish("scope-pending", "Новая область устройств ещё не применена. Прежняя конфигурация сохранена.")
			}
			return finish("applied", "Проверенный путь применён к выбранным устройствам.")
		}
		if len(ready) < p.ReserveTarget {
			return finish("healthy", "Работающий путь сохранён. Целевой резерв ещё не заполнен; подбор продолжится.")
		}
		return finish("healthy", "Работающий путь сохранён. Проверенные резервные узлы подготовлены отдельно.")
	}
	if !replace {
		return finish("unconfirmed", "Текущий путь не подтверждён. Разрешённый резерв проверен отдельно; без основания и свежего доказательства маршрут не меняется.")
	}
	return finish("searching", "Подбор продолжится; прежняя конфигурация сохранена.")
}

func (a *App) autonomyProbeRoute(ctx context.Context, s catalog.Service, route, profile string) string {
	return a.autonomyProbeRouteObservation(ctx, s, route, profile).Verdict
}

type autonomyRouteObservation struct {
	Verdict           string
	RetryAfterSeconds int
	Reason            string // closed diagnostic code; never provider details or identifiers
}

// A rate limit schedules only this service. It breaks failure confirmation,
// no alternate path is selected and no old positive proof is renewed.
func (o autonomyRouteObservation) pause(r *autonomy.Runtime) bool {
	if o.RetryAfterSeconds <= 0 {
		return false
	}
	r.CheckedAt = time.Now().UTC()
	r.Failures, r.FirstFailure, r.LastFailure = 0, time.Time{}, time.Time{}
	r.NextCheck = r.CheckedAt.Add(time.Duration(max(30, min(o.RetryAfterSeconds, 30*60))) * time.Second)
	r.State = "unconfirmed"
	r.Message = nodeServiceRateLimitMessage
	return true
}

func (a *App) autonomyProbeRouteObservation(ctx context.Context, s catalog.Service, route, profile string) (observation autonomyRouteObservation) {
	defer func() {
		if observation.Verdict == "INCONCLUSIVE" && observation.Reason != "" {
			log.Printf("autonomy route observation inconclusive: reason=%s", observation.Reason)
		}
	}()
	unknown := func(reason string) autonomyRouteObservation {
		return autonomyRouteObservation{Verdict: "INCONCLUSIVE", Reason: reason}
	}
	if a.TestLab == nil || a.RouteProber == nil || a.Store == nil {
		return unknown("probe-unavailable")
	}
	probeCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	p := a.autonomyPolicy()
	a.autonomy.mu.Lock()
	spec, known := a.autonomy.doc.Services[s.ID]
	a.autonomy.mu.Unlock()
	store := a.Store
	cfg := store.Get()
	if !known {
		return unknown("service-not-enrolled")
	}
	if err := a.autonomyResourceGuard(probeCtx, p, spec, cfg, s); err != nil {
		return unknown(autonomyObservationContextReason(probeCtx, "resource-before", err))
	}
	observed, err := a.freshNetworkProfile(probeCtx)
	if err != nil || observed != profile {
		return unknown(autonomyObservationContextReason(probeCtx, "network-before", err))
	}
	// Autonomy consumes this private verdict in its own round. Keep the batch
	// unrecorded so a closing refusal cannot leak observations into TestLab
	// history before resource admission. The prober still owns full cleanup.
	runner, prober := a.TestLab, a.RouteProber
	results := runner.ProbeRoutesUnrecorded(probeCtx, a.catalogSnapshot(), []string{s.ID}, []string{route}, prober)
	current, err := a.freshNetworkProfile(probeCtx)
	if err != nil || current != observed {
		return unknown(autonomyObservationContextReason(probeCtx, "network-after", err))
	}
	if a.TestLab != runner || a.Store != store {
		return unknown("observation-owner-changed")
	}
	for i := range results {
		r := &results[i]
		if r.NetworkProfileID != "" && r.NetworkProfileID != observed || r.EvidenceV2 != nil && r.EvidenceV2.NetworkProfile != "" && r.EvidenceV2.NetworkProfile != observed {
			return unknown("result-network-mismatch")
		}
		r.NetworkProfileID = observed
		if r.EvidenceV2 != nil {
			r.EvidenceV2.NetworkProfile = observed
		}
	}
	if err := a.autonomyResourceGuard(probeCtx, p, spec, cfg, s); err != nil {
		return unknown(autonomyObservationContextReason(probeCtx, "resource-after", err))
	}
	for _, r := range testlab.AggregateScenarios(results) {
		if r.ServiceID != s.ID || r.Route != route {
			continue
		}
		r.NormalizeEvidence()
		checkedAt, checkedErr := time.Parse(time.RFC3339, r.CheckedAt)
		until, untilErr := time.Parse(time.RFC3339, r.EvidenceFreshUntil)
		fresh := checkedErr == nil && untilErr == nil && !checkedAt.After(time.Now()) && until.After(time.Now())
		if fresh && r.Status == "pass" && r.RouteConfirmed && string(r.Verdict) == "PASS" {
			return autonomyRouteObservation{Verdict: "PASS"}
		}
		// Only an attributed, current service failure can replace a local route.
		// Missing process/capability or uncertain route evidence is not a FAIL.
		if fresh && r.Status == "fail" && (string(r.Verdict) == "BLOCKED" || string(r.Verdict) == "ERROR") && r.RouteConfirmed && r.RouteProofError == "" {
			return autonomyRouteObservation{Verdict: "FAIL"}
		}
		if fresh && r.Status == "partial" && r.HTTPStatus == 429 && r.ErrorCode == "http-429" && r.Verdict == "PARTIAL" && r.RouteConfirmed && r.RouteProofError == "" {
			delay := r.RetryAfterSeconds
			if delay <= 0 {
				delay = 5 * 60
			}
			return autonomyRouteObservation{Verdict: "INCONCLUSIVE", RetryAfterSeconds: max(30, min(delay, 30*60)), Reason: "service-rate-limited"}
		}
		if !fresh {
			return unknown("result-not-fresh")
		}
		code := r.ErrorCode
		if code == "" && r.EvidenceV2 != nil {
			code = r.EvidenceV2.ErrorCode
		}
		switch code {
		case "timeout":
			return unknown("probe-timeout")
		case "tls-certificate-mismatch":
			return unknown("probe-tls-rejected")
		}
		if !r.RouteConfirmed || r.RouteProofError != "" {
			switch r.RouteProofError {
			case "nfq-stock-preflight-refused", "nfq-cleanup-refused", "nfq-socket-counter-unavailable", "nfq-socket-unobserved", "nfq-stock-readback-refused", "nfq-kernel-queue-unavailable", "nfq-process-readback-refused", "nfq-queue-changed", "nfq-process-changed", "nfq-route-interface-changed", "nfq-rules-changed", "nfq-route-changed", "nfq-source-changed", "nfq-policy-changed", "nfq-stock-counter-not-advanced":
				return unknown(r.RouteProofError)
			}
			return unknown("route-proof-unconfirmed")
		}
		if r.Status == "not-ready" {
			return unknown("probe-not-ready")
		}
		return unknown("service-verdict-inconclusive")
	}
	return unknown("result-missing")
}

func autonomyObservationContextReason(ctx context.Context, stage string, failures ...error) string {
	failure := errors.Join(append(failures, ctx.Err())...)
	if errors.Is(failure, context.DeadlineExceeded) {
		return stage + "-deadline"
	}
	if errors.Is(failure, context.Canceled) {
		return stage + "-canceled"
	}
	return stage + "-refused"
}

func (a *App) applyAutonomyRoute(ctx context.Context, p autonomy.Policy, s autonomy.Service, base config.Config, profile, route string) error {
	return a.applyAutonomyServiceRoute(ctx, p, s, base, profile, route, false, nil)
}

// Called only by the closed, unapplied starter branch, never ordinary node,
// retained profile, removal or global pending-recipe application.
func (a *App) applyAutonomyNFQFirstStartRoute(ctx context.Context, p autonomy.Policy, s autonomy.Service, base config.Config, profile string) error {
	return a.applyAutonomyServiceRoute(ctx, p, s, base, profile, "nfqws2", true, nil)
}

func (a *App) applyAutonomyServiceRoute(ctx context.Context, p autonomy.Policy, s autonomy.Service, base config.Config, profile, route string, firstStart bool, incumbent *dataplane.Plan) error {
	store := a.Store
	if !a.autonomyConsent(p, s) || a.autonomyDiskCurrent(ctx) != nil || ctx.Err() != nil {
		return dataplane.ErrReviewChanged
	}
	service, known := a.autonomyService(s.ID)
	if !known {
		return dataplane.ErrReviewChanged
	}
	if err := a.autonomyResourceGuard(ctx, p, s, base, service); err != nil {
		return err
	}
	if refusal := a.autonomyCapabilityRefusal(base, s.ID, route); refusal != nil {
		return refusal
	}
	if base.NetworkPolicy != nil && strings.HasPrefix(route, "xray:node-") {
		if err := a.applyManagedAutonomyXray(ctx, p, s, base, profile, route); err != nil {
			return err
		}
		return a.recordAutonomyRoute(ctx, p, s, route)
	}
	hypothetical := nodeRouteConfigForScope(base, s.ID, "unused", s.Sources)
	useDesiredRecipe := firstStart && route == "nfqws2" && base.AppliedNFQWSFirstStartRecipe == "" && base.NFQWSFirstStartRecipe != "" && !base.AppliedServices[s.ID].Enabled
	for _, applied := range base.AppliedServices {
		// A retained AUTO selection may already resolve to NFQWS2. It cannot
		// prove the global profile is uninitialized from config alone.
		if applied.Enabled && (selectedRoute(applied) == "nfqws2" || selectedRoute(applied) == "auto") {
			useDesiredRecipe = false
		}
	}
	if useDesiredRecipe {
		if !base.NFQWSFirstStartRecipe.Valid() || !catalog.IsNFQWS2Starter(service) || !s.AllLAN || len(s.Sources) != 0 || len(service.Domains) == 0 || len(service.CIDRs) != 0 {
			return dataplane.ErrReviewChanged
		}
		hypothetical.NFQWSFirstStartRecipe = base.NFQWSFirstStartRecipe
		// Node-scope planning deliberately reads the applied recipe. This is
		// the predicted first-start publication image, not a Store mutation.
		hypothetical.AppliedNFQWSFirstStartRecipe = base.NFQWSFirstStartRecipe
	}
	state := hypothetical.Services[s.ID]
	state.Route = route
	state.Mode = route
	hypothetical.Services[s.ID] = state
	plan, err := a.buildPlanReprovingRetained(ctx, hypothetical, profile)
	var dependency *routePlanDependencyError
	if errors.As(err, &dependency) {
		return dependency
	}
	var refusal *capabilityRefusal
	if errors.As(err, &refusal) {
		return refusal
	}
	if err != nil || !plan.Ready {
		return errAutonomyPlanNotReady
	}
	if incumbent != nil && !domainRefreshKeepsNeighbors(*incumbent, plan, s.ID) {
		return dataplane.ErrReviewChanged
	}
	generation := uint64(0)
	if a.Nodes != nil {
		snap, e := a.Nodes.Snapshot(ctx, time.Now())
		if e != nil {
			return e
		}
		generation = snap.Generation
	}
	committed := false
	// The guard re-checks revision, network, node permission and a fresh route
	// proof on every call; the window only bounds the whole application. Two
	// minutes expired mid-transaction on the owner's router, where replacing
	// a sing-box policy alone takes about a minute, so it follows the apply budget.
	expires := time.Now().Add(defaultDataplaneApplyTimeout)
	guard := func(ctx context.Context) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if a.Store != store || !time.Now().Before(expires) || !a.autonomyConsent(p, s) || a.autonomyDiskCurrent(ctx) != nil {
			return dataplane.ErrReviewChanged
		}
		cfg := a.Store.Get()
		expected := base.Revision
		if committed {
			expected++
		}
		if cfg.Revision != expected || cfg.SafeMode || cfg.ServiceControl.Stopped || cfg.ServiceControl.EffectiveMode() == "manual" {
			return dataplane.ErrReviewChanged
		}
		if useDesiredRecipe {
			expectedRecipe := base.AppliedNFQWSFirstStartRecipe
			if committed {
				expectedRecipe = base.NFQWSFirstStartRecipe
			}
			if cfg.NFQWSFirstStartRecipe != base.NFQWSFirstStartRecipe || cfg.AppliedNFQWSFirstStartRecipe != expectedRecipe {
				return dataplane.ErrReviewChanged
			}
		}
		if !sameAutonomyResourcePolicy(cfg, base) {
			return dataplane.ErrReviewChanged
		}
		if err := a.guardAutonomyWARP(ctx); err != nil {
			return err
		}
		if err := a.guardAutonomyUSQUE(ctx); err != nil {
			return err
		}
		observation := base
		if committed {
			observation = cfg
		}
		if err := a.autonomyResourceGuard(ctx, p, s, observation, service); err != nil {
			return err
		}
		observed, e := a.freshNetworkProfile(ctx)
		if e != nil || observed != profile {
			return dataplane.ErrNetworkChanged
		}
		service, ok := a.autonomyService(s.ID)
		if !ok || autonomyDefinition(service) != s.Definition {
			return dataplane.ErrReviewChanged
		}
		routeEngine := autonomyNodeEngine(route)
		if strings.HasPrefix(route, routeEngine+":node-") {
			snap, e := a.Nodes.Snapshot(ctx, time.Now())
			if e != nil || snap.Generation != generation {
				return dataplane.ErrReviewChanged
			}
			id := strings.TrimPrefix(route, routeEngine+":")
			permitted := false
			for _, n := range snap.Nodes {
				if n.ID == id && allowedAutonomyNode(p, n, time.Now()) {
					permitted = true
				}
			}
			if !permitted {
				return dataplane.ErrReviewChanged
			}
			if _, e = a.Nodes.ResolveRouteForEngine(ctx, routeEngine, id, s.ID, profile, "", time.Time{}, time.Now()); e != nil {
				return e
			}
		}
		return nil
	}
	if err = guard(ctx); err != nil {
		return err
	}
	if incumbent != nil {
		current, found, err := a.Dataplane.Committed()
		if err != nil || !found || !reflect.DeepEqual(current, *incumbent) {
			return dataplane.ErrReviewChanged
		}
	}
	ctx = dataplane.WithReviewGuard(ctx, guard)
	execution, err := a.applyDataplane(ctx, plan, func() (func() error, error) {
		if e := guard(ctx); e != nil {
			return nil, e
		}
		var undo func() error
		var e error
		if useDesiredRecipe {
			undo, e = a.Store.ApplyAutonomyNFQFirstStartRouteWithRollback(s.ID, s.Sources, base.NFQWSFirstStartRecipe, base.Revision)
		} else {
			undo, e = a.Store.ApplyAutonomyRouteWithRollback(s.ID, route, s.Sources, base.Revision)
		}
		if e == nil {
			committed = true
		}
		return undo, e
	})
	if err != nil {
		return &autonomyApplyFailure{Plan: plan, Execution: execution, Cause: err}
	}
	if s.ExpectedRoute == "auto" && route == "nfqws2" && catalog.IsNFQWS2Starter(service) &&
		nfqws2FirstStartScope(s, service) && (firstStart || nfqws2StarterApplied(base, s.ID)) {
		// The Manager has committed. Close the bookkeeping under this same
		// admission even if the request deadline expired during the commit.
		receiptCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		return a.recordAutonomyRouteReceipt(receiptCtx, p, s, route, true)
	}
	return a.recordAutonomyRoute(ctx, p, s, route)
}

func (a *App) recordAutonomyRoute(ctx context.Context, p autonomy.Policy, s autonomy.Service, route string) error {
	return a.recordAutonomyRouteReceipt(ctx, p, s, route, false)
}

func (a *App) recordAutonomyRouteReceipt(ctx context.Context, p autonomy.Policy, s autonomy.Service, route string, autoStarter bool) error {
	if a.autonomyDiskCurrent(ctx) != nil {
		return dataplane.ErrReviewChanged
	}
	// A crash before this sidecar receipt safely pauses for review; it never
	// authorizes blind re-application. Dataplane still has its durable journal.
	a.autonomy.mu.Lock()
	defer a.autonomy.mu.Unlock()
	if ctx.Err() != nil || !a.autonomyConsentLocked(p, s) {
		return dataplane.ErrReviewChanged
	}
	current := a.autonomy.doc.Services[s.ID]
	// Keep Auto for the closed NFQWS2 starter and node assignments. The
	// applied config stores the concrete route used for observation.
	if current.ExpectedRoute != "auto" || !autoStarter && !strings.HasPrefix(route, autonomyNodeEngine(route)+":node-") {
		current.ExpectedRoute = route
	}
	current.DraftFingerprint = autonomyDraftFingerprint(a.Store.Get().Services[s.ID])
	a.autonomy.doc.Services[s.ID] = current
	persistCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	err := a.persistAutonomyLocked(persistCtx)
	if err != nil {
		a.autonomy.doc.Services[s.ID] = s
	}
	return err
}

// Translate structured checker evidence into the private failure quorum input.
// Protocol/DNS/runtime/cleanup problems without definite network evidence never
// count as consecutive service failures. The public verdict is unchanged.
func autonomyNodeObservation(r dataplane.NodeCheckResult, now time.Time) string {
	if r.FinishedAt.IsZero() || r.FinishedAt.After(now) || !r.ExpiresAt.After(now) {
		return "INCONCLUSIVE"
	}
	if r.Available && string(r.Verdict) == "PASS" && !r.DirectLeak && r.TestLevel == "service" {
		return "PASS"
	}
	if nodeAutofallbackDefiniteFailure(r) {
		return "FAIL"
	}
	return "INCONCLUSIVE"
}
