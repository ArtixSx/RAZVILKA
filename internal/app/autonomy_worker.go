package app

import (
	"context"
	"errors"
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
	"github.com/ArtixSx/razvilka/internal/testlab"
)

func allowedAutonomyNode(p autonomy.Policy, n nodestore.Node, now time.Time) bool {
	if n.Disabled || !slices.Contains(p.Protocols, strings.ToLower(strings.TrimSpace(n.Protocol))) {
		return false
	}
	for _, o := range n.Origins {
		if slices.Contains(p.SourceIDs, o.SourceID) && !now.Before(o.ReceivedAt) && now.Before(o.ExpiresAt) {
			return true
		}
	}
	return false
}
func (a *App) autonomyConsent(p autonomy.Policy, s autonomy.Service) bool {
	a.autonomy.mu.Lock()
	defer a.autonomy.mu.Unlock()
	current, ok := a.autonomy.doc.Services[s.ID]
	return !a.autonomy.blocked && a.autonomy.doc.Policy.Revision == p.Revision && a.autonomy.doc.Policy.Enabled && ok && current.Enabled && reflect.DeepEqual(s, current)
}

// One service per coordinator round; all mutations use the same admission as
// manual Apply/restore. No browser timer or second networking daemon is used.
func (a *App) autonomyRound(ctx context.Context, now time.Time) {
	ctx, release, err := a.scopedRuntimeOperation(ctx)
	if err != nil {
		return
	}
	retained := false
	defer func() {
		if !retained {
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
	a.autonomyMaintenance(ctx, p, now)
	if a.componentMaintenancePending() {
		return
	}
	if a.runAutoInstall(ctx, p) {
		// The installer stops this process; until then nothing else runs.
		a.SelfUpdate.RetainHandoff(release)
		retained = true
		return
	}
	if !cfg.SafeMode {
		_, _ = a.pruneExpiredFeedNodes(ctx, now)
	}
	if !p.Enabled || ctx.Err() != nil || cfg.SafeMode || cfg.ServiceControl.Stopped || cfg.ServiceControl.EffectiveMode() == "manual" || a.Dataplane == nil {
		return
	}
	if err = a.autonomyEnsureFeeds(ctx, p); err != nil {
		a.autonomy.mu.Lock()
		a.autonomy.maintenanceMessage = "Не удалось сохранить подписку; рабочие маршруты не менялись."
		a.autonomy.mu.Unlock()
	}
	a.autonomy.mu.Lock()
	ids := []string{}
	disabledChanged := false
	activate := []autonomy.Service{}
	for id, s := range a.autonomy.doc.Services {
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
	chosen := ""
	var spec autonomy.Service
	var state autonomy.Runtime
	for _, id := range ids {
		r := a.autonomy.doc.Runtime[id]
		if now.Before(r.NextCheck) {
			continue
		}
		if chosen == "" || r.NextCheck.Before(state.NextCheck) {
			chosen = id
			spec = a.autonomy.doc.Services[id]
			state = r.Clone()
		}
	}
	a.autonomy.mu.Unlock()
	if len(activate) > 0 {
		a.activateHandedOverServices(ctx, p, activate)
		return
	}
	if chosen == "" {
		return
	}
	// Retain one original selected-device Review through checks, ordinary
	// route publication and passive refill. No later guard can reopen it.
	if !spec.Removing && cfg.NetworkPolicy != nil && cfg.NetworkPolicy.Clients.Mode == "selected_devices" {
		window, cancelWindow := context.WithTimeout(ctx, defaultDataplaneApplyTimeout)
		defer cancelWindow()
		owned, closeDevices, err := a.autonomyDeviceContext(window, cfg)
		if err != nil {
			state.State, state.Message = "paused", "Выбранные устройства или их исходная область не подтверждены. Маршрут не меняется."
			state.NextCheck = now.Add(time.Duration(p.CheckSeconds) * time.Second)
			a.autonomyRuntime(chosen, state)
			return
		}
		ctx = owned
		defer func() {
			if err := closeDevices(); err != nil {
				a.Operations.FenceJournal()
				state.State, state.Message = "paused", "Не удалось завершить наблюдение устройств. Автоматические действия остановлены."
				a.autonomyRuntime(chosen, state)
			}
		}()
	}
	state.NextCheck = now.Add(time.Duration(p.CheckSeconds) * time.Second)
	state.State = "checking"
	state.Message = "Проверяем точный путь сервиса."
	a.autonomyRuntime(chosen, state)
	// Publish only bounded descriptions; raw endpoint/config/transport errors are
	// deliberately never copied into the autonomy journal.
	state = a.runAutonomyService(ctx, p, spec, state, now)
	if !state.NextCheck.After(time.Now()) {
		state.NextCheck = time.Now().Add(time.Duration(p.CheckSeconds) * time.Second)
	}
	a.autonomyRuntime(chosen, state)
	// Refill is passive catalogue work, not route selection. A failed current
	// node cannot cause repeated fetches if the permitted pool is already full.
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
	return !draft.Enabled && !cfg.AppliedServices[s.ID].Enabled && autonomyDraftFingerprint(draft) == s.DraftFingerprint
}

// activateHandedOverServices enables the drafts of handed-over services with
// their expected route under the config revision it read, then records the new
// draft fingerprint on the unchanged autopilot record. Checks start next round.
func (a *App) activateHandedOverServices(ctx context.Context, p autonomy.Policy, services []autonomy.Service) {
	sort.Slice(services, func(i, j int) bool { return services[i].ID < services[j].ID })
	for _, s := range services {
		cfg := a.Store.Get()
		if ctx.Err() != nil || cfg.Services[s.ID].Enabled || !handedOverUnassigned(cfg, s) {
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
		a.autonomyRuntime(s.ID, r)
	}
}

func (a *App) runAutonomyService(ctx context.Context, p autonomy.Policy, s autonomy.Service, r autonomy.Runtime, now time.Time) autonomy.Runtime {
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
	profile, e := a.freshNetworkProfile(ctx)
	if e != nil {
		return finish("network-unknown", "Текущая сеть не подтверждена. Переключение отложено.")
	}
	if !serviceHasNodeProbe(service) {
		return finish("unsupported-scenario", "Для сервиса нет безопасной веб-проверки. Доступ не объявляется подтверждённым.")
	}
	if catalog.IsNFQWS2Starter(service) && s.ExpectedRoute == "nfqws2" {
		return a.runNFQWS2Starter(ctx, p, s, r, service, cfg, profile)
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
		engine = autonomyNodeEngine(s.ExpectedRoute)
	}
	currentNode := ""
	isNode := strings.HasPrefix(current, engine+":node-")
	if isNode {
		currentNode = strings.TrimPrefix(current, engine+":")
	}
	if current != "" && !isNode {
		// Only a confirmed failure of the current path may replace an existing
		// non-proxy route. Unsupported probes are not counted as a failure.
		observation := a.autonomyProbeRouteObservation(ctx, service, current, profile)
		if observation.pause(&r) {
			return r
		}
		verdict := observation.Verdict
		r.CheckedAt = time.Now().UTC()
		healthy = verdict == "PASS"
		replace = r.Observe(current, profile, verdict, time.Now(), time.Duration(p.FailureConfirmSeconds)*time.Second)
		if !healthy && !replace {
			if verdict == "FAIL" {
				r.NextCheck = time.Now().Add(time.Duration(p.FailureConfirmSeconds) * time.Second)
			}
			return finish("unconfirmed", "Отказ действующего обхода пока не подтверждён; маршрут сохранён.")
		}
	}
	if current == "" {
		// A limit of the saved mode is named before any probe or node check
		// when no route this round could apply is open.
		if refusal := a.autonomyUnappliedRefusal(cfg, p, s, engine); refusal != nil {
			return autonomyCapabilityRefused(refusal, &r)
		}
		for _, route := range p.PreferredRoutes {
			if ctx.Err() != nil {
				return finish("paused", "Подбор отменён.")
			}
			ready := false
			for _, o := range a.nodeRouteOptions() {
				if o.ID == route && o.Ready {
					ready = true
				}
			}
			if !ready {
				continue
			}
			observation := a.autonomyProbeRouteObservation(ctx, service, route, profile)
			if observation.pause(&r) {
				return r
			}
			if observation.Verdict == "PASS" {
				if !r.ReserveSwitch(time.Now(), p.MaxSwitchesPerHour) {
					return finish("rate-limited", "Лимит применений исчерпан; проверенный обход пока не меняется.")
				}
				a.autonomyRuntime(s.ID, r)
				if err := a.applyAutonomyRoute(ctx, p, s, cfg, profile, route); err != nil {
					return finish(autonomyLegacyApplyRefused(err, &r, "Применение локального обхода не подтверждено; выполнена защита/откат."))
				}
				return finish("applied", "Подходящий обход применён через общую транзакцию.")
			}
		}
	}
	if a.Nodes == nil {
		return finish("checker-unavailable", "Точная проверка подключений недоступна.")
	}
	if _, err := a.nodeCheckerForEngine(engine); err != nil {
		return finish("checker-unavailable", "Точная проверка выбранного движка недоступна.")
	}
	snapshot, e := a.Nodes.Snapshot(ctx, time.Now())
	if e != nil {
		return finish("catalog-unavailable", "Каталог подключений недоступен.")
	}
	if isNode && nfqws2StandardScope(service, s) && !nodeRecoveryNodePresent(snapshot, currentNode, time.Now()) && a.nfqws2RouteReady() {
		return a.returnToNFQWS2Standard(ctx, p, s, r, service, cfg, profile)
	}
	eligible := map[string]nodestore.Node{}
	ids := []string{}
	r.PruneCandidateFailures(profile, s.Definition, autonomy.ScopeFingerprint(s.Sources), time.Now())
	for _, n := range snapshot.Nodes {
		if allowedAutonomyNode(p, n, time.Now()) {
			eligible[n.ID] = n
			if !r.CandidateCoolingDown(n.ID) {
				ids = append(ids, n.ID)
			}
		}
	}
	if engine == "sing-box" {
		ids = orderAutonomyCandidates(snapshot, ids, s.ID, profile, time.Now())
	} else {
		slices.Sort(ids)
	}
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
			a.autonomyRuntime(s.ID, r)
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
			a.autonomyRuntime(s.ID, r)
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
		return a.runAutonomyFirstUsable(ctx, p, s, r, cfg, service, engine, profile, currentNode, ids)
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
		if !sameNodeRecoveryStrings(cfg.AppliedServices[s.ID].Sources, s.Sources) {
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

func (a *App) autonomyProbeRouteObservation(ctx context.Context, s catalog.Service, route, profile string) autonomyRouteObservation {
	unknown := autonomyRouteObservation{Verdict: "INCONCLUSIVE"}
	if a.TestLab == nil || a.RouteProber == nil || a.Store == nil {
		return unknown
	}
	probeCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	p := a.autonomyPolicy()
	a.autonomy.mu.Lock()
	spec, known := a.autonomy.doc.Services[s.ID]
	a.autonomy.mu.Unlock()
	store := a.Store
	cfg := store.Get()
	if !known || a.autonomyResourceGuard(probeCtx, p, spec, cfg, s) != nil {
		return unknown
	}
	observed, err := a.freshNetworkProfile(probeCtx)
	if err != nil || observed != profile {
		return unknown
	}
	// Autonomy consumes this private verdict in its own round. Keep the batch
	// unrecorded so a closing refusal cannot leak observations into TestLab
	// history before resource admission. The prober still owns full cleanup.
	runner, prober := a.TestLab, a.RouteProber
	results := runner.ProbeRoutesUnrecorded(probeCtx, a.catalogSnapshot(), []string{s.ID}, []string{route}, prober)
	current, err := a.freshNetworkProfile(probeCtx)
	if err != nil || current != observed || a.TestLab != runner || a.Store != store {
		return unknown
	}
	for i := range results {
		r := &results[i]
		if r.NetworkProfileID != "" && r.NetworkProfileID != observed || r.EvidenceV2 != nil && r.EvidenceV2.NetworkProfile != "" && r.EvidenceV2.NetworkProfile != observed {
			return unknown
		}
		r.NetworkProfileID = observed
		if r.EvidenceV2 != nil {
			r.EvidenceV2.NetworkProfile = observed
		}
	}
	if a.autonomyResourceGuard(probeCtx, p, spec, cfg, s) != nil {
		return unknown
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
			return autonomyRouteObservation{Verdict: "INCONCLUSIVE", RetryAfterSeconds: max(30, min(delay, 30*60))}
		}
	}
	return unknown
}

func (a *App) applyAutonomyRoute(ctx context.Context, p autonomy.Policy, s autonomy.Service, base config.Config, profile, route string) error {
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
		if !sameAutonomyResourcePolicy(cfg, base) {
			return dataplane.ErrReviewChanged
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
	ctx = dataplane.WithReviewGuard(ctx, guard)
	execution, err := a.applyDataplane(ctx, plan, func() (func() error, error) {
		if e := guard(ctx); e != nil {
			return nil, e
		}
		undo, e := a.Store.ApplyAutonomyRouteWithRollback(s.ID, route, s.Sources, base.Revision)
		if e == nil {
			committed = true
		}
		return undo, e
	})
	if err != nil {
		return &autonomyApplyFailure{Plan: plan, Execution: execution, Cause: err}
	}
	return a.recordAutonomyRoute(ctx, p, s, route)
}

func (a *App) recordAutonomyRoute(ctx context.Context, p autonomy.Policy, s autonomy.Service, route string) error {
	if !a.autonomyConsent(p, s) || a.autonomyDiskCurrent(ctx) != nil {
		return dataplane.ErrReviewChanged
	}
	// A crash before this sidecar receipt safely pauses for review; it never
	// authorizes blind re-application. Dataplane still has its durable journal.
	a.autonomy.mu.Lock()
	defer a.autonomy.mu.Unlock()
	current := a.autonomy.doc.Services[s.ID]
	current.ExpectedRoute = route
	current.DraftFingerprint = autonomyDraftFingerprint(a.Store.Get().Services[s.ID])
	a.autonomy.doc.Services[s.ID] = current
	return a.persistAutonomyLocked(context.WithoutCancel(ctx))
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
