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
	release, err := a.Operations.Exclusive(ctx)
	if err != nil {
		return
	}
	defer release()
	if a.loadAutonomy(ctx) != nil || a.Store == nil {
		return
	}
	p := a.autonomyPolicy()
	cfg := a.Store.Get()
	if !p.SetupComplete {
		return
	}
	a.autonomyMaintenance(ctx, p, now)
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
	for id, s := range a.autonomy.doc.Services {
		if s.Enabled {
			ids = append(ids, id)
		}
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
	if chosen == "" {
		return
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
		return finish("definition-changed", "Состав сервиса изменился. Повторно подтвердите его область и проверки.")
	}
	cfg := a.Store.Get()
	if autonomyDraftFingerprint(cfg.Services[s.ID]) != s.DraftFingerprint {
		return finish("manual-change", "Обнаружено ручное изменение сервиса. Автоматическое применение приостановлено.")
	}
	if !a.autonomyConsent(p, s) || ctx.Err() != nil {
		return finish("paused", "Разрешение отозвано или действие отменено.")
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
	currentNode := strings.TrimPrefix(current, "sing-box:")
	isNode := strings.HasPrefix(current, "sing-box:node-")
	if current != "" && !isNode {
		// Only a confirmed failure of the current path may replace an existing
		// non-proxy route. Unsupported probes are not counted as a failure.
		verdict := a.autonomyProbeRoute(ctx, service, current, profile)
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
			if a.autonomyProbeRoute(ctx, service, route, profile) == "PASS" {
				if !r.ReserveSwitch(time.Now(), p.MaxSwitchesPerHour) {
					return finish("rate-limited", "Лимит применений исчерпан; проверенный обход пока не меняется.")
				}
				a.autonomyRuntime(s.ID, r)
				if err := a.applyAutonomyRoute(ctx, p, s, cfg, profile, route); err != nil {
					return finish("apply-refused", "Применение локального обхода не подтверждено; выполнена защита/откат.")
				}
				return finish("applied", "Подходящий обход применён через общую транзакцию.")
			}
		}
	}
	if a.Nodes == nil || a.NodeChecker == nil {
		return finish("checker-unavailable", "Точная проверка подключений недоступна.")
	}
	snapshot, e := a.Nodes.Snapshot(ctx, time.Now())
	if e != nil {
		return finish("catalog-unavailable", "Каталог подключений недоступен.")
	}
	eligible := map[string]nodestore.Node{}
	ids := []string{}
	for _, n := range snapshot.Nodes {
		if allowedAutonomyNode(p, n, time.Now()) {
			eligible[n.ID] = n
			ids = append(ids, n.ID)
		}
	}
	sort.Strings(ids)
	if isNode {
		if _, ok := eligible[currentNode]; !ok {
			// No new authority is created for a disabled/revoked/expired node. Search
			// for a permitted replacement, but never renew the old receipt ourselves.
			replace = true
			r.State = "origin-expired"
		} else {
			check, _, err := a.checkAndRecordNode(ctx, currentNode, service, profile, 0)
			verdict := "INCONCLUSIVE"
			if err == nil {
				verdict = autonomyNodeObservation(check, time.Now())
				healthy = verdict == "PASS"
				if healthy {
					_, resolveErr := a.Nodes.ResolveRoute(ctx, currentNode, service.ID, profile, "", time.Time{}, time.Now())
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
		matched := false
		for _, route := range committed.Routes {
			if route.ServiceID == s.ID && route.Resolved == current && route.Selected == selectedRoute(cfg.AppliedServices[s.ID]) && sameNodeRecoveryStrings(route.Sources, cfg.AppliedServices[s.ID].Sources) && nodeRecoveryServiceMatches(route, service) {
				matched = true
			}
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
		if a.Dataplane.CheckCommittedNodeHealth(dataplane.WithReviewGuard(ctx, guard), committed) != nil {
			if guard(ctx) != nil {
				return finish("paused", "Проверка маршрута отменена: сеть или разрешения изменились.")
			}
			if !r.ReserveSwitch(time.Now(), p.MaxSwitchesPerHour) {
				return finish("rate-limited", "Работа локального маршрута не подтверждена. Лимит восстановлений исчерпан.")
			}
			r.State, r.Message = "applying", "Восстанавливаем прежний проверенный узел без замены подключения."
			a.autonomyRuntime(s.ID, r)
			if err := a.applyAutonomyRoute(ctx, p, s, cfg, profile, current); err != nil {
				return finish("apply-refused", "Восстановление прежнего маршрута не подтверждено; использована защита и откат.")
			}
			return finish("applied", "Прежний проверенный узел и его область восстановлены через общую транзакцию.")
		}
	}
	checkedThisRound := map[string]bool{}
	ready := []string{}
	if healthy && isNode {
		ready = append(ready, currentNode)
	}
	for _, id := range ids {
		if slices.Contains(ready, id) {
			continue
		}
		if _, err := a.Nodes.ResolveRoute(ctx, id, s.ID, profile, "", time.Time{}, time.Now()); err == nil {
			ready = append(ready, id)
		}
	}
	// Revisit reserves at their own interval, even when their proof has not yet
	// expired. Walk through all candidates, not only the first rows of a feed.
	needRefresh := !time.Now().Before(r.ReserveCheckedAt.Add(time.Duration(p.ReserveSeconds) * time.Second))
	shortlist, next := autonomy.CandidateBatch(ids, currentNode, r.Cursor, p.CandidatesPerRound)
	r.Cursor = next
	if len(ready) < p.ReserveTarget || needRefresh {
		for _, id := range shortlist {
			if ctx.Err() != nil {
				break
			}
			check, _, err := a.checkAndRecordNode(ctx, id, service, profile, 0)
			checkedThisRound[id] = true
			ready = slices.DeleteFunc(ready, func(v string) bool { return v == id })
			if err == nil && check.Available && string(check.Verdict) == "PASS" && !check.DirectLeak {
				ready = append(ready, id)
			}
		}
		r.ReserveCheckedAt = time.Now().UTC()
	}
	if len(ready) > p.ReserveTarget {
		ready = ready[:p.ReserveTarget]
	}
	r.Reserves = ready
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
	if len(ready) == 0 {
		return finish("searching", "Подходящий узел пока не найден. Продолжается ограниченный подбор.")
	}
	// A previously cached PASS is not sufficient during a current outage.
	// Recheck the chosen replacement in this round before changing the route.
	if !checkedThisRound[ready[0]] {
		check, _, checkErr := a.checkAndRecordNode(ctx, ready[0], service, profile, 0)
		if checkErr != nil || autonomyNodeObservation(check, time.Now()) != "PASS" {
			r.Reserves = slices.DeleteFunc(r.Reserves, func(id string) bool { return id == ready[0] })
			return finish("searching", "Сохранённый резерв не прошёл новую проверку; прежний маршрут не менялся.")
		}
	}
	if !r.ReserveSwitch(time.Now(), p.MaxSwitchesPerHour) {
		return finish("rate-limited", "Лимит переключений исчерпан; автоматическое применение отложено.")
	}
	// Persist the budget BEFORE entering Activate, including failed attempts.
	r.State = "applying"
	r.Message = "Подготовлен проверенный узел; выполняется транзакция."
	a.autonomyRuntime(s.ID, r)
	if err := a.applyAutonomyRoute(ctx, p, s, cfg, profile, "sing-box:"+ready[0]); err != nil {
		return finish("apply-refused", "Изменение не подтверждено. Сохранены защитные проверки и откат.")
	}
	r.Failures = 0
	r.FirstFailure = time.Time{}
	r.LastFailure = time.Time{}
	return finish("applied", "Проверенный узел применён только к этому сервису и его устройствам.")
}

func (a *App) autonomyProbeRoute(ctx context.Context, s catalog.Service, route, profile string) string {
	if a.TestLab == nil || a.RouteProber == nil {
		return "INCONCLUSIVE"
	}
	probeCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	results, observed, err := a.probeRoutesInCurrentNetwork(probeCtx, a.catalogSnapshot(), []string{s.ID}, []string{route})
	if err != nil || observed != profile {
		return "INCONCLUSIVE"
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
			return "PASS"
		}
		// Only an attributed, current service failure can replace a local route.
		// Missing process/capability or uncertain route evidence is not a FAIL.
		if fresh && r.Status == "fail" && (string(r.Verdict) == "BLOCKED" || string(r.Verdict) == "ERROR") && r.RouteConfirmed && r.RouteProofError == "" {
			return "FAIL"
		}
	}
	return "INCONCLUSIVE"
}

func (a *App) applyAutonomyRoute(ctx context.Context, p autonomy.Policy, s autonomy.Service, base config.Config, profile, route string) error {
	if !a.autonomyConsent(p, s) || a.autonomyDiskCurrent(ctx) != nil || ctx.Err() != nil {
		return dataplane.ErrReviewChanged
	}
	hypothetical := nodeRouteConfigForScope(base, s.ID, "unused", s.Sources)
	state := hypothetical.Services[s.ID]
	state.Route = route
	state.Mode = route
	hypothetical.Services[s.ID] = state
	plan, err := a.buildDataplanePlanForScope(hypothetical, a.nodeRouteOptions(), changeScopeNode, "")
	if err != nil || !plan.Ready {
		return errors.New("autonomous plan not ready")
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
	expires := time.Now().Add(2 * time.Minute)
	guard := func(ctx context.Context) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !time.Now().Before(expires) || !a.autonomyConsent(p, s) || a.autonomyDiskCurrent(ctx) != nil {
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
		observed, e := a.freshNetworkProfile(ctx)
		if e != nil || observed != profile {
			return dataplane.ErrNetworkChanged
		}
		service, ok := a.autonomyService(s.ID)
		if !ok || autonomyDefinition(service) != s.Definition {
			return dataplane.ErrReviewChanged
		}
		if strings.HasPrefix(route, "sing-box:node-") {
			snap, e := a.Nodes.Snapshot(ctx, time.Now())
			if e != nil || snap.Generation != generation {
				return dataplane.ErrReviewChanged
			}
			id := strings.TrimPrefix(route, "sing-box:")
			permitted := false
			for _, n := range snap.Nodes {
				if n.ID == id && allowedAutonomyNode(p, n, time.Now()) {
					permitted = true
				}
			}
			if !permitted {
				return dataplane.ErrReviewChanged
			}
			if _, e = a.Nodes.ResolveRoute(ctx, id, s.ID, profile, "", time.Time{}, time.Now()); e != nil {
				return e
			}
		}
		return nil
	}
	if err = guard(ctx); err != nil {
		return err
	}
	ctx = dataplane.WithReviewGuard(ctx, guard)
	_, err = a.Dataplane.Apply(ctx, plan, func() (func() error, error) {
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
		return err
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
