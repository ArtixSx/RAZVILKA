package app

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/nodestore"
)

const nodeAutofallbackInterval = time.Minute
const nodeAutofallbackCandidates = 3

type nodeAutofallbackService struct {
	ServiceID      string     `json:"service_id"`
	GroupID        string     `json:"group_id"`
	NodeID         string     `json:"node_id"`
	CandidateID    string     `json:"candidate_id,omitempty"`
	State          string     `json:"state"`
	Failures       int        `json:"failures"`
	Healthy        bool       `json:"healthy"`
	CheckedAt      *time.Time `json:"checked_at,omitempty"`
	NextCheckAt    time.Time  `json:"next_check_at"`
	CooldownUntil  *time.Time `json:"cooldown_until,omitempty"`
	NetworkProfile string     `json:"network_profile,omitempty"`
	Message        string     `json:"message"`
	Trigger        string     `json:"trigger,omitempty"`
}

type nodeAutofallbackEntry struct {
	status       nodeAutofallbackService
	key          string
	cursor       int
	lastSwitched time.Time
}

type nodeAutofallbackState struct {
	once          sync.Once
	mu            sync.Mutex
	entries       map[string]nodeAutofallbackEntry
	done          chan struct{}
	cancel        context.CancelFunc
	attemptCancel context.CancelFunc
	pausedUntil   time.Time
}

func (a *App) StartNodeAutofallback(ctx context.Context) {
	a.nodeAutofallback.once.Do(func() {
		ctx, cancel := context.WithCancel(ctx)
		a.nodeAutofallback.mu.Lock()
		a.nodeAutofallback.done = make(chan struct{})
		a.nodeAutofallback.cancel = cancel
		done := a.nodeAutofallback.done
		a.nodeAutofallback.mu.Unlock()
		go func() {
			defer close(done)
			defer cancel()
			timer := time.NewTimer(2 * time.Second)
			defer timer.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-timer.C:
					a.nodeAutofallbackRound(ctx, time.Now())
					timer.Reset(nodeAutofallbackInterval)
				}
			}
		}()
	})
}

func (a *App) WaitNodeAutofallback(ctx context.Context) error {
	a.nodeAutofallback.mu.Lock()
	if a.nodeAutofallback.cancel != nil {
		a.nodeAutofallback.cancel()
	}
	done := a.nodeAutofallback.done
	a.nodeAutofallback.mu.Unlock()
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (a *App) nodeAutofallbackSnapshot() []nodeAutofallbackService {
	a.nodeAutofallback.mu.Lock()
	defer a.nodeAutofallback.mu.Unlock()
	statuses := make([]nodeAutofallbackService, 0, len(a.nodeAutofallback.entries))
	for _, entry := range a.nodeAutofallback.entries {
		statuses = append(statuses, entry.status)
	}
	sort.Slice(statuses, func(i, j int) bool { return statuses[i].ServiceID < statuses[j].ServiceID })
	return statuses
}

func (a *App) nodeAutofallbackStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodDelete {
		a.nodeAutofallback.mu.Lock()
		a.nodeAutofallback.pausedUntil = time.Now().Add(nodeAutofallbackInterval)
		if a.nodeAutofallback.attemptCancel != nil {
			a.nodeAutofallback.attemptCancel()
		}
		for id, entry := range a.nodeAutofallback.entries {
			entry.status.NextCheckAt = a.nodeAutofallback.pausedUntil
			entry.status.Healthy = false
			entry.status.State, entry.status.Message = "paused", "Автоматическая проверка отложена на минуту."
			if a.nodeAutofallback.attemptCancel != nil {
				entry.status.State, entry.status.Message = "canceling", "Останавливаем автоматическую проверку. Повтор начнётся не раньше чем через минуту."
			}
			a.nodeAutofallback.entries[id] = entry
		}
		a.nodeAutofallback.mu.Unlock()
	} else if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	a.nodeAutofallback.mu.Lock()
	active, pausedUntil := a.nodeAutofallback.attemptCancel != nil, a.nodeAutofallback.pausedUntil
	a.nodeAutofallback.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"services": a.nodeAutofallbackSnapshot(), "active": active, "paused_until": pausedUntil, "interval_seconds": int(nodeAutofallbackInterval.Seconds()),
		"note": "Автозамена работает только для применённой резервной группы Sing-box. В первой тестовой версии весь применённый план должен состоять из узлов Sing-box."})
}

func (a *App) setNodeAutofallbackEntry(entry nodeAutofallbackEntry) {
	a.nodeAutofallback.mu.Lock()
	if a.nodeAutofallback.entries == nil {
		a.nodeAutofallback.entries = make(map[string]nodeAutofallbackEntry)
	}
	if entry.status.NextCheckAt.Before(a.nodeAutofallback.pausedUntil) {
		entry.status.NextCheckAt = a.nodeAutofallback.pausedUntil
	}
	a.nodeAutofallback.entries[entry.status.ServiceID] = entry
	a.nodeAutofallback.mu.Unlock()
}

// A fallback group in applied configuration is the explicit switch authority.
// Plain nodes, AUTO routes, manual groups and unapplied drafts never opt in.
func (a *App) nodeAutofallbackRound(ctx context.Context, now time.Time) {
	if a.Store == nil || a.Dataplane == nil || a.Nodes == nil || a.NodeChecker == nil {
		return
	}
	a.nodeAutofallback.mu.Lock()
	paused := now.Before(a.nodeAutofallback.pausedUntil)
	a.nodeAutofallback.mu.Unlock()
	if paused {
		return
	}
	release, err := a.Operations.Enter(ctx)
	if err != nil {
		return
	}
	previous, exists, err := a.Dataplane.Committed()
	if err != nil || !exists {
		release()
		return
	}
	snapshot, err := a.Nodes.Snapshot(ctx, now)
	if err != nil {
		release()
		return
	}
	cfg := a.Store.Get()
	groups := make(map[string]nodestore.NodeGroup)
	for _, group := range snapshot.Groups {
		if group.Mode == "fallback" {
			groups[group.ID] = group
		}
	}
	eligible := make(map[string]nodestore.NodeGroup)
	var selected string
	var selectedDue time.Time
	a.nodeAutofallback.mu.Lock()
	if a.nodeAutofallback.entries == nil {
		a.nodeAutofallback.entries = make(map[string]nodeAutofallbackEntry)
	}
	for _, route := range previous.Routes {
		group, ok := groups[strings.TrimPrefix(route.Selected, "sing-box:")]
		state := cfg.AppliedServices[route.ServiceID]
		if !ok || !state.Enabled || selectedRoute(state) != route.Selected || !strings.HasPrefix(route.Resolved, "sing-box:node-") {
			continue
		}
		eligible[route.ServiceID] = group
		entry, found := a.nodeAutofallback.entries[route.ServiceID]
		if !found || entry.status.GroupID != group.ID {
			entry = nodeAutofallbackEntry{status: nodeAutofallbackService{ServiceID: route.ServiceID, GroupID: group.ID, NodeID: strings.TrimPrefix(route.Resolved, "sing-box:"), State: "pending", Message: "Ожидает проверки применённого узла."}}
		}
		if cfg.SafeMode || cfg.ServiceControl.Stopped || cfg.ServiceControl.EffectiveMode() == "manual" {
			entry.status.State, entry.status.Message, entry.status.Healthy = "paused", "Безопасный режим включён. Автозамена приостановлена.", false
			if !cfg.SafeMode && cfg.ServiceControl.Stopped {
				entry.status.Message = "Маршруты проекта остановлены. Автозамена приостановлена."
			} else if !cfg.SafeMode {
				entry.status.Message = "Включён общий ручной режим. Автозамена приостановлена."
			}
		} else if policy, exists := cfg.ServicePolicies[route.ServiceID]; exists {
			policyState, reason := servicePolicyState(cfg, policy)
			if policyState != "ready" {
				entry.status.State, entry.status.Message, entry.status.Healthy = policyState, reason, false
			} else if policy.PinnedNodeID != "" && policy.PinnedNodeID != strings.TrimPrefix(route.Resolved, "sing-box:") && !policy.PinFallback {
				entry.status.State, entry.status.Message, entry.status.Healthy = "blocked-by-policy", "Закреплённый узел отличается от применённого. Сначала примените ручной выбор.", false
			} else if !now.Before(entry.status.NextCheckAt) && (selected == "" || entry.status.NextCheckAt.Before(selectedDue)) {
				selected, selectedDue = route.ServiceID, entry.status.NextCheckAt
			}
		} else if !now.Before(entry.status.NextCheckAt) && (selected == "" || entry.status.NextCheckAt.Before(selectedDue)) {
			selected, selectedDue = route.ServiceID, entry.status.NextCheckAt
		}
		a.nodeAutofallback.entries[route.ServiceID] = entry
	}
	for serviceID := range a.nodeAutofallback.entries {
		if _, ok := eligible[serviceID]; !ok {
			delete(a.nodeAutofallback.entries, serviceID)
		}
	}
	a.nodeAutofallback.mu.Unlock()
	release()
	if selected == "" || ctx.Err() != nil {
		return
	}
	// Re-read all authority after the short observation admission is replaced.
	release, err = a.Operations.Exclusive(ctx)
	if err != nil {
		return
	}
	defer release()
	current, found, err := a.Dataplane.Committed()
	if err != nil || !found || !sameNodeRecoveryPlan(previous, current) {
		return
	}
	a.nodeAutofallback.mu.Lock()
	entry := a.nodeAutofallback.entries[selected]
	a.nodeAutofallback.mu.Unlock()
	entry.status.NextCheckAt = now.Add(nodeAutofallbackInterval)
	if policy, exists := a.Store.Get().ServicePolicies[selected]; exists {
		entry.status.NextCheckAt = now.Add(time.Duration(policy.CheckIntervalSeconds) * time.Second)
	}
	entry.status.CandidateID, entry.status.Healthy = "", false
	runtimeStatus, runtimeErr := a.Dataplane.Status()
	if runtimeErr != nil || runtimeStatus.Execution != nil && runtimeStatus.Execution.State == "rollback-failed" {
		entry.status.State, entry.status.Message = "requires-review", "Откат или журнал состояния требуют проверки. Автозамена остановлена до успешного применения маршрута."
		a.setNodeAutofallbackEntry(entry)
		return
	}
	profile, err := a.freshNetworkProfile(ctx)
	if err != nil {
		entry.status.State, entry.status.Message, entry.status.Failures = "unknown", "Сеть не подтверждена. Узел автоматически не меняется.", 0
		a.setNodeAutofallbackEntry(entry)
		return
	}
	key := previous.PlanID + "/" + profile + "/" + strconv.FormatUint(a.Store.Get().Revision, 10) + "/" + eligible[selected].UpdatedAt.Format(time.RFC3339Nano)
	if entry.key != key {
		entry.key, entry.status.Failures, entry.cursor = key, 0, 0
		entry.status.State = "pending"
	}
	if entry.status.State == "requires-review" {
		a.setNodeAutofallbackEntry(entry)
		return
	}
	entry.status.NetworkProfile = profile
	entry.status.State, entry.status.Message = "checking", "Проверяем применённый узел для выбранного сервиса."
	a.setNodeAutofallbackEntry(entry)
	attempt, cancel := context.WithTimeout(ctx, defaultDataplaneApplyTimeout)
	defer cancel()
	a.nodeAutofallback.mu.Lock()
	if time.Now().Before(a.nodeAutofallback.pausedUntil) {
		a.nodeAutofallback.mu.Unlock()
		return
	}
	a.nodeAutofallback.attemptCancel = cancel
	a.nodeAutofallback.mu.Unlock()
	defer func() {
		a.nodeAutofallback.mu.Lock()
		a.nodeAutofallback.attemptCancel = nil
		a.nodeAutofallback.mu.Unlock()
	}()
	entry = a.runNodeAutofallback(attempt, now, previous, profile, eligible[selected], entry)
	a.setNodeAutofallbackEntry(entry)
}

type nodeAutofallbackIntent struct {
	base       nodeRecoveryIntent
	group      nodestore.NodeGroup
	routeIndex int
	nodeID     string
}

func (a *App) guardNodeAutofallback(ctx context.Context, intent nodeAutofallbackIntent, proofs bool) error {
	if err := a.guardNodeAutofallbackBase(ctx, intent); err != nil {
		return err
	}
	if err := a.guardFallbackPolicy(ctx, intent, proofs); err != nil {
		return err
	}
	snapshot, err := a.Nodes.Snapshot(ctx, time.Now())
	if err != nil || snapshot.Generation != intent.base.generation {
		return dataplane.ErrReviewChanged
	}
	var group nodestore.NodeGroup
	for _, current := range snapshot.Groups {
		if current.ID == intent.group.ID {
			group = current
			break
		}
	}
	if group.Mode != "fallback" || !reflect.DeepEqual(group, intent.group) || !slices.Contains(group.NodeIDs, intent.nodeID) {
		return dataplane.ErrReviewChanged
	}
	if proofs {
		for index, route := range intent.base.plan.Routes {
			nodeID := strings.TrimPrefix(route.Resolved, "sing-box:")
			if index == intent.routeIndex {
				nodeID = intent.nodeID
			}
			if !nodeRecoveryNodePresent(snapshot, nodeID, time.Now()) {
				return dataplane.ErrReviewChanged
			}
			proof, err := a.Nodes.ResolveRoute(ctx, nodeID, route.ServiceID, intent.base.profile, "", time.Time{}, time.Now())
			if err != nil || proof.Route != "sing-box:"+nodeID {
				return dataplane.ErrReviewChanged
			}
		}
	}
	return ctx.Err()
}

// The applied group, service and client scope remain the switch authority when
// the old node's feed receipt expires. Expiry permits replacing that old node,
// never dialing it, renewing its receipt or retaining it in a new plan. Every
// retained route and the replacement still require fresh origin and proof.
func (a *App) newNodeAutofallbackIntent(ctx context.Context, previous dataplane.Plan, profile string, group nodestore.NodeGroup, serviceID string) (nodeAutofallbackIntent, error) {
	base := nodeRecoveryIntent{config: a.Store.Get(), plan: previous, profile: profile}
	intent := nodeAutofallbackIntent{base: base, group: group, routeIndex: -1}
	if a.Nodes == nil || a.NodeChecker == nil || base.config.SafeMode || previous.State != "committed" || !previous.Ready || previous.SafeMode || previous.Noop ||
		previous.Revision != base.config.AppliedRevision || len(previous.Routes) == 0 || len(previous.Routes) > maxNodeRecoveryRoutes || len(previous.Adapters) != 1 || previous.Adapters[0] != "sing-box" {
		return intent, errNodeRecoveryReview
	}
	services := map[string]catalog.Service{}
	for _, service := range a.catalogSnapshot().Services {
		services[service.ID] = service
	}
	seen := map[string]bool{}
	for index, route := range previous.Routes {
		state := base.config.AppliedServices[route.ServiceID]
		service, found := services[route.ServiceID]
		if !found || seen[route.ServiceID] || !state.Enabled || selectedRoute(state) != route.Selected || !strings.HasPrefix(route.Resolved, "sing-box:node-") ||
			!sameNodeRecoveryStrings(state.Sources, route.Sources) || !nodeRecoveryServiceMatches(route, service) || !serviceHasNodeProbe(service) {
			return intent, errNodeRecoveryReview
		}
		if route.Selected != route.Resolved && route.Selected != "auto" && !strings.HasPrefix(route.Selected, "sing-box:group-") {
			return intent, errNodeRecoveryReview
		}
		if route.ServiceID == serviceID && route.Selected == "sing-box:"+group.ID {
			intent.routeIndex, intent.nodeID = index, strings.TrimPrefix(route.Resolved, "sing-box:")
		}
		seen[route.ServiceID] = true
		intent.base.services = append(intent.base.services, service)
	}
	for id, state := range base.config.AppliedServices {
		if state.Enabled && !seen[id] {
			return intent, errNodeRecoveryReview
		}
	}
	if intent.routeIndex < 0 {
		return intent, errNodeRecoveryReview
	}
	snapshot, err := a.Nodes.Snapshot(ctx, time.Now())
	if err != nil {
		return intent, err
	}
	intent.base.generation = snapshot.Generation
	return intent, a.guardNodeAutofallback(ctx, intent, false)
}

func (a *App) guardNodeAutofallbackBase(ctx context.Context, intent nodeAutofallbackIntent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	current, err := a.freshNetworkProfile(ctx)
	if err != nil || current != intent.base.profile {
		return dataplane.ErrNetworkChanged
	}
	cfg := a.Store.Get()
	if cfg.SafeMode || cfg.Revision != intent.base.config.Revision || cfg.AppliedRevision != intent.base.config.AppliedRevision || !reflect.DeepEqual(cfg.AppliedServices, intent.base.config.AppliedServices) {
		return dataplane.ErrReviewChanged
	}
	committed, exists, err := a.Dataplane.Committed()
	if err != nil || !exists || !sameNodeRecoveryPlan(committed, intent.base.plan) {
		return dataplane.ErrReviewChanged
	}
	snapshot, err := a.Nodes.Snapshot(ctx, time.Now())
	if err != nil || snapshot.Generation != intent.base.generation {
		return dataplane.ErrReviewChanged
	}
	services := map[string]catalog.Service{}
	for _, service := range a.catalogSnapshot().Services {
		services[service.ID] = service
	}
	for index, route := range intent.base.plan.Routes {
		service, exists := services[route.ServiceID]
		if !exists || !nodeRecoveryServiceMatches(route, service) || !reflect.DeepEqual(service.Probes, intent.base.services[index].Probes) {
			return errNodeRecoveryReview
		}
		nodeID := strings.TrimPrefix(route.Resolved, "sing-box:")
		present := nodeRecoveryNodePresent(snapshot, nodeID, time.Now())
		if index == intent.routeIndex {
			present = false
			for _, node := range snapshot.Nodes {
				if node.ID == nodeID && !node.Disabled {
					present = true
					break
				}
			}
		}
		if !present || !nodeRecoverySelectorOwns(snapshot, route.Selected, nodeID) {
			return errNodeRecoveryReview
		}
	}
	return ctx.Err()
}

func (a *App) runNodeAutofallback(ctx context.Context, now time.Time, previous dataplane.Plan, profile string, group nodestore.NodeGroup, entry nodeAutofallbackEntry) nodeAutofallbackEntry {
	intent, err := a.newNodeAutofallbackIntent(ctx, previous, profile, group, entry.status.ServiceID)
	if err != nil {
		return nodeAutofallbackFailure(entry, err, "")
	}
	entry.status.NodeID = intent.nodeID
	if err := a.guardNodeAutofallback(ctx, intent, false); err != nil {
		return nodeAutofallbackFailure(entry, err, "")
	}
	snapshot, err := a.Nodes.Snapshot(ctx, time.Now())
	if err != nil {
		return nodeAutofallbackFailure(entry, err, "")
	}
	expiredOriginal := !nodeRecoveryNodePresent(snapshot, intent.nodeID, time.Now())
	policy, hasPolicy := intent.base.config.ServicePolicies[entry.status.ServiceID]
	if hasPolicy && !policyAllowsNode(policy, snapshot, intent.nodeID, time.Now()) {
		expiredOriginal = true
	}
	entry.status.Trigger = ""
	if !expiredOriginal {
		result, latest, err := a.checkAndRecordNode(ctx, intent.nodeID, intent.base.services[intent.routeIndex], profile, intent.base.generation)
		checked := time.Now().UTC()
		entry.status.CheckedAt = &checked
		if err != nil {
			return nodeAutofallbackFailure(entry, err, "")
		}
		snapshot = latest
		intent.base.generation = snapshot.Generation
		if err := a.guardNodeAutofallback(ctx, intent, false); err != nil {
			return nodeAutofallbackFailure(entry, err, "")
		}
		if result.Available {
			entry.status.Failures, entry.status.Healthy = 0, false
			if previous.NetworkProfileID == profile {
				guarded := dataplane.WithReviewGuard(ctx, func(ctx context.Context) error { return a.guardNodeAutofallback(ctx, intent, true) })
				if err := a.Dataplane.CheckCommittedNodeHealth(guarded, previous); err == nil {
					entry.status.State, entry.status.Message, entry.status.Healthy = "healthy", "Текущий узел и применённый маршрут подтвердили проверки.", true
					return entry
				}
				entry.status.Trigger = "runtime-unhealthy"
			}
			// A new process/network epoch requires the same applied targets to pass
			// the ordinary transaction too, even when replacement is unnecessary.
			return a.applyNodeAutofallback(ctx, now, intent, entry, false)
		}
		if !nodeAutofallbackDefiniteFailure(result) {
			entry.status.State, entry.status.Message, entry.status.Failures = "unknown", "Проверка не дала достоверного результата. Повторим без переключения.", 0
			if result.Stage == "cleanup" {
				entry.status.State, entry.status.Message = "requires-review", "Очистка проверочного процесса требует внимания. Автозамена приостановлена."
			}
			return entry
		}
		entry.status.Failures++
		if entry.status.Failures < 2 {
			entry.status.State, entry.status.Message = "suspect", "Узел не подтвердил сервис. Повторим проверку перед заменой."
			return entry
		}
		entry.status.Failures = 2
	} else {
		entry.status.Trigger, entry.status.Failures = "origin-expired", 0
		entry.status.State, entry.status.Message = "origin-expired", "Срок данных применённого узла истёк. Проверяем свежий резерв из той же группы."
	}
	cooldown := entry.lastSwitched.Add(time.Duration(group.HoldDownSeconds) * time.Second)
	if hasPolicy {
		cooldown = entry.lastSwitched.Add(time.Duration(policy.HoldDownSeconds) * time.Second)
	}
	if !entry.lastSwitched.IsZero() && now.Before(cooldown) {
		entry.status.CooldownUntil = &cooldown
		entry.status.State, entry.status.Message = "cooldown", "Повторные отказы обнаружены. Действует заданная пауза между переключениями."
		return entry
	}
	entry.status.CooldownUntil = nil
	candidates := make([]string, 0, len(group.NodeIDs))
	for _, nodeID := range group.NodeIDs {
		if nodeID != entry.status.NodeID && nodeRecoveryNodePresent(snapshot, nodeID, time.Now()) && (!hasPolicy || policyAllowsNode(policy, snapshot, nodeID, time.Now()) && (policy.PinnedNodeID == "" || policy.PinFallback || nodeID == policy.PinnedNodeID)) {
			candidates = append(candidates, nodeID)
		}
	}
	if group.PreferredNodeID != "" {
		slices.SortStableFunc(candidates, func(a, b string) int {
			if a == group.PreferredNodeID {
				return -1
			}
			if b == group.PreferredNodeID {
				return 1
			}
			return strings.Compare(a, b)
		})
	}
	limit := min(nodeAutofallbackCandidates, len(candidates))
	for offset := 0; offset < limit; offset++ {
		candidate := candidates[(entry.cursor+offset)%len(candidates)]
		intent.nodeID = candidate
		if err := a.guardNodeAutofallback(ctx, intent, false); err != nil {
			return nodeAutofallbackFailure(entry, err, "")
		}
		entry.status.State, entry.status.CandidateID, entry.status.Message = "checking-reserve", candidate, "Проверяем резервный узел из применённой группы."
		a.setNodeAutofallbackEntry(entry)
		result, latest, err := a.checkAndRecordNode(ctx, candidate, intent.base.services[intent.routeIndex], profile, intent.base.generation)
		checked := time.Now().UTC()
		entry.status.CheckedAt = &checked
		if err != nil {
			return nodeAutofallbackFailure(entry, err, "")
		}
		intent.base.generation = latest.Generation
		if err := a.guardNodeAutofallback(ctx, intent, false); err != nil {
			return nodeAutofallbackFailure(entry, err, "")
		}
		if result.Available {
			entry.cursor = 0
			return a.applyNodeAutofallback(ctx, now, intent, entry, true)
		}
		if result.Stage == "cleanup" {
			return nodeAutofallbackFailure(entry, errNodeRecoveryReview, "")
		}
	}
	entry.cursor += limit
	entry.status.State, entry.status.Message, entry.status.CandidateID = "no-working-reserve", "Рабочий резерв пока не найден. Следующая попытка проверит до трёх узлов этой группы.", ""
	entry.status.NextCheckAt = now.Add(3 * time.Minute)
	return entry
}

func nodeAutofallbackDefiniteFailure(result dataplane.NodeCheckResult) bool {
	if result.Available || result.Verdict == evidence.VerdictInconclusive || result.Verdict == evidence.VerdictPass || result.Verdict == "" {
		return false
	}
	switch result.Stage {
	case "transport", "egress", "service":
		return true
	case "service_ip":
		return result.ErrorCode == "node-service-ip-path-failed"
	default:
		return false
	}
}

func (a *App) applyNodeAutofallback(ctx context.Context, now time.Time, intent nodeAutofallbackIntent, entry nodeAutofallbackEntry, replacement bool) nodeAutofallbackEntry {
	// Revalidate any retained node whose proof has expired. Never replace it,
	// and never apply a partial plan if another applied service fails.
	for index, route := range intent.base.plan.Routes {
		if err := a.guardNodeAutofallback(ctx, intent, false); err != nil {
			return nodeAutofallbackFailure(entry, err, "")
		}
		nodeID := strings.TrimPrefix(route.Resolved, "sing-box:")
		if index == intent.routeIndex {
			nodeID = intent.nodeID
		}
		if _, err := a.Nodes.ResolveRoute(ctx, nodeID, route.ServiceID, intent.base.profile, "", time.Time{}, time.Now()); err == nil {
			continue
		}
		result, snapshot, err := a.checkAndRecordNode(ctx, nodeID, intent.base.services[index], intent.base.profile, intent.base.generation)
		if err != nil {
			return nodeAutofallbackFailure(entry, err, "")
		}
		intent.base.generation = snapshot.Generation
		if !result.Available {
			return nodeAutofallbackFailure(entry, nodestore.ErrRouteProof, "")
		}
	}
	if err := a.guardNodeAutofallback(ctx, intent, true); err != nil {
		return nodeAutofallbackFailure(entry, err, "")
	}
	build := intent.base
	build.plan.Routes = append([]dataplane.Route(nil), intent.base.plan.Routes...)
	build.plan.Routes[intent.routeIndex].Resolved = "sing-box:" + intent.nodeID
	plan, err := a.buildNodeRecoveryPlan(build)
	if err != nil || !plan.Ready {
		return nodeAutofallbackFailure(entry, errNodeRecoveryReview, "")
	}
	entry.status.State, entry.status.Message = "applying", "Применяем проверенный узел с возможностью отката."
	if replacement {
		if policy, exists := intent.base.config.ServicePolicies[entry.status.ServiceID]; exists {
			if err := a.reserveFallbackSwitch(ctx, policy, now); err != nil {
				entry.status.State, entry.status.Message, entry.status.Healthy = "backoff", "Лимит замен или журнал автоматики не разрешает новое переключение.", false
				entry.status.NextCheckAt = now.Add(time.Hour)
				return entry
			}
		}
	}
	a.setNodeAutofallbackEntry(entry)
	ctx = dataplane.WithReviewGuard(ctx, func(ctx context.Context) error { return a.guardNodeAutofallback(ctx, intent, true) })
	execution, err := a.Dataplane.Apply(ctx, plan, nil)
	if err != nil || execution.State != "committed" {
		return nodeAutofallbackFailure(entry, err, execution.State)
	}
	entry.status.NodeID, entry.status.CandidateID, entry.status.Failures, entry.status.Healthy = intent.nodeID, "", 0, true
	entry.status.State, entry.status.Message = "revalidated", "Применённый узел повторно проверен и восстановлен в текущей сети."
	if replacement {
		entry.lastSwitched = now
		cooldown := now.Add(time.Duration(intent.group.HoldDownSeconds) * time.Second)
		entry.status.CooldownUntil = &cooldown
		entry.status.State, entry.status.Message = "switched", "Сервис переключён на проверенный резервный узел. Проверьте его на выбранном устройстве."
	}
	entry.key = execution.PlanID + "/" + intent.base.profile + "/" + strconv.FormatUint(intent.base.config.Revision, 10) + "/" + intent.group.UpdatedAt.Format(time.RFC3339Nano)
	return entry
}

func nodeAutofallbackFailure(entry nodeAutofallbackEntry, err error, executionState string) nodeAutofallbackEntry {
	entry.status.Healthy, entry.status.CandidateID, entry.status.Failures = false, "", 0
	entry.status.State, entry.status.Message = "unknown", "Проверка или применение не завершены. Работоспособность маршрута не подтверждена."
	if executionState == "rollback-failed" {
		entry.status.State, entry.status.Message = "requires-review", "Откат не подтверждён. Автозамена остановлена; проверьте состояние маршрута."
	} else if errors.Is(err, errNodeRecoveryReview) || errors.Is(err, dataplane.ErrReviewChanged) {
		entry.status.State, entry.status.Message = "requires-review", "Состав или область маршрута требуют повторного просмотра. Автозамена поддерживает полный план до восьми сервисов через узлы Sing-box."
	} else if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		entry.status.State, entry.status.Message = "canceled", "Автоматическая проверка остановлена."
	} else if executionState == "rolled-back" {
		entry.status.State, entry.status.Message = "rolled-back", "Новый узел не прошёл применение. Выполнен откат; работоспособность прежнего маршрута требует проверки."
	}
	return entry
}
