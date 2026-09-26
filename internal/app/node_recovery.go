package app

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/nodestore"
)

const maxNodeRecoveryRoutes = 8
const maxNodeRecoveryAttempts = 3

var errNodeRecoveryReview = errors.Join(dataplane.ErrReviewChanged, errors.New("applied node recovery requires review"))

// This DTO contains no node material, probe output, endpoint or raw errors.
type nodeRecoveryStatus struct {
	State         string    `json:"state"`
	PlanID        string    `json:"plan_id,omitempty"`
	Stage         string    `json:"stage,omitempty"`
	Attempt       int       `json:"attempt"`
	NextAttemptAt time.Time `json:"next_attempt_at,omitempty"`
	Message       string    `json:"message"`
}

type nodeRecoveryState struct {
	once   sync.Once
	mu     sync.Mutex
	key    string
	status nodeRecoveryStatus
	done   chan struct{}
	update *selfUpdateNodeRecovery
}

func (a *App) nodeRecoverySnapshot() nodeRecoveryStatus {
	a.nodeRecovery.mu.Lock()
	defer a.nodeRecovery.mu.Unlock()
	status := a.nodeRecovery.status
	if status.State == "" {
		status.State = "idle"
	}
	return status
}

func (a *App) setNodeRecoveryStatus(status nodeRecoveryStatus) {
	a.nodeRecovery.mu.Lock()
	a.nodeRecovery.status = status
	a.nodeRecovery.mu.Unlock()
}

// StartNodeRecovery must be called after the HTTP listener is ready. Shutdown
// waits for checker cleanup / transactional rollback before releasing admission.
func (a *App) StartNodeRecovery(ctx context.Context) {
	a.nodeRecovery.once.Do(func() {
		a.nodeRecovery.mu.Lock()
		a.nodeRecovery.done = make(chan struct{})
		done := a.nodeRecovery.done
		a.nodeRecovery.mu.Unlock()
		go func() {
			defer close(done)
			timer := time.NewTimer(time.Second)
			defer timer.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-timer.C:
					a.nodeRecoveryRound(ctx, time.Now())
					timer.Reset(30 * time.Second)
				}
			}
		}()
	})
}

func (a *App) WaitNodeRecovery(ctx context.Context) error {
	a.nodeRecovery.mu.Lock()
	done := a.nodeRecovery.done
	a.nodeRecovery.mu.Unlock()
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

// The cheap observation uses shared admission; only a stale committed plan
// needs exclusive admission. Busy user operations are never interrupted.
func (a *App) nodeRecoveryRound(ctx context.Context, now time.Time) {
	if a.Store == nil || a.Dataplane == nil {
		return
	}
	release, err := a.nodeRecoveryAdmission(ctx, false)
	if err != nil {
		return
	}
	plan, exists, planErr := a.Dataplane.Committed()
	if a.Store.Get().ServiceControl.Stopped {
		release()
		return
	}
	if planErr != nil || !exists || !plan.RequiresNetworkProof() {
		release()
		return
	}
	profile, profileErr := a.freshNetworkProfile(ctx)
	release()
	if ctx.Err() != nil {
		return
	}
	if profileErr == nil && profile == plan.NetworkProfileID {
		status := a.nodeRecoverySnapshot()
		if status.PlanID != plan.PlanID || status.State != "recovered" {
			a.setNodeRecoveryStatus(nodeRecoveryStatus{State: "idle", PlanID: plan.PlanID})
		}
		return // Existing runtime authority is unchanged; TTL is checked on writes.
	}
	if profileErr != nil {
		status := a.nodeRecoverySnapshot()
		if status.PlanID != plan.PlanID {
			status = nodeRecoveryStatus{PlanID: plan.PlanID}
		}
		if status.State != "requires-review" {
			status.State, status.Message = "network-stale", "Сеть пока не подтверждена. Применённый маршрут не переключается; проверка повторится автоматически."
		}
		a.setNodeRecoveryStatus(status)
		return
	}
	key := plan.PlanID + "/" + profile
	a.nodeRecovery.mu.Lock()
	if a.nodeRecovery.key != key {
		a.nodeRecovery.key = key
		a.nodeRecovery.status = nodeRecoveryStatus{PlanID: plan.PlanID}
	}
	status := a.nodeRecovery.status
	if status.Attempt >= maxNodeRecoveryAttempts || status.State == "requires-review" || now.Before(status.NextAttemptAt) {
		a.nodeRecovery.mu.Unlock()
		return
	}
	a.nodeRecovery.mu.Unlock()
	// The recovery re-reads all authority after acquiring this lease.
	release, err = a.nodeRecoveryAdmission(ctx, true)
	if err != nil {
		return
	}
	defer release()
	status = nodeRecoveryStatus{State: "revalidating", PlanID: plan.PlanID, Stage: "checks", Attempt: status.Attempt + 1,
		Message: "Повторно проверяются только уже применённые узлы и сервисы. Черновики сохраняются."}
	a.setNodeRecoveryStatus(status)
	attemptCtx, cancel := context.WithTimeout(ctx, defaultDataplaneApplyTimeout)
	execution, err := a.recoverAppliedNodes(attemptCtx, plan, profile)
	cancel()
	status.Stage = ""
	if err == nil {
		status.State, status.PlanID = "recovered", execution.PlanID
		status.Message = "Применённые маршруты повторно проверены и восстановлены. Проверьте сервис на выбранном устройстве."
	} else if errors.Is(err, errNodeRecoveryReview) || status.Attempt >= maxNodeRecoveryAttempts || execution.State == "rollback-failed" {
		status.State = "requires-review"
		status.Message = "Автоматическое восстановление не подтверждено. Проверьте применённые узлы и просмотрите маршрут; другой узел автоматически не выбирается."
	} else {
		status.State = "network-stale"
		status.NextAttemptAt = now.Add(time.Duration(status.Attempt*status.Attempt) * time.Minute)
		status.Message = "Повторная проверка не завершена. Сохранившийся маршрут не считается подтверждённым; будет ограниченная повторная попытка."
	}
	a.setNodeRecoveryStatus(status)
}

type nodeRecoveryIntent struct {
	config     config.Config
	plan       dataplane.Plan
	services   []catalog.Service
	generation uint64
	profile    string
}

// Caller owns Operations.Exclusive for checks, writes and all cleanup. The
// prior committed configuration authorizes ONLY the identical applied targets;
// fresh exact proofs authorize execution in the new network epoch.
func (a *App) recoverAppliedNodes(ctx context.Context, previous dataplane.Plan, profile string) (dataplane.Execution, error) {
	intent, err := a.nodeRecoveryIntent(ctx, previous, profile)
	if err != nil {
		return dataplane.Execution{}, err
	}
	for index, route := range intent.plan.Routes {
		if err := a.guardNodeRecoveryIntent(ctx, intent, false); err != nil {
			return dataplane.Execution{}, err
		}
		if route.Resolved == "nfqws2" {
			continue // The full transaction still validates and checks NFQWS2.
		}
		result, snapshot, err := a.checkAndRecordNode(ctx, strings.TrimPrefix(route.Resolved, "sing-box:"), intent.services[index], profile, intent.generation)
		if err != nil {
			return dataplane.Execution{}, err
		}
		intent.generation = snapshot.Generation
		if !result.Available {
			return dataplane.Execution{}, nodestore.ErrRouteProof
		}
	}
	if err := a.guardNodeRecoveryIntent(ctx, intent, true); err != nil {
		return dataplane.Execution{}, err
	}
	plan, err := a.buildNodeRecoveryPlan(intent)
	if err != nil {
		return dataplane.Execution{}, err
	}
	if !plan.Ready {
		return dataplane.Execution{}, errNodeRecoveryReview
	}
	status := a.nodeRecoverySnapshot()
	status.Stage = "transaction"
	a.setNodeRecoveryStatus(status)
	ctx = dataplane.WithReviewGuard(ctx, func(ctx context.Context) error { return a.guardNodeRecoveryIntent(ctx, intent, true) })
	// Configuration intent is unchanged. In particular, do not call the node
	// selection commit, which would overwrite a desired draft and bump revision.
	return a.applyDataplane(ctx, plan, nil)
}

func (a *App) nodeRecoveryIntent(ctx context.Context, previous dataplane.Plan, profile string) (nodeRecoveryIntent, error) {
	intent := nodeRecoveryIntent{config: a.Store.Get(), plan: previous, profile: profile}
	if a.Nodes == nil || a.NodeChecker == nil || intent.config.SafeMode || previous.State != "committed" || !previous.Ready || previous.SafeMode || previous.Noop || previous.Revision != intent.config.AppliedRevision ||
		len(previous.Routes) == 0 || len(previous.Routes) > maxNodeRecoveryRoutes || !nodeRecoveryAdaptersSupported(previous) {
		return intent, errNodeRecoveryReview
	}
	// Recover the entire applied plan, including unchanged NFQWS2 routes.
	// Other mixed adapters still require a reviewed plan; never drop a subset.
	services := map[string]catalog.Service{}
	for _, service := range a.catalogSnapshot().Services {
		services[service.ID] = service
	}
	seen := map[string]bool{}
	for _, route := range previous.Routes {
		state := intent.config.AppliedServices[route.ServiceID]
		service, ok := services[route.ServiceID]
		if !ok || seen[route.ServiceID] || !state.Enabled || selectedRoute(state) != route.Selected ||
			!sameNodeRecoveryStrings(state.Sources, route.Sources) || !nodeRecoveryServiceMatches(route, service) || !serviceHasNodeProbe(service) {
			return intent, errNodeRecoveryReview
		}
		if route.Selected != route.Resolved && route.Selected != "auto" && !(route.Resolved != "nfqws2" && strings.HasPrefix(route.Selected, "sing-box:group-")) {
			return intent, errNodeRecoveryReview
		}
		seen[route.ServiceID] = true
		intent.services = append(intent.services, service)
	}
	for id, service := range intent.config.AppliedServices {
		if service.Enabled && !seen[id] {
			return intent, errNodeRecoveryReview
		}
	}
	snapshot, err := a.Nodes.Snapshot(ctx, time.Now())
	if err != nil {
		return intent, err
	}
	intent.generation = snapshot.Generation
	if err := a.guardNodeRecoveryIntent(ctx, intent, false); err != nil {
		return intent, err
	}
	return intent, nil
}

func nodeRecoveryAdaptersSupported(plan dataplane.Plan) bool {
	used := map[string]bool{}
	for _, route := range plan.Routes {
		switch {
		case strings.HasPrefix(route.Resolved, "sing-box:node-"):
			used["sing-box"] = true
		case route.Resolved == "nfqws2":
			used["nfqws2"] = true
		default:
			return false
		}
	}
	if !used["sing-box"] || len(plan.Adapters) != len(used) {
		return false
	}
	for _, id := range plan.Adapters {
		if !used[id] {
			return false
		}
		delete(used, id)
	}
	return len(used) == 0
}

func (a *App) guardNodeRecoveryIntent(ctx context.Context, intent nodeRecoveryIntent, proofs bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := a.guardSelfUpdateNodeRecovery(ctx); err != nil {
		return err
	}
	current, err := a.freshNetworkProfile(ctx)
	if err != nil || current != intent.profile {
		return dataplane.ErrNetworkChanged
	}
	cfg := a.Store.Get()
	if cfg.SafeMode || cfg.Revision != intent.config.Revision || cfg.AppliedRevision != intent.config.AppliedRevision || !reflect.DeepEqual(cfg.AppliedServices, intent.config.AppliedServices) {
		return dataplane.ErrReviewChanged
	}
	committed, exists, err := a.Dataplane.Committed()
	if err != nil || !exists || !sameNodeRecoveryPlan(committed, intent.plan) {
		return dataplane.ErrReviewChanged
	}
	services := map[string]catalog.Service{}
	for _, service := range a.catalogSnapshot().Services {
		services[service.ID] = service
	}
	snapshot, err := a.Nodes.Snapshot(ctx, time.Now())
	if err != nil || snapshot.Generation != intent.generation {
		return dataplane.ErrReviewChanged
	}
	for index, route := range intent.plan.Routes {
		service, ok := services[route.ServiceID]
		if !ok || !nodeRecoveryServiceMatches(route, service) || !reflect.DeepEqual(service.Probes, intent.services[index].Probes) {
			return errNodeRecoveryReview
		}
		if route.Resolved == "nfqws2" {
			continue
		}
		nodeID := strings.TrimPrefix(route.Resolved, "sing-box:")
		if !nodeRecoveryNodePresent(snapshot, nodeID, time.Now()) || !nodeRecoverySelectorOwns(snapshot, route.Selected, nodeID) {
			return errNodeRecoveryReview
		}
		if proofs {
			proof, err := a.Nodes.ResolveRoute(ctx, nodeID, route.ServiceID, intent.profile, "", time.Time{}, time.Now())
			if err != nil || proof.Route != route.Resolved {
				return dataplane.ErrReviewChanged
			}
		}
	}
	// Scope equality above includes current source enrichment. Missing/expired
	// enrichment that contributed targets therefore refuses recovery. Do not
	// require every enabled list to have a receipt: a never-downloaded list has
	// contributed no targets, and cannot invalidate the identical committed
	// catalog scope. Unlike AUTO switching, this path cannot add/drop targets.
	return a.guardSelfUpdateNodeRecovery(ctx)
}

func nodeRecoveryNodePresent(snapshot nodestore.Snapshot, id string, now time.Time) bool {
	for _, node := range snapshot.Nodes {
		if node.ID != id || node.Disabled {
			continue
		}
		for _, origin := range node.Origins {
			if !now.Before(origin.ReceivedAt) && now.Before(origin.ExpiresAt) {
				return true
			}
		}
	}
	return false
}

func nodeRecoverySelectorOwns(snapshot nodestore.Snapshot, selected, nodeID string) bool {
	if selected == "sing-box:"+nodeID || selected == "auto" {
		return true
	}
	for _, group := range snapshot.Groups {
		if selected == "sing-box:"+group.ID {
			return slices.Contains(group.NodeIDs, nodeID) && (group.Mode != "manual" || group.PreferredNodeID == nodeID)
		}
	}
	return false
}

func sameNodeRecoveryPlan(a, b dataplane.Plan) bool {
	// Compare the full persisted plan, not merely user-visible IDs that could
	// remain unchanged after a journal replacement or restore.
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return string(left) == string(right)
}

func sameNodeRecoveryStrings(a, b []string) bool {
	return reflect.DeepEqual(mergeUniqueStrings(nil, sortedRecoveryStrings(a)), mergeUniqueStrings(nil, sortedRecoveryStrings(b)))
}

func sortedRecoveryStrings(values []string) []string {
	values = append([]string(nil), values...)
	for index := range values {
		values[index] = strings.TrimSpace(values[index])
	}
	slices.Sort(values)
	return values
}

func nodeRecoveryServiceMatches(route dataplane.Route, service catalog.Service) bool {
	return route.ServiceID == service.ID && route.ProbeURL == service.ProbeURL && sameNodeRecoveryStrings(route.Domains, service.Domains) &&
		sameNodeRecoveryStrings(route.CIDRs, service.CIDRs) && sameNodeRecoveryStrings(route.SourceRefs, service.SourceRefs)
}

func (a *App) buildNodeRecoveryPlan(intent nodeRecoveryIntent) (dataplane.Plan, error) {
	var engines []dataplane.Engine
	for _, option := range a.nodeRouteOptions() {
		if slices.Contains(intent.plan.Adapters, option.ID) {
			engines = append(engines, dataplane.Engine{ID: option.ID, Installed: option.Installed, Configured: option.ID == "sing-box" || option.Configured, Running: option.Running, Activatable: a.Dataplane.Capable(option.ID), Canary: a.Dataplane.CanaryCapable(option.ID)})
		}
	}
	conflicts := []dataplane.ResourceConflict{}
	if a.EngineLab != nil {
		for _, conflict := range a.EngineLab.Inspect().ApplyConflicts(intent.plan.Adapters) {
			conflicts = append(conflicts, dataplane.ResourceConflict{Kind: conflict.Kind, Value: conflict.Value, Engines: conflict.Engines, SystemUse: conflict.SystemUse})
		}
	}
	host := dataplane.DiscoverHost()
	if a.DataplaneHost != nil {
		host = a.DataplaneHost()
	}
	// Copy exact applied targets; do not resolve AUTO/group or load any draft.
	routes := append([]dataplane.Route(nil), intent.plan.Routes...)
	return dataplane.Build(dataplane.Input{NetworkProfileID: intent.profile, Revision: intent.config.AppliedRevision, SafeMode: intent.config.SafeMode,
		Routes: routes, Engines: engines, ResourceConflicts: conflicts, Host: host})
}
