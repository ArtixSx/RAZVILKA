package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/routekind"
)

// committedNodeHealthEngines selects only exact resolved node executors. An
// engine profile/default cell in the same plan grants no node health evidence.
func committedNodeHealthEngines(plan Plan) ([]string, error) {
	adapters := make(map[string]bool, len(plan.Adapters))
	for _, id := range plan.Adapters {
		if adapters[id] {
			return nil, ErrReviewChanged
		}
		adapters[id] = true
	}
	engines, routed := map[string]bool{}, map[string]bool{}
	for _, route := range plan.Routes {
		selectedEngine, selectedTarget, selected, err := committedNodeHealthReference(route.Selected)
		if err != nil {
			return nil, err
		}
		engine, target, resolved, err := committedNodeHealthReference(route.Resolved)
		if err != nil {
			return nil, err
		}
		if selected && (!resolved || selectedEngine != engine ||
			strings.HasPrefix(selectedTarget, "node-") && selectedTarget != target) {
			return nil, ErrReviewChanged
		}
		routed[adapterID(route.Resolved)] = true
		if resolved {
			if !strings.HasPrefix(target, "node-") || !adapters[engine] {
				return nil, ErrReviewChanged
			}
			engines[engine] = true
		}
	}
	for _, id := range []string{"sing-box", "xray"} {
		if adapters[id] && !routed[id] {
			return nil, ErrReviewChanged
		}
	}
	if len(engines) == 0 {
		return nil, ErrReviewChanged
	}
	ordered := make([]string, 0, len(engines))
	for id := range engines {
		ordered = append(ordered, id)
	}
	slices.Sort(ordered)
	return ordered, nil
}

func committedNodeHealthReference(ref string) (engine, target string, node bool, err error) {
	if engine, target, ok := routekind.ParseNodeRoute(ref); ok {
		return engine, target, true, nil
	}
	// Classify suspicious references without canonicalizing them into grants.
	// Profiles such as sing-box:home remain ordinary non-node plan cells.
	normalized := strings.ToLower(strings.TrimSpace(ref))
	_, suffix, found := strings.Cut(normalized, ":")
	if !found {
		suffix = normalized
	}
	suffix = strings.TrimSpace(suffix)
	if suffix == "node" || suffix == "group" || strings.HasPrefix(suffix, "node-") || strings.HasPrefix(suffix, "group-") {
		return "", "", false, ErrReviewChanged
	}
	return "", "", false, nil
}

// CheckCommittedNodeHealth checks each actual committed node runtime. An
// isolated node check proves a remote candidate, not the live process/TUN.
// This method never reconciles, starts or stops runtime; callers may repair a
// failed check through a freshly guarded Apply transaction with rollback.
func (m *Manager) CheckCommittedNodeHealth(ctx context.Context, expected Plan) error {
	if m == nil || m.StateRoot == "" || expected.State != "committed" || expected.SafeMode || !expected.Ready || expected.Noop ||
		!expected.RequiresNetworkProof() ||
		!validPlanID(expected.PlanID) {
		return ErrReviewChanged
	}
	engines, err := committedNodeHealthEngines(expected)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := m.beginOperation(ctx); err != nil {
		return err
	}
	defer m.endOperation()
	verify := func() error {
		committed, exists, err := m.committedLocked()
		if err != nil || !exists {
			return ErrReviewChanged
		}
		left, _ := json.Marshal(committed)
		right, _ := json.Marshal(expected)
		if string(left) != string(right) {
			return ErrReviewChanged
		}
		return m.checkPlanNetwork(ctx, expected)
	}
	for _, id := range engines {
		if err := verify(); err != nil {
			return err
		}
		adapter, exists := m.adapter(id)
		if !exists || adapter == nil || adapter.ID() != id {
			return errors.New("committed node runtime adapter is unavailable")
		}
		if id == "xray" {
			owned, ok := adapter.(*ProxyTunnelAdapter)
			if !ok || owned == nil || !owned.NodeRouteVerificationCapable() {
				return errors.New("committed Xray node runtime verifier is unavailable")
			}
		}
		var healthErr error
		if committed, ok := adapter.(interface {
			CommittedNodeHealth(context.Context, Plan) error
		}); ok {
			healthErr = committed.CommittedNodeHealth(ctx, expected)
		} else {
			// Preserve the supported legacy Sing-box adapter contract only.
			root := filepath.Join(m.StateRoot, "transactions", expected.PlanID, id)
			healthErr = adapter.Health(ctx, expected, root)
		}
		if healthErr != nil {
			return healthErr
		}
		if err := verify(); err != nil {
			return err
		}
	}
	return nil
}

// RefreshPolicy updates the live policy without rewriting the original staged
// transaction. Validate that current policy so ordinary DNS refresh cannot make
// a healthy runtime look stale and cause repeated transactional restarts.
func (a *ProxyTunnelAdapter) CommittedNodeHealth(ctx context.Context, plan Plan) error {
	if err := a.checkPlanNetwork(ctx, plan); err != nil {
		return err
	}
	state, exists, err := a.loadPolicy()
	if err != nil {
		return err
	}
	if !exists || !regularFile(a.engineConfigPath()) || !regularFile(a.sidecarConfigPath()) {
		return errors.New("committed node runtime state is missing")
	}
	if state.Interface != a.Interface || state.Table != a.Table || state.PriorityBase != a.Priority || len(state.Prefixes) == 0 || len(effectivePolicyRules(state))+len(state.Exclusions) > maxPolicyPrefixes {
		return errors.New("invalid committed node policy ownership")
	}
	allowedSources := make(map[string]bool)
	for _, route := range plan.Routes {
		if adapterID(route.Resolved) != a.ID() {
			continue
		}
		if len(route.Sources) == 0 {
			allowedSources[""] = true
		}
		for _, source := range route.Sources {
			allowedSources[source] = true
		}
	}
	observedSources := make(map[string]bool)
	for _, rule := range effectivePolicyRules(state) {
		if !allowedSources[rule.Source] {
			return errors.New("committed node client scope differs from applied plan")
		}
		observedSources[rule.Source] = true
	}
	if len(observedSources) != len(allowedSources) {
		return errors.New("committed node client scope is incomplete")
	}
	for _, value := range state.Exclusions {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.Addr().IsGlobalUnicast() || prefix.Addr().IsPrivate() || prefix.Addr().IsLoopback() || prefix.Addr().IsLinkLocalUnicast() || prefix.Bits() != prefix.Addr().BitLen() {
			return errors.New("invalid committed node endpoint exclusion")
		}
	}
	if err := a.verifyCommittedReceipt(ctx, state); err != nil {
		return err
	}
	return a.healthState(ctx, plan, state)
}
