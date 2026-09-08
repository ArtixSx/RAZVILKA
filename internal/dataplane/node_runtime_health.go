package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"time"
)

// CheckCommittedNodeHealth checks the actual committed Sing-box runtime. An
// isolated node check proves a remote candidate, not the live process/TUN.
// This method never reconciles, starts or stops runtime; callers may repair a
// failed check through a freshly guarded Apply transaction with rollback.
func (m *Manager) CheckCommittedNodeHealth(ctx context.Context, expected Plan) error {
	if m == nil || m.StateRoot == "" || expected.State != "committed" || expected.SafeMode || !expected.Ready || expected.Noop ||
		!slices.Contains(expected.Adapters, "sing-box") || !expected.RequiresNetworkProof() ||
		!regexp.MustCompile(`^dp-[0-9a-f]{16}$`).MatchString(expected.PlanID) {
		return ErrReviewChanged
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
	if err := verify(); err != nil {
		return err
	}
	adapter, exists := m.adapter("sing-box")
	if !exists {
		return errors.New("committed node runtime adapter is unavailable")
	}
	var healthErr error
	if committed, ok := adapter.(interface {
		CommittedNodeHealth(context.Context, Plan) error
	}); ok {
		healthErr = committed.CommittedNodeHealth(ctx, expected)
	} else {
		root := filepath.Join(m.StateRoot, "transactions", expected.PlanID, "sing-box")
		healthErr = adapter.Health(ctx, expected, root)
	}
	if healthErr != nil {
		return healthErr
	}
	return verify()
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
	return a.healthState(ctx, plan, state)
}
