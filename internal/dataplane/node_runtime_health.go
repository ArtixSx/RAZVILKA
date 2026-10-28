package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"path/filepath"
	"reflect"
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
	if a.xrayPlanDispatch {
		view, frozen, err := a.dispatchCurrentXrayPlan(ctx, plan)
		if err != nil {
			return err
		}
		if !view.scopedXray {
			return ErrNodeTUNProofRequired
		}
		return view.CommittedNodeHealth(ctx, frozen)
	}
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
	if err := a.verifyCommittedNodeClientScope(ctx, plan, state); err != nil {
		return err
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
	if err := a.healthState(ctx, plan, state); err != nil {
		return err
	}
	if a.committedNodeAllLAN(plan) {
		current, exists, err := a.loadPolicy()
		if err != nil || !exists || !reflect.DeepEqual(current, state) {
			return errors.Join(ErrReviewChanged, err)
		}
		if err := a.verifyCommittedReceipt(ctx, state); err != nil {
			return err
		}
		return a.checkPlanNetwork(ctx, plan)
	}
	return nil
}

func (a *ProxyTunnelAdapter) committedXrayAllLAN(plan Plan) bool {
	if a.ID() != "xray" || !a.scopedXray || !a.nodeRouterVerifier {
		return false
	}
	for _, route := range plan.Routes {
		if adapterID(route.Resolved) == a.ID() && len(route.Sources) == 0 {
			return true
		}
	}
	return false
}

// Sing-box uses the same physical LAN expansion during Stage. Only an exact
// node plan with its configured materializer gets that recorded-scope check;
// a profile/default route cannot grant all-LAN node authority. Xray keeps its
// original scoped/owned-verifier requirements unchanged.
func (a *ProxyTunnelAdapter) committedNodeAllLAN(plan Plan) bool {
	if a.committedXrayAllLAN(plan) {
		return true
	}
	if a.ID() != "sing-box" || a.NodeRoutes == nil || a.FreshProfile == nil || a.Configs == nil || a.Processes == nil ||
		a.Interface != "rz-sing" || a.Table != 203 || a.Priority != 22000 {
		return false
	}
	allLAN := false
	for _, route := range plan.Routes {
		if adapterID(route.Resolved) != a.ID() {
			continue
		}
		engine, target, exact := routekind.ParseNodeRoute(route.Resolved)
		if !exact || engine != a.ID() || !strings.HasPrefix(target, "node-") {
			return false
		}
		if len(route.Sources) == 0 {
			allLAN = true
		}
	}
	return allLAN
}

// Health validates the recorded scope; a newly connected bridge is not new
// authority. Recompile only those recorded rules, never an empty-source plan
// which would discover and append new LAN prefixes during a health poll.
func (a *ProxyTunnelAdapter) verifyCommittedNodeClientScope(ctx context.Context, plan Plan, state PolicyState) error {
	allLAN := a.committedNodeAllLAN(plan)
	allowed, observed := map[string]bool{}, map[string]bool{}
	for _, route := range plan.Routes {
		if adapterID(route.Resolved) != a.ID() {
			continue
		}
		if len(route.Sources) == 0 && !allLAN {
			allowed[""] = true
		}
		for _, source := range route.Sources {
			allowed[source] = true
		}
	}
	networks := map[bool][]proxyLANPrefix{}
	for _, rule := range effectivePolicyRules(state) {
		if !allowed[rule.Source] {
			source, err := netip.ParsePrefix(rule.Source)
			if !allLAN || err != nil || source != source.Masked() || !privateLANPrefix(source) {
				return errors.New("committed node client scope differs from applied plan")
			}
			v6 := source.Addr().Is6()
			lan, known := networks[v6]
			if !known {
				lan, err = a.connectedLANPrefixes(ctx, v6)
				if err != nil {
					return err
				}
				networks[v6] = lan
			}
			connected := false
			for _, network := range lan {
				if network.prefix == source && (rule.Ingress == "" || rule.Ingress == network.ingress) {
					connected = true
					break
				}
			}
			if !connected {
				return errors.New("committed node LAN prefix is no longer on its physical bridge")
			}
		}
		observed[rule.Source] = true
	}
	for source := range allowed {
		covered := observed[source]
		if !covered && allLAN {
			wanted, err := netip.ParsePrefix(source)
			if err == nil {
				for recorded := range observed {
					p, err := netip.ParsePrefix(recorded)
					if err == nil && p.Bits() <= wanted.Bits() && p.Contains(wanted.Addr()) {
						covered = true
						break
					}
				}
			}
		}
		if !covered {
			return errors.New("committed node client scope is incomplete")
		}
	}
	if !allLAN && len(observed) != len(allowed) || allLAN && len(observed) == 0 {
		return errors.New("committed node client scope is incomplete")
	}
	if allLAN {
		if err := a.verifyCommittedNodeRuleTuples(ctx, plan, state); err != nil {
			return err
		}
		current, err := a.compileForwarding(ctx, state)
		if err != nil {
			return err
		}
		if state.Forwarding == nil || !reflect.DeepEqual(current, state.Forwarding) {
			return errors.New("committed node LAN forwarding differs from its recorded physical scope")
		}
		return a.checkPlanNetwork(ctx, plan)
	}
	return nil
}

// Canonical intent keeps each destination/ingress tied to its own source
// grant. An all-LAN route for A must never broaden a selected-only route B.
func (a *ProxyTunnelAdapter) verifyCommittedNodeRuleTuples(ctx context.Context, plan Plan, state PolicyState) error {
	for _, route := range plan.Routes {
		if adapterID(route.Resolved) == a.ID() && len(route.Domains) != 0 {
			return ErrProxyDomainAuthority
		}
	}
	prefixes, intent, err := resolvePolicyRules(ctx, plan, a.ID(), nil)
	if err != nil {
		return err
	}
	recordedPrefixes := slices.Clone(state.Prefixes)
	slices.Sort(recordedPrefixes)
	if !slices.Equal(prefixes, recordedPrefixes) {
		return errors.New("committed node destination scope differs from applied plan")
	}
	actual := effectivePolicyRules(state)
	expected := map[PolicyRule]bool{}
	for _, rule := range intent {
		if rule.Source != "" {
			expected[rule] = true
			continue
		}
		found := false
		for _, recorded := range actual {
			if recorded.Destination == rule.Destination && recorded.Ingress == rule.Ingress {
				expanded := rule
				expanded.Source = recorded.Source
				expected[expanded] = true
				found = true
			}
		}
		if !found {
			return errors.New("committed node all-LAN destination scope is incomplete")
		}
	}
	if len(actual) != len(expected) {
		return errors.New("committed node source/destination scope differs from applied plan")
	}
	for _, rule := range actual {
		if !expected[rule] {
			return errors.New("committed node source/destination/ingress tuple differs from applied plan")
		}
	}
	return nil
}
