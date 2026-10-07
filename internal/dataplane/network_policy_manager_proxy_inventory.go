package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// This is an in-call observation, never a serializable consumer allowance.
// Its descriptor stays open across both complete inventory captures.
type networkPolicyProxyObservation struct {
	engine, root, receiptID, runtimeID string
	state                              PolicyState
	rows                               []BackendInventoryRow
	anchor                             os.FileInfo
	owner                              *ownedfs.Root
	receipt                            networkPolicyReceiptObservation
}

func closeNetworkPolicyProxyObservations(observations []networkPolicyProxyObservation) {
	for _, observation := range observations {
		observation.owner.Close()
		observation.receipt.owner.Close()
	}
}

func checkNetworkPolicyProxyObservations(observations []networkPolicyProxyObservation) error {
	for _, observation := range observations {
		info, err := os.Lstat(observation.root)
		if err != nil || !networkPolicyPrivateDirectory(info) || !os.SameFile(observation.anchor, info) {
			return errors.Join(ErrNetworkPolicyConsumers, err)
		}
		info, err = os.Lstat(observation.receipt.path)
		if err != nil || !networkPolicyPrivateDirectory(info) || !os.SameFile(observation.receipt.anchor, info) {
			return errors.Join(ErrNetworkPolicyConsumers, err)
		}
	}
	return nil
}

func equalNetworkPolicyProxyObservations(a, b []networkPolicyProxyObservation) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].engine != b[i].engine || a[i].root != b[i].root || a[i].receiptID != b[i].receiptID || a[i].runtimeID != b[i].runtimeID ||
			!os.SameFile(a[i].anchor, b[i].anchor) || !reflect.DeepEqual(a[i].state, b[i].state) || !reflect.DeepEqual(a[i].rows, b[i].rows) {
			return false
		}
		if a[i].receipt.path != b[i].receipt.path || a[i].receipt.checksum != b[i].receipt.checksum || !os.SameFile(a[i].receipt.anchor, b[i].receipt.anchor) {
			return false
		}
	}
	return true
}

func (c *NetworkPolicyChecks) proxyConsumers(ctx context.Context, lan *LANPolicyRuntimePlan) (observations []networkPolicyProxyObservation, result error) {
	defer func() {
		if result != nil {
			closeNetworkPolicyProxyObservations(observations)
			observations = nil
		}
	}()
	if lan == nil {
		return nil, nil
	}
	var plan *Plan
	for _, id := range c.ids {
		actual, ok := c.adapters[id].(*ProxyTunnelAdapter)
		if !ok {
			continue
		}
		// A frozen view retains the actual owner runner/process controller. It
		// cannot be replaced by caller-provided expected rules or a mark token.
		view := *actual
		lease, exists, err := view.readForwardingLease()
		if err != nil {
			return observations, errors.Join(ErrNetworkPolicyConsumers, err)
		}
		if !exists {
			continue
		}
		if plan == nil {
			p, err := c.consumerPlan(ctx, lan)
			if err != nil {
				return observations, err
			}
			plan = &p
		}
		// This first production bridge supports the concrete scoped Xray owner.
		// Other live producers need their own independently receipted observers;
		// their rows cannot be inferred from a common positive mark.
		if id != "xray" || !view.scopedXray && !view.xrayPlanDispatch {
			return observations, ErrNetworkPolicyConsumers
		}
		mode, err := view.xrayPlanMode(*plan)
		if err != nil || mode != proxyXrayModeNode {
			return observations, errors.Join(ErrNetworkPolicyConsumers, err)
		}
		bound, err := view.xrayModeView(mode)
		if err != nil {
			return observations, err
		}
		observation, err := c.observeScopedProxy(ctx, bound, *plan, lease)
		if err != nil {
			return observations, errors.Join(ErrNetworkPolicyConsumers, err)
		}
		observations = append(observations, observation)
	}
	return observations, ctx.Err()
}

func (c *NetworkPolicyChecks) observeScopedProxy(ctx context.Context, a *ProxyTunnelAdapter, p Plan, lease proxyForwardingLease) (observation networkPolicyProxyObservation, result error) {
	if !filepath.IsAbs(a.StateRoot) || filepath.Clean(a.StateRoot) != a.StateRoot || a.IPTables != c.gate.Binding.Runtime.IPTables || a.IP6Tables != c.gate.Binding.Runtime.IP6Tables || a.IP != c.gate.Binding.Runtime.IP {
		return observation, ErrNetworkPolicyConsumers
	}
	owner, anchor, err := openNetworkPolicyObservationRoot(a.StateRoot)
	if err != nil {
		return observation, err
	}
	defer func() {
		if result != nil {
			owner.Close()
		}
	}()
	state := lease.Policy
	generation, defaultScope, err := NetworkPolicyRouteAuthority(p, a.ID())
	if err != nil || generation == "" || generation != p.LAN.Generation || state.NetworkPolicyGeneration != generation || state.NetworkDefault != defaultScope || validPolicyLayout(state) != nil {
		return observation, errors.Join(ErrNetworkPolicyConsumers, err)
	}
	// Managed routes have frozen literal destinations, sources and ingress.
	// This compiler path performs no DNS discovery or arbitrary DTO widening.
	prefixes, rules, err := resolvePolicyRules(ctx, p, a.ID(), nil)
	if err != nil || !reflect.DeepEqual(prefixes, state.Prefixes) || !reflect.DeepEqual(rules, state.Rules) || state.Interface != a.Interface || state.Table != a.Table || state.PriorityBase != a.Priority {
		return observation, errors.Join(ErrNetworkPolicyConsumers, err)
	}
	manifest, err := a.checkScopedNodeState(ctx, p)
	if err != nil {
		return observation, err
	}
	var endpoints []string
	for _, endpoint := range manifest.Endpoints {
		ip, err := netip.ParseAddr(endpoint.IP)
		if err != nil || ip.Is4In6() || !ip.IsGlobalUnicast() {
			return observation, ErrNetworkPolicyConsumers
		}
		endpoints = append(endpoints, endpoint.Host, endpoint.IP)
	}
	exclusions, err := resolveEndpointExclusions(ctx, sortedUnique(endpoints), a.Resolver)
	if err != nil || !reflect.DeepEqual(exclusions, state.Exclusions) {
		return observation, errors.Join(ErrNetworkPolicyConsumers, err)
	}
	if err := a.verifyForwarding(ctx, state); err != nil {
		return observation, err
	}
	for _, table := range proxyFirewallTables(state) {
		if !lease.owns(table) {
			return observation, ErrNetworkPolicyConsumers
		}
	}
	receipt, err := c.scopedProxyReceipt(ctx, a, p, state)
	if err != nil {
		return observation, err
	}
	defer func() {
		if result != nil {
			receipt.owner.Close()
		}
	}()
	if err := a.verifyScopedNodeInterface(ctx); err != nil {
		return observation, err
	}
	runtimeID, err := a.scopedRuntimeIdentity()
	if err != nil || runtimeID == "" {
		return observation, errors.Join(ErrNetworkPolicyConsumers, err)
	}
	if err := verifyPolicyEvidence(ctx, a.Runner, a.ip(), state); err != nil {
		return observation, err
	}
	afterRuntime, err := a.scopedRuntimeIdentity()
	if err != nil || afterRuntime != runtimeID {
		return observation, errors.Join(ErrNetworkPolicyConsumers, err)
	}
	observation = networkPolicyProxyObservation{engine: a.ID(), root: a.StateRoot, anchor: anchor, owner: owner, state: state, receiptID: receipt.status.ID, runtimeID: runtimeID, receipt: receipt}
	for _, table := range proxyFirewallTables(state) {
		family := 4
		if table.v6 {
			family = 6
		}
		observation.rows = append(observation.rows, BackendInventoryRow{Family: family, Table: table.table, Tokens: []string{"-N", table.chain}})
		for _, rule := range table.rules {
			observation.rows = append(observation.rows, BackendInventoryRow{Family: family, Table: table.table, Tokens: append([]string{"-A", table.chain}, slices.Clone(rule)...)})
		}
		for _, jump := range table.jumps {
			observation.rows = append(observation.rows, BackendInventoryRow{Family: family, Table: table.table, Tokens: append([]string{"-A", table.parent}, slices.Clone(jump)...)})
		}
	}
	if err := checkNetworkPolicyProxyObservations([]networkPolicyProxyObservation{observation}); err != nil {
		return observation, err
	}
	return observation, ctx.Err()
}

func (c *NetworkPolicyChecks) scopedProxyReceipt(ctx context.Context, a *ProxyTunnelAdapter, p Plan, state PolicyState) (networkPolicyReceiptObservation, error) {
	var unknown networkPolicyReceiptObservation
	boot, err := a.currentBootIdentity()
	if err != nil || boot != c.gate.identity.value.BootID {
		return unknown, errors.Join(ErrNetworkPolicyIdentity, err)
	}
	root := filepath.Join(c.root, "transactions", p.PlanID, a.ID())
	relative, err := filepath.Rel(c.root, filepath.Join(root, "policy-additions.json"))
	if err != nil || c.owner.Check(relative) != nil {
		return unknown, ErrNetworkPolicyConsumers
	}
	_, statErr := c.owner.Stat(relative)
	if statErr == nil {
		staged, err := a.readStagedPolicy(root)
		if err != nil || !samePolicy(staged, state) {
			return unknown, errors.Join(ErrNetworkPolicyConsumers, err)
		}
		receipt, err := a.readCandidatePolicyReceipt(root, state)
		if err != nil || receipt.Phase != "complete" || receipt.Boot != boot {
			return unknown, errors.Join(ErrNetworkPolicyConsumers, err)
		}
		additionRoot := root
		if receipt.Generation != "" {
			additionRoot, err = a.policyGenerationRoot(receipt.Generation)
			if err != nil {
				return unknown, err
			}
		}
		observed, err := observeNetworkPolicyProxyAddition(ctx, state, additionRoot, a.additionOptions())
		if err != nil {
			return unknown, err
		}
		status := observed.status
		if !status.Complete || status.Removed || status.Unknown || status.Promoted || receipt.Generation != "" && status.ID != receipt.Generation {
			observed.owner.Close()
			return unknown, ErrNetworkPolicyConsumers
		}
		return observed, nil
	}
	if !errors.Is(statErr, os.ErrNotExist) {
		return unknown, errors.Join(ErrNetworkPolicyConsumers, statErr)
	}
	committed, exists, err := a.loadPolicy()
	if err != nil || !exists || !samePolicy(committed, state) {
		return unknown, errors.Join(ErrNetworkPolicyConsumers, err)
	}
	binding, exists, err := a.readPolicyBinding(state)
	if err != nil || !exists || binding.Phase != "active" || binding.ReceiptID == "" {
		return unknown, errors.Join(ErrNetworkPolicyConsumers, err)
	}
	root, err = a.policyGenerationRoot(binding.Generation)
	if err != nil {
		return unknown, err
	}
	observed, err := observeNetworkPolicyProxyAddition(ctx, state, root, a.additionOptions())
	if err != nil {
		return unknown, err
	}
	status := observed.status
	if !status.Complete || status.Removed || status.Unknown || status.Promoted || status.ID != binding.ReceiptID {
		observed.owner.Close()
		return unknown, ErrNetworkPolicyConsumers
	}
	return observed, nil
}
