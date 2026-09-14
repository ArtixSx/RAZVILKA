package dataplane

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"time"
)

// RestoreCommittedForwarding restores only fully vanished firewall objects
// already authorized by a committed proxy creation lease. It does not resolve
// new destinations, replace policy, change routes, or restart any process.
// The caller must also hold its configuration/stop/revision operation lease;
// WithReviewGuard binds that application authority across this operation.
func (m *Manager) RestoreCommittedForwarding(ctx context.Context, expected Plan) (repaired map[string]bool, retErr error) {
	if m == nil || m.StateRoot == "" || expected.State != "committed" || expected.SafeMode || !expected.Ready || expected.Noop || len(expected.Routes) == 0 {
		return nil, ErrReviewChanged
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if err := m.beginOperation(ctx); err != nil {
		return nil, err
	}
	defer m.endOperation()
	verify := func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		current, exists, err := m.Committed()
		if err != nil || !exists || !reflect.DeepEqual(current, expected) {
			return ErrReviewChanged
		}
		return m.checkPlanNetwork(ctx, expected)
	}
	if err := verify(ctx); err != nil {
		return nil, err
	}
	var repairs []*proxyForwardingRepair
	seenAdapters := map[string]bool{}
	// Admit every table before the first write, including intact siblings.
	for _, id := range expected.Adapters {
		if seenAdapters[id] {
			return nil, ErrReviewChanged
		}
		seenAdapters[id] = true
		registered, exists := m.adapter(id)
		if !exists {
			return nil, errors.New("committed forwarding adapter unavailable")
		}
		a, proxy := registered.(*ProxyTunnelAdapter)
		if !proxy {
			continue
		}
		r, err := a.prepareForwardingRepair(ctx, expected)
		if err != nil {
			return nil, err
		}
		if r.missing {
			repairs = append(repairs, r)
		}
	}
	defer func() {
		if retErr == nil {
			return
		}
		// Keep the operation lease while cleaning only this attempt's objects.
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer stop()
		for i := len(repairs) - 1; i >= 0; i-- {
			retErr = errors.Join(retErr, repairs[i].rollback(cleanup))
		}
		repaired = nil
	}()
	repaired = map[string]bool{}
	for _, r := range repairs {
		if err := verify(ctx); err != nil {
			return nil, err
		}
		changed, err := r.restore(ctx, expected, verify)
		if err != nil {
			return nil, err
		}
		if changed {
			repaired[r.adapter.ID()] = true
			for _, next := range repairs {
				if next != r {
					next.accountForRestoredAttachments(r)
				}
			}
		}
	}
	for _, r := range repairs {
		if err := r.verifyEnvironment(ctx, expected); err != nil {
			return nil, err
		}
		if err := r.adapter.observeOwnedRuntime(ctx); err != nil {
			return nil, err
		}
	}
	if err := verify(ctx); err != nil {
		return nil, err
	}
	return repaired, nil
}

type proxyForwardingRepairTable struct {
	table     proxyFirewallTable
	initial   proxyFirewallSnapshot
	missing   bool
	created   bool
	attempted proxyFirewallTable
	installed proxyFirewallTable
}

type proxyForwardingRepair struct {
	adapter *ProxyTunnelAdapter
	state   PolicyState
	lease   proxyForwardingLease
	tables  []*proxyForwardingRepairTable
	missing bool
}

// Several adapters can lose the same NDM table in one reset. Carry only the
// exact attachments made by this guarded attempt into later parent baselines;
// never adopt an arbitrary concurrent firewall snapshot as new authority.
func (r *proxyForwardingRepair) accountForRestoredAttachments(done *proxyForwardingRepair) {
	for _, item := range r.tables {
		if !item.missing {
			continue
		}
		for _, restored := range done.tables {
			if item.table.v6 != restored.table.v6 || item.table.table != restored.table.table || len(restored.installed.jumps) == 0 {
				continue
			}
			if item.table.table == "nat" {
				item.initial.parent = append(slices.Clone(restored.installed.jumps), item.initial.parent...)
			} else {
				item.initial.parent = append(item.initial.parent, restored.installed.jumps...)
			}
		}
	}
}

func (a *ProxyTunnelAdapter) prepareForwardingRepair(ctx context.Context, plan Plan) (*proxyForwardingRepair, error) {
	state, exists, err := a.loadPolicy()
	if err != nil || !exists {
		return nil, errors.New("committed proxy policy unavailable for forwarding restoration")
	}
	lease, exists, err := a.readForwardingLease()
	if err != nil || !exists || !reflect.DeepEqual(lease.Policy, state) {
		return nil, errors.New("committed proxy forwarding lease does not match the current policy")
	}
	r := &proxyForwardingRepair{adapter: a, state: state, lease: lease}
	for _, table := range proxyFirewallTables(state) {
		if !lease.owns(table) {
			return nil, errors.New("proxy firewall table has no acknowledged creation lease")
		}
		snapshot, err := a.firewallSnapshot(ctx, table)
		if err != nil {
			return nil, err
		}
		missing := !snapshot.declared && len(snapshot.own) == 0 && len(snapshot.references) == 0
		if !missing && !completeProxyFirewall(snapshot, table) {
			return nil, errors.New("proxy firewall objects are partially missing, changed or foreign; automatic restoration refused")
		}
		item := &proxyForwardingRepairTable{table: table, initial: snapshot, missing: missing, attempted: table, installed: table}
		item.attempted.rules, item.attempted.jumps = nil, nil
		item.installed.rules, item.installed.jumps = nil, nil
		r.tables = append(r.tables, item)
		r.missing = r.missing || missing
	}
	// Healthy polling only inspects the recorded firewall objects. A full
	// process/ingress/FIB proof is necessary only before an actual restoration.
	if r.missing {
		if err := r.verifyEnvironment(ctx, plan); err != nil {
			return nil, err
		}
	}
	return r, nil
}

func (r *proxyForwardingRepair) verifyEnvironment(ctx context.Context, plan Plan) error {
	a := r.adapter
	if err := a.checkPlanNetwork(ctx, plan); err != nil {
		return err
	}
	state, exists, err := a.loadPolicy()
	if err != nil || !exists || !reflect.DeepEqual(state, r.state) {
		return errors.New("proxy policy changed during forwarding restoration")
	}
	lease, exists, err := a.readForwardingLease()
	if err != nil || !exists || !reflect.DeepEqual(lease, r.lease) {
		return errors.New("proxy creation lease changed during forwarding restoration")
	}
	if state.Interface != a.Interface || state.Table != a.Table || state.PriorityBase != a.Priority || len(state.Prefixes) == 0 || !regularFile(a.engineConfigPath()) || !regularFile(a.sidecarConfigPath()) || a.Processes == nil || !a.Processes.Running(a.engineProcess()) || !a.Processes.Running(a.sidecarProcess()) {
		return errors.New("committed proxy processes or policy identity are unavailable")
	}
	// Current DNS addresses may differ from the old transaction snapshot, but
	// the lease may never acquire a client outside the actually committed plan.
	allowed, observed := map[string]bool{}, map[string]bool{}
	allLAN := false
	for _, route := range plan.Routes {
		if adapterID(route.Resolved) == a.ID() {
			allLAN = allLAN || len(route.Sources) == 0
			for _, source := range route.Sources {
				allowed[source] = true
			}
		}
	}
	for _, rule := range effectivePolicyRules(state) {
		if !allowed[rule.Source] {
			prefix, err := netip.ParsePrefix(rule.Source)
			if !allLAN || err != nil || !privateLANPrefix(prefix) {
				return errors.New("proxy forwarding client is outside the committed scope")
			}
		}
		observed[rule.Source] = true
	}
	if len(observed) == 0 || len(allowed) == 0 && !allLAN {
		return errors.New("committed proxy client scope is incomplete")
	}
	for source := range allowed {
		covered := observed[source]
		if !covered && allLAN {
			wanted, err := netip.ParsePrefix(source)
			if err == nil {
				for recorded := range observed {
					prefix, err := netip.ParsePrefix(recorded)
					if err == nil && prefix.Bits() <= wanted.Bits() && prefix.Contains(wanted.Addr()) {
						covered = true
					}
				}
			}
		}
		if !covered {
			return errors.New("committed proxy client scope is incomplete")
		}
	}
	current, err := a.compileForwarding(ctx, state)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(current, state.Forwarding) {
		return errors.New("proxy client ingress changed since forwarding was committed")
	}
	return verifyPolicyEvidence(ctx, a.Runner, a.ip(), state)
}

func completeProxyFirewall(snapshot proxyFirewallSnapshot, table proxyFirewallTable) bool {
	return snapshot.declared && len(snapshot.own) == len(table.rules) && len(snapshot.references) == len(table.jumps) && proxyFirewallSubset(snapshot, table) && proxyFirewallOrdering(snapshot.parent, table)
}

func sameProxyFirewallRules(left, right [][]string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if proxyFirewallRuleKey(left[i]) != proxyFirewallRuleKey(right[i]) {
			return false
		}
	}
	return true
}

func (r *proxyForwardingRepair) verifyTables(ctx context.Context) error {
	for _, item := range r.tables {
		snapshot, err := r.adapter.firewallSnapshot(ctx, item.table)
		if err != nil {
			return err
		}
		if !item.missing {
			if !completeProxyFirewall(snapshot, item.table) {
				return errors.New("intact proxy firewall sibling changed during restoration")
			}
			continue
		}
		parent := slices.Clone(item.initial.parent)
		if item.table.table == "nat" {
			parent = append(slices.Clone(item.installed.jumps), parent...)
		} else {
			parent = append(parent, item.installed.jumps...)
		}
		if snapshot.declared != item.created || len(snapshot.own) != len(item.installed.rules) || len(snapshot.references) != len(item.installed.jumps) || !proxyFirewallSubset(snapshot, item.installed) || !sameProxyFirewallRules(snapshot.parent, parent) {
			return errors.New("proxy firewall changed during restoration; ownership is uncertain")
		}
	}
	return nil
}

func (r *proxyForwardingRepair) restore(ctx context.Context, plan Plan, guard func(context.Context) error) (bool, error) {
	changed := false
	for _, item := range r.tables {
		if !item.missing {
			continue
		}
		if err := guard(ctx); err != nil {
			return false, err
		}
		if err := r.verifyEnvironment(ctx, plan); err != nil {
			return false, err
		}
		if err := r.verifyTables(ctx); err != nil {
			return false, err
		}
		a, table := r.adapter, item.table
		if _, err := a.run(ctx, a.firewallBinary(table.v6), "-t", table.table, "-N", table.chain); err != nil {
			return false, fmt.Errorf("recreate absent owned proxy chain: %w", err)
		}
		item.created = true
		for _, rule := range table.rules {
			if err := guard(ctx); err != nil {
				return false, err
			}
			item.attempted.rules = append(item.attempted.rules, rule)
			if _, err := a.run(ctx, a.firewallBinary(table.v6), append([]string{"-t", table.table, "-A", table.chain}, rule...)...); err != nil {
				return false, fmt.Errorf("restore exact proxy forwarding rule: %w", err)
			}
			item.installed.rules = append(item.installed.rules, rule)
		}
		// The chain stays unattached until its complete contents, all sibling
		// tables, live processes, route precedence and caller authority agree.
		if err := guard(ctx); err != nil {
			return false, err
		}
		if err := r.verifyEnvironment(ctx, plan); err != nil {
			return false, err
		}
		if err := r.verifyTables(ctx); err != nil {
			return false, err
		}
		for i, rule := range table.jumps {
			if err := guard(ctx); err != nil {
				return false, err
			}
			args := []string{"-t", table.table, "-A", table.parent}
			if table.table == "nat" {
				args = []string{"-t", table.table, "-I", table.parent, fmt.Sprint(i + 1)}
			}
			item.attempted.jumps = append(item.attempted.jumps, rule)
			if _, err := a.run(ctx, a.firewallBinary(table.v6), append(args, rule...)...); err != nil {
				return false, fmt.Errorf("restore exact proxy forwarding attachment: %w", err)
			}
			item.installed.jumps = append(item.installed.jumps, rule)
		}
		if err := r.verifyTables(ctx); err != nil {
			return false, err
		}
		changed = true
	}
	return changed, nil
}

func (r *proxyForwardingRepair) rollback(ctx context.Context) error {
	var failures []error
	for i := len(r.tables) - 1; i >= 0; i-- {
		item := r.tables[i]
		if !item.created {
			continue
		}
		a, table := r.adapter, item.attempted
		snapshot, err := a.firewallSnapshot(ctx, table)
		if err != nil || !proxyFirewallSubset(snapshot, table) {
			failures = append(failures, errors.Join(errors.New("restoration cleanup ownership is uncertain; foreign objects retained"), err))
			continue
		}
		// Only exact tuples attempted after our successful chain creation are
		// eligible; never flush or remove another intact table/the original lease.
		for _, actual := range snapshot.references {
			if _, err := a.run(ctx, a.firewallBinary(table.v6), append([]string{"-t", table.table, "-D"}, actual...)...); err != nil {
				failures = append(failures, err)
			}
		}
		for _, actual := range snapshot.own {
			if _, err := a.run(ctx, a.firewallBinary(table.v6), append([]string{"-t", table.table, "-D", table.chain}, actual...)...); err != nil {
				failures = append(failures, err)
			}
		}
		if snapshot.declared {
			if _, err := a.run(ctx, a.firewallBinary(table.v6), "-t", table.table, "-X", table.chain); err != nil {
				failures = append(failures, err)
			}
		}
	}
	return errors.Join(failures...)
}
