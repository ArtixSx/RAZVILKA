package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strings"
)

type wgNetworkFirewallEffect struct {
	table      proxyFirewallTable
	chain      string
	rule       []string
	creation   bool
	attachment bool
}

type wgNetworkEffects struct {
	plan     PolicyEffectPlan
	routing  int
	firewall map[int]wgNetworkFirewallEffect
	tables   []proxyFirewallTable
}

// One compiler supplies the common mixed receipt. Source NAT uses the tunnel's
// own family address so a normal server peer can return traffic to LAN clients.
// No hook, global masquerade, source-preserving proxy exemption or second
// forwarding ledger substitutes for these exact tuples.
func (a *WARPWireGuardAdapter) compileWGNetworkEffects(ref warpWGPolicyReference) (wgNetworkEffects, error) {
	var out wgNetworkEffects
	if ref.Policy.NetworkPolicyGeneration == "" || ref.Policy.Forwarding == nil {
		return out, ErrWGNetworkPolicy
	}
	if _, err := a.wgFrozenLANForState(ref.Policy, ref.FrozenLAN); err != nil {
		return out, err
	}
	forward := ref.Policy.Forwarding
	observer := a.wgForwardingObserver()
	if forward.Chain != observer.forwardingChain() || len(forward.Rules) != len(effectivePolicyRules(ref.Policy)) || len(forward.Rules) > 512 {
		return out, ErrWGNetworkPolicy
	}
	addresses := map[bool]netip.Addr{}
	if len(ref.NetworkTunnelSources) == 0 || len(ref.NetworkTunnelSources) > 2 {
		return out, ErrWGNetworkPolicy
	}
	for _, value := range ref.NetworkTunnelSources {
		addr, err := netip.ParseAddr(value)
		if err != nil || addr.String() != value || addr.Is4In6() || addr.Zone() != "" || !addr.IsGlobalUnicast() || addresses[addr.Is6()].IsValid() {
			return out, ErrWGNetworkPolicy
		}
		addresses[addr.Is6()] = addr
	}
	rules := effectivePolicyRules(ref.Policy)
	for i, grant := range forward.Rules {
		if grant.Source != rules[i].Source || grant.Destination != rules[i].Destination || grant.Ingress != rules[i].Ingress {
			return out, ErrWGNetworkPolicy
		}
		source, se := netip.ParsePrefix(grant.Source)
		dest, de := netip.ParsePrefix(grant.Destination)
		if se != nil || de != nil || source.Addr().BitLen() != dest.Addr().BitLen() || !addresses[source.Addr().Is6()].IsValid() {
			return out, ErrWGNetworkPolicy
		}
	}
	steps, err := policyAdditionExpected(ref.Policy)
	if err != nil {
		return out, err
	}
	identity := ref
	identity.ID, identity.Checksum = "", ""
	out.plan.Generation = wgPolicyReferenceChecksum(identity)
	out.routing = len(steps)
	out.firewall = map[int]wgNetworkFirewallEffect{}
	for i, step := range steps {
		e := PolicyEffect{Tool: PolicyEffectIP, Add: slices.Clone(step.Add), Delete: slices.Clone(step.Delete)}
		if i > 0 {
			e.Needs = []int{i - 1}
		}
		out.plan.Effects = append(out.plan.Effects, e)
	}
	out.tables = proxyFirewallTables(ref.Policy)
	for i := range out.tables {
		table := &out.tables[i]
		if table.table == "nat" {
			for j := range table.rules {
				rule := slices.Clone(table.rules[j])
				rule[len(rule)-1] = "SNAT"
				table.rules[j] = append(rule, "--to-source", addresses[table.v6].String())
			}
		}
	}
	add := func(effect PolicyEffect, firewall wgNetworkFirewallEffect) int {
		index := len(out.plan.Effects)
		out.plan.Effects = append(out.plan.Effects, effect)
		out.firewall[index] = firewall
		return index
	}
	// Private bodies precede attachments. All attachment prerequisites include
	// routing and every body, and filter opens after source NAT is installed.
	last := out.routing - 1
	for _, table := range out.tables {
		tool := PolicyEffectIPTables
		if table.v6 {
			tool = PolicyEffectIP6Tables
		}
		chain := add(PolicyEffect{Tool: tool, Add: []string{"-t", table.table, "-N", table.chain}, Delete: []string{"-t", table.table, "-X", table.chain}, Needs: []int{last}}, wgNetworkFirewallEffect{table: table, chain: table.chain, creation: true})
		last = chain
		for _, rule := range table.rules {
			last = add(PolicyEffect{Tool: tool, Add: append([]string{"-t", table.table, "-A", table.chain}, rule...), Delete: append([]string{"-t", table.table, "-D", table.chain}, rule...), Needs: []int{last}}, wgNetworkFirewallEffect{table: table, chain: table.chain, rule: rule})
		}
	}
	for _, kind := range []string{"nat", "filter"} {
		for _, table := range out.tables {
			if table.table != kind {
				continue
			}
			tool := PolicyEffectIPTables
			if table.v6 {
				tool = PolicyEffectIP6Tables
			}
			for _, rule := range table.jumps {
				addArgs := []string{"-t", kind, "-A", table.parent}
				if kind == "nat" {
					addArgs = []string{"-t", kind, "-I", table.parent, "1"}
				}
				last = add(PolicyEffect{Tool: tool, Add: append(addArgs, rule...), Delete: append([]string{"-t", kind, "-D", table.parent}, rule...), Needs: []int{last}}, wgNetworkFirewallEffect{table: table, chain: table.parent, rule: rule, attachment: true})
			}
		}
	}
	_, err = PolicyEffectPlanDigest(out.plan)
	return out, err
}

func (a *WARPWireGuardAdapter) wgForwardingObserver() *ProxyTunnelAdapter {
	return &ProxyTunnelAdapter{EngineID: a.ID(), Interface: a.interfaceName(), StateRoot: a.StateRoot, Runner: a.Runner, IP: a.ip(), IPTables: a.wgNetworkFirewallBinary(false), IP6Tables: a.wgNetworkFirewallBinary(true), LANBridgeMembers: a.networkLANBridgeMembers}
}

// Frozen forwarding intent must still fit the whole current assigned,
// connected bridge prefix. A successful lookup from one address cannot prove
// that the rest of a reviewed /24 or /64 remains physically admitted.
func (a *WARPWireGuardAdapter) verifyWGNetworkForwarding(ctx context.Context, state PolicyState) error {
	if state.NetworkPolicyGeneration == "" {
		return nil
	}
	current, err := a.wgForwardingObserver().compileForwarding(ctx, state)
	if err != nil || !reflect.DeepEqual(current, state.Forwarding) {
		return errors.Join(err, ErrWGNetworkPolicy)
	}
	return ctx.Err()
}

func (a *WARPWireGuardAdapter) wgNetworkFirewallBinary(v6 bool) string {
	if v6 && a.IP6Tables != "" {
		return a.IP6Tables
	}
	if !v6 && a.IPTables != "" {
		return a.IPTables
	}
	if v6 {
		return findExecutable("/opt/sbin/ip6tables", "/usr/sbin/ip6tables", "/sbin/ip6tables", "ip6tables")
	}
	return findExecutable("/opt/sbin/iptables", "/usr/sbin/iptables", "/sbin/iptables", "iptables")
}

// Kernel -S readback elides a universe source/destination. Normalize only that
// canonical prefix of this exact tool family; every narrower selector remains
// part of the key. Detect duplicates before elision so they cannot disappear.
func wgNetworkFirewallKey(rule []string, v6 bool) string {
	var rest []string
	nat := ""
	seen := map[string]bool{}
	for i := 0; i < len(rule); i += 2 {
		if i+1 >= len(rule) || seen[rule[i]] {
			return "!" + strings.Join(rule, " ")
		}
		seen[rule[i]] = true
		if rule[i] == "-s" || rule[i] == "-d" {
			prefix, err := netip.ParsePrefix(rule[i+1])
			if err != nil || prefix.Addr().Is4In6() || prefix.Addr().Is6() != v6 {
				return "!" + strings.Join(rule, " ")
			}
			if prefix.Bits() == 0 {
				if prefix != prefix.Masked() {
					return "!" + strings.Join(rule, " ")
				}
				continue
			}
		}
		if rule[i] == "--to-source" {
			addr, err := netip.ParseAddr(rule[i+1])
			if err != nil || addr.Is4In6() || addr.Zone() != "" || addr.Is6() != v6 {
				return "!" + strings.Join(rule, " ")
			}
			nat = addr.String()
		} else {
			rest = append(rest, rule[i], rule[i+1])
		}
	}
	key := proxyFirewallRuleKey(rest)
	if strings.HasPrefix(key, "!") {
		return key
	}
	return key + " --to-source=" + nat
}

func (a *WARPWireGuardAdapter) wgNetworkEffectRuntime(ref warpWGPolicyReference, compiled wgNetworkEffects, guarded bool) PolicyEffectRuntime {
	observer := a.wgForwardingObserver()
	runtime := PolicyEffectRuntime{Runner: a.Runner, Tools: PolicyEffectTools{IP: a.ip(), IPTables: observer.firewallBinary(false), IP6Tables: observer.firewallBinary(true)}}
	if guarded {
		runtime.Runner = wgNamedForwardRunner{base: a.Runner}
	}
	snapshot := func(ctx context.Context, table proxyFirewallTable) (proxyFirewallSnapshot, error) {
		read, err := observer.firewallSnapshot(ctx, table)
		if err != nil {
			return read, err
		}
		allowed := map[string]bool{}
		for _, rule := range table.rules {
			allowed[wgNetworkFirewallKey(rule, table.v6)] = true
		}
		for _, rule := range read.own {
			key := wgNetworkFirewallKey(rule, table.v6)
			if !allowed[key] || strings.HasPrefix(key, "!") {
				return read, ErrWGNetworkPolicy
			}
		}
		allowed = map[string]bool{}
		for _, rule := range table.jumps {
			allowed[wgNetworkFirewallKey(rule, table.v6)] = true
		}
		for _, rule := range read.references {
			if len(rule) == 0 || rule[0] != table.parent || !allowed[wgNetworkFirewallKey(rule[1:], table.v6)] {
				return read, ErrWGNetworkPolicy
			}
		}
		return read, nil
	}
	runtime.Preflight = func(ctx context.Context) error {
		if guarded {
			if err := checkWGNetworkReview(ctx); err != nil {
				return err
			}
		}
		// Exact tuple absence alone does not prove that an earlier foreign
		// selector cannot intercept this scope, or that reserved slots are free.
		if err := verifyPolicyPrecedence(ctx, numericPolicyReadRunner{base: a.Runner}, a.ip(), ref.Policy, true); err != nil {
			return err
		}
		if err := a.verifyWGNetworkForwarding(ctx, ref.Policy); err != nil {
			return err
		}
		for _, table := range compiled.tables {
			read, err := snapshot(ctx, table)
			if err != nil || read.declared || len(read.own) != 0 || len(read.references) != 0 {
				return errors.Join(err, ErrWGNetworkPolicy)
			}
		}
		for i := 0; i < compiled.routing; i++ {
			n, err := runtime.ExactPresence(ctx, i)
			if err != nil || n != 0 {
				return errors.Join(err, ErrWGNetworkPolicy)
			}
		}
		return nil
	}
	runtime.ExactPresence = func(ctx context.Context, index int) (int, error) {
		if index < 2 {
			return a.wgNetworkServiceTablePresence(ctx, ref.Policy, 4+index*2)
		}
		if index < compiled.routing {
			return policyAdditionPresence(ctx, numericPolicyReadRunner{base: a.Runner}, a.ip(), ref.Policy, index)
		}
		e, ok := compiled.firewall[index]
		if !ok {
			return 0, ErrWGNetworkPolicy
		}
		read, err := snapshot(ctx, e.table)
		if err != nil {
			return 0, err
		}
		if e.creation {
			if read.declared {
				return 1, nil
			}
			return 0, nil
		}
		rows := read.own
		if e.attachment {
			rows = read.parent
		}
		count, key := 0, wgNetworkFirewallKey(e.rule, e.table.v6)
		for _, row := range rows {
			if wgNetworkFirewallKey(row, e.table.v6) == key {
				count++
			}
		}
		return count, nil
	}
	runtime.BeforeDelete = func(ctx context.Context, index int) error {
		if index < 2 {
			for _, table := range compiled.tables {
				read, err := snapshot(ctx, table)
				if err != nil || read.declared || len(read.own) != 0 || len(read.references) != 0 {
					return errors.Join(err, ErrWGNetworkPolicy)
				}
			}
			return AssertPolicyDefaultUnreferencedWithLAN(ctx, a.Runner, a.ip(), ref.Policy, 4+index*2, ref.FrozenLAN)
		}
		if e, ok := compiled.firewall[index]; ok && !e.attachment {
			read, err := snapshot(ctx, e.table)
			if err != nil || len(read.references) != 0 || e.creation && len(read.own) != 0 {
				return errors.Join(err, ErrWGNetworkPolicy)
			}
		}
		return ctx.Err()
	}
	runtime.Guard = func(ctx context.Context, _ int) error {
		if guarded {
			return checkWGNetworkReview(ctx)
		}
		return ctx.Err()
	}
	return runtime
}

// Every health/Stop inspection reconstructs the complete tuple set from the
// immutable reference, rather than deserializing executable receipt argv.
func (a *WARPWireGuardAdapter) verifyWGNetworkEffectPresence(ctx context.Context, ref warpWGPolicyReference, wanted int) error {
	if wanted == 1 {
		if err := a.verifyWGNetworkForwarding(ctx, ref.Policy); err != nil {
			return err
		}
	}
	compiled, err := a.compileWGNetworkEffects(ref)
	if err != nil {
		return err
	}
	runtime := a.wgNetworkEffectRuntime(ref, compiled, false)
	for index := range compiled.plan.Effects {
		count, err := runtime.ExactPresence(ctx, index)
		if err != nil || count != wanted {
			return errors.Join(err, ErrWGNetworkPolicy)
		}
	}
	if wanted == 1 {
		observer := a.wgForwardingObserver()
		for _, table := range compiled.tables {
			if table.table != "nat" {
				continue
			}
			read, err := observer.firewallSnapshot(ctx, table)
			if err != nil {
				return err
			}
			if len(read.parent) < len(table.jumps) {
				return ErrWGNetworkPolicy
			}
			for _, row := range read.parent[:len(table.jumps)] {
				if len(row) < 2 || row[len(row)-1] != table.chain {
					return ErrWGNetworkPolicy
				}
			}
		}
	}
	return ctx.Err()
}

func wgNetworkSourceStrings(sources []netip.Addr) []string {
	result := make([]string, len(sources))
	for i, source := range sources {
		result[i] = source.String()
	}
	slices.Sort(result)
	return result
}
