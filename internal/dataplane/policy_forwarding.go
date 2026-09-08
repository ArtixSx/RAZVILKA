package dataplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
)

// These are forwarding grants, not a packet/HTTP success certificate. Filter
// jumps go at the tail of FORWARD: existing router ACLs retain their priority.
// NAT exemptions preserve the client source address inside the userspace TUN.
// ACCEPT in the nat table does not bypass the filter table.
const maxProxyForwardingRules = 128

type ProxyForwardingState struct {
	Chain string                `json:"chain"`
	Rules []ProxyForwardingRule `json:"rules"`
}

type ProxyForwardingRule struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Ingress     string `json:"ingress"`
}

var proxyFirewallInterface = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`)

func (a *ProxyTunnelAdapter) forwardingChain() string {
	digest := sha256.Sum256([]byte(filepath.Clean(a.StateRoot) + "\x00" + a.ID()))
	return "RZP_" + hex.EncodeToString(digest[:6])
}

func (a *ProxyTunnelAdapter) forwardingPath() string {
	return filepath.Join(a.StateRoot, "forwarding.json")
}

func (a *ProxyTunnelAdapter) compileForwarding(ctx context.Context, state PolicyState) (*ProxyForwardingState, error) {
	ctx, cancel := context.WithTimeout(ctx, a.timeout())
	defer cancel()
	result := &ProxyForwardingState{Chain: a.forwardingChain()}
	ingresses := map[string]string{}
	wanByFamily := map[bool]map[string]bool{}
	lanByFamily := map[bool][]proxyLANPrefix{}
	rules := effectivePolicyRules(state)
	if len(rules) == 0 || len(rules) > maxProxyForwardingRules {
		return nil, errors.New("proxy forwarding rule count exceeds its safe bound")
	}
	for _, rule := range rules {
		if rule.Source == "" {
			return nil, errors.New("proxy forwarding requires an explicit directly connected client source; LAN ingress is unknown")
		}
		source, err := netip.ParsePrefix(rule.Source)
		dest, destErr := netip.ParsePrefix(rule.Destination)
		if err != nil || destErr != nil || source.Addr().Is4In6() || dest.Addr().Is4In6() || source.Addr().BitLen() != dest.Addr().BitLen() || source.Bits() != source.Addr().BitLen() && !privateLANPrefix(source) {
			return nil, errors.New("proxy forwarding requires an exact client address or a proven private LAN subnet of the destination family")
		}
		ingress, ok := ingresses[source.String()]
		if !ok {
			if source.Bits() == source.Addr().BitLen() {
				ingress, err = policySourceIngress(ctx, a.Runner, a.ip(), source.Addr(), state.Interface)
			} else {
				v6 := source.Addr().Is6()
				lan, known := lanByFamily[v6]
				if !known {
					lan, err = a.connectedLANPrefixes(ctx, v6)
					if err != nil {
						return nil, err
					}
					lanByFamily[v6] = lan
				}
				ingress, err = connectedLANIngress(lan, source)
			}
			if err != nil {
				return nil, err
			}
			if ingress == "" || !proxyFirewallInterface.MatchString(ingress) {
				return nil, errors.New("proxy forwarding client ingress is unavailable")
			}
			ingresses[source.String()] = ingress
		}
		wan, known := wanByFamily[source.Addr().Is6()]
		if !known {
			wan, err = a.forwardingWANInterfaces(ctx, source.Addr().Is6())
			if err != nil {
				return nil, err
			}
			wanByFamily[source.Addr().Is6()] = wan
		}
		if wan[ingress] {
			return nil, errors.New("proxy forwarding cannot grant traffic arriving from a WAN default interface")
		}
		result.Rules = append(result.Rules, ProxyForwardingRule{Source: source.Masked().String(), Destination: dest.Masked().String(), Ingress: ingress})
	}
	if err := a.validateForwarding(state, result); err != nil {
		return nil, err
	}
	return result, nil
}

func (a *ProxyTunnelAdapter) forwardingWANInterfaces(ctx context.Context, v6 bool) (map[string]bool, error) {
	args := []string{"route", "show", "table", "main", "default"}
	if v6 {
		args = append([]string{"-6"}, args...)
	}
	output, err := a.run(ctx, a.ip(), args...)
	if err != nil {
		return nil, errors.New("proxy forwarding WAN interfaces cannot be inspected")
	}
	if len(output) > 1<<20 {
		return nil, errors.New("proxy forwarding WAN route output exceeds its safe bound")
	}
	result := map[string]bool{}
	lines := strings.Split(string(output), "\n")
	if len(lines) > 16384 {
		return nil, errors.New("proxy forwarding WAN route count exceeds its safe bound")
	}
	pendingDefault := false
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "unicast" {
			fields = fields[1:]
			if len(fields) == 0 {
				return nil, errors.New("proxy forwarding WAN route syntax is unknown")
			}
		}
		if fields[0] != "default" && fields[0] != "nexthop" {
			if pendingDefault {
				return nil, errors.New("proxy forwarding WAN default has no interface")
			}
			// BusyBox ip may ignore the trailing `default` selector and return
			// the complete main table. A well-formed non-default prefix/host
			// contributes no WAN authority; unfamiliar lines remain errors.
			prefix, parseErr := netip.ParsePrefix(fields[0])
			address, addressErr := netip.ParseAddr(fields[0])
			if parseErr == nil && prefix.Bits() > 0 || addressErr == nil && !address.IsUnspecified() {
				continue
			}
			return nil, errors.New("proxy forwarding WAN route syntax is unknown")
		}
		if fields[0] == "default" && pendingDefault {
			return nil, errors.New("proxy forwarding WAN default has no interface")
		}
		found := false
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] == "dev" {
				if !proxyFirewallInterface.MatchString(fields[i+1]) {
					return nil, errors.New("proxy forwarding WAN interface is invalid")
				}
				result[fields[i+1]] = true
				found = true
			}
		}
		if fields[0] == "nexthop" && !found {
			return nil, errors.New("proxy forwarding WAN nexthop interface is unknown")
		}
		pendingDefault = !found
	}
	if pendingDefault {
		return nil, errors.New("proxy forwarding WAN default has no interface")
	}
	return result, nil
}

func (a *ProxyTunnelAdapter) validateForwarding(state PolicyState, forwarding *ProxyForwardingState) error {
	if forwarding == nil || forwarding.Chain != a.forwardingChain() || len(forwarding.Rules) == 0 || len(forwarding.Rules) > maxProxyForwardingRules || state.Interface != a.Interface || !proxyFirewallInterface.MatchString(state.Interface) {
		return errors.New("proxy forwarding manifest is missing or has invalid ownership/bounds")
	}
	rules := effectivePolicyRules(state)
	if len(rules) != len(forwarding.Rules) {
		return errors.New("proxy forwarding does not match the routing policy")
	}
	for i, grant := range forwarding.Rules {
		source, err := netip.ParsePrefix(grant.Source)
		dest, destErr := netip.ParsePrefix(grant.Destination)
		if err != nil || destErr != nil || source.Bits() != source.Addr().BitLen() && !privateLANPrefix(source) || source.Addr().Is4In6() || dest.Addr().Is4In6() || !source.Addr().IsGlobalUnicast() || !dest.Addr().IsGlobalUnicast() || dest.Bits() == 0 || source.Addr().BitLen() != dest.Addr().BitLen() || source.Masked().String() != grant.Source || dest.Masked().String() != grant.Destination || grant.Source != rules[i].Source || grant.Destination != rules[i].Destination || !proxyFirewallInterface.MatchString(grant.Ingress) || grant.Ingress == state.Interface || grant.Ingress == "lo" {
			return errors.New("proxy forwarding manifest contains an invalid or unrelated grant")
		}
	}
	return nil
}

type proxyFirewallTable struct {
	v6     bool
	table  string
	parent string
	chain  string
	rules  [][]string
	jumps  [][]string
}

func proxyFirewallTables(state PolicyState) []proxyFirewallTable {
	var tables []proxyFirewallTable
	if state.Forwarding == nil {
		return tables
	}
	for _, v6 := range []bool{false, true} {
		filter := proxyFirewallTable{v6: v6, table: "filter", parent: "FORWARD", chain: state.Forwarding.Chain}
		nat := proxyFirewallTable{v6: v6, table: "nat", parent: "POSTROUTING", chain: state.Forwarding.Chain}
		for _, grant := range state.Forwarding.Rules {
			if strings.Contains(grant.Source, ":") != v6 {
				continue
			}
			out := []string{"-i", grant.Ingress, "-o", state.Interface, "-s", grant.Source, "-d", grant.Destination}
			back := []string{"-i", state.Interface, "-o", grant.Ingress, "-s", grant.Destination, "-d", grant.Source, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED"}
			for _, match := range [][]string{out, back} {
				filter.rules = append(filter.rules, append(append([]string{}, match...), "-j", "ACCEPT"))
				filter.jumps = append(filter.jumps, append(append([]string{}, match...), "-j", filter.chain))
			}
			// POSTROUTING has no input interface match. The exact source, service
			// destination and owned output TUN bind this source-preserving exception.
			match := []string{"-o", state.Interface, "-s", grant.Source, "-d", grant.Destination}
			nat.rules = append(nat.rules, append(append([]string{}, match...), "-j", "ACCEPT"))
			nat.jumps = append(nat.jumps, append(append([]string{}, match...), "-j", nat.chain))
		}
		if len(filter.rules) > 0 {
			tables = append(tables, filter, nat)
		}
	}
	return tables
}

func (a *ProxyTunnelAdapter) firewallBinary(v6 bool) string {
	if v6 {
		if a.IP6Tables != "" {
			return a.IP6Tables
		}
		return findExecutable("/opt/sbin/ip6tables", "/usr/sbin/ip6tables", "/sbin/ip6tables", "ip6tables")
	}
	if a.IPTables != "" {
		return a.IPTables
	}
	return findExecutable("/opt/sbin/iptables", "/usr/sbin/iptables", "/sbin/iptables", "iptables")
}

type proxyFirewallSnapshot struct {
	declared                bool
	own, references, parent [][]string
}

// iptables -S may reorder match options and conntrack states. Compare a strict
// token vocabulary as unordered key/value pairs; never parse shell commands.
func proxyFirewallRuleKey(rule []string) string {
	if len(rule)%2 != 0 {
		return "!" + strings.Join(rule, " ")
	}
	parts := make([]string, 0, len(rule)/2)
	seen := map[string]bool{}
	for i := 0; i < len(rule); i += 2 {
		key, value := rule[i], rule[i+1]
		if seen[key] {
			return "!" + strings.Join(rule, " ")
		}
		seen[key] = true
		switch key {
		case "-s", "-d":
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				return "!" + strings.Join(rule, " ")
			}
			value = prefix.Masked().String()
		case "--ctstate":
			states := strings.Split(value, ",")
			sort.Strings(states)
			value = strings.Join(states, ",")
		case "-i", "-o", "-m", "-j":
		default:
			return "!" + strings.Join(rule, " ")
		}
		parts = append(parts, key+"="+value)
	}
	sort.Strings(parts)
	return strings.Join(parts, " ")
}

func (a *ProxyTunnelAdapter) firewallSnapshot(ctx context.Context, table proxyFirewallTable) (proxyFirewallSnapshot, error) {
	var result proxyFirewallSnapshot
	output, err := a.run(ctx, a.firewallBinary(table.v6), "-t", table.table, "-S")
	if err != nil {
		return result, fmt.Errorf("inspect proxy %s forwarding capability: %w", table.table, err)
	}
	if len(output) > 1<<20 {
		return result, errors.New("firewall ruleset exceeds safe inspection limit")
	}
	lines := strings.Split(string(output), "\n")
	if len(lines) > 16384 {
		return result, errors.New("firewall ruleset exceeds safe rule limit")
	}
	parentSeen := false
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) == 3 && fields[0] == "-P" && fields[1] == table.parent {
			parentSeen = true
		}
		if len(fields) == 2 && fields[0] == "-N" && fields[1] == table.chain {
			result.declared = true
		}
		if len(fields) < 4 || fields[0] != "-A" {
			continue
		}
		if fields[1] == table.chain {
			result.own = append(result.own, fields[2:])
		}
		if fields[1] == table.parent {
			result.parent = append(result.parent, fields[2:])
		}
		for i := 2; i+1 < len(fields); i++ {
			if (fields[i] == "-j" || fields[i] == "-g") && fields[i+1] == table.chain {
				result.references = append(result.references, fields[1:])
				break
			}
		}
	}
	if !parentSeen {
		return result, errors.New("firewall parent chain cannot be inspected")
	}
	return result, nil
}

type proxyForwardingLease struct {
	Version int         `json:"version"`
	Policy  PolicyState `json:"policy"`
	Created []string    `json:"created_tables"`
}

func proxyFirewallTableKey(table proxyFirewallTable) string {
	return fmt.Sprintf("%t/%s", table.v6, table.table)
}

func (lease proxyForwardingLease) owns(table proxyFirewallTable) bool {
	for _, key := range lease.Created {
		if key == proxyFirewallTableKey(table) {
			return true
		}
	}
	return false
}

func (a *ProxyTunnelAdapter) readForwardingLease() (proxyForwardingLease, bool, error) {
	data, exists, err := optionalFile(a.forwardingPath())
	if err != nil || !exists {
		return proxyForwardingLease{}, exists, err
	}
	if len(data) > 128<<10 {
		return proxyForwardingLease{}, true, errors.New("proxy forwarding ownership manifest is too large")
	}
	var lease proxyForwardingLease
	if err := json.Unmarshal(data, &lease); err != nil {
		return lease, true, err
	}
	if lease.Version != 1 || len(lease.Created) > 4 {
		return lease, true, errors.New("invalid proxy firewall creation lease")
	}
	return lease, true, a.validateForwarding(lease.Policy, lease.Policy.Forwarding)
}

func (a *ProxyTunnelAdapter) readForwardingManifest() (PolicyState, bool, error) {
	lease, exists, err := a.readForwardingLease()
	return lease.Policy, exists, err
}

func (a *ProxyTunnelAdapter) writeForwardingLease(lease proxyForwardingLease) error {
	data, err := json.MarshalIndent(lease, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(a.forwardingPath(), data, 0o600)
}

func (a *ProxyTunnelAdapter) preflightForwarding(ctx context.Context, desired PolicyState) error {
	if err := a.validateForwarding(desired, desired.Forwarding); err != nil {
		return err
	}
	current, err := a.compileForwarding(ctx, desired)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(current, desired.Forwarding) {
		return errors.New("proxy client ingress changed since staging")
	}
	lease, exists, err := a.readForwardingLease()
	if err != nil {
		return err
	}
	for _, table := range proxyFirewallTables(desired) {
		snapshot, err := a.firewallSnapshot(ctx, table)
		if err != nil {
			return err
		}
		if snapshot.declared || len(snapshot.references) > 0 {
			if !exists || !lease.owns(table) {
				return errors.New("proxy firewall chain exists without this adapter's ownership manifest")
			}
			var expected *proxyFirewallTable
			for _, old := range proxyFirewallTables(lease.Policy) {
				if old.v6 == table.v6 && old.table == table.table {
					copy := old
					expected = &copy
					break
				}
			}
			if expected == nil || !proxyFirewallSubset(snapshot, *expected) {
				return errors.New("proxy firewall chain has foreign or ambiguous rules")
			}
		}
	}
	return nil
}

func proxyFirewallSubset(snapshot proxyFirewallSnapshot, table proxyFirewallTable) bool {
	own := map[string]int{}
	refs := map[string]int{}
	for _, rule := range table.rules {
		own[proxyFirewallRuleKey(rule)]++
	}
	for _, rule := range table.jumps {
		refs[table.parent+" "+proxyFirewallRuleKey(rule)]++
	}
	for _, rule := range snapshot.own {
		key := proxyFirewallRuleKey(rule)
		own[key]--
		if own[key] < 0 {
			return false
		}
	}
	for _, rule := range snapshot.references {
		key := rule[0] + " " + proxyFirewallRuleKey(rule[1:])
		refs[key]--
		if refs[key] < 0 {
			return false
		}
	}
	return true
}

func (a *ProxyTunnelAdapter) installForwarding(ctx context.Context, state PolicyState) (retErr error) {
	if err := a.preflightForwarding(ctx, state); err != nil {
		return err
	}
	if _, exists, err := a.readForwardingManifest(); err != nil {
		return err
	} else if exists {
		return errors.New("previous proxy forwarding ownership must be removed before installation")
	}
	lease := proxyForwardingLease{Version: 1, Policy: state}
	if err := os.MkdirAll(a.StateRoot, 0o700); err != nil {
		return err
	}
	// Persist intent before the first mutation; acknowledge successful chain
	// creation durably before adding a rule. A crash between those two writes
	// can leave only an empty, unattached chain with uncertain ownership.
	if err := a.writeForwardingLease(lease); err != nil {
		return err
	}
	defer func() {
		if retErr != nil {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), a.timeout())
			defer cancel()
			retErr = errors.Join(retErr, a.removeForwardingLease(cleanup, lease))
		}
	}()
	for _, table := range proxyFirewallTables(state) {
		if _, err := a.run(ctx, a.firewallBinary(table.v6), "-t", table.table, "-N", table.chain); err != nil {
			return fmt.Errorf("create owned proxy firewall chain: %w", err)
		}
		lease.Created = append(lease.Created, proxyFirewallTableKey(table))
		if err := a.writeForwardingLease(lease); err != nil {
			return err
		}
		for _, rule := range table.rules {
			args := append([]string{"-t", table.table, "-A", table.chain}, rule...)
			if _, err := a.run(ctx, a.firewallBinary(table.v6), args...); err != nil {
				return fmt.Errorf("install scoped proxy forwarding rule: %w", err)
			}
		}
		for i, rule := range table.jumps {
			args := []string{"-t", table.table, "-A", table.parent}
			if table.table == "nat" {
				args = []string{"-t", table.table, "-I", table.parent, fmt.Sprint(i + 1)}
			}
			args = append(args, rule...)
			if _, err := a.run(ctx, a.firewallBinary(table.v6), args...); err != nil {
				return fmt.Errorf("attach scoped proxy forwarding rule: %w", err)
			}
		}
	}
	return a.verifyForwarding(ctx, state)
}

func (a *ProxyTunnelAdapter) verifyForwarding(ctx context.Context, state PolicyState) error {
	if err := a.validateForwarding(state, state.Forwarding); err != nil {
		return err
	}
	current, err := a.compileForwarding(ctx, state)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(current, state.Forwarding) {
		return errors.New("proxy client ingress changed since installation")
	}
	lease, exists, err := a.readForwardingLease()
	if err != nil {
		return err
	}
	if !exists || !reflect.DeepEqual(lease.Policy.Forwarding, state.Forwarding) {
		return errors.New("proxy forwarding ownership is not committed to this policy")
	}
	for _, table := range proxyFirewallTables(state) {
		if !lease.owns(table) {
			return errors.New("proxy firewall chain creation is not acknowledged")
		}
		snapshot, err := a.firewallSnapshot(ctx, table)
		if err != nil {
			return err
		}
		if !snapshot.declared || len(snapshot.own) != len(table.rules) || len(snapshot.references) != len(table.jumps) || !proxyFirewallSubset(snapshot, table) {
			return errors.New("scoped proxy forwarding rules are missing or changed")
		}
		if len(snapshot.parent) < len(table.jumps) {
			return errors.New("proxy firewall attachment is incomplete")
		}
		if !proxyFirewallOrdering(snapshot.parent, table) {
			return errors.New("proxy firewall attachment ordering changed; router ACL priority cannot be proven")
		}
	}
	return nil
}

func proxyFirewallOrdering(parent [][]string, table proxyFirewallTable) bool {
	// A disjoint interface/address rule cannot affect this grant. This lets
	// multiple adapters coexist without trusting another chain's name, while a
	// newly appended matching ACL always invalidates an earlier filter grant.
	for _, grant := range table.jumps {
		position := -1
		for i, rule := range parent {
			if proxyFirewallRuleKey(rule) == proxyFirewallRuleKey(grant) {
				position = i
				break
			}
		}
		if position < 0 {
			return false
		}
		for i, rule := range parent {
			wrongSide := i > position
			if table.table == "nat" {
				wrongSide = i < position
			}
			if !wrongSide {
				continue
			}
			own := false
			for _, jump := range table.jumps {
				if proxyFirewallRuleKey(jump) == proxyFirewallRuleKey(rule) {
					own = true
					break
				}
			}
			if !own && proxyFirewallMayOverlap(rule, grant) {
				return false
			}
		}
	}
	return true
}

func proxyFirewallMayOverlap(rule, grant []string) bool {
	// Negation, wildcard interfaces and unfamiliar syntax remain potentially
	// matching. Only exact positive selectors can prove two rules disjoint.
	for _, part := range rule {
		if part == "!" {
			return true
		}
	}
	values := map[string]string{}
	for i := 0; i+1 < len(grant); i += 2 {
		values[grant[i]] = grant[i+1]
	}
	for i := 0; i+1 < len(rule); i++ {
		key, value := rule[i], rule[i+1]
		wanted := values[key]
		if wanted == "" {
			continue
		}
		if (key == "-i" || key == "-o") && !strings.Contains(value, "+") && value != wanted {
			return false
		}
		if key == "-s" || key == "-d" {
			actual, e1 := netip.ParsePrefix(value)
			expected, e2 := netip.ParsePrefix(wanted)
			if e1 == nil && e2 == nil && !actual.Overlaps(expected) {
				return false
			}
		}
	}
	return true
}

func (a *ProxyTunnelAdapter) removeForwarding(ctx context.Context) error {
	lease, exists, err := a.readForwardingLease()
	if err != nil || !exists {
		return err
	}
	return a.removeForwardingLease(ctx, lease)
}

func (a *ProxyTunnelAdapter) removeForwardingLease(ctx context.Context, lease proxyForwardingLease) error {
	var failures []error
	for _, table := range proxyFirewallTables(lease.Policy) {
		snapshot, err := a.firewallSnapshot(ctx, table)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if !lease.owns(table) {
			if snapshot.declared || len(snapshot.references) > 0 {
				failures = append(failures, errors.New("proxy firewall chain creation has uncertain ownership; retained without mutation"))
			}
			continue
		}
		// Never flush a chain. Delete only exact manifest-owned specifications;
		// foreign additions/references survive and make deletion fail closed.
		for _, rule := range table.jumps {
			for _, actual := range snapshot.references {
				if actual[0] == table.parent && proxyFirewallRuleKey(actual[1:]) == proxyFirewallRuleKey(rule) {
					args := append([]string{"-t", table.table, "-D", table.parent}, actual[1:]...)
					if _, err := a.run(ctx, a.firewallBinary(table.v6), args...); err != nil {
						failures = append(failures, err)
					}
					break
				}
			}
		}
		for _, rule := range table.rules {
			for _, actual := range snapshot.own {
				if proxyFirewallRuleKey(actual) == proxyFirewallRuleKey(rule) {
					args := append([]string{"-t", table.table, "-D", table.chain}, actual...)
					if _, err := a.run(ctx, a.firewallBinary(table.v6), args...); err != nil {
						failures = append(failures, err)
					}
					break
				}
			}
		}
		if snapshot.declared {
			if _, err := a.run(ctx, a.firewallBinary(table.v6), "-t", table.table, "-X", table.chain); err != nil {
				failures = append(failures, fmt.Errorf("owned proxy chain still has rules or references: %w", err))
			}
		}
	}
	if len(failures) > 0 {
		return errors.Join(failures...)
	}
	if err := os.Remove(a.forwardingPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (a *ProxyTunnelAdapter) applyOwnedPolicy(ctx context.Context, state PolicyState) error {
	if err := a.installForwarding(ctx, state); err != nil {
		return err
	}
	if err := applyPolicy(ctx, a.Runner, a.ip(), state); err != nil {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), a.timeout())
		defer cancel()
		return errors.Join(err, a.removeForwarding(cleanup))
	}
	return nil
}

func (a *ProxyTunnelAdapter) removeOwnedPolicy(ctx context.Context, state PolicyState) error {
	return errors.Join(a.removeForwarding(ctx), removePolicy(ctx, a.Runner, a.ip(), state))
}

func (a *ProxyTunnelAdapter) replaceOwnedPolicy(ctx context.Context, oldState, newState PolicyState) error {
	if err := a.removeOwnedPolicy(ctx, oldState); err != nil {
		return err
	}
	if err := a.restorePreviousPolicy(ctx, newState); err != nil {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), a.timeout())
		defer cancel()
		return errors.Join(err, a.restorePreviousPolicy(cleanup, oldState))
	}
	return nil
}

// Rollback restores exactly the previous authority. Legacy routing-only state
// receives no newly inferred firewall permissions.
func (a *ProxyTunnelAdapter) restorePreviousPolicy(ctx context.Context, state PolicyState) error {
	if state.Forwarding == nil {
		return applyPolicy(ctx, a.Runner, a.ip(), state)
	}
	return a.applyOwnedPolicy(ctx, state)
}
