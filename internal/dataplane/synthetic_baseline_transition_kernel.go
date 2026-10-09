package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/publicfetch"
)

// Retains the SAME original reader/network owner and compiler payload. It
// cannot be reconstructed from a backend snapshot, receipt argv or Ready bit.
// This is the kernel readback component, not the combined publication lease.
type syntheticBaselineKernelInspector struct {
	self     *syntheticBaselineKernelInspector
	backend  *BackendInventory
	identity *networkPolicyIdentity
	plan     PolicyEffectPlan
	mapping  *dnscontrol.SyntheticDNSMapping
}

func newSyntheticBaselineKernelInspector(ctx context.Context, backend *BackendInventory, identity *networkPolicyIdentity, transport *SyntheticDNSTransportPlan, domain *DomainPolicyRuntimePlan, mapping *dnscontrol.SyntheticDNSMapping) (*syntheticBaselineKernelInspector, error) {
	if backend == nil || identity == nil || identity.value.Validate() != nil || identity.withCurrent == nil {
		return nil, ErrSyntheticBaselineTransition
	}
	plan, err := SyntheticBaselineTransitionEffects(ctx, transport, domain, mapping)
	if err != nil {
		return nil, err
	}
	if _, err := syntheticBaselineTupleFromPlan(plan); err != nil {
		return nil, err
	}
	i := &syntheticBaselineKernelInspector{backend: backend, identity: identity, plan: plan, mapping: mapping}
	i.self = i
	return i, nil
}

func (i *syntheticBaselineKernelInspector) read(ctx context.Context) (backendInventorySnapshot, error) {
	if i == nil || i.self != i || ctx == nil || ctx.Err() != nil {
		return backendInventorySnapshot{}, ErrSyntheticBaselineTransition
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return backendInventorySnapshot{}, ErrSyntheticBaselineTransition
	}
	if err := i.identity.check(ctx); err != nil {
		return backendInventorySnapshot{}, err
	}
	view, err := i.backend.Read(ctx, i.identity.value)
	if err != nil {
		return backendInventorySnapshot{}, errors.Join(ErrSyntheticBaselineTransition, err)
	}
	if err := view.requireLANBackendCoverage(); err != nil {
		return backendInventorySnapshot{}, errors.Join(ErrSyntheticBaselineTransition, err)
	}
	if view.Scope.Network != i.identity.value {
		return backendInventorySnapshot{}, ErrSyntheticBaselineTransition
	}
	if err := i.identity.check(ctx); err != nil {
		return backendInventorySnapshot{}, err
	}
	return view, nil
}

// Actual full inventory, never the common receipt's ACK metadata. Every
// foreign body/reference and every duplicate refuses the entire owner.
func (i *syntheticBaselineKernelInspector) ExactPresence(ctx context.Context, index int) (int, error) {
	view, err := i.read(ctx)
	if err != nil {
		return 0, err
	}
	return syntheticBaselineExactPresence(view.Rows, i.plan, index)
}

func (i *syntheticBaselineKernelInspector) CheckPreDNAT(ctx context.Context) error {
	view, err := i.read(ctx)
	if err != nil {
		return err
	}
	// Authenticate the entire own chain before excluding its restorative
	// translation from the comparison of firmware's earlier hooks.
	if _, err := syntheticBaselineExactPresence(view.Rows, i.plan, 0); err != nil {
		return err
	}
	return syntheticBaselinePreDNATEquivalent(view.Rows, i.plan)
}

// This is only actual kernel dependency readback. It never settles cached DNS,
// late SYNs or original conntrack IDs; those retained owners must separately
// authorize cleanup before a runtime reaches COMMON Remove.
func (i *syntheticBaselineKernelInspector) BeforeDelete(ctx context.Context, index int) error {
	view, err := i.read(ctx)
	if err != nil {
		return err
	}
	return syntheticBaselineDeletionReady(view.Rows, i.plan, index)
}

func syntheticBaselineDeletionReady(rows []backendInventoryRow, plan PolicyEffectPlan, index int) error {
	if _, err := syntheticBaselineExactPresence(rows, plan, index); err != nil {
		return err
	}
	for child, effect := range plan.Effects {
		if !slices.Contains(effect.Needs, index) {
			continue
		}
		count, err := syntheticBaselineExactPresence(rows, plan, child)
		if err != nil || count != 0 {
			return ErrSyntheticBaselineTransition
		}
	}
	return nil
}

func syntheticBaselineExactPresence(rows []backendInventoryRow, plan PolicyEffectPlan, index int) (int, error) {
	if _, err := syntheticBaselineTupleFromPlan(plan); err != nil || index < 0 || index >= len(plan.Effects) {
		return 0, ErrSyntheticBaselineTransition
	}
	chain := plan.Effects[0].Add[3]
	counts := make([]int, len(plan.Effects))
	for _, row := range rows {
		t := row.Tokens
		owned := len(t) > 1 && t[1] == chain
		for n := 2; n+1 < len(t); n++ {
			if (t[n] == "-j" || t[n] == "-g" || t[n] == "--jump" || t[n] == "--goto") && t[n+1] == chain {
				owned = true
			}
		}
		if !owned {
			continue
		}
		if row.Family != 4 || row.Table != "nat" {
			return 0, ErrSyntheticBaselineTransition
		}
		actualKey, err := syntheticBaselineRuleKey(t)
		if err != nil {
			return 0, err
		}
		match := -1
		for n, e := range plan.Effects {
			key, err := syntheticBaselineRuleKey(e.Add[2:])
			if err != nil {
				return 0, err
			}
			if actualKey == key {
				if match != -1 {
					return 0, ErrSyntheticBaselineTransition
				}
				match = n
			}
		}
		if match == -1 {
			return 0, ErrSyntheticBaselineTransition
		}
		counts[match]++
		if counts[match] > 1 {
			return 0, ErrSyntheticBaselineTransition
		}
	}
	return counts[index], nil
}

// xtables -S reorders base predicates and emits upper-case MACs. Compare only
// this closed vocabulary; duplicate options, extra matches and wider masks
// remain foreign. This canonical key is comparison, never command input.
func syntheticBaselineRuleKey(t []string) (string, error) {
	if len(t) == 2 && t[0] == "-N" {
		data, _ := json.Marshal(t)
		return string(data), nil
	}
	if len(t) < 4 || t[0] != "-A" || len(t)%2 != 0 {
		return "", ErrSyntheticBaselineTransition
	}
	parts := []string{t[0], t[1]}
	seen := map[string]bool{}
	modules := map[string]bool{}
	for n := 2; n < len(t); n += 2 {
		key, value := t[n], t[n+1]
		if key != "-m" && seen[key] {
			return "", ErrSyntheticBaselineTransition
		}
		seen[key] = true
		switch key {
		case "-s", "-d":
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				address, e := netip.ParseAddr(value)
				if e != nil {
					return "", ErrSyntheticBaselineTransition
				}
				prefix = netip.PrefixFrom(address, address.BitLen())
			}
			if !prefix.Addr().Is4() || prefix.Addr().Is4In6() {
				return "", ErrSyntheticBaselineTransition
			}
			value = prefix.Masked().String()
		case "--mac-source":
			mac, err := net.ParseMAC(value)
			if err != nil || len(mac) != 6 || mac[0]&1 != 0 {
				return "", ErrSyntheticBaselineTransition
			}
			value = mac.String()
		case "-m":
			if !slices.Contains([]string{"mac", "tcp"}, value) || modules[value] {
				return "", ErrSyntheticBaselineTransition
			}
			modules[value] = true
		case "--to-destination":
			address, err := netip.ParseAddr(value)
			if err != nil || !address.Is4() || !publicfetch.PublicAddress(address) {
				return "", ErrSyntheticBaselineTransition
			}
			value = address.String()
		case "-i":
			if !proxyFirewallInterface.MatchString(value) || value == "lo" {
				return "", ErrSyntheticBaselineTransition
			}
		case "-p":
			if value != "tcp" {
				return "", ErrSyntheticBaselineTransition
			}
		case "--dport":
			if value != "80" && value != "443" {
				return "", ErrSyntheticBaselineTransition
			}
		case "-j":
		default:
			return "", ErrSyntheticBaselineTransition
		}
		parts = append(parts, key+"="+value)
	}
	slices.Sort(parts[2:])
	data, _ := json.Marshal(parts)
	return string(data), nil
}

// Tuple extraction is private comparison only. The production inspector
// above accepts the original mapping, not this parsed tuple or a saved plan.
type syntheticBaselineTuple struct {
	client, synthetic, real netip.Addr
	mac, ingress            string
}

func syntheticBaselineTupleFromPlan(plan PolicyEffectPlan) (syntheticBaselineTuple, error) {
	var tuple syntheticBaselineTuple
	if len(plan.Effects) != 4 || !lanPolicyHash(plan.Generation) {
		return tuple, ErrSyntheticBaselineTransition
	}
	first := plan.Effects[0]
	if first.Tool != PolicyEffectIPTables || len(first.Add) != 4 || !slices.Equal(first.Add[:3], []string{"-t", "nat", "-N"}) || len(first.Needs) != 0 {
		return tuple, ErrSyntheticBaselineTransition
	}
	chain := first.Add[3]
	if len(chain) != 25 || !strings.HasPrefix(chain, "RZSB_") {
		return tuple, ErrSyntheticBaselineTransition
	}
	for _, c := range chain[5:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return tuple, ErrSyntheticBaselineTransition
		}
	}
	body := plan.Effects[1].Add
	if len(body) != 10 {
		return tuple, ErrSyntheticBaselineTransition
	}
	real, err := netip.ParseAddr(body[9])
	if err != nil || !real.Is4() || !publicfetch.PublicAddress(real) {
		return tuple, ErrSyntheticBaselineTransition
	}
	selector := plan.Effects[2].Add
	if len(selector) != 22 {
		return tuple, ErrSyntheticBaselineTransition
	}
	client, err := netip.ParsePrefix(selector[7])
	if err != nil || client.Bits() != 32 || !client.Addr().Is4() || !client.Addr().IsPrivate() {
		return tuple, ErrSyntheticBaselineTransition
	}
	synth, err := netip.ParsePrefix(selector[9])
	if err != nil || synth.Bits() != 32 || !netip.MustParsePrefix("198.18.0.0/15").Contains(synth.Addr()) {
		return tuple, ErrSyntheticBaselineTransition
	}
	mac, err := net.ParseMAC(selector[13])
	if err != nil || len(mac) != 6 || mac[0]&1 != 0 || mac.String() != selector[13] || !proxyFirewallInterface.MatchString(selector[5]) || selector[5] == "lo" {
		return tuple, ErrSyntheticBaselineTransition
	}
	tuple = syntheticBaselineTuple{client: client.Addr(), synthetic: synth.Addr(), real: real, mac: selector[13], ingress: selector[5]}
	expected := PolicyEffectPlan{Generation: plan.Generation, Effects: []PolicyEffect{
		{Tool: PolicyEffectIPTables, Add: []string{"-t", "nat", "-N", chain}, Delete: []string{"-t", "nat", "-X", chain}},
		{Tool: PolicyEffectIPTables, Add: []string{"-t", "nat", "-A", chain, "-p", "tcp", "-j", "DNAT", "--to-destination", real.String()}, Delete: []string{"-t", "nat", "-D", chain, "-p", "tcp", "-j", "DNAT", "--to-destination", real.String()}, Needs: []int{0}},
	}}
	for _, port := range []string{"80", "443"} {
		args := []string{"PREROUTING", "-i", tuple.ingress, "-s", client.String(), "-d", synth.String(), "-m", "mac", "--mac-source", tuple.mac, "-p", "tcp", "-m", "tcp", "--dport", port, "-j", chain}
		expected.Effects = append(expected.Effects, PolicyEffect{Tool: PolicyEffectIPTables, Add: append([]string{"-t", "nat", "-A"}, args...), Delete: append([]string{"-t", "nat", "-D"}, args...), Needs: []int{0, 1}})
	}
	// Normalize nil/empty Needs through the same common compiler copier.
	frozen, _, err := copyPolicyEffectPlan(plan)
	if err != nil {
		return syntheticBaselineTuple{}, err
	}
	expected, _, err = copyPolicyEffectPlan(expected)
	if err != nil || !reflect.DeepEqual(frozen, expected) {
		return syntheticBaselineTuple{}, ErrSyntheticBaselineTransition
	}
	return tuple, nil
}

// Closed failure classes only: never echo rule bytes, addresses or MACs.
type syntheticBaselinePolicyFailure struct{ stage string }

func (e *syntheticBaselinePolicyFailure) Error() string {
	return "synthetic baseline policy equivalence refused at " + e.stage
}
func (e *syntheticBaselinePolicyFailure) Unwrap() error { return ErrSyntheticBaselineTransition }
func syntheticBaselinePolicyRefusal(stage string) error {
	return &syntheticBaselinePolicyFailure{stage}
}

// ONLY the applicable pre-DNAT classic component. Full readiness also needs
// native RPDB/routing and post-DNAT filter/conntrack proof, original control,
// consumer leases, receipt ACKs and cache/conntrack settlement. Unknown refuses.
func syntheticBaselinePreDNATEquivalent(rows []backendInventoryRow, own PolicyEffectPlan) error {
	tuple, err := syntheticBaselineTupleFromPlan(own)
	if err != nil {
		return err
	}
	for _, table := range []string{"raw", "mangle", "nat"} {
		chains := map[string][][]string{}
		declared := map[string]bool{}
		for _, row := range rows {
			if row.Family != 4 || row.Table != table {
				continue
			}
			t := row.Tokens
			if len(t) == 2 && t[0] == "-N" {
				if declared[t[1]] {
					return syntheticBaselinePolicyRefusal("pre-dnat.declaration")
				}
				declared[t[1]] = true
				continue
			}
			if len(t) == 3 && t[0] == "-P" {
				if declared[t[1]] || !slices.Contains([]string{"ACCEPT", "DROP"}, t[2]) {
					return syntheticBaselinePolicyRefusal("pre-dnat.policy")
				}
				declared[t[1]] = true
				continue
			}
			if len(t) < 4 || t[0] != "-A" {
				return syntheticBaselinePolicyRefusal("pre-dnat.shape")
			}
			if table == "nat" {
				owned := false
				actualKey, keyErr := syntheticBaselineRuleKey(t)
				for _, e := range own.Effects {
					expectedKey, err := syntheticBaselineRuleKey(e.Add[2:])
					if keyErr == nil && err == nil && actualKey == expectedKey {
						owned = true
						break
					}
				}
				if owned {
					continue
				}
			}
			chains[t[1]] = append(chains[t[1]], t[2:])
		}
		if !declared["PREROUTING"] {
			return syntheticBaselinePolicyRefusal("pre-dnat.missing-hook")
		}
		for _, port := range []uint16{80, 443} {
			seen, active := map[string]bool{}, map[string]bool{}
			var visit func(string, int) error
			visit = func(chain string, depth int) error {
				if depth > 32 || active[chain] {
					return syntheticBaselinePolicyRefusal("pre-dnat.chain-cycle")
				}
				if seen[chain] {
					return nil
				}
				seen[chain] = true
				active[chain] = true
				defer delete(active, chain)
				for _, tokens := range chains[chain] {
					target, err := syntheticBaselinePreDNATRule(tokens, tuple, port)
					if err != nil {
						return err
					}
					if target == "" {
						continue
					} // A known conjunct proves this rule cannot match.
					if declared[target] {
						if err := visit(target, depth+1); err != nil {
							return err
						}
					} else if !slices.Contains([]string{"ACCEPT", "DROP", "REJECT", "RETURN", "MARK", "LOG"}, target) {
						return syntheticBaselinePolicyRefusal("pre-dnat.target")
					}
				}
				return nil
			}
			if err := visit("PREROUTING", 0); err != nil {
				return err
			}
		}
	}
	return nil
}

func syntheticBaselinePreDNATRule(t []string, tuple syntheticBaselineTuple, port uint16) (string, error) {
	target := ""
	nonmatch := false
	negated := false
	var uncertain error
	for n := 0; n < len(t); n++ {
		key := t[n]
		if key == "!" {
			if negated {
				return "", syntheticBaselinePolicyRefusal("pre-dnat.syntax")
			}
			negated = true
			continue
		}
		if n+1 >= len(t) {
			return "", syntheticBaselinePolicyRefusal("pre-dnat.syntax")
		}
		value := t[n+1]
		n++
		known, match := false, true
		switch key {
		case "-s", "--source":
			p, err := netip.ParsePrefix(value)
			if err != nil || !p.Addr().Is4() {
				return "", syntheticBaselinePolicyRefusal("pre-dnat.source")
			}
			known, match = true, p.Contains(tuple.client)
		case "-i", "--in-interface":
			if value == "" || strings.ContainsAny(value, "+*?!") {
				uncertain = syntheticBaselinePolicyRefusal("pre-dnat.interface")
			} else {
				known, match = true, value == tuple.ingress
			}
		case "-p", "--protocol":
			if value == "tcp" || value == "6" {
				known, match = true, true
			} else if value == "udp" || value == "17" || value == "icmp" || value == "1" {
				known, match = true, false
			} else {
				uncertain = syntheticBaselinePolicyRefusal("pre-dnat.protocol")
			}
		case "--dport", "--destination-port":
			lo, hi, err := syntheticBaselinePortRange(value)
			if err != nil {
				return "", err
			}
			known, match = true, port >= lo && port <= hi
		case "--mac-source":
			mac, err := net.ParseMAC(value)
			if err != nil || len(mac) != 6 {
				return "", syntheticBaselinePolicyRefusal("pre-dnat.mac")
			}
			known, match = true, mac.String() == tuple.mac
		case "--sport", "--source-port":
			if _, _, err := syntheticBaselinePortRange(value); err != nil {
				return "", err
			}
		case "--mark", "--set-mark", "--set-xmark", "--log-prefix", "--log-level", "--reject-with":
			// Destination-independent predicates and deterministic mark/log targets.
		case "-m":
			if negated || !slices.Contains([]string{"tcp", "udp", "mark", "mac"}, value) {
				uncertain = syntheticBaselinePolicyRefusal("pre-dnat.match-extension")
			}
		case "-j", "-g", "--jump", "--goto":
			if target != "" || negated {
				return "", syntheticBaselinePolicyRefusal("pre-dnat.target-syntax")
			}
			target = value
			if value == "CONNMARK" {
				uncertain = syntheticBaselinePolicyRefusal("pre-dnat.conntrack-or-target")
			}
		default:
			if key == "-d" || key == "--destination" || strings.Contains(key, "orig") || strings.Contains(key, "ct") || key == "--match-set" {
				uncertain = syntheticBaselinePolicyRefusal("pre-dnat.destination-or-conntrack")
			} else {
				uncertain = syntheticBaselinePolicyRefusal("pre-dnat.unknown-option")
			}
		}
		if known {
			if negated {
				match = !match
			}
			if !match {
				nonmatch = true
			}
		}
		negated = false
	}
	if negated || target == "" {
		return "", syntheticBaselinePolicyRefusal("pre-dnat.syntax")
	}
	if nonmatch {
		return "", nil
	}
	if uncertain != nil {
		return "", uncertain
	}
	return target, nil
}

func syntheticBaselinePortRange(value string) (uint16, uint16, error) {
	parts := strings.Split(value, ":")
	if len(parts) > 2 || len(parts) == 0 {
		return 0, 0, syntheticBaselinePolicyRefusal("pre-dnat.port")
	}
	lo, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil || lo == 0 {
		return 0, 0, syntheticBaselinePolicyRefusal("pre-dnat.port")
	}
	hi := lo
	if len(parts) == 2 {
		hi, err = strconv.ParseUint(parts[1], 10, 16)
		if err != nil || hi < lo {
			return 0, 0, syntheticBaselinePolicyRefusal("pre-dnat.port")
		}
	}
	return uint16(lo), uint16(hi), nil
}
