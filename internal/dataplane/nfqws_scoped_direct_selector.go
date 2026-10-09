package dataplane

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// Only CompileNFQWSScopedPlan calls this after validating the complete frozen
// DEFAULT matches and NFQ-only LAN intent. Destination negatives have already
// been subtracted by that original producer; a generic route never supplies
// replacement ports, destinations or positive coverage here.
func nfqwsScopedDirectChains(lan *LANPolicyRuntimePlan, spec NFQWSScopedSpec, nameHash string) ([]nfqwsScopedChain, error) {
	if lan == nil || lan.Mode != LANPolicyNFQWSDirectMode || len(spec.Matches) == 0 {
		return nil, ErrNFQWSScopedOwner
	}
	ingress := make(map[string]LANPolicyIngress, len(lan.Ingress))
	for _, gate := range lan.Ingress {
		ingress[gate.Interface] = gate
	}
	// Bound the MAC product before allocating rule argv. Never truncate the
	// original scope to make an oversized selector look executable.
	captures := 0
	for _, match := range spec.Matches {
		gate, exists := ingress[match.Ingress]
		if !exists {
			return nil, ErrNFQWSScopedOwner
		}
		captures += max(1, len(gate.IncludedMACs))
		if captures > 2048 {
			return nil, ErrNFQWSScopedOwner
		}
	}
	var chains []nfqwsScopedChain
	effectCount := 0
	for _, family := range []int{4, 6} {
		chain := nfqwsScopedChain{tool: PolicyEffectIPTables, name: fmt.Sprintf("RZQ_%s_%d", nameHash[:18], family)}
		if family == 6 {
			chain.tool = PolicyEffectIP6Tables
		}
		positives, jumps := map[string][]string{}, map[string][]string{}
		interfaces := map[string]bool{}
		for _, match := range spec.Matches {
			if match.Source.Addr().Is6() != (family == 6) {
				continue
			}
			gate := ingress[match.Ingress]
			macs := []string{""}
			if gate.Membership == "mac" {
				macs = gate.IncludedMACs
			}
			for _, mac := range macs {
				scope := []string{"-i", match.Ingress, "-s", match.Source.String()}
				if mac != "" {
					scope = append(scope, "-m", "mac", "--mac-source", mac)
				}
				port := strconv.Itoa(int(match.FirstPort))
				if match.LastPort != match.FirstPort {
					port += ":" + strconv.Itoa(int(match.LastPort))
				}
				rule := append(slices.Clone(scope), "-d", match.Destination.String(), "-p", match.Protocol, "-m", match.Protocol, "--dport", port, "-j", "NFQUEUE", "--queue-num", strconv.Itoa(int(spec.Queue)))
				positives[strings.Join(rule, "\x00")] = rule
				jump := append(slices.Clone(scope), "-j", chain.name)
				jumps[strings.Join(jump, "\x00")] = jump
				interfaces[match.Ingress] = true
			}
		}
		if len(positives) == 0 {
			continue // A negative-only family does not manufacture an attachment.
		}
		// Each negative is scoped by its own physical ingress. Keep this entire
		// prefix ahead of every positive, including positives of other routes.
		for _, iface := range sortedMapKeys(interfaces) {
			gate := ingress[iface]
			for _, mac := range gate.ExcludedMACs {
				chain.body = append(chain.body, []string{"-i", iface, "-m", "mac", "--mac-source", mac, "-j", "RETURN"})
			}
			for _, source := range gate.ExcludedSources {
				if strings.Contains(source, ":") == (family == 6) {
					chain.body = append(chain.body, []string{"-i", iface, "-s", source, "-j", "RETURN"})
				}
			}
		}
		for _, key := range nfqwsScopedDirectRuleKeys(positives) {
			chain.body = append(chain.body, positives[key])
		}
		for _, key := range nfqwsScopedDirectRuleKeys(jumps) {
			chain.jumps = append(chain.jumps, jumps[key])
		}
		effectCount += 1 + len(chain.body) + len(chain.jumps)
		if effectCount > MaxPolicyEffects {
			return nil, ErrNFQWSScopedOwner
		}
		chains = append(chains, chain)
	}
	return chains, nil
}

func nfqwsScopedDirectRuleKeys(rules map[string][]string) []string {
	keys := make([]string, 0, len(rules))
	for key := range rules {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}
