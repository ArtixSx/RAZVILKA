package dataplane

import (
	"context"
	"errors"
	"strings"
)

// This observer grants no effect authority. Unlike normal inactivity checking,
// an offline retirement may retain old files until they have been archived.
// Processes/interfaces bracket kernel readback; metadata is checked separately.
func observeBootRetirement(parent context.Context, a *ProxyTunnelAdapter, proof proxyInactiveProof) error {
	ctx, cancel := context.WithTimeout(parent, proxyInactiveBudget)
	defer cancel()
	owner, transit, err := a.inactiveCoordinates()
	if err != nil {
		return err
	}
	for pass := 0; pass < 2; pass++ {
		if err := proxyInactiveProc(ctx, proof, a); err != nil {
			return err
		}
		interfaces, err := proof.interfaces()
		if err != nil || len(interfaces) == 0 || len(interfaces) > 4096 {
			return ErrProxyRuntimeInactive
		}
		seen, loopback := map[string]bool{}, false
		for _, device := range interfaces {
			if device.Index < 1 || device.Name == "" || seen[device.Name] || device.Name == a.Interface {
				return ErrProxyRuntimeInactive
			}
			seen[device.Name] = true
			loopback = loopback || device.Name == "lo"
		}
		if !loopback {
			return ErrProxyRuntimeInactive
		}
		if pass == 0 {
			if err := observeBootRetirementKernel(ctx, a, owner, transit); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}

func observeBootRetirementKernel(ctx context.Context, a *ProxyTunnelAdapter, owner PolicyOwnershipSpec, transit int) error {
	runner := proxyInactiveRunner{adapter: a}
	numeric := numericPolicyReadRunner{base: runner}
	for _, family := range []int{4, 6} {
		if err := AssertPolicyDefaultUnreferenced(ctx, runner, a.ip(), PolicyState{Table: a.Table}, family); err != nil {
			return err
		}
		lines, err := readPolicyRules(ctx, numeric, a.ip(), family)
		if err != nil {
			return err
		}
		local, main, seen := false, false, map[int]bool{}
		for _, raw := range lines {
			line := strings.Join(strings.Fields(raw), " ")
			if line == "" {
				continue
			}
			priority, ok := policyLinePriority(line)
			if !ok || seen[priority] || priority >= owner.PriorityBase && priority <= owner.PriorityEnd ||
				priority >= owner.SharedPriorityBase && priority <= owner.SharedPriorityEnd || priority == transit {
				return ErrProxyRuntimeInactive
			}
			seen[priority] = true
			switch line {
			case "0: from all lookup 255":
				local = true
			case "32766: from all lookup 254":
				main = true
			case "32767: from all lookup 253":
			default:
				if parsed, ok := parseKernelPolicyRule(family, line); ok {
					if parsed.table == a.Table {
						return ErrProxyRuntimeInactive
					}
				} else if table, known := knownWGTransportRuleTable(family, line); known && table != a.Table {
					continue
				} else if !firmwarePolicyRule(family, line) {
					return ErrProxyRuntimeInactive
				}
			}
		}
		if !local || !main {
			return ErrProxyRuntimeInactive
		}
		routes, err := readPolicyTable(ctx, numeric, a.ip(), PolicyState{Table: a.Table}, family)
		if err != nil || strings.TrimSpace(string(routes)) != "" {
			return errors.Join(ErrProxyRuntimeInactive, err)
		}
	}
	for _, v6 := range []bool{false, true} {
		for _, pair := range [][2]string{{"filter", "FORWARD"}, {"nat", "POSTROUTING"}} {
			snapshot, err := a.firewallSnapshot(ctx, proxyFirewallTable{v6: v6, table: pair[0], parent: pair[1], chain: a.forwardingChain()})
			if err != nil || snapshot.declared || len(snapshot.own) != 0 || len(snapshot.references) != 0 {
				return errors.Join(ErrProxyRuntimeInactive, err)
			}
		}
	}
	return ctx.Err()
}
