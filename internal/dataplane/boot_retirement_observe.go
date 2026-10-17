package dataplane

import (
	"context"
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
		return bootProxyRetirementAt("proxy-coordinates", err)
	}
	for pass := 0; pass < 2; pass++ {
		if err := proxyInactiveProc(ctx, proof, a); err != nil {
			return bootProxyRetirementAt("proxy-processes", err)
		}
		interfaces, err := proof.interfaces()
		if err != nil {
			return bootProxyRetirementAt("proxy-interfaces", err)
		}
		if len(interfaces) == 0 || len(interfaces) > 4096 {
			return bootProxyRetirementAt("proxy-interface-inventory", nil)
		}
		seen, loopback := map[string]bool{}, false
		for _, device := range interfaces {
			if device.Index < 1 || device.Name == "" || seen[device.Name] {
				return bootProxyRetirementAt("proxy-interface-inventory", nil)
			}
			if device.Name == a.Interface {
				return bootProxyRetirementAt("proxy-interface-present", nil)
			}
			seen[device.Name] = true
			loopback = loopback || device.Name == "lo"
		}
		if !loopback {
			return bootProxyRetirementAt("proxy-loopback", nil)
		}
		if pass == 0 {
			if err := observeBootRetirementKernel(ctx, a, owner, transit); err != nil {
				return err
			}
		}
	}
	if ctx.Err() != nil {
		return bootProxyRetirementAt("proxy-context", ctx.Err())
	}
	return nil
}

func observeBootRetirementKernel(ctx context.Context, a *ProxyTunnelAdapter, owner PolicyOwnershipSpec, transit int) error {
	runner := proxyInactiveRunner{adapter: a}
	numeric := numericPolicyReadRunner{base: runner}
	for _, family := range []int{4, 6} {
		if err := AssertPolicyDefaultUnreferenced(ctx, runner, a.ip(), PolicyState{Table: a.Table}, family); err != nil {
			return bootProxyRetirementAt("proxy-default-references", err)
		}
		lines, err := readPolicyRules(ctx, numeric, a.ip(), family)
		if err != nil {
			return bootProxyRetirementAt("proxy-rules-read", err)
		}
		local, main, seen := false, false, map[int]bool{}
		for _, raw := range lines {
			line := strings.Join(strings.Fields(raw), " ")
			if line == "" {
				continue
			}
			priority, ok := policyLinePriority(line)
			if !ok || seen[priority] {
				return bootProxyRetirementAt("proxy-rules-inventory", nil)
			}
			if priority >= owner.PriorityBase && priority <= owner.PriorityEnd ||
				priority >= owner.SharedPriorityBase && priority <= owner.SharedPriorityEnd || priority == transit {
				return bootProxyRetirementAt("proxy-rules-owned", nil)
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
						return bootProxyRetirementAt("proxy-rules-owned", nil)
					}
				} else if table, known := knownWGTransportRuleTable(family, line); known && table != a.Table {
					continue
				} else if !firmwarePolicyRule(family, line) {
					return bootProxyRetirementAt("proxy-rules-unrecognized", nil)
				}
			}
		}
		if !local || !main {
			return bootProxyRetirementAt("proxy-rules-required", nil)
		}
		routes, err := readPolicyTable(ctx, numeric, a.ip(), PolicyState{Table: a.Table}, family)
		if err != nil {
			return bootProxyRetirementAt("proxy-table-read", err)
		}
		if strings.TrimSpace(string(routes)) != "" {
			return bootProxyRetirementAt("proxy-table-present", nil)
		}
	}
	for _, v6 := range []bool{false, true} {
		for _, pair := range [][2]string{{"filter", "FORWARD"}, {"nat", "POSTROUTING"}} {
			snapshot, err := a.firewallSnapshot(ctx, proxyFirewallTable{v6: v6, table: pair[0], parent: pair[1], chain: a.forwardingChain()})
			if err != nil {
				return bootProxyRetirementAt("proxy-firewall-read", err)
			}
			if snapshot.declared || len(snapshot.own) != 0 || len(snapshot.references) != 0 {
				return bootProxyRetirementAt("proxy-firewall-present", nil)
			}
		}
	}
	if ctx.Err() != nil {
		return bootProxyRetirementAt("proxy-context", ctx.Err())
	}
	return nil
}
