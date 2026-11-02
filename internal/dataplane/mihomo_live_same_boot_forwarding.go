package dataplane

import (
	"context"
	"errors"
	"reflect"
)

// Unlike the warm finalizer this leaves the original forwarding manifest in
// place. The complete runtime is moved into inert history only AFTER fresh
// process/kernel absence. No pathname unlink can remove a foreign replacement.
func removeMihomoSameBootForwarding(ctx context.Context, o *mihomoSameBootCleanup, a *ProxyTunnelAdapter, lease proxyForwardingLease) error {
	if o == nil || o.self != o || a == nil || a.Runner != o || a.StateRoot != o.read.proxy.StateRoot || !reflect.DeepEqual(lease.Policy, o.inputs.definition.Policy) {
		return ErrProxyPolicyUnknown
	}
	if err := o.current(ctx); err != nil {
		return err
	}
	for _, table := range proxyFirewallTables(lease.Policy) {
		if !lease.owns(table) {
			return ErrProxyPolicyUnknown
		}
		read := func() (proxyFirewallSnapshot, error) {
			if err := o.current(ctx); err != nil {
				return proxyFirewallSnapshot{}, err
			}
			snapshot, err := a.firewallSnapshot(ctx, table)
			if err != nil || !proxyFirewallSubset(snapshot, table) {
				return proxyFirewallSnapshot{}, errors.Join(ErrProxyPolicyUnknown, err)
			}
			if err := o.current(ctx); err != nil {
				return proxyFirewallSnapshot{}, err
			}
			return snapshot, nil
		}
		for _, parent := range []bool{true, false} {
			expected := table.rules
			if parent {
				expected = table.jumps
			}
			for _, rule := range expected {
				snapshot, err := read()
				if err != nil {
					return err
				}
				var selected []string
				chain := table.chain
				if parent {
					chain = table.parent
					for _, actual := range snapshot.references {
						if len(actual) > 0 && actual[0] == chain && proxyFirewallRuleKey(actual[1:]) == proxyFirewallRuleKey(rule) {
							if selected != nil {
								return ErrProxyPolicyUnknown
							}
							selected = actual[1:]
						}
					}
				} else {
					for _, actual := range snapshot.own {
						if proxyFirewallRuleKey(actual) == proxyFirewallRuleKey(rule) {
							if selected != nil {
								return ErrProxyPolicyUnknown
							}
							selected = actual
						}
					}
				}
				if selected == nil {
					continue
				}
				args := append([]string{"-t", table.table, "-D", chain}, selected...)
				if _, err := a.run(ctx, a.firewallBinary(table.v6), args...); err != nil {
					return err
				}
				closing, err := read()
				if err != nil {
					o.effectUnknown = true
					return err
				}
				if parent {
					for _, actual := range closing.references {
						if len(actual) > 0 && actual[0] == chain && proxyFirewallRuleKey(actual[1:]) == proxyFirewallRuleKey(selected) {
							o.effectUnknown = true
							return ErrProxyPolicyUnknown
						}
					}
				} else {
					for _, actual := range closing.own {
						if proxyFirewallRuleKey(actual) == proxyFirewallRuleKey(selected) {
							o.effectUnknown = true
							return ErrProxyPolicyUnknown
						}
					}
				}
			}
		}
		snapshot, err := read()
		if err != nil {
			return err
		}
		if len(snapshot.own) != 0 || len(snapshot.references) != 0 {
			return ErrProxyPolicyUnknown
		}
		if snapshot.declared {
			if _, err := a.run(ctx, a.firewallBinary(table.v6), "-t", table.table, "-X", table.chain); err != nil {
				return err
			}
		}
		closing, err := read()
		if err != nil || closing.declared || len(closing.own) != 0 || len(closing.references) != 0 {
			o.effectUnknown = true
			return errors.Join(ErrProxyPolicyUnknown, err)
		}
	}
	return o.current(ctx)
}
