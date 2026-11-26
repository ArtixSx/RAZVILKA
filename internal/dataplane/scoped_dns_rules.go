package dataplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

type scopedDNSRule struct {
	chain        string
	args, target []string
}

func (a *ScopedDNSAdapter) rules(p *ScopedDNSPlan) []scopedDNSRule {
	seen := map[string]bool{}
	var clients []string
	for _, b := range p.Bindings {
		if !seen[b.Client] {
			seen[b.Client] = true
			clients = append(clients, b.Client)
		}
	}
	sort.Strings(clients)
	gateway := netip.MustParseAddrPort(p.Listener).Addr().String() + "/32"
	var rules []scopedDNSRule
	for _, client := range clients {
		for _, protocol := range []string{"udp", "tcp"} {
			id := sha256.Sum256([]byte(filepath.Clean(a.StateRoot) + "\x00" + p.Listener + "\x00" + p.Ingress + "\x00" + client + "\x00" + protocol))
			chain := "RZD_" + hex.EncodeToString(id[:10])
			args := []string{"-s", client + "/32", "-d", gateway, "-i", p.Ingress, "-p", protocol, "-m", protocol, "--dport", "53", "-j", chain}
			rules = append(rules, scopedDNSRule{chain, args, []string{"-p", protocol, "-j", "DNAT", "--to-destination", p.Listener}})
		}
	}
	return rules
}

func (a *ScopedDNSAdapter) firewall(ctx context.Context, args ...string) ([]byte, error) {
	if a.Runner == nil || a.IPTables == "" {
		return nil, errors.New("scoped DNS firewall unavailable")
	}
	return runFirewallCommand(ctx, a.Runner, a.IPTables, append([]string{"-t", "nat"}, args...)...)
}

type dnsRulePresence struct{ chain, target, jump bool }

// Dedicated chains avoid the optional xt_comment module absent on some
// Keenetic kernels. The name is only an index: every rule and ALL references
// must match the recorded tuple before changing or removing anything.
func (a *ScopedDNSAdapter) rulePresent(ctx context.Context, r scopedDNSRule) (dnsRulePresence, error) {
	var p dnsRulePresence
	data, err := a.firewall(ctx, "-S")
	if err != nil || len(data) > 1<<20 {
		return p, errors.New("cannot inspect scoped DNS redirects")
	}
	chains, targets, refs := 0, 0, 0
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "-N" && f[1] == r.chain {
			chains++
		}
		if len(f) > 2 && f[0] == "-A" && f[1] == r.chain {
			if !reflect.DeepEqual(f[2:], r.target) {
				return p, errors.New("scoped DNS chain contains an unowned rule")
			}
			targets++
		}
		for i := 2; i+1 < len(f); i++ {
			if (f[i] == "-j" || f[i] == "-g") && f[i+1] == r.chain {
				if f[0] != "-A" || f[1] != "PREROUTING" {
					return p, errors.New("scoped DNS chain has a foreign reference")
				}
				refs++
			}
		}
	}
	if chains > 1 || targets > 1 || refs > 1 || chains == 0 && (targets != 0 || refs != 0) {
		return p, errors.New("scoped DNS chain ownership is ambiguous")
	}
	if refs == 1 {
		if _, err := a.firewall(ctx, append([]string{"-C", "PREROUTING"}, r.args...)...); err != nil {
			return p, errors.New("scoped DNS client redirect differs from its record")
		}
	}
	return dnsRulePresence{chains == 1, targets == 1, refs == 1}, ctx.Err()
}

func (a *ScopedDNSAdapter) readbackRules(ctx context.Context, p *ScopedDNSPlan, wanted bool) error {
	for _, r := range a.rules(p) {
		actual, err := a.rulePresent(ctx, r)
		if err != nil {
			return err
		}
		if actual != (dnsRulePresence{wanted, wanted, wanted}) {
			return errors.New("scoped DNS redirect readback differs")
		}
	}
	return ctx.Err()
}

func (a *ScopedDNSAdapter) changeRules(ctx context.Context, p *ScopedDNSPlan, add bool) error {
	rules := a.rules(p)
	for _, r := range rules {
		if _, err := a.rulePresent(ctx, r); err != nil {
			return err
		}
	}
	for _, r := range rules {
		present, err := a.rulePresent(ctx, r)
		if err != nil {
			return err
		}
		var commands [][]string
		if add {
			if !present.chain {
				commands = append(commands, []string{"-N", r.chain})
			}
			if !present.target {
				commands = append(commands, append([]string{"-A", r.chain}, r.target...))
			}
			if !present.jump {
				commands = append(commands, append([]string{"-I", "PREROUTING"}, r.args...))
			}
		} else {
			if present.jump {
				commands = append(commands, append([]string{"-D", "PREROUTING"}, r.args...))
			}
			if present.target {
				commands = append(commands, append([]string{"-D", r.chain}, r.target...))
			}
			if present.chain {
				commands = append(commands, []string{"-X", r.chain})
			}
		}
		for _, command := range commands {
			if _, err := a.firewall(ctx, command...); err != nil {
				return errors.New("scoped DNS redirect change failed")
			}
		}
	}
	return nil
}
