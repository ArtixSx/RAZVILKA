package dataplane

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"sync"
)

const maxPolicyPrefixes = 1024

// PolicyOwnershipSpec publishes the kernel resources reserved by each
// transactional tunnel adapter. Engine Lab uses the same source of truth as
// activation, so preflight cannot silently drift from runtime defaults.
type PolicyOwnershipSpec struct {
	Adapter      string
	Interface    string
	Table        int
	PriorityBase int
	PriorityEnd  int
}

func PolicyOwnershipSpecs() []PolicyOwnershipSpec {
	return []PolicyOwnershipSpec{
		{Adapter: "warp-wg", Interface: "rz-warp", Table: 201, PriorityBase: 18100, PriorityEnd: 18100 + maxPolicyPrefixes - 1},
		{Adapter: "usque", Interface: "rz-usque", Table: 202, PriorityBase: 20000, PriorityEnd: 20000 + maxPolicyPrefixes - 1},
		{Adapter: "sing-box", Interface: "rz-sing", Table: 203, PriorityBase: 22000, PriorityEnd: 22000 + maxPolicyPrefixes - 1},
		{Adapter: "xray", Interface: "rz-xray", Table: 204, PriorityBase: 24000, PriorityEnd: 24000 + maxPolicyPrefixes - 1},
		{Adapter: "amneziawg", Interface: "rz-awg", Table: 205, PriorityBase: 26000, PriorityEnd: 26000 + maxPolicyPrefixes - 1},
	}
}

type PrefixResolver func(context.Context, string) ([]netip.Addr, error)

type PolicyState struct {
	Interface    string       `json:"interface"`
	Table        int          `json:"table"`
	PriorityBase int          `json:"priority_base"`
	Prefixes     []string     `json:"prefixes"`
	Rules        []PolicyRule `json:"rules,omitempty"`
}

type PolicyRule struct {
	Source      string `json:"source,omitempty"`
	Destination string `json:"destination"`
}

func resolvePolicyPrefixes(ctx context.Context, plan Plan, adapter string, resolver PrefixResolver) ([]string, error) {
	if resolver == nil {
		resolver = func(ctx context.Context, domain string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", domain)
		}
	}
	prefixes := map[string]bool{}
	domains := map[string]bool{}
	for _, route := range plan.Routes {
		if adapterID(route.Resolved) != adapter {
			continue
		}
		for _, value := range route.CIDRs {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				address, addressErr := netip.ParseAddr(value)
				if addressErr != nil {
					return nil, fmt.Errorf("invalid policy prefix %q", value)
				}
				prefix = netip.PrefixFrom(address.Unmap(), address.BitLen())
			}
			prefixes[prefix.Masked().String()] = true
		}
		for _, domain := range route.Domains {
			domains[strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))] = true
		}
	}
	type result struct {
		addresses []netip.Addr
		err       error
	}
	semaphore := make(chan struct{}, 8)
	results := make(chan result, len(domains))
	var wait sync.WaitGroup
	for domain := range domains {
		if domain == "" {
			continue
		}
		wait.Add(1)
		go func(domain string) {
			defer wait.Done()
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-ctx.Done():
				results <- result{err: ctx.Err()}
				return
			}
			addresses, err := resolver(ctx, domain)
			results <- result{addresses: addresses, err: err}
		}(domain)
	}
	wait.Wait()
	close(results)
	resolved := 0
	for result := range results {
		if result.err != nil {
			continue
		}
		for _, address := range result.addresses {
			address = address.Unmap()
			if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
				continue
			}
			prefixes[netip.PrefixFrom(address, address.BitLen()).String()] = true
			resolved++
		}
	}
	if len(domains) > 0 && resolved == 0 && len(prefixes) == 0 {
		return nil, errors.New("none of the service domains resolved to a public address")
	}
	if len(prefixes) > maxPolicyPrefixes {
		return nil, fmt.Errorf("resolved policy contains %d prefixes; maximum is %d", len(prefixes), maxPolicyPrefixes)
	}
	out := make([]string, 0, len(prefixes))
	for prefix := range prefixes {
		out = append(out, prefix)
	}
	sort.Slice(out, func(i, j int) bool {
		left, _ := netip.ParsePrefix(out[i])
		right, _ := netip.ParsePrefix(out[j])
		if left.Addr().BitLen() != right.Addr().BitLen() {
			return left.Addr().BitLen() < right.Addr().BitLen()
		}
		return out[i] < out[j]
	})
	return out, nil
}

func resolvePolicyRules(ctx context.Context, plan Plan, adapter string, resolver PrefixResolver) ([]string, []PolicyRule, error) {
	prefixSet := map[string]bool{}
	ruleSet := map[string]PolicyRule{}
	global := map[string]bool{}
	for _, route := range plan.Routes {
		if adapterID(route.Resolved) != adapter {
			continue
		}
		prefixes, err := resolvePolicyPrefixes(ctx, Plan{Routes: []Route{route}}, adapter, resolver)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve %s policy for %s: %w", adapter, route.ServiceName, err)
		}
		sources := make([]netip.Prefix, 0, len(route.Sources))
		for _, value := range route.Sources {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				address, addressErr := netip.ParseAddr(value)
				if addressErr != nil {
					return nil, nil, fmt.Errorf("invalid device source %q", value)
				}
				address = address.Unmap()
				prefix = netip.PrefixFrom(address, address.BitLen())
			}
			sources = append(sources, prefix.Masked())
		}
		for _, destination := range prefixes {
			prefixSet[destination] = true
			destinationPrefix, _ := netip.ParsePrefix(destination)
			if len(sources) == 0 {
				global[destination] = true
				for key, rule := range ruleSet {
					if rule.Destination == destination {
						delete(ruleSet, key)
					}
				}
				ruleSet["\x00"+destination] = PolicyRule{Destination: destination}
				continue
			}
			if global[destination] {
				continue
			}
			for _, source := range sources {
				if source.Addr().Is4() != destinationPrefix.Addr().Is4() {
					continue
				}
				rule := PolicyRule{Source: source.String(), Destination: destination}
				ruleSet[rule.Source+"\x00"+rule.Destination] = rule
			}
		}
	}
	prefixes := make([]string, 0, len(prefixSet))
	for prefix := range prefixSet {
		prefixes = append(prefixes, prefix)
	}
	sort.Strings(prefixes)
	rules := make([]PolicyRule, 0, len(ruleSet))
	for _, rule := range ruleSet {
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Destination == rules[j].Destination {
			return rules[i].Source < rules[j].Source
		}
		return rules[i].Destination < rules[j].Destination
	})
	if len(rules) == 0 && len(prefixes) > 0 {
		return nil, nil, errors.New("device scopes do not match the destination address family")
	}
	if len(rules) > maxPolicyPrefixes {
		return nil, nil, fmt.Errorf("policy contains %d source/destination rules; maximum is %d", len(rules), maxPolicyPrefixes)
	}
	return prefixes, rules, nil
}

func applyPolicy(ctx context.Context, runner NFQWS2Runner, ipCommand string, state PolicyState) error {
	if runner == nil || ipCommand == "" {
		return errors.New("policy routing command runner is unavailable")
	}
	rules := effectivePolicyRules(state)
	if state.Table < 1 || state.Table > 252 || state.PriorityBase < 1000 || state.Interface == "" || len(rules) > maxPolicyPrefixes {
		return errors.New("invalid policy routing state")
	}
	if _, err := runner.Run(ctx, ipCommand, "route", "replace", "default", "dev", state.Interface, "table", fmt.Sprint(state.Table)); err != nil {
		return fmt.Errorf("create IPv4 policy table: %w", err)
	}
	_, _ = runner.Run(ctx, ipCommand, "-6", "route", "replace", "default", "dev", state.Interface, "table", fmt.Sprint(state.Table))
	added := []PolicyRule{}
	for index, rule := range rules {
		prefix, err := netip.ParsePrefix(rule.Destination)
		if err != nil {
			_ = removePolicy(ctx, runner, ipCommand, PolicyState{Interface: state.Interface, Table: state.Table, PriorityBase: state.PriorityBase, Rules: added})
			return err
		}
		args := []string{"rule", "add", "priority", fmt.Sprint(state.PriorityBase + index)}
		if rule.Source != "" {
			args = append(args, "from", rule.Source)
		}
		args = append(args, "to", prefix.String(), "lookup", fmt.Sprint(state.Table))
		if prefix.Addr().Is6() {
			args = append([]string{"-6"}, args...)
		}
		if _, err := runner.Run(ctx, ipCommand, args...); err != nil {
			_ = removePolicy(ctx, runner, ipCommand, PolicyState{Interface: state.Interface, Table: state.Table, PriorityBase: state.PriorityBase, Rules: added})
			return fmt.Errorf("add policy rule for %s: %w", prefix, err)
		}
		added = append(added, rule)
	}
	return nil
}

func removePolicy(ctx context.Context, runner NFQWS2Runner, ipCommand string, state PolicyState) error {
	if runner == nil || ipCommand == "" {
		return errors.New("policy routing command runner is unavailable")
	}
	var firstErr error
	rules := effectivePolicyRules(state)
	for index, rule := range rules {
		prefix, err := netip.ParsePrefix(rule.Destination)
		if err != nil {
			continue
		}
		args := []string{"rule", "del", "priority", fmt.Sprint(state.PriorityBase + index)}
		if rule.Source != "" {
			args = append(args, "from", rule.Source)
		}
		args = append(args, "to", prefix.String(), "lookup", fmt.Sprint(state.Table))
		if prefix.Addr().Is6() {
			args = append([]string{"-6"}, args...)
		}
		if _, err := runner.Run(ctx, ipCommand, args...); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if _, err := runner.Run(ctx, ipCommand, "route", "flush", "table", fmt.Sprint(state.Table)); err != nil && firstErr == nil {
		firstErr = err
	}
	_, _ = runner.Run(ctx, ipCommand, "-6", "route", "flush", "table", fmt.Sprint(state.Table))
	verified := false
	for _, familyArgs := range [][]string{{"rule", "show"}, {"-6", "rule", "show"}} {
		output, err := runner.Run(ctx, ipCommand, familyArgs...)
		if err != nil {
			continue
		}
		verified = true
		text := string(output)
		for index := range rules {
			priority := fmt.Sprint(state.PriorityBase + index)
			if strings.Contains(text, priority+":") || strings.Contains(text, "priority "+priority+" ") {
				return fmt.Errorf("policy rule priority %s remains after cleanup", priority)
			}
		}
	}
	if verified {
		return nil
	}
	return firstErr
}

func verifyPolicyEvidence(ctx context.Context, runner NFQWS2Runner, ipCommand string, state PolicyState) error {
	rules := effectivePolicyRules(state)
	if runner == nil || ipCommand == "" || state.Interface == "" || len(rules) == 0 {
		return errors.New("policy routing evidence is unavailable")
	}
	checked := 0
	for _, rule := range rules {
		prefix, err := netip.ParsePrefix(rule.Destination)
		if err != nil {
			return err
		}
		args := []string{"route", "get", prefix.Addr().String()}
		if rule.Source != "" {
			source, sourceErr := netip.ParsePrefix(rule.Source)
			if sourceErr != nil {
				return sourceErr
			}
			args = append(args, "from", source.Addr().String())
		}
		if prefix.Addr().Is6() {
			args = append([]string{"-6"}, args...)
		}
		output, routeErr := runner.Run(ctx, ipCommand, args...)
		if routeErr != nil || !strings.Contains(string(output), "dev "+state.Interface) {
			return fmt.Errorf("kernel route evidence for %s does not use %s: %s", prefix, state.Interface, shortOutput(output, routeErr))
		}
		checked++
		if checked >= 4 {
			break
		}
	}
	return nil
}

func effectivePolicyRules(state PolicyState) []PolicyRule {
	if len(state.Rules) > 0 {
		return state.Rules
	}
	rules := make([]PolicyRule, 0, len(state.Prefixes))
	for _, prefix := range state.Prefixes {
		rules = append(rules, PolicyRule{Destination: prefix})
	}
	return rules
}

func samePolicy(left, right PolicyState) bool {
	return left.Interface == right.Interface && left.Table == right.Table && left.PriorityBase == right.PriorityBase && reflect.DeepEqual(left.Prefixes, right.Prefixes) && reflect.DeepEqual(effectivePolicyRules(left), effectivePolicyRules(right))
}

func replacePolicy(ctx context.Context, runner NFQWS2Runner, ipCommand string, oldState, newState PolicyState) error {
	if samePolicy(oldState, newState) {
		return nil
	}
	if err := removePolicy(ctx, runner, ipCommand, oldState); err != nil {
		return fmt.Errorf("remove old policy: %w", err)
	}
	if err := applyPolicy(ctx, runner, ipCommand, newState); err != nil {
		_ = removePolicy(ctx, runner, ipCommand, newState)
		if restoreErr := applyPolicy(ctx, runner, ipCommand, oldState); restoreErr != nil {
			return fmt.Errorf("apply refreshed policy: %w; restore old policy: %v", err, restoreErr)
		}
		return fmt.Errorf("apply refreshed policy: %w", err)
	}
	return nil
}
