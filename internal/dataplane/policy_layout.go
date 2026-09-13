package dataplane

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// initializePolicyLayout is used only for a newly reviewed/compiled policy.
// Restoring a recorded snapshot must retain its original kernel coordinates.
func initializePolicyLayout(state *PolicyState) {
	for _, spec := range PolicyOwnershipSpecs() {
		if state.Interface == spec.Interface && state.Table == spec.Table && state.PriorityBase == spec.PriorityBase {
			state.RuleLayout, state.SharedPriorityBase = 2, spec.SharedPriorityBase
			return
		}
	}
}

func validPolicyLayout(state PolicyState) error {
	if state.RuleLayout == 0 && state.SharedPriorityBase == 0 {
		return nil
	}
	if state.RuleLayout == 2 {
		for _, spec := range PolicyOwnershipSpecs() {
			if state.Interface == spec.Interface && state.Table == spec.Table && state.PriorityBase == spec.PriorityBase && state.SharedPriorityBase == spec.SharedPriorityBase {
				return nil
			}
		}
	}
	return errors.New("invalid recorded policy rule layout")
}

// Equal-priority rules are unambiguous: every endpoint rule selects main and
// every service rule selects this adapter's table. Separate slots preserve
// exclusion order; different adapters never share a slot. Client selectors on
// early exclusions prevent changing other devices' existing firmware policies.
func kernelRulesForPolicy(state PolicyState) ([]kernelPolicyRule, error) {
	if err := validPolicyLayout(state); err != nil {
		return nil, err
	}
	if state.Table < 1 || state.Table > 252 || state.PriorityBase < 1000 || state.Interface == "" {
		return nil, errors.New("invalid policy routing state")
	}
	services := effectivePolicyRules(state)
	if len(services)+len(state.Exclusions) > maxPolicyPrefixes {
		return nil, errors.New("policy routing rule bound exceeded")
	}
	var out []kernelPolicyRule
	appendRule := func(source, destination string, priority, table int) error {
		dest, err := netip.ParsePrefix(destination)
		if err != nil || dest.Addr().Is4In6() || dest != dest.Masked() {
			return errors.New("invalid policy routing destination")
		}
		if source == "" {
			source = "all"
		} else {
			src, err := netip.ParsePrefix(source)
			if err != nil || src.Addr().Is4In6() || src != src.Masked() || src.Addr().Is4() != dest.Addr().Is4() {
				return errors.New("invalid policy routing source")
			}
			if src.Bits() == 0 {
				source = "all"
			}
		}
		family := 6
		if dest.Addr().Is4() {
			family = 4
		}
		out = append(out, kernelPolicyRule{family: family, priority: priority, table: table, source: source, destination: dest.String()})
		if len(out) > maxPolicyPrefixes {
			return errors.New("expanded policy routing rule bound exceeded")
		}
		return nil
	}
	for index, destination := range state.Exclusions {
		if state.RuleLayout == 0 {
			if err := appendRule("", destination, state.PriorityBase+index, 254); err != nil {
				return nil, err
			}
			continue
		}
		dest, err := netip.ParsePrefix(destination)
		if err != nil {
			return nil, err
		}
		sources := map[string]bool{}
		for _, service := range services {
			serviceDest, err := netip.ParsePrefix(service.Destination)
			if err != nil {
				return nil, err
			}
			if serviceDest.Addr().Is4() == dest.Addr().Is4() {
				sources[service.Source] = true
			}
		}
		ordered := make([]string, 0, len(sources))
		for source := range sources {
			ordered = append(ordered, source)
		}
		sort.Strings(ordered)
		for _, source := range ordered {
			if err := appendRule(source, destination, state.SharedPriorityBase, 254); err != nil {
				return nil, err
			}
		}
	}
	for index, service := range services {
		priority := state.PriorityBase + len(state.Exclusions) + index
		if state.RuleLayout == 2 {
			priority = state.SharedPriorityBase + 1
		}
		if err := appendRule(service.Source, service.Destination, priority, state.Table); err != nil {
			return nil, err
		}
	}
	seen := map[kernelPolicyRule]bool{}
	for _, rule := range out {
		if seen[rule] {
			return nil, errors.New("duplicate policy routing selector")
		}
		seen[rule] = true
	}
	return out, nil
}

func kernelRuleArgs(action string, rule kernelPolicyRule) []string {
	args := []string{"rule", action, "priority", strconv.Itoa(rule.priority)}
	if rule.source != "all" {
		args = append(args, "from", rule.source)
	}
	args = append(args, "to", rule.destination, "lookup")
	if rule.table == 254 {
		args = append(args, "main")
	} else {
		args = append(args, strconv.Itoa(rule.table))
	}
	if rule.family == 6 {
		args = append([]string{"-6"}, args...)
	}
	return args
}

func readPolicyRules(ctx context.Context, runner NFQWS2Runner, ipCommand string, family int) ([]string, error) {
	args := []string{"rule", "show"}
	if family == 6 {
		args = append([]string{"-6"}, args...)
	}
	output, err := runner.Run(ctx, ipCommand, args...)
	if err != nil || len(output) > 1<<20 {
		return nil, errors.New("kernel policy rule inspection unavailable")
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) > 8192 {
		return nil, errors.New("kernel policy rule inspection exceeds bound")
	}
	return lines, nil
}

func policyLinePriority(line string) (int, bool) {
	fields := strings.Fields(line)
	if len(fields) == 0 || !strings.HasSuffix(fields[0], ":") {
		return 0, false
	}
	text := strings.TrimSuffix(fields[0], ":")
	priority, err := strconv.Atoi(text)
	return priority, err == nil && priority >= 0 && strconv.Itoa(priority) == text
}

// Positive source/destination constraints can prove an earlier foreign rule
// disjoint even when its fwmark is unknown. Negation or unknown addresses never
// grant that exception. We do not infer a packet's skb mark from conntrack.
func policyLineMayOverlap(line string, target kernelPolicyRule) bool {
	fields := strings.Fields(line)
	selectorCounts := map[string]int{}
	for _, field := range fields {
		if field == "not" || field == "!" {
			return true
		}
		if field == "from" || field == "to" {
			selectorCounts[field]++
			if selectorCounts[field] > 1 {
				return true
			}
		}
	}
	for _, selector := range []struct{ name, target string }{{"from", target.source}, {"to", target.destination}} {
		if selector.target == "all" {
			continue
		}
		wanted, err := netip.ParsePrefix(selector.target)
		if err != nil {
			return true
		}
		count := 0
		for i, field := range fields {
			if field != selector.name {
				continue
			}
			count++
			if count > 1 || i+1 >= len(fields) {
				return true
			}
			value := fields[i+1]
			if value == "all" {
				continue
			}
			actual, err := netip.ParsePrefix(value)
			if err != nil {
				address, addressErr := netip.ParseAddr(value)
				if addressErr != nil {
					return true
				}
				actual = netip.PrefixFrom(address, address.BitLen())
			}
			if actual.Addr().Is4In6() || actual != actual.Masked() {
				return true
			}
			if !actual.Overlaps(wanted) {
				return false
			}
		}
	}
	return true
}

// A complete early mark-independent selector proves routing precedence for any
// skb mark, even on BusyBox ip without `route get ... mark`. Unmarked FIB output
// alone does not. Before creation the reserved slots must be completely empty;
// after creation every recorded tuple must exist exactly once and no foreign
// selector may share the slots or potentially intercept the same traffic.
func verifyPolicyPrecedence(ctx context.Context, runner NFQWS2Runner, ipCommand string, state PolicyState, beforeApply bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if runner == nil || ipCommand == "" {
		return errors.New("kernel policy rule inspection unavailable")
	}
	expected, err := kernelRulesForPolicy(state)
	if err != nil {
		return err
	}
	for _, family := range []int{4, 6} {
		want := map[kernelPolicyRule]bool{}
		for _, rule := range expected {
			if rule.family == family {
				want[rule] = true
			}
		}
		if len(want) == 0 {
			continue
		}
		lines, err := readPolicyRules(ctx, runner, ipCommand, family)
		if err != nil {
			return err
		}
		seen := map[kernelPolicyRule]bool{}
		for _, line := range lines {
			if err := ctx.Err(); err != nil {
				return err
			}
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			priority, ok := policyLinePriority(line)
			if !ok {
				return errors.New("unrecognized kernel policy rule")
			}
			parsed, simple := parseKernelPolicyRule(family, line)
			if state.RuleLayout == 2 && priority >= state.SharedPriorityBase && priority <= state.SharedPriorityBase+1 {
				if beforeApply || !simple || !want[parsed] || seen[parsed] {
					return fmt.Errorf("reserved policy priority %d has foreign or duplicate rules", priority)
				}
				seen[parsed] = true
				continue
			}
			if simple && want[parsed] {
				continue // Legacy tuple; retained only for legacy recovery.
			}
			normalized := strings.Join(strings.Fields(line), " ")
			if normalized == "0: from all lookup local" || normalized == "0: from all lookup 255" {
				continue // FIB check still proves the public destination is non-local.
			}
			for rule := range want {
				if err := ctx.Err(); err != nil {
					return err
				}
				if priority <= rule.priority && policyLineMayOverlap(line, rule) {
					return fmt.Errorf("earlier foreign policy priority %d may intercept the selected traffic", priority)
				}
			}
		}
		if state.RuleLayout == 2 && !beforeApply && len(seen) != len(want) {
			return errors.New("recorded early policy selectors are missing")
		}
	}
	return ctx.Err()
}
