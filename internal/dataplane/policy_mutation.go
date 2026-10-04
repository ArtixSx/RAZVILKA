package dataplane

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

func applyRecordedPolicy(ctx context.Context, runner NFQWS2Runner, ipCommand string, state PolicyState) error {
	if runner == nil || ipCommand == "" {
		return errors.New("policy routing command runner is unavailable")
	}
	rules, err := kernelRulesForPolicy(state)
	if err != nil {
		return err
	}
	if len(rules) == 0 {
		return errors.New("policy routing rules are empty")
	}
	// A table number grants no ownership of defaults installed by another
	// process. Inspect BOTH families before the first mutation; do not infer
	// admission from the cleanup helper, which intentionally skips other devs.
	if err := inspectPolicyDefaults(ctx, runner, ipCommand, state, false); err != nil {
		return err
	}
	if state.RuleLayout == 2 {
		if err := verifyPolicyPrecedence(ctx, runner, ipCommand, state, true); err != nil {
			return err
		}
	}
	added := make([]kernelPolicyRule, 0, len(rules))
	created := map[int]bool{}
	rollback := func(cause error) error {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		return errors.Join(cause, removeAddedPolicy(cleanup, runner, ipCommand, state, added, created))
	}
	for _, family := range []int{4, 6} {
		args := []string{"route", "add", "default", "dev", state.Interface, "table", strconv.Itoa(state.Table), "proto", "boot", "metric", "0"}
		if family == 6 {
			args[len(args)-1] = "1024"
			args = append([]string{"-6"}, args...)
		}
		if _, err := runner.Run(ctx, ipCommand, args...); err != nil {
			return rollback(fmt.Errorf("create IPv%d policy table: %w", family, err))
		}
		created[family] = true
	}
	// A different-metric occupant may coexist with a successful netlink add.
	// Refuse it before selectors can route traffic to an ambiguous default.
	if err := inspectPolicyDefaults(ctx, runner, ipCommand, state, true); err != nil {
		return rollback(err)
	}
	for _, rule := range rules {
		if _, err := runner.Run(ctx, ipCommand, kernelRuleArgs("add", rule)...); err != nil {
			return rollback(fmt.Errorf("add exact policy selector: %w", err))
		}
		added = append(added, rule)
	}
	return nil
}

func readPolicyTable(ctx context.Context, runner NFQWS2Runner, command string, state PolicyState, family int) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	args := []string{"route", "show", "table", strconv.Itoa(state.Table)}
	if family == 6 {
		args = append([]string{"-6"}, args...)
	}
	out, err := runner.Run(ctx, command, args...)
	if contextErr := ctx.Err(); contextErr != nil {
		return nil, contextErr
	}
	if err != nil && ctx.Err() == nil {
		absent := fmt.Sprintf("Error: ipv%d: FIB table does not exist.", family)
		message := strings.TrimSpace(string(out))
		if message == absent || message == absent+"\nDump terminated" {
			return nil, nil
		}
	}
	if err != nil || len(out) > 1<<20 {
		return nil, errors.New("policy table inspection unavailable")
	}
	return out, nil
}

func inspectPolicyDefaults(ctx context.Context, runner NFQWS2Runner, command string, state PolicyState, created bool) error {
	var failures error
	for _, family := range []int{4, 6} {
		out, err := readPolicyTable(ctx, runner, command, state, family)
		if err != nil {
			failures = errors.Join(failures, err)
			continue
		}
		defaults := 0
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			switch fields[0] {
			case "unicast", "blackhole", "unreachable", "prohibit", "throw":
				fields = fields[1:]
			}
			if len(fields) == 0 {
				failures = errors.Join(failures, errors.New("unrecognized policy table entry"))
				continue
			}
			if fields[0] == "default" || fields[0] == "0.0.0.0/0" || fields[0] == "::/0" {
				defaults++
				continue
			}
			// Endpoint pins can coexist. Diagnostic text, multipath continuation
			// lines and unknown route syntax cannot prove an empty default slot.
			_, prefixErr := netip.ParsePrefix(fields[0])
			_, addrErr := netip.ParseAddr(fields[0])
			if prefixErr != nil && addrErr != nil {
				failures = errors.Join(failures, errors.New("unrecognized policy table entry"))
			}
		}
		if !created && defaults != 0 {
			failures = errors.Join(failures, fmt.Errorf("IPv%d policy table has an existing default", family))
		}
		if created {
			selector, err := recordedDefaultRoute(ctx, runner, command, state, family)
			if defaults != 1 || err != nil || len(selector) == 0 {
				failures = errors.Join(failures, err, fmt.Errorf("IPv%d policy default ownership is unconfirmed", family))
			}
		}
	}
	return failures
}

func removeAddedPolicy(ctx context.Context, runner NFQWS2Runner, command string, state PolicyState, rules []kernelPolicyRule, created map[int]bool) error {
	defaults := map[int][]string{}
	for _, family := range []int{4, 6} {
		if !created[family] {
			continue
		} // A failed add grants no cleanup authority.
		args, err := recordedDefaultRoute(ctx, runner, command, state, family)
		if err != nil {
			return err
		}
		defaults[family] = args
	}
	return removeKernelPolicyTuples(ctx, runner, command, state, rules, defaults)
}

func removeRecordedPolicy(ctx context.Context, runner NFQWS2Runner, ipCommand string, state PolicyState) error {
	if runner == nil || ipCommand == "" {
		return errors.New("policy routing command runner is unavailable")
	}
	rules, err := kernelRulesForPolicy(state)
	if err != nil {
		return err
	}
	return removeKernelPolicy(ctx, runner, ipCommand, state, rules)
}

// Deletion matches full recorded tuples, never an entire shared priority. A
// foreign/ambiguous occupant stops cleanup before any mutation: deleting a rule
// with omitted mark attributes could otherwise remove an unowned near-match.
func removeKernelPolicy(ctx context.Context, runner NFQWS2Runner, ipCommand string, state PolicyState, rules []kernelPolicyRule) error {
	// Snapshot both families before removing selectors. A table is a namespace,
	// not an ownership grant: endpoint pins and foreign routes may coexist.
	defaults := map[int][]string{}
	for _, family := range []int{4, 6} {
		args, err := recordedDefaultRoute(ctx, runner, ipCommand, state, family)
		if err != nil {
			return err
		}
		defaults[family] = args
	}
	return removeKernelPolicyTuples(ctx, runner, ipCommand, state, rules, defaults)
}

func removeKernelPolicyTuples(ctx context.Context, runner NFQWS2Runner, ipCommand string, state PolicyState, rules []kernelPolicyRule, defaults map[int][]string) error {
	wanted := map[kernelPolicyRule]bool{}
	families := map[int]bool{}
	priorities := map[int]bool{}
	for _, rule := range rules {
		wanted[rule] = true
		families[rule.family] = true
		priorities[rule.priority] = true
	}
	if state.RuleLayout == 2 {
		for family := range families {
			lines, err := readPolicyRules(ctx, runner, ipCommand, family)
			if err != nil {
				return err
			}
			seen := map[kernelPolicyRule]bool{}
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				priority, ok := policyLinePriority(line)
				if !ok {
					return errors.New("unrecognized policy rule during cleanup")
				}
				if priority < state.SharedPriorityBase || priority > state.SharedPriorityBase+1 {
					continue
				}
				parsed, ok := parseKernelPolicyRule(family, line)
				if !ok || !wanted[parsed] || seen[parsed] {
					return errors.New("shared policy cleanup has foreign or duplicate selectors")
				}
				seen[parsed] = true
			}
		}
	}
	var firstErr error
	for _, rule := range rules {
		if _, err := runner.Run(ctx, ipCommand, kernelRuleArgs("del", rule)...); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	var routeErr error
	for _, family := range []int{4, 6} {
		if args := defaults[family]; len(args) > 0 {
			_, deleteErr := runner.Run(ctx, ipCommand, args...)
			remaining, readErr := recordedDefaultRoute(ctx, runner, ipCommand, state, family)
			if readErr != nil || len(remaining) > 0 {
				routeErr = errors.Join(routeErr, deleteErr, readErr, fmt.Errorf("IPv%d owned default route removal is unconfirmed", family))
			}
		}
	}
	verified := false
	for _, family := range []int{4, 6} {
		if state.RuleLayout == 2 && !families[family] {
			continue
		}
		lines, err := readPolicyRules(ctx, runner, ipCommand, family)
		if err != nil {
			if state.RuleLayout == 2 {
				return errors.Join(firstErr, err)
			}
			continue
		}
		verified = true
		for _, line := range lines {
			priority, ok := policyLinePriority(line)
			if ok && priorities[priority] {
				return fmt.Errorf("policy rule priority %d remains after cleanup", priority)
			}
		}
	}
	if verified {
		return routeErr
	}
	return errors.Join(firstErr, routeErr)
}

// Returns a complete deletion selector only for the default installed by
// applyRecordedPolicy. Unknown attributes on a matching interface are not ours.
func recordedDefaultRoute(ctx context.Context, runner NFQWS2Runner, command string, state PolicyState, family int) ([]string, error) {
	out, err := readPolicyTable(ctx, runner, command, state, family)
	if err != nil {
		return nil, err
	}
	var deletion []string
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "unicast" {
			fields = fields[1:]
		}
		if len(fields) == 0 || fields[0] != "default" && fields[0] != "0.0.0.0/0" && fields[0] != "::/0" {
			continue
		}
		if policyRouteDevice([]byte(line)) != state.Interface {
			continue
		}
		if deletion != nil {
			return nil, errors.New("ambiguous default routes on owned interface")
		}
		selector := []string{"route", "del", "default", "dev", state.Interface, "table", strconv.Itoa(state.Table)}
		seen := map[string]bool{}
		for i := 1; i < len(fields); i += 2 {
			if i+1 >= len(fields) || seen[fields[i]] {
				return nil, errors.New("unrecognized default route attributes")
			}
			key, value := fields[i], fields[i+1]
			seen[key] = true
			switch key {
			case "dev":
				if value != state.Interface {
					return nil, errors.New("default route interface mismatch")
				}
			case "proto":
				if value != "boot" && value != "3" {
					return nil, errors.New("default route has foreign protocol")
				}
				selector = append(selector, key, "boot")
			case "scope":
				if value != "link" && value != "253" {
					return nil, errors.New("default route has foreign scope")
				}
				selector = append(selector, key, "link")
			case "metric":
				if value != "0" && !(family == 6 && value == "1024") {
					return nil, errors.New("default route has foreign metric")
				}
				selector = append(selector, key, value)
			case "pref":
				if family != 6 || value != "medium" {
					return nil, errors.New("default route has foreign preference")
				}
			default:
				return nil, errors.New("default route has unowned attributes")
			}
		}
		if family == 6 {
			selector = append([]string{"-6"}, selector...)
		}
		deletion = selector
	}
	return deletion, nil
}
