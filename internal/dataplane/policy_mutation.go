package dataplane

import (
	"context"
	"errors"
	"fmt"
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
	if state.RuleLayout == 2 {
		if err := verifyPolicyPrecedence(ctx, runner, ipCommand, state, true); err != nil {
			return err
		}
	}
	if _, err := runner.Run(ctx, ipCommand, "route", "replace", "default", "dev", state.Interface, "table", strconv.Itoa(state.Table)); err != nil {
		return fmt.Errorf("create IPv4 policy table: %w", err)
	}
	_, _ = runner.Run(ctx, ipCommand, "-6", "route", "replace", "default", "dev", state.Interface, "table", strconv.Itoa(state.Table))
	added := make([]kernelPolicyRule, 0, len(rules))
	for _, rule := range rules {
		if _, err := runner.Run(ctx, ipCommand, kernelRuleArgs("add", rule)...); err != nil {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			defer cancel()
			return errors.Join(fmt.Errorf("add exact policy selector: %w", err), removeKernelPolicy(cleanup, runner, ipCommand, state, added))
		}
		added = append(added, rule)
	}
	return nil
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
	args := []string{"route", "show", "table", strconv.Itoa(state.Table)}
	if family == 6 {
		args = append([]string{"-6"}, args...)
	}
	out, err := runner.Run(ctx, command, args...)
	if err != nil && ctx.Err() == nil {
		// iproute2 returns status 2 for a genuinely absent FIB. Other read
		// failures (including permissions or a lost command) remain unknown.
		message := strings.TrimSpace(string(out))
		empty := fmt.Sprintf("Error: ipv%d: FIB table does not exist.\nDump terminated", family)
		if message == empty {
			return nil, nil
		}
	}
	if err != nil || len(out) > 1<<20 {
		return nil, errors.New("policy table inspection unavailable during cleanup")
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
				if value != "boot" {
					return nil, errors.New("default route has foreign protocol")
				}
				selector = append(selector, key, value)
			case "scope":
				if value != "link" {
					return nil, errors.New("default route has foreign scope")
				}
				selector = append(selector, key, value)
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
