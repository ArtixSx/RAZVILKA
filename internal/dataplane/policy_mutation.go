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
	if _, err := runner.Run(ctx, ipCommand, "route", "flush", "table", strconv.Itoa(state.Table)); err != nil && firstErr == nil {
		firstErr = err
	}
	_, _ = runner.Run(ctx, ipCommand, "-6", "route", "flush", "table", strconv.Itoa(state.Table))
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
		return nil
	}
	return firstErr
}
