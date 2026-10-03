package dataplane

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
)

func (r *LANPolicyRuntime) read(ctx context.Context, tool string, args ...string) (string, error) {
	out, err := r.Runner.Run(ctx, r.command(tool), args...)
	if err != nil || len(out) > 1<<20 || len(strings.Split(string(out), "\n")) > 8192 {
		return "", errors.Join(ErrLANPolicyRuntime, err)
	}
	return string(out), ctx.Err()
}

func lanPolicyRuleKey(line string) string {
	f := strings.Fields(line)
	// iproute2 writes selectors in its canonical order, regardless of argv.
	return strings.Join(f, " ")
}

// Preflight is read-only and admits a NEW generation only. Replacement of
// an earlier gate must be coordinated by the existing Manager/receipt owner;
// an identical-looking occupant is never adopted here.
func (r *LANPolicyRuntime) Preflight(ctx context.Context, p *LANPolicyRuntimePlan) error {
	if err := r.check(ctx, p); err != nil {
		return err
	}
	for _, family := range []int{4, 6} {
		args := []string{"-4", "-N", "rule", "show"}
		if family == 6 {
			args[0] = "-6"
		}
		output, err := r.read(ctx, "ip", args...)
		if err != nil {
			return err
		}
		for _, line := range strings.Split(output, "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			priority, ok := policyLinePriority(line)
			if !ok || !lanPolicyRuleSyntax(line) {
				return ErrLANPolicyRuntime
			}
			if priority == LANPolicySkipPriority || priority == LANPolicyAnchorPriority {
				return ErrLANPolicyRuntime
			}
			f := strings.Fields(line)
			for i, value := range f {
				if value == "goto" && i+1 < len(f) && f[i+1] == "73" {
					return ErrLANPolicyRuntime
				}
				if value == "fwmark" && i+1 < len(f) && lanPolicyMarkTouches(f[i+1]) {
					return ErrLANPolicyRuntime
				}
				if (value == "lookup" || value == "table") && i+1 < len(f) {
					for _, owner := range PolicyOwnershipSpecs() {
						// Old IP-only selectors, especially indexed priorities,
						// cannot be skipped safely while preserving firmware.
						if f[i+1] == strconv.Itoa(owner.Table) {
							return ErrLANPolicyRuntime
						}
					}
				}
			}
		}
		tool := "iptables"
		if family == 6 {
			tool = "ip6tables"
		}
		for _, table := range []string{"mangle", "nat", "filter", "raw"} {
			output, err := r.read(ctx, tool, "-t", table, "-S")
			if err != nil {
				return err // missing table/capability is an explicit refusal
			}
			for _, line := range strings.Split(output, "\n") {
				f := strings.Fields(line)
				for i, value := range f {
					if strings.HasPrefix(value, "RZG_") {
						return ErrLANPolicyRuntime
					}
					if slices.Contains([]string{"--mark", "--set-mark", "--set-xmark", "--or-mark", "--xor-mark"}, value) && i+1 < len(f) && lanPolicyMarkTouches(f[i+1]) {
						return ErrLANPolicyRuntime
					}
					if value == "CONNMARK" || value == "--and-mark" {
						return ErrLANPolicyRuntime // no inferred connmark compatibility
					}
				}
			}
		}
	}
	return r.check(ctx, p)
}

func lanPolicyMarkTouches(value string) bool {
	parts := strings.Split(value, "/")
	if len(parts) == 0 || len(parts) > 2 {
		return true
	}
	mark, err := strconv.ParseUint(parts[0], 0, 32)
	if err != nil {
		return true
	}
	mask := uint64(^uint32(0))
	if len(parts) == 2 {
		mask, err = strconv.ParseUint(parts[1], 0, 32)
		if err != nil {
			return true
		}
	}
	return (mask|mark)&uint64(LANPolicyGateMask) != 0
}

// Verify checks exact chain order and ALL references, plus positive-gated
// owned RPDB selectors. This is required before another consumer activates.
func (r *LANPolicyRuntime) Verify(ctx context.Context, plan *LANPolicyRuntimePlan) error {
	p := CloneLANPolicyRuntime(plan)
	if err := r.check(ctx, p); err != nil {
		return err
	}
	for _, family := range []int{4, 6} {
		output, err := r.read(ctx, "ip", "-"+strconv.Itoa(family), "-N", "rule", "show")
		if err != nil {
			return err
		}
		want := map[string]int{}
		for _, rule := range lanPolicyRules(p) {
			if rule.family == family {
				want[rule.line()]++
			}
		}
		for _, line := range strings.Split(output, "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			priority, ok := policyLinePriority(line)
			if !ok || !lanPolicyRuleSyntax(line) {
				return ErrLANPolicyRuntime
			}
			if priority == LANPolicySkipPriority || priority == LANPolicyAnchorPriority {
				key := lanPolicyRuleKey(line)
				if want[key] != 1 {
					return ErrLANPolicyRuntime
				}
				want[key]--
			}
			f := strings.Fields(line)
			ownedPositive := false
			for i, value := range f {
				if value == "goto" && i+1 < len(f) && f[i+1] == "73" && priority != LANPolicySkipPriority {
					return ErrLANPolicyRuntime
				}
				if (value == "lookup" || value == "table") && i+1 < len(f) {
					for _, owner := range PolicyOwnershipSpecs() {
						if f[i+1] == strconv.Itoa(owner.Table) {
							if priority < 60 || priority > 72 || !strings.Contains(" "+strings.Join(f, " ")+" ", " fwmark 0x20000000/0x28000000 ") || !lanPolicyRuleIngress(f, p) {
								return ErrLANPolicyRuntime
							}
							ownedPositive = true
						}
					}
				}
			}
			for i, value := range f {
				if value == "fwmark" && i+1 < len(f) && lanPolicyMarkTouches(f[i+1]) && priority != LANPolicySkipPriority && !ownedPositive {
					return ErrLANPolicyRuntime
				}
			}
			if ownedPositive {
				if r.ConsumerCheck == nil {
					return ErrLANPolicyRuntime
				}
				if err := r.ConsumerCheck(ctx, CloneLANPolicyRuntime(p)); err != nil {
					return err
				}
			}
		}
		for _, count := range want {
			if count != 0 {
				return ErrLANPolicyRuntime
			}
		}
		tool := "iptables"
		if family == 6 {
			tool = "ip6tables"
		}
		output, err = r.read(ctx, tool, "-t", "mangle", "-S")
		if err != nil {
			return err
		}
		// All admission jumps must precede other PREROUTING actions. An
		// appended gate would arrive after a proxy/default mark or NFQUEUE.
		first := map[string]bool{}
		for _, c := range lanPolicyChains(p) {
			if c.family == family {
				first[lanClassifierChainKey(c.jump)] = true
			}
		}
		remaining := len(first)
		for _, line := range strings.Split(output, "\n") {
			f := strings.Fields(line)
			if remaining > 0 && len(f) > 2 && f[0] == "-A" && f[1] == "PREROUTING" {
				key := lanClassifierChainKey(f[2:])
				if !first[key] {
					return ErrLANPolicyRuntime
				}
				delete(first, key)
				remaining--
			}
		}
		for _, c := range lanPolicyChains(p) {
			if c.family != family {
				continue
			}
			if err := lanClassifierChainReadback(output, c.name, c.rules); err != nil {
				return err
			}
			refs := 0
			for _, line := range strings.Split(output, "\n") {
				f := strings.Fields(line)
				for i := 2; i+1 < len(f); i++ {
					if (f[i] == "-j" || f[i] == "-g") && f[i+1] == c.name {
						if len(f) < 3 || f[0] != "-A" || f[1] != "PREROUTING" || lanClassifierChainKey(f[2:]) != lanClassifierChainKey(c.jump) {
							return ErrLANPolicyRuntime
						}
						refs++
					}
				}
			}
			if refs != 1 {
				return ErrLANPolicyRuntime
			}
		}
		for _, table := range []string{"mangle", "nat", "filter", "raw"} {
			text := output
			if table != "mangle" {
				text, err = r.read(ctx, tool, "-t", table, "-S")
				if err != nil {
					return err
				}
			}
			for _, line := range strings.Split(text, "\n") {
				f := strings.Fields(line)
				if len(f) > 2 && f[0] == "-A" && lanPolicyOwnChain(p, f[1], family) {
					continue
				} // exact body was checked above
				for i, value := range f {
					if value == "CONNMARK" || value == "--and-mark" {
						return ErrLANPolicyRuntime
					}
					if slices.Contains([]string{"--mark", "--set-mark", "--set-xmark", "--or-mark", "--xor-mark"}, value) && i+1 < len(f) && lanPolicyMarkTouches(f[i+1]) {
						if value != "--mark" || f[i+1] != "0x20000000/0x28000000" || r.ConsumerCheck == nil {
							return ErrLANPolicyRuntime
						}
						if err := r.ConsumerCheck(ctx, CloneLANPolicyRuntime(p)); err != nil {
							return err
						}
					}
				}
			}
		}
	}
	return r.check(ctx, p)
}

func lanPolicyOwnChain(p *LANPolicyRuntimePlan, name string, family int) bool {
	for _, c := range lanPolicyChains(p) {
		if c.family == family && c.name == name {
			return true
		}
	}
	return false
}

// -N requests numeric tables. Named aliases are refused even if an old ip
// implementation silently ignores that option; an alias must not hide an
// owned table or let goto73 fall into a legacy tunnel selector.
func lanPolicyRuleSyntax(line string) bool {
	f := strings.Fields(line)
	if len(f) < 3 {
		return false
	}
	if _, ok := policyLinePriority(line); !ok {
		return false
	}
	for i := 1; i < len(f); i++ {
		switch f[i] {
		case "not", "nop", "blackhole", "unreachable", "prohibit", "l3mdev":
		case "from", "to", "fwmark", "iif", "oif", "goto", "lookup", "table", "tos", "dsfield", "uidrange", "ipproto", "sport", "dport", "suppress_prefixlength", "suppress_ifgroup", "protocol", "proto", "realms":
			kind := f[i]
			i++
			if i >= len(f) {
				return false
			}
			if kind == "lookup" || kind == "table" {
				if f[i] == "local" || f[i] == "main" || f[i] == "default" {
					continue
				}
				if n, err := strconv.ParseUint(f[i], 10, 32); err != nil || n == 0 {
					return false
				}
			}
			if kind == "proto" {
				if n, err := strconv.ParseUint(f[i], 10, 8); err != nil || n == 0 {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

// BeforeDelete is deliberately stronger than the count inspector. An anchor
// may not disappear while any goto still references it, and a chain must not
// disappear until ALL contents/references have been removed. Current review
// and Stop are not consulted during exact receipt-owned cleanup.
func (r *LANPolicyRuntime) BeforeDelete(ctx context.Context, p *LANPolicyRuntimePlan, e LANPolicyEffect) error {
	count, foreign, err := r.InspectEffect(ctx, p, e)
	if err != nil || foreign || count > 1 {
		return errors.Join(err, ErrLANPolicyRuntime)
	}
	if e.Tool == "ip" {
		isAnchor := slices.Contains(e.Add, "nop")
		if !isAnchor {
			return nil
		}
		text, err := r.read(ctx, "ip", e.Add[0], "-N", "rule", "show")
		if err != nil {
			return err
		}
		for _, line := range strings.Split(text, "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			if !lanPolicyRuleSyntax(line) {
				return ErrLANPolicyRuntime
			}
			f := strings.Fields(line)
			for i, value := range f {
				if value == "goto" && i+1 < len(f) && f[i+1] == "73" {
					return ErrLANPolicyRuntime
				}
			}
		}
		return nil
	}
	if len(e.Add) > 3 && (e.Add[2] == "-N" || e.Add[2] == "-A") {
		text, err := r.read(ctx, e.Tool, "-t", "mangle", "-S")
		if err != nil {
			return err
		}
		name := e.Add[3]
		for _, line := range strings.Split(text, "\n") {
			f := strings.Fields(line)
			if e.Add[2] == "-N" && len(f) > 2 && f[0] == "-A" && f[1] == name {
				return ErrLANPolicyRuntime
			}
			for i := 2; i+1 < len(f); i++ {
				if (f[i] == "-j" || f[i] == "-g") && f[i+1] == name {
					return ErrLANPolicyRuntime
				}
			}
		}
	}
	return nil
}

func lanPolicyRuleIngress(fields []string, p *LANPolicyRuntimePlan) bool {
	for i, field := range fields {
		if field == "iif" && i+1 < len(fields) {
			for _, g := range p.Ingress {
				if fields[i+1] == g.Interface {
					return true
				}
			}
		}
	}
	return false
}

// InspectEffect is the common receipt's read-only count/foreign inspector.
// The expected effect is reconstructed from the sealed plan, never trusted
// from receipt JSON. It also checks partial chain order and all references.
func (r *LANPolicyRuntime) InspectEffect(ctx context.Context, p *LANPolicyRuntimePlan, effect LANPolicyEffect) (count int, foreign bool, err error) {
	// Cleanup must remain possible after Stop, scope expiry and provider
	// changes. Current review authority is checked only before new effects.
	if err = r.checkTools(ctx, p); err != nil {
		return 0, false, err
	}
	effects, err := p.Effects()
	if err != nil {
		return 0, false, err
	}
	valid := false
	for _, expected := range effects {
		if expected.Tool == effect.Tool && slices.Equal(expected.Add, effect.Add) && slices.Equal(expected.Delete, effect.Delete) && slices.Equal(expected.Needs, effect.Needs) {
			valid = true
			break
		}
	}
	if !valid {
		return 0, true, ErrLANPolicyRuntime
	}
	if effect.Tool == "ip" {
		family := effect.Add[0]
		output, err := r.read(ctx, "ip", family, "-N", "rule", "show")
		if err != nil {
			return 0, false, err
		}
		for _, rule := range lanPolicyRules(p) {
			if slices.Equal(rule.args("add"), effect.Add) {
				for _, line := range strings.Split(output, "\n") {
					if strings.TrimSpace(line) == "" {
						continue
					}
					priority, ok := policyLinePriority(line)
					if !ok || !lanPolicyRuleSyntax(line) {
						return 0, true, ErrLANPolicyRuntime
					}
					f := strings.Fields(line)
					for i, value := range f {
						if value == "goto" && i+1 < len(f) && f[i+1] == "73" && priority != LANPolicySkipPriority {
							foreign = true
						}
					}
					if !ok || priority != rule.priority {
						continue
					}
					key, expected := lanPolicyRuleKey(line), false
					for _, peer := range lanPolicyRules(p) {
						if peer.family == rule.family && peer.priority == priority && peer.line() == key {
							expected = true
						}
					}
					foreign = foreign || !expected
					if key == rule.line() {
						count++
					}
				}
			}
		}
		return count, foreign || count > 1, nil
	}
	output, err := r.read(ctx, effect.Tool, "-t", "mangle", "-S")
	if err != nil {
		return 0, false, err
	}
	want := slices.Clone(effect.Add[2:])
	if want[0] == "-I" {
		want = append([]string{"-A", want[1]}, want[3:]...)
	}
	for _, line := range strings.Split(output, "\n") {
		if lanClassifierChainKey(strings.Fields(line)) == lanClassifierChainKey(want) {
			count++
		}
	}
	for _, c := range lanPolicyChains(p) {
		if c.family == 6 && effect.Tool != "ip6tables" || c.family == 4 && effect.Tool != "iptables" {
			continue
		}
		index, declared, refs := 0, 0, 0
		for _, line := range strings.Split(output, "\n") {
			f := strings.Fields(line)
			if len(f) == 2 && f[0] == "-N" && f[1] == c.name {
				declared++
			}
			if len(f) > 2 && f[0] == "-A" && f[1] == c.name {
				// Every partial prefix is an allowed interrupted installation;
				// reverse cleanup leaves such a prefix as well.
				if index >= len(c.rules) || lanClassifierChainKey(f[2:]) != lanClassifierChainKey(c.rules[index]) {
					foreign = true
				}
				index++
			}
			for i := 2; i+1 < len(f); i++ {
				if (f[i] == "-j" || f[i] == "-g") && f[i+1] == c.name {
					refs++
					foreign = foreign || f[0] != "-A" || f[1] != "PREROUTING" || lanClassifierChainKey(f[2:]) != lanClassifierChainKey(c.jump)
				}
			}
		}
		foreign = foreign || declared > 1 || refs > 1 || declared == 0 && (index != 0 || refs != 0) || refs > 0 && index != len(c.rules)
	}
	return count, foreign || count > 1, nil
}
