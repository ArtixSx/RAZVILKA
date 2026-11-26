package dataplane

import (
	"context"
	"errors"
	"slices"
	"strings"
)

// LANPolicySuspensionBinding uses the SAME mixed receipt implementation and
// Manager-owned retained references as the LAN gate. Fence gets a NEW resource
// root allocated by that Manager; it never opens the unknown consumer root to
// rewrite grants or turn observations into cleanup rights.
type LANPolicySuspensionBinding struct {
	Runtime *LANPolicyRuntime
	// FenceGuard admits this blocking action under current Stop/control, not
	// the expired candidate Apply review. Runner consumes process-start admission.
	FenceGuard   func(context.Context, *LANPolicySuspensionPlan, PolicyEffect) error
	CleanupGuard func(context.Context, *LANPolicySuspensionPlan, PolicyEffect) error
	// CaptureCheck proves complete class coverage and current physical scope,
	// absence of earlier raw consumers, and every protected baseline lease.
	// Unknown capture outcome may remain; unknown intent/coverage cannot pass.
	CaptureCheck func(context.Context, *LANPolicySuspensionPlan) error
	// ReleaseCheck proves all old captures/owned flows exactly settled. Fresh
	// replacement/changed exclusions are not a supported release shortcut.
	ReleaseCheck func(context.Context, *LANPolicySuspensionPlan) error
	options      policyAdditionOptions // package tests only
}

type lanPolicySuspensionCall struct {
	plan    *LANPolicySuspensionPlan
	lan     LANPolicyRuntime
	mixed   PolicyEffectPlan
	runtime PolicyEffectRuntime
}

// One fresh, bounded read batch per effect boundary. It cannot execute a
// mutation and is discarded before the next admission check/RPC.
type lanPolicySuspensionReadSnapshot map[string][]byte

func (s lanPolicySuspensionReadSnapshot) Run(ctx context.Context, tool string, args ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, ok := s[tool+"\x00"+strings.Join(args, "\x00")]
	if !ok {
		return nil, ErrLANPolicyRuntime
	}
	return slices.Clone(data), nil
}

func cloneLANPolicySuspensionEffect(e PolicyEffect) PolicyEffect {
	e.Add, e.Delete, e.Needs = slices.Clone(e.Add), slices.Clone(e.Delete), slices.Clone(e.Needs)
	return e
}

func (b *LANPolicySuspensionBinding) knownPrior(ctx context.Context, c *lanPolicySuspensionCall, priorRoot string) error {
	prior, err := LANPolicyEffectsPlan(c.plan.PriorLAN)
	if err != nil {
		return err
	}
	status, err := inspectPolicyEffects(ctx, prior, priorRoot, b.options)
	if err != nil || !status.Complete || status.Unknown || status.Removed || status.Promoted {
		return errors.Join(err, ErrPolicyAdditionUnknown)
	}
	effects, err := c.plan.PriorLAN.Effects()
	if err != nil {
		return err
	}
	reads := lanPolicySuspensionReadSnapshot{}
	for _, request := range []struct {
		tool string
		args []string
	}{
		{"ip", []string{"-4", "-N", "rule", "show"}}, {"ip", []string{"-6", "-N", "rule", "show"}},
		{"iptables", []string{"-t", "mangle", "-S"}}, {"ip6tables", []string{"-t", "mangle", "-S"}},
	} {
		output, err := c.lan.read(ctx, request.tool, request.args...)
		if err != nil {
			return err
		}
		reads[c.lan.command(request.tool)+"\x00"+strings.Join(request.args, "\x00")] = []byte(output)
	}
	reader := c.lan
	reader.Runner = reads
	for _, e := range effects {
		count, foreign, err := reader.InspectEffect(ctx, c.plan.PriorLAN, e)
		if err != nil || foreign || count != 1 {
			return errors.Join(err, ErrLANPolicyRuntime)
		}
	}
	return ctx.Err()
}

func (b *LANPolicySuspensionBinding) prepare(ctx context.Context, plan *LANPolicySuspensionPlan, priorRoot string, cleanup bool) (*lanPolicySuspensionCall, error) {
	if b == nil || b.Runtime == nil || b.FenceGuard == nil || b.CleanupGuard == nil || b.CaptureCheck == nil || b.ReleaseCheck == nil {
		return nil, ErrLANPolicyRuntime
	}
	if err := ValidateLANPolicySuspensionPlan(plan); err != nil {
		return nil, err
	}
	c := &lanPolicySuspensionCall{plan: CloneLANPolicySuspensionPlan(plan), lan: *b.Runtime}
	if err := c.lan.checkTools(ctx, c.plan.PriorLAN); err != nil {
		return nil, err
	}
	var err error
	c.mixed, err = c.plan.Effects()
	if err != nil {
		return nil, err
	}
	guard := b.FenceGuard
	if cleanup {
		guard = b.CleanupGuard
	}
	c.runtime = PolicyEffectRuntime{
		Runner: c.lan.Runner, Tools: PolicyEffectTools{IP: c.lan.IP, IPTables: c.lan.IPTables, IP6Tables: c.lan.IP6Tables},
		Preflight: func(ctx context.Context) error {
			if err := b.knownPrior(ctx, c, priorRoot); err != nil {
				return err
			}
			if err := b.CaptureCheck(ctx, CloneLANPolicySuspensionPlan(c.plan)); err != nil {
				return err
			}
			for _, tool := range []string{"iptables", "ip6tables"} {
				for _, table := range []string{"raw", "mangle", "nat", "filter"} {
					output, err := c.lan.read(ctx, tool, "-t", table, "-S")
					if err != nil {
						return err
					}
					for _, token := range strings.Fields(output) {
						if strings.HasPrefix(token, "RZB_") {
							return ErrLANPolicyRuntime
						}
					}
				}
			}
			return ctx.Err()
		},
		ExactPresence: func(ctx context.Context, index int) (int, error) { return c.inspect(ctx, index) },
		BeforeDelete: func(ctx context.Context, index int) error {
			if err := b.ReleaseCheck(ctx, CloneLANPolicySuspensionPlan(c.plan)); err != nil {
				return err
			}
			return c.beforeDelete(ctx, index)
		},
		Guard: func(ctx context.Context, index int) error {
			if index < 0 || index >= len(c.mixed.Effects) {
				return ErrLANPolicyRuntime
			}
			if err := errors.Join(ctx.Err(), guard(ctx, CloneLANPolicySuspensionPlan(c.plan), cloneLANPolicySuspensionEffect(c.mixed.Effects[index]))); err != nil {
				return err
			}
			if err := b.knownPrior(ctx, c, priorRoot); err != nil {
				return err
			}
			if cleanup {
				return b.ReleaseCheck(ctx, CloneLANPolicySuspensionPlan(c.plan))
			}
			return b.CaptureCheck(ctx, CloneLANPolicySuspensionPlan(c.plan))
		},
	}
	return c, nil
}

func (c *lanPolicySuspensionCall) readTable(ctx context.Context, tool PolicyEffectTool) (string, error) {
	return c.lan.read(ctx, string(tool), "-t", "mangle", "-S")
}

func (c *lanPolicySuspensionCall) inspect(ctx context.Context, index int) (int, error) {
	if index < 0 || index >= len(c.mixed.Effects) {
		return 0, ErrLANPolicyRuntime
	}
	effect := c.mixed.Effects[index]
	output, err := c.readTable(ctx, effect.Tool)
	if err != nil {
		return 0, err
	}
	want := slices.Clone(effect.Add[2:])
	if want[0] == "-I" {
		want = append([]string{"-A", want[1]}, want[3:]...)
	}
	count := 0
	chains := lanPolicySuspensionChains(c.plan)
	expected := map[string]lanPolicyChain{}
	for _, chain := range chains {
		if chain.family == 4 && effect.Tool == PolicyEffectIPTables || chain.family == 6 && effect.Tool == PolicyEffectIP6Tables {
			expected[chain.name] = chain
		}
	}
	for _, line := range strings.Split(output, "\n") {
		f := strings.Fields(line)
		if lanClassifierChainKey(f) == lanClassifierChainKey(want) {
			count++
		}
		for _, token := range f {
			if strings.HasPrefix(token, "RZB_") {
				if _, ok := expected[token]; !ok {
					return 0, ErrLANPolicyRuntime
				}
			}
		}
	}
	for _, chain := range expected {
		declared, body, refs := 0, 0, 0
		pastHead := false
		for _, line := range strings.Split(output, "\n") {
			f := strings.Fields(line)
			if len(f) == 2 && f[0] == "-N" && f[1] == chain.name {
				declared++
			}
			if len(f) > 2 && f[0] == "-A" && f[1] == chain.name {
				if body >= len(chain.rules) || lanClassifierChainKey(f[2:]) != lanClassifierChainKey(chain.rules[body]) {
					return 0, ErrLANPolicyRuntime
				}
				body++
			}
			if len(f) > 2 && f[0] == "-A" && f[1] == "PREROUTING" {
				barrierJump := false
				for _, peer := range expected {
					barrierJump = barrierJump || lanClassifierChainKey(f[2:]) == lanClassifierChainKey(peer.jump)
				}
				pastHead = pastHead || !barrierJump
			}
			for i := 2; i+1 < len(f); i++ {
				if (f[i] == "-j" || f[i] == "-g") && f[i+1] == chain.name {
					if f[0] != "-A" || f[1] != "PREROUTING" || lanClassifierChainKey(f[2:]) != lanClassifierChainKey(chain.jump) || pastHead {
						return 0, ErrLANPolicyRuntime
					}
					refs++
				}
			}
		}
		if declared > 1 || refs > 1 || declared == 0 && (body != 0 || refs != 0) || refs > 0 && body != len(chain.rules) {
			return 0, ErrLANPolicyRuntime
		}
	}
	if count > 1 {
		return 0, ErrLANPolicyRuntime
	}
	return count, ctx.Err()
}

func (c *lanPolicySuspensionCall) beforeDelete(ctx context.Context, index int) error {
	if index < 0 || index >= len(c.mixed.Effects) {
		return ErrLANPolicyRuntime
	}
	e := c.mixed.Effects[index]
	if e.Add[2] == "-I" {
		return nil
	}
	output, err := c.readTable(ctx, e.Tool)
	if err != nil {
		return err
	}
	chain := e.Add[3]
	for _, line := range strings.Split(output, "\n") {
		f := strings.Fields(line)
		for i := 2; i+1 < len(f); i++ {
			if (f[i] == "-j" || f[i] == "-g") && f[i+1] == chain {
				return ErrLANPolicyRuntime
			}
		}
		if e.Add[2] == "-N" && len(f) > 2 && f[0] == "-A" && f[1] == chain {
			return ErrLANPolicyRuntime
		}
	}
	return ctx.Err()
}

func (c *lanPolicySuspensionCall) verify(ctx context.Context, present bool) error {
	want := 0
	if present {
		want = 1
	}
	for i := range c.mixed.Effects {
		n, err := c.inspect(ctx, i)
		if err != nil || n != want {
			return errors.Join(err, ErrLANPolicyRuntime)
		}
	}
	return ctx.Err()
}

func (b *LANPolicySuspensionBinding) Fence(ctx context.Context, plan *LANPolicySuspensionPlan, priorRoot, root string) error {
	if policyAdditionRootHash(priorRoot) == policyAdditionRootHash(root) {
		return ErrLANPolicyRuntime
	}
	c, err := b.prepare(ctx, plan, priorRoot, false)
	if err != nil {
		return err
	}
	if err := applyPolicyEffects(ctx, c.runtime, c.mixed, root, b.options); err != nil {
		return err
	}
	if err := c.verify(ctx, true); err != nil {
		return err
	}
	return c.runtime.Guard(ctx, len(c.mixed.Effects)-1)
}

func (b *LANPolicySuspensionBinding) Remove(ctx context.Context, plan *LANPolicySuspensionPlan, priorRoot, root string) error {
	if policyAdditionRootHash(priorRoot) == policyAdditionRootHash(root) {
		return ErrLANPolicyRuntime
	}
	c, err := b.prepare(ctx, plan, priorRoot, true)
	if err != nil {
		return err
	}
	if err := b.ReleaseCheck(ctx, CloneLANPolicySuspensionPlan(c.plan)); err != nil {
		return err
	}
	if err := removePolicyEffects(ctx, c.runtime, c.mixed, root, b.options); err != nil {
		return err
	}
	if err := c.verify(ctx, false); err != nil {
		return err
	}
	return c.runtime.Guard(ctx, 0)
}

func (b *LANPolicySuspensionBinding) Inspect(ctx context.Context, plan *LANPolicySuspensionPlan, root string) (PolicyAdditionStatus, error) {
	if b == nil {
		return PolicyAdditionStatus{}, ErrLANPolicyRuntime
	}
	expected, err := plan.Effects()
	if err != nil {
		return PolicyAdditionStatus{}, err
	}
	return inspectPolicyEffects(ctx, expected, root, b.options)
}

func (b *LANPolicySuspensionBinding) Promote(ctx context.Context, plan *LANPolicySuspensionPlan, priorRoot, source, destination string) error {
	if policyAdditionRootHash(priorRoot) == policyAdditionRootHash(source) || policyAdditionRootHash(priorRoot) == policyAdditionRootHash(destination) {
		return ErrLANPolicyRuntime
	}
	c, err := b.prepare(ctx, plan, priorRoot, false)
	if err != nil {
		return err
	}
	if err := c.runtime.Guard(ctx, len(c.mixed.Effects)-1); err != nil {
		return err
	}
	if err := c.verify(ctx, true); err != nil {
		return err
	}
	if err := promotePolicyEffects(ctx, c.mixed, source, destination, b.options); err != nil {
		return err
	}
	return c.runtime.Guard(ctx, len(c.mixed.Effects)-1)
}
