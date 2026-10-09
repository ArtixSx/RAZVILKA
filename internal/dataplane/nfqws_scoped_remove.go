package dataplane

import (
	"context"
	"slices"
)

// Remove-only, inside the existing common receipt operation. A matching frozen
// Delete identifies the effect but grants no ownership: common durable intent,
// hasUnsettledChild and the original CleanupGuard remain the deletion authority.
type nfqwsScopedRemoveRunner struct {
	base    NFQWS2Runner
	binding *NFQWSScopedBinding
	scoped  *NFQWSScopedPlan
	plan    PolicyEffectPlan
	tools   PolicyEffectTools
	guard   func(context.Context, int) error
}

func (r nfqwsScopedRemoveRunner) Run(ctx context.Context, command string, args ...string) ([]byte, error) {
	if ctx == nil || r.base == nil || r.binding == nil || r.scoped == nil || r.guard == nil {
		return nil, ErrNFQWSScopedOwner
	}
	index := -1
	for i, effect := range r.plan.Effects {
		if command == r.tools.command(effect.Tool) && slices.Equal(args, effect.Delete) {
			if index != -1 {
				return nil, ErrNFQWSScopedOwner
			}
			index = i
		}
	}
	if index < 0 {
		return nil, ErrNFQWSScopedOwner
	}
	if err := r.guard(ctx, index); err != nil {
		return nil, err
	}
	if err := r.binding.cleanupBoundary(ctx, r.scoped, index); err != nil {
		return nil, err
	}
	// Discard the bracket's image before its closing process/queue callbacks.
	// A new whole image must prove the exact reverse prefix and references
	// after all of those callbacks, immediately before the actual base RPC.
	rules, err := r.binding.readFinalRules(ctx, r.scoped)
	if err != nil {
		return nil, err
	}
	counts, err := r.binding.ruleCountsImage(r.scoped, rules, nfqwsScopedCleanup)
	if err != nil {
		return nil, err
	}
	if err := r.scoped.deleteReady(rules.rules, counts, index); err != nil {
		return nil, err
	}
	for i, count := range counts {
		wanted := 0
		if i <= index {
			wanted = 1
		}
		if count != wanted {
			return nil, ErrNFQWSScopedOwner
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// CORE admission is still consumed by the original runner at Cmd.Start.
	out, err := r.base.Run(ctx, command, slices.Clone(r.plan.Effects[index].Delete)...)
	if err != nil {
		return nil, err // An error after mutation never acknowledges removal.
	}
	if err := r.binding.postDelete(ctx, r.scoped, r.plan.Effects[index].Tool, index); err != nil {
		return nil, err // Keep common cleanup-intent on any uncertain result.
	}
	return out, nil
}

// One whole image within the exact inactive/ECHILD/ACK + empty queue bracket.
// This boundary does not return an image or a count. BeforeDelete's caller
// still performs its full ExactPresence, including absent-target settlement.
func (b *NFQWSScopedBinding) cleanupBoundary(ctx context.Context, p *NFQWSScopedPlan, index int) error {
	if ctx == nil || p == nil || index < 0 || index >= len(p.mixed.Effects) {
		return ErrNFQWSScopedOwner
	}
	if err := b.checkProcess(ctx, p, true); err != nil {
		return err
	}
	rules, err := b.readRules(ctx, p)
	if err != nil {
		return err
	}
	counts, err := b.ruleCountsImage(p, rules, nfqwsScopedCleanup)
	if err != nil {
		return err
	}
	if err := p.deleteReady(rules.rules, counts, index); err != nil {
		return err
	}
	return b.checkProcess(ctx, p, true)
}

// Pure dependency/reference checks on the SAME image. These assertions do not
// adopt an exact row or infer durable cleanup grants from kernel cardinality.
func (p *NFQWSScopedPlan) deleteReady(rules nfqwsScopedRules, counts []int, index int) error {
	if index < 0 || index >= len(p.mixed.Effects) || len(counts) != len(p.mixed.Effects) {
		return ErrNFQWSScopedOwner
	}
	for child, e := range p.mixed.Effects {
		if counts[child] != 0 && slices.Contains(e.Needs, index) {
			return ErrNFQWSScopedOwner
		}
	}
	e := p.mixed.Effects[index]
	if e.Add[2] != "-N" {
		return nil
	}
	name := e.Add[3]
	for _, tables := range rules {
		for _, rows := range tables {
			for _, fields := range rows {
				if fields[0] == "-A" && fields[1] == name {
					return ErrNFQWSScopedOwner
				}
				for i := 2; i+1 < len(fields); i++ {
					if (fields[i] == "-j" || fields[i] == "-g") && fields[i+1] == name {
						return ErrNFQWSScopedOwner
					}
				}
			}
		}
	}
	return nil
}

// A fresh target-table observation acknowledges only this completed RPC. It
// never replaces the common full post-delete ExactPresence or VerifyInactive.
func (b *NFQWSScopedBinding) postDelete(ctx context.Context, p *NFQWSScopedPlan, tool PolicyEffectTool, index int) error {
	if ctx == nil || p == nil || index < 0 || index >= len(p.mixed.Effects) || p.mixed.Effects[index].Tool != tool {
		return ErrNFQWSScopedOwner
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	image, err := b.readEffectImage(ctx, p, tool)
	if err != nil {
		return err
	}
	counts, err := b.scopedRowCountsImage(p, image)
	if err != nil {
		return err
	}
	for i, count := range counts {
		if p.mixed.Effects[i].Tool != tool {
			continue // No peer-family fact survives the actual Delete RPC.
		}
		wanted := 0
		if i < index {
			wanted = 1
		}
		if count != wanted {
			return ErrNFQWSScopedOwner
		}
	}
	return ctx.Err()
}
