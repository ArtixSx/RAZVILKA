package dataplane

import (
	"context"
	"slices"
)

// Apply-only, held inside the common receipt operation. The frozen compiler
// argv identifies a command; only that operation's durable intent/Needs and
// the original Guard authorize it. No private receipt, queue discovery or
// cached namespace grant is created by this wrapper.
type nfqwsScopedApplyRunner struct {
	base    NFQWS2Runner
	binding *NFQWSScopedBinding
	scoped  *NFQWSScopedPlan
	plan    PolicyEffectPlan
	tools   PolicyEffectTools
	guard   func(context.Context, int) error
}

func (r nfqwsScopedApplyRunner) Run(ctx context.Context, command string, args ...string) ([]byte, error) {
	if ctx == nil || r.base == nil || r.binding == nil || r.scoped == nil || r.guard == nil {
		return nil, ErrNFQWSScopedOwner
	}
	index := -1
	for i, effect := range r.plan.Effects {
		if command == r.tools.command(effect.Tool) && slices.Equal(args, effect.Add) {
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
	if err := r.binding.readbackPrefix(ctx, r.scoped, nfqwsScopedPartial, index, index); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// The original runner consumes CORE authority at the actual Cmd.Start.
	// Keep the executed argv detached even from the wrapper's private copy.
	out, err := r.base.Run(ctx, command, slices.Clone(r.plan.Effects[index].Add)...)
	if err != nil {
		return nil, err // A possibly completed RPC still retains common intent.
	}
	if err := r.binding.postAdd(ctx, r.scoped, r.plan.Effects[index].Tool, index); err != nil {
		return nil, err // Never ACK a missing/duplicate/unknown actual result.
	}
	return out, nil
}

// A fresh target-table observation after RPC grants no whole namespace or
// next-effect permission. Both full ExactPresence calls and the full pre-RPC
// proof remain fresh for every subsequent effect; Apply closes with COMPLETE.
func (b *NFQWSScopedBinding) postAdd(ctx context.Context, p *NFQWSScopedPlan, tool PolicyEffectTool, index int) error {
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
			continue // No stale peer-family facts are borrowed from pre-RPC.
		}
		wanted := 0
		if i <= index {
			wanted = 1
		}
		if count != wanted {
			return ErrNFQWSScopedOwner
		}
	}
	return ctx.Err()
}
