package dataplane

import (
	"context"
	"errors"
	"reflect"
	"sync"
)

// This issuer exists only around the actual original COMMON Runner.Run.
// Receipt status and copied command metadata cannot create it. It does not
// authorize tools, an NFQ process or a Gate operation on their own.
type policyEffectCommandInvocation struct {
	self       *policyEffectCommandInvocation
	mu         sync.Mutex
	session    *policyEffectSession
	tools      PolicyEffectTools
	index      int
	cleanup    bool
	open, used bool
}

type policyEffectCommandInvocationKey struct{}

func (s *policyEffectSession) runCommand(ctx context.Context, runtime PolicyEffectRuntime, index int, cleanup bool, args []string) ([]byte, error) {
	if s.borrow == nil || ctx == nil || ctx.Err() != nil || index < 0 || index >= len(s.plan.Effects) {
		return nil, ErrPolicyAdditionReceipt
	}
	i := &policyEffectCommandInvocation{session: s, tools: runtime.Tools, index: index, cleanup: cleanup, open: true}
	i.self = i
	defer func() { i.mu.Lock(); i.open = false; i.mu.Unlock() }()
	ctx = context.WithValue(ctx, policyEffectCommandInvocationKey{}, i)
	return runtime.Runner.Run(ctx, runtime.Tools.command(s.plan.Effects[index].Tool), append([]string(nil), args...)...)
}

func observePolicyEffectCommandInvocation(ctx context.Context, plan PolicyEffectPlan, root, name string, args []string) (*policyEffectCommandInvocation, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrPolicyAdditionReceipt
	}
	i, ok := ctx.Value(policyEffectCommandInvocationKey{}).(*policyEffectCommandInvocation)
	if !ok || i == nil || i.self != i {
		return nil, ErrPolicyAdditionReceipt
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if !i.open || i.used || i.session == nil || i.index < 0 || i.index >= len(i.session.plan.Effects) || root != i.session.path || !reflect.DeepEqual(plan, i.session.plan) {
		return nil, ErrPolicyAdditionReceipt
	}
	effect := i.session.plan.Effects[i.index]
	expected := effect.Add
	if i.cleanup {
		expected = effect.Delete
	}
	if name != i.tools.command(effect.Tool) || !reflect.DeepEqual(args, expected) {
		return nil, ErrPolicyAdditionReceipt
	}
	if err := i.current(ctx); err != nil {
		return nil, err
	}
	return i, nil
}

// Called with i.mu held. Only original COMMON file/parser bookends are used;
// no tool/provider/Store/Scope/Gate/runner callback is reachable here.
func (i *policyEffectCommandInvocation) current(ctx context.Context) error {
	s := i.session
	if s == nil || s.borrow == nil || ctx.Value(policyEffectReceiptBorrowKey{}) != s.borrow {
		return ErrPolicyAdditionReceipt
	}
	o, present, err := observeBorrowedPolicyEffects(ctx, s.plan, s.path)
	if err != nil || !present {
		return errors.Join(ErrPolicyAdditionReceipt, err)
	}
	defer o.close()
	if o.absent || len(o.states) != len(s.plan.Effects) {
		return ErrPolicyAdditionReceipt
	}
	if i.cleanup {
		if o.states[i.index] != "cleanup-intent" {
			return ErrPolicyAdditionReceipt
		}
		for child := i.index + 1; child < len(s.plan.Effects); child++ {
			for _, parent := range s.plan.Effects[child].Needs {
				if parent == i.index && o.states[child] != "removed" && o.states[child] != "planned" {
					return ErrPolicyAdditionReceipt
				}
			}
		}
	} else {
		if o.states[i.index] != "intent" {
			return ErrPolicyAdditionReceipt
		}
		for _, parent := range s.plan.Effects[i.index].Needs {
			if o.states[parent] != "added" {
				return ErrPolicyAdditionReceipt
			}
		}
	}
	return o.current(ctx)
}

// withStart consumes this original per-RPC issuer exactly once. begin is the
// concrete NFQ owner's short control admission around the actual tool Start.
// Successful command Wait remains the COMMON writer's separate durable ACK.
func (i *policyEffectCommandInvocation) withStart(ctx context.Context, begin func() error) error {
	if i == nil || i.self != i || ctx == nil || ctx.Err() != nil || begin == nil || ctx.Value(policyEffectCommandInvocationKey{}) != i {
		return ErrPolicyAdditionReceipt
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if !i.open || i.used {
		return ErrPolicyAdditionReceipt
	}
	i.used = true // No retry, including refusal or an unknown actual Start.
	if err := i.current(ctx); err != nil {
		return err
	}
	err := begin()
	return errors.Join(err, i.current(ctx))
}
