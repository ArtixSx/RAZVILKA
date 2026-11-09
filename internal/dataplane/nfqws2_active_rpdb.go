package dataplane

import (
	"context"
	"errors"
	"reflect"
	"sync"
)

type nfqwsOriginalLANRPDBObserver interface {
	WithOriginalNFQWSLANRPDB(context.Context, func(context.Context) error) error
}

// Only this original NFQ execution lends the policy runner to its frozen
// direct LAN Verify. Its enclosing verifyLAN observation still closes all
// source bytes before any result succeeds; no effect crosses either scope.
func (e *nfqws2ActiveExecution) verifyLANRPDB(ctx context.Context, lan *LANPolicyRuntimePlan) error {
	if e == nil {
		return ErrNFQWSScopedOwner
	}
	// Freeze the complete original runtime BEFORE invoking the optional issuer.
	// A custom issuer cannot replace ScopeCheck or command aliases used by Verify.
	runtime := e.runtimeFrozen
	return e.observeLANRPDB(ctx, lan, func(observed context.Context) error { return runtime.Verify(observed, lan) })
}

func (e *nfqws2ActiveExecution) observeLANRPDB(ctx context.Context, lan *LANPolicyRuntimePlan, use func(context.Context) error) error {
	if e == nil || use == nil {
		return ErrNFQWSScopedOwner
	}
	if e.binding == nil || e.resource == nil || lan == nil || !lanPolicyDirectMode(lan.Mode) {
		return use(ctx)
	}
	original, ok := e.runtimeFrozen.Runner.(nfqwsOriginalLANRPDBObserver)
	if !ok {
		return use(ctx)
	}
	material, resource, binding, runner := e.material, e.resource, e.binding, e.runtimeFrozen.Runner
	expectedLAN := CloneLANPolicyRuntime(lan)
	aliases := [3]string{e.runtimeFrozen.IP, e.runtimeFrozen.IPTables, e.runtimeFrozen.IP6Tables}
	same := func(current context.Context) error {
		if current == nil || current.Err() != nil || e.self != e || current.Value(nfqws2ActiveExecutionKey{}) != e || e.material != material || material == nil || material.self != material || material.execution != e || !material.executionBound || e.resource != resource || e.binding != binding || e.runtime == nil || !sameNetworkPolicyDependency(runner, e.runtimeFrozen.Runner) || !sameNetworkPolicyDependency(runner, e.runtime.Runner) || !sameNetworkPolicyDependency(runner, binding.Runner) || aliases != [3]string{e.runtimeFrozen.IP, e.runtimeFrozen.IPTables, e.runtimeFrozen.IP6Tables} || aliases != [3]string{e.runtime.IP, e.runtime.IPTables, e.runtime.IP6Tables} || !reflect.DeepEqual(lan, expectedLAN) || !reflect.DeepEqual(expectedLAN, e.plan.LAN) {
			return ErrNFQWSScopedOwner
		}
		return nil
	}
	if err := same(ctx); err != nil {
		return err
	}
	var mu sync.Mutex
	var users sync.WaitGroup
	active, calls := true, 0
	var callbackErr error
	finish := func() {
		mu.Lock()
		active = false
		mu.Unlock()
		users.Wait()
	}
	defer finish()
	result := original.WithOriginalNFQWSLANRPDB(ctx, func(observed context.Context) error {
		mu.Lock()
		if !active || calls != 0 {
			callbackErr = errors.Join(callbackErr, ErrNFQWSScopedOwner)
			mu.Unlock()
			return ErrNFQWSScopedOwner
		}
		calls++
		users.Add(1)
		mu.Unlock()
		defer users.Done()
		err := same(observed)
		if err == nil {
			err = use(observed)
		}
		err = errors.Join(err, same(observed))
		mu.Lock()
		callbackErr = errors.Join(callbackErr, err)
		mu.Unlock()
		return err
	})
	finish()
	mu.Lock()
	if calls != 1 {
		callbackErr = errors.Join(callbackErr, ErrNFQWSScopedOwner)
	}
	result = errors.Join(result, callbackErr)
	mu.Unlock()
	return errors.Join(result, same(ctx), ctx.Err())
}
