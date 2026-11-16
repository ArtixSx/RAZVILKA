package dataplane

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"sync"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// This is a pure original NFQ-only inventory comparison, not an allowance.
// The complete body still performs every consumer/kernel capture and closes
// every temporary receipt FD before this source loan ends. The collector's
// SAME admitted CheckTools contract already runs within its original capture
// loan; this scope does not admit arbitrary consumer or identity callbacks.
type networkPolicyNFQInventorySources struct {
	read              *networkPolicyNFQReadSources
	dispatch          *networkPolicyOriginalInventoryReader
	intent, plan      Plan
	ids               []string
	inactivityCleanup *operationgate.ExclusiveCleanupReview
	inactivityControl *operationgate.ControlEpochReview
}

const (
	nfqInventoryForeign = iota + 1
	nfqInventoryNoLAN
	nfqInventoryMode
	nfqInventoryContextNil
	nfqInventoryAdapters
	nfqInventoryDispatch
	nfqInventoryCollector
	nfqInventorySource
	nfqInventoryPlanMissing
	nfqInventoryPlanLAN
	nfqInventoryPlanShape
	nfqInventoryPlanIntent
	nfqInventoryEligible
	nfqInventoryEntered
	nfqInventoryBodyCompleted
	nfqInventoryBodyError
	nfqInventoryCompleted
	nfqInventoryError
	nfqInventoryContextBase
)

func networkPolicyNFQInventoryContext(ctx context.Context) bool {
	return networkPolicyNFQInventoryContextFailure(ctx) == 0
}

func networkPolicyNFQInventoryContextFailure(ctx context.Context) int {
	if ctx == nil {
		return nfqInventoryContextNil
	}
	for index, key := range []any{
		wgOperationOwnerKey{}, wgOperationMaterialKey{}, wgOperationCleanupKey{}, wgInactivityCleanupKey{},
		xrayOperationOwnerKey{}, xrayOperationMaterialKey{}, xrayOperationCleanupKey{},
		xraySelectedTCPExecutionKey{}, xraySelectedTCPPreResourceKey{}, xraySelectedTCPReplacementKey{},
		xraySelectedTCPInventoryScopeKey{}, xraySelectedTCPPreparedInventoryScopeKey{},
		nfqwsRetiredInventoryKey{}, nfqwsProbeCleanupKey{}, nfqws2RemovalIntentKey{}, nfqws2RollbackHookContextKey{},
	} {
		if raw := ctx.Value(key); raw != nil {
			if index == 3 {
				cleanup, typed := raw.(*operationgate.ExclusiveCleanupReview)
				e, original := ctx.Value(nfqws2ActiveExecutionKey{}).(*nfqws2ActiveExecution)
				if typed && cleanup != nil && original && e != nil && e.self == e && e.inventoryInactivityCleanup == cleanup {
					continue
				}
			}
			return nfqInventoryContextBase + index
		}
	}
	return 0
}

func networkPolicyNFQInventoryAdapters(c *NetworkPolicyChecks) bool {
	if c == nil {
		return false
	}
	for _, adapter := range c.adapters {
		switch a := adapter.(type) {
		case *NetworkPolicyAdapter:
			if a == nil {
				return false
			}
		case *NFQWS2Adapter:
			if a == nil {
				return false
			}
		case *ProxyTunnelAdapter:
			if a == nil {
				return false
			}
		case *WARPWireGuardAdapter:
			if a == nil {
				return false
			}
		case *ScopedDNSAdapter:
			if a == nil {
				return false
			}
		default:
			return false // Even an unknown adapter's ID method is external code.
		}
	}
	return true
}

func (c *NetworkPolicyChecks) nfqInventorySources(ctx context.Context, lan *LANPolicyRuntimePlan, foreign bool) *networkPolicyNFQInventorySources {
	if foreign {
		noteNFQInventoryRead(nfqInventoryForeign)
		return nil
	}
	if lan == nil {
		noteNFQInventoryRead(nfqInventoryNoLAN)
		return nil
	}
	if lan.Mode != LANPolicyNFQWSDirectMode {
		noteNFQInventoryRead(nfqInventoryMode)
		return nil
	}
	if reason := networkPolicyNFQInventoryContextFailure(ctx); reason != 0 {
		noteNFQInventoryRead(reason)
		return nil
	}
	if !networkPolicyNFQInventoryAdapters(c) {
		noteNFQInventoryRead(nfqInventoryAdapters)
		return nil
	}
	dispatch, original := c.readSource.(*networkPolicyOriginalInventoryReader)
	if !original || dispatch == nil {
		noteNFQInventoryRead(nfqInventoryDispatch)
		return nil
	}
	if dispatch.inventory == nil || dispatch.inventory != c.inventory {
		noteNFQInventoryRead(nfqInventoryCollector)
		return nil
	}
	s := c.nfqReadSources(ctx)
	p, present := ctx.Value(networkPolicyConsumerPlanKey{}).(Plan)
	if s == nil {
		noteNFQInventoryRead(nfqInventorySource)
		return nil
	}
	if !present {
		noteNFQInventoryRead(nfqInventoryPlanMissing)
		return nil
	}
	if !reflect.DeepEqual(p.LAN, lan) {
		noteNFQInventoryRead(nfqInventoryPlanLAN)
		return nil
	}
	if ValidateNetworkPolicyLAN(p.LAN, p.Routes) != nil {
		noteNFQInventoryRead(nfqInventoryPlanShape)
		return nil
	}
	if !nfqws2ActiveSamePlan(s.execution.plan, p) {
		noteNFQInventoryRead(nfqInventoryPlanIntent)
		return nil
	}
	// The original NFQ direct validator requires every resolved route to be
	// NFQ. Even a newly appearing legacy proxy lease can therefore only refuse
	// at xrayPlanMode, before any external scoped-proxy callback is called.
	noteNFQInventoryRead(nfqInventoryEligible)
	return &networkPolicyNFQInventorySources{read: s, dispatch: dispatch, intent: cloneExecutionResourcePlan(s.execution.plan), plan: cloneExecutionResourcePlan(p), ids: slices.Clone(c.ids), inactivityCleanup: s.execution.inventoryInactivityCleanup, inactivityControl: s.material.control}
}

func (s *networkPolicyNFQInventorySources) current(ctx context.Context) error {
	if s == nil || s.read == nil || s.read.execution == nil || s.read.material == nil || s.read.material.self != s.read.material || s.read.execution.material != s.read.material || !networkPolicyNFQInventoryContext(ctx) || !networkPolicyNFQInventoryAdapters(s.read.checks) {
		return ErrNetworkPolicyConsumers
	}
	c := s.read.checks
	p, present := ctx.Value(networkPolicyConsumerPlanKey{}).(Plan)
	if c.readSource != s.dispatch || s.dispatch == nil || s.dispatch.inventory != c.inventory ||
		!slices.Equal(c.ids, s.ids) || !present || !reflect.DeepEqual(p, s.plan) || !reflect.DeepEqual(s.read.execution.plan, s.intent) {
		return ErrNetworkPolicyConsumers
	}
	rawCleanup := ctx.Value(wgInactivityCleanupKey{})
	if (s.inactivityCleanup == nil && rawCleanup != nil) || (s.inactivityCleanup != nil && rawCleanup != s.inactivityCleanup) || s.read.execution.inventoryInactivityCleanup != s.inactivityCleanup {
		return ErrNetworkPolicyConsumers
	}
	if s.inactivityCleanup != nil {
		if s.read.material.control == nil || s.read.material.control != s.inactivityControl {
			return ErrNetworkPolicyConsumers
		}
		if err := s.read.material.control.Current(ctx); err != nil {
			return errors.Join(ErrNetworkPolicyConsumers, err)
		}
		if err := s.read.material.control.CurrentForCleanupOperation(ctx, s.inactivityCleanup); err != nil {
			return errors.Join(ErrNetworkPolicyConsumers, err)
		}
	}
	return s.read.current(ctx)
}

func (c *NetworkPolicyChecks) observeNFQInventoryRead(ctx context.Context, lan *LANPolicyRuntimePlan, foreign bool, use func(context.Context) error) error {
	s := c.nfqInventorySources(ctx, lan, foreign)
	if s == nil {
		return use(ctx) // Original custom, mixed, cleanup and cold paths unchanged.
	}
	completed := false
	defer func() {
		if !completed {
			noteNFQInventoryRead(nfqInventoryError)
		}
	}()
	if err := s.current(ctx); err != nil {
		return err
	}
	err := networkPolicyNFQInventoryReadOnce(ctx, s.read.execution,
		func(request context.Context, read func(context.Context) error) error {
			return s.read.binding.observeActiveTools(request, s.read.plan, read)
		}, s.current, func(read context.Context) error {
			noteNFQInventoryRead(nfqInventoryEntered)
			err := use(read)
			noteNFQInventoryRead(nfqInventoryBodyCompleted)
			if err != nil {
				noteNFQInventoryRead(nfqInventoryBodyError)
			}
			return err
		})
	if err == nil {
		completed = true
		noteNFQInventoryRead(nfqInventoryCompleted)
	}
	return err
}

// Join an entered reader before returning to the enclosing Provider boundary.
// No lock spans source/body callbacks; late and duplicate admission refuse.
func networkPolicyNFQInventoryReadOnce(parent context.Context, execution *nfqws2ActiveExecution, observe func(context.Context, func(context.Context) error) error, current func(context.Context) error, use func(context.Context) error) error {
	if parent == nil || nfqws2ActiveOperation(parent) != nil || observe == nil || current == nil || use == nil {
		return ErrNetworkPolicyConsumers
	}
	request, cancel := context.WithCancel(parent)
	defer cancel()
	var mu sync.Mutex
	open, entered, misuse := true, false, false
	var bodyErr error
	done := make(chan struct{})
	closeRead := func() bool {
		mu.Lock()
		open = false
		started := entered
		mu.Unlock()
		if started {
			select {
			case <-done:
			default:
				mu.Lock()
				misuse = true
				mu.Unlock()
				cancel()
				<-done
			}
		}
		return started
	}
	defer closeRead()
	outerErr := observe(request, func(child context.Context) error {
		mu.Lock()
		if !open || entered {
			misuse = true
			mu.Unlock()
			return ErrNetworkPolicyConsumers
		}
		entered = true
		mu.Unlock()
		completed := false
		defer func() {
			if !completed {
				mu.Lock()
				misuse = true // An observer cannot recover a body panic into success.
				mu.Unlock()
			}
			close(done)
		}()
		if err := networkPolicyNFQReadContext(request, child, execution); err != nil {
			bodyErr = err
			return err
		}
		deadline, _ := request.Deadline()
		read, revoke := context.WithDeadline(child, deadline)
		defer revoke()
		stop := context.AfterFunc(request, revoke)
		defer stop()
		if request.Err() != nil {
			revoke()
		}
		bodyErr = current(read)
		if bodyErr == nil {
			bodyErr = use(read)
			bodyErr = errors.Join(bodyErr, current(read))
		}
		bodyErr = errors.Join(bodyErr, read.Err(), request.Err())
		completed = true
		return bodyErr
	})
	started := closeRead()
	mu.Lock()
	bad := misuse
	mu.Unlock()
	if !started || bad {
		outerErr = errors.Join(outerErr, ErrNetworkPolicyConsumers)
	}
	return errors.Join(outerErr, bodyErr, current(parent), parent.Err())
}

// The App carries this same comparison review during forward Apply as well as
// compensation. Capture it only under original material/selection admission;
// it never substitutes for forward control, source, process or receipt checks.
func nfqInventoryOriginalInactivityCleanup(ctx context.Context, control *operationgate.ControlEpochReview) (*operationgate.ExclusiveCleanupReview, error) {
	raw := ctx.Value(wgInactivityCleanupKey{})
	if raw == nil {
		return nil, nil
	}
	cleanup, ok := raw.(*operationgate.ExclusiveCleanupReview)
	if !ok || cleanup == nil || control == nil {
		return nil, ErrNetworkPolicyConsumers
	}
	if err := control.Current(ctx); err != nil {
		return nil, errors.Join(ErrNetworkPolicyConsumers, err)
	}
	if err := control.CurrentForCleanupOperation(ctx, cleanup); err != nil {
		return nil, errors.Join(ErrNetworkPolicyConsumers, err)
	}
	return cleanup, nil
}
