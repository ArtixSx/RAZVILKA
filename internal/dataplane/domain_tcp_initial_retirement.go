package dataplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"sync/atomic"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

// Only an actual failed original first publication creates this capsule. It
// cannot target a later generation with the same plan or baseline anchor.
type DomainTCPUnstartedFailure struct {
	self   *DomainTCPUnstartedFailure
	cursor *domainTCPGlobalSuccessor
	cause  error
}

func (f *DomainTCPUnstartedFailure) Error() string {
	if f == nil || f.cause == nil {
		return "original unstarted domain generation requires cleanup"
	}
	return f.cause.Error()
}
func (f *DomainTCPUnstartedFailure) Unwrap() error {
	if f == nil {
		return nil
	}
	return f.cause
}

func domainTCPUnstartedFailure(c *domainTCPGlobalSuccessor, cause error) error {
	f := &DomainTCPUnstartedFailure{cursor: c, cause: cause}
	f.self = f
	return f
}

type domainTCPInitialRetirement struct {
	self        *domainTCPInitialRetirement
	cursor      *domainTCPGlobalSuccessor
	keeper      *domainTCPGlobalKeeper
	cleanup     *operationgate.ExclusiveCleanupReview
	control     *operationgate.ControlEpochReview
	ctx         context.Context // Current serialized cleanup operation only.
	active      atomic.Bool
	finished    atomic.Bool
	published   bool
	scopeClosed bool
	closeErr    error // An actual close failure is sticky, not a retryable pre-cut.
	after       Execution
	image       []byte
}

func (r *domainTCPInitialRetirement) local(c *domainTCPGlobalSuccessor, ctx context.Context) error {
	if r == nil || r.self != r || r.cursor != c || c == nil || c.terminal != r || !r.active.Load() || !sameNetworkPolicyDependency(r.ctx, ctx) || xraySelectedTCPFinite(ctx) != nil || r.cleanup == nil || r.control == nil || r.keeper == nil {
		return ErrPolicyAdditionUnknown
	}
	return nil
}

func (r *domainTCPInitialRetirement) unentered() error {
	if r == nil || r.self != r {
		return ErrPolicyAdditionUnknown
	}
	c := r.cursor
	if c == nil || c.original() != nil {
		return ErrPolicyAdditionUnknown
	}
	c.mu.Lock()
	started := c.actionStarted
	c.mu.Unlock()
	s := c.scope
	s.mu.Lock()
	valid := !started && s.execution != nil && s.owned != nil && s.anchor != nil && s.cancel != nil && len(s.execution.Resources) == 0 && len(s.issued) == 0 && len(s.nfqws) == 0 && len(s.syntheticBaselines) == 0 && len(s.xraySelectedTCP) == 0 && len(s.xrayDomainTCP) == 0 && len(s.domainTCPCaptures) == 0 && len(s.domainTCPBaselines) == 0 && s.domainTCPOwner == nil && s.domainDNSBinding == nil && (s.open || r.scopeClosed)
	s.mu.Unlock()
	if !valid {
		return ErrPolicyAdditionUnknown
	}
	return nil
}

// RetireUnstartedDomainTCPContinuation retires only metadata from an operation
// whose action NEVER entered. Prior published aliases remain owned and served.
// The exact failure capsule prevents a stale caller from retiring a newer
// generation, even if its plan happens to be byte-identical.
func (m *Manager) RetireUnstartedDomainTCPContinuation(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview, history *updatecheck.ExecutionHistoryAdmission, failure *DomainTCPUnstartedFailure) error {
	if m == nil || cleanup == nil || history == nil || failure == nil || failure.self != failure || failure.cursor == nil || failure.cursor.scope == nil || failure.cursor.scope.manager != m || xraySelectedTCPFinite(ctx) != nil {
		return ErrPolicyAdditionUnknown
	}
	c := failure.cursor
	if err := m.beginOperation(ctx); err != nil {
		return err
	}
	defer m.endOperation()
	if c.terminal != nil && c.terminal.finished.Load() {
		return nil
	} // SAME acknowledged cleanup only.
	if err := history.CheckWrite(ctx, 8); err != nil {
		return err
	} // No leaf mutex held.
	if err := c.original(); err != nil {
		return err
	}
	entries, err := c.pool.originals()
	if err != nil {
		return err
	}
	last := entries[len(entries)-1]
	if last == nil || last.detached == nil || last.detached.owner == nil || last.detached.owner.process == nil || last.detached.owner.process.material == nil {
		return ErrPolicyAdditionUnknown
	}
	control := last.detached.owner.process.material.control
	if err := control.CurrentForCleanupOperation(ctx, cleanup); err != nil {
		return err
	}
	r := c.terminal
	if r == nil {
		r = &domainTCPInitialRetirement{cursor: c, control: control}
		r.self = r
		r.keeper = &domainTCPGlobalKeeper{pool: c.pool, cursor: c, records: c.records, continuation: c.continuation}
		r.keeper.self = r.keeper
		c.terminal = r
	}
	if r.self != r || r.cursor != c || r.control != control || r.closeErr != nil {
		return errors.Join(ErrPolicyAdditionUnknown, r.closeErr)
	}
	r.cleanup, r.ctx = cleanup, ctx
	if !r.active.CompareAndSwap(false, true) {
		return ErrPolicyAdditionUnknown
	}
	defer r.active.Store(false)
	if err := r.unentered(); err != nil {
		return err
	}
	c.mu.Lock()
	accepted, sealed := c.globalAccepted, c.sealed
	c.mu.Unlock()
	if accepted && !sealed {
		if err := c.sealAcceptedGlobal(ctx); err != nil {
			return err
		}
	}
	if len(r.image) == 0 {
		c.scope.mu.Lock()
		before, err := json.Marshal(c.scope.execution)
		var after Execution
		if err == nil {
			err = json.Unmarshal(before, &after)
		}
		if err == nil && len(after.Steps) != 1 {
			err = ErrExecutionJournal
		}
		if err == nil {
			after.State = "temporary-complete"
			after.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
			after.Error = "original unstarted domain generation retired; no action entered"

			after.Steps[0].State, after.Steps[0].Detail, after.Steps[0].FinishedAt = "failed", after.Error, after.FinishedAt
			err = validateExecutionResources(after, true)
		}
		if err == nil {
			r.image, err = json.Marshal(after)
		}
		if err == nil {
			r.after = after
			*c.scope.execution = after
			r.keeper.image = bytes.Clone(r.image)
			r.keeper.digest = sha256.Sum256(r.image)
		}
		c.scope.mu.Unlock()
		if err != nil {
			return err
		}
	}
	if !r.published {
		if err := c.publishFrame(ctx, r.image, r); err != nil {
			return err
		}
		r.published = true
	}
	if err := r.local(c, ctx); err != nil {
		return err
	}
	if err := r.keeper.compareFiles(ctx); err != nil {
		return err
	}
	if err := control.CurrentForCleanupOperation(ctx, cleanup); err != nil {
		return err
	}
	if err := r.closeScopeOwner(ctx); err != nil {
		return err
	}
	if err := c.comparePrior(ctx, true); err != nil {
		return err
	}
	if err := r.keeper.compareFiles(ctx); err != nil {
		return err
	}
	if err := control.CurrentForCleanupOperation(ctx, cleanup); err != nil {
		return err
	}
	c.pool.mu.Lock()
	if c.pool.successor != c || c.pool.keeper != nil && c.pool.keeper != r.keeper {
		c.pool.mu.Unlock()
		return ErrPolicyAdditionUnknown
	}
	r.keeper.ready.Store(true)
	c.pool.keeper = r.keeper
	c.pool.mu.Unlock()
	c.scope.mu.Lock()
	c.scope.pending = false
	c.scope.failure = nil
	c.scope.mu.Unlock()
	c.mu.Lock()
	c.pending = false
	c.mu.Unlock()
	r.finished.Store(true)
	return nil
}

// Called only after durable terminal publication and fresh original cleanup
// admission. This closes the original directory holder, never journal FDs or
// native resources. The remaining keeper owns all documentary comparison.
func (r *domainTCPInitialRetirement) closeScopeOwner(ctx context.Context) error {
	if r == nil || r.self != r || r.cursor == nil || !r.published || r.closeErr != nil {
		if r != nil {
			return errors.Join(ErrPolicyAdditionUnknown, r.closeErr)
		}
		return ErrPolicyAdditionUnknown
	}
	if err := r.unentered(); err != nil {
		return err
	}
	if err := r.keeper.compareFiles(ctx); err != nil {
		return err
	}
	if r.scopeClosed {
		return ctx.Err()
	}
	c := r.cursor
	rootInfo, rootErr := c.scope.owned.RootInfo()
	recordInfo, recordErr := c.records.transactionRoot.RootInfo()
	if rootErr != nil || recordErr != nil || rootInfo == nil || recordInfo == nil || !os.SameFile(c.scope.anchor, rootInfo) || !os.SameFile(c.records.transactionAnchor, recordInfo) || !os.SameFile(rootInfo, recordInfo) || !networkPolicyPrivateDirectory(rootInfo) {
		return errors.Join(ErrPolicyAdditionUnknown, rootErr, recordErr)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := c.scope.owned.Close(); err != nil {
		r.closeErr = errors.Join(ErrPolicyAdditionUnknown, err)
		return r.closeErr
	}
	r.scopeClosed = true
	c.scope.mu.Lock()
	c.scope.open = false
	c.scope.observationOpen.Store(false)
	c.scope.cancel()
	c.scope.mu.Unlock()
	return ctx.Err()
}
