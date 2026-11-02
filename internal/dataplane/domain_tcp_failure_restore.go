package dataplane

import (
	"context"
	"encoding/json"
	"path/filepath"
	"time"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

// RetireFailedDomainTCPContinuation preserves published aliases as restorative
// standby. Only a SAME joined ledger proving never-issued permits the further
// original COMMON removal/keeper path. Neither outcome claims service access.
func (m *Manager) RetireFailedDomainTCPContinuation(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview, history *updatecheck.ExecutionHistoryAdmission, failure *DomainTCPCleanupFailure) error {
	var original domainTCPFailureRestoredHandles
	if err := m.cleanupFailedDomainTCP(ctx, cleanup, history, failure, true, &original); err != nil {
		return err
	}
	if original.owner == nil || original.closed == nil || original.control == nil {
		return ErrPolicyAdditionUnknown
	}
	if err := original.control.CurrentForCleanupOperation(ctx, cleanup); err != nil {
		return err
	}
	row, err := original.closed.ObserveClosed(ctx)
	if err != nil {
		return err
	}
	if row.PossiblyIssued {
		return original.owner.RetainedStandbyCurrent(ctx)
	}
	// The first serialized operation has ended. Original retirement now owns
	// its own operation and fresh fleet8 admission, including all retry cuts.
	return original.owner.RetireUnpublishedStandby(ctx, cleanup)
}

// Copied under Manager.operation only after full original restoration. These
// stable handles are not mutable cursor state and mint no owner/admission.
// Their methods independently recheck originals after the operation gap.
type domainTCPFailureRestoredHandles struct {
	owner   *DomainTCPOriginalScope
	closed  *dnscontrol.SyntheticDNSRetirementReview
	control *operationgate.ControlEpochReview
}

func (r *domainTCPFailureCleanup) copyRestoredHandles(out *domainTCPFailureRestoredHandles) error {
	if out == nil || r == nil || r.self != r || !r.restored || r.standby == nil || r.standby.self != r.standby || r.standby.original == nil || r.resource == nil || r.resource.material == nil || r.resource.material.retirement == nil || r.control == nil {
		return ErrPolicyAdditionUnknown
	}
	*out = domainTCPFailureRestoredHandles{owner: r.standby.original, closed: r.resource.material.retirement, control: r.control}
	return nil
}

func (r *domainTCPFailureCleanup) restoreOriginalStandby(ctx context.Context, history *updatecheck.ExecutionHistoryAdmission, cause error) error {
	p := r.resource
	if err := r.local(ctx, p); err != nil {
		return err
	}
	s := p.scope
	s.mu.Lock()
	o := s.domainTCPOwner
	s.mu.Unlock()
	if o == nil || o.self != o || o.binding != p.material.binding || o.process != p {
		return ErrDomainPolicyTCPConsumer
	}
	// This repeats actual source/session/handler joins and original COMMON
	// capture removal. A remembered standbyReady bit is never a substitute.
	if r.standby == nil {
		if err := o.finishCapture(ctx, p); err != nil && err != dnscontrol.ErrSyntheticDNSTransitionPending {
			return err
		}
	}
	if err := o.standbyCurrent(ctx); err != nil {
		return err
	}
	if r.standby == nil {
		owner := &domainTCPStandbyOwner{original: o, process: p, baseline: o.baseline}
		owner.self = owner
		retained := &retainedXrayExecution{scope: s, records: p.records, standby: owner, pending: true}
		retained.self = retained
		if err := s.manager.reservePendingDomainStandby(retained); err != nil {
			return err
		}
		r.standby, r.retained = owner, retained
		o.mu.Lock()
		if o.standbyOwner != nil || o.standbyHistory != nil {
			o.mu.Unlock()
			return ErrPolicyAdditionUnknown
		}
		o.standbyOwner, o.standbyHistory = owner, history
		o.mu.Unlock()
		s.mu.Lock()
		s.retained, s.retainedXrayOwner = true, retained
		s.mu.Unlock()
	}
	owner, retained := r.standby, r.retained
	if owner == nil || owner.self != owner || owner.original != o || retained == nil || retained.self != retained || retained.standby != owner || s.manager.retainedXrayOwner() != retained {
		return ErrPolicyAdditionUnknown
	}
	if err := r.publishStandbyImage(ctx, cause); err != nil {
		return err
	}
	if err := o.standbyCurrent(ctx); err != nil {
		return err
	}
	if !p.records.standbyAlias.Load() {
		if err := p.records.detachStandbyAlias(ctx, owner); err != nil {
			return err
		}
		if r.fault != nil {
			if err := r.fault("alias"); err != nil {
				return err
			}
		}
	}
	if err := r.restoredStandbyCurrent(ctx); err != nil {
		return err
	}
	if err := r.control.CurrentForCleanupOperation(ctx, r.cleanup); err != nil {
		return err
	}
	if err := r.restoredStandbyCurrent(ctx); err != nil {
		return err
	}
	// Both actual writers, original alias transfer, receipts/kernel and closed
	// source now agree. Actual close errors remain sticky in their FD owners.
	s.mu.Lock()
	if !s.retained || s.retainedXrayOwner != retained || s.manager.retainedXrayOwner() != retained || ctx.Err() != nil {
		s.mu.Unlock()
		return ErrPolicyAdditionUnknown
	}
	s.failure = nil
	s.pending = false
	retained.pending = false
	s.observationOpen.Store(false)
	s.cancel()
	s.mu.Unlock()
	r.cursor.mu.Lock()
	r.cursor.pending = false
	r.cursor.mu.Unlock()
	r.cursor.failedCustody.Store(false)
	r.restored = true
	return nil
}

func (r *domainTCPFailureCleanup) restoredStandbyCurrent(ctx context.Context) error {
	if r == nil || r.standby == nil || r.retained == nil || r.standby.self != r.standby || r.retained.standby != r.standby || r.local(ctx, r.resource) != nil {
		return ErrPolicyAdditionUnknown
	}
	if err := r.standby.original.compareStandby(ctx, false); err != nil {
		return err
	}
	if err := r.standby.globalRecordCurrent(r.resource.scope.manager.StateRoot, *r.resource.scope.execution); err != nil {
		return err
	}
	return r.resource.records.current(ctx, true)
}

func (r *domainTCPFailureCleanup) publishStandbyImage(ctx context.Context, cause error) error {
	s := r.resource.scope
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.local(ctx, r.resource) != nil || !s.open || s.domainTCPOwner != r.standby.original || !s.retained || s.retainedXrayOwner != r.retained {
		return ErrPolicyAdditionUnknown
	}
	if r.standbyImage == nil {
		var next Execution
		if !r.imageACK || r.imageStage != "capture" || json.Unmarshal(r.image, &next) != nil || len(next.Steps) != 1 {
			return ErrExecutionJournal
		}
		found := false
		for i := range next.Resources {
			if next.Resources[i].ID == filepath.Base(r.standby.baseline.relative) {
				if next.Resources[i].SyntheticBaseline == nil || next.Resources[i].State != "prepared" {
					return ErrExecutionJournal
				}
				next.Resources[i].Phase = "standby-retained"
				found = true
			} else if next.Resources[i].State != "removed" && next.Resources[i].State != "unused" {
				return ErrExecutionJournal
			}
		}
		if !found {
			return ErrExecutionJournal
		}
		next.State = "resource-failed"
		next.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		next.Steps[0].State, next.Steps[0].FinishedAt = "failed", next.FinishedAt
		if cause != nil {
			next.Error = cause.Error()
			next.Steps[0].Detail = cause.Error()
		}
		var err error
		r.standbyImage, err = json.Marshal(next)
		if err != nil {
			return err
		}
	}
	var next Execution
	if json.Unmarshal(r.standbyImage, &next) != nil {
		return ErrExecutionJournal
	}
	*s.execution = next
	return r.publishStageLocked(ctx, "standby", filepath.Base(r.standby.baseline.relative), r.standbyImage)
}
