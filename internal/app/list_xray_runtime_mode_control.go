package app

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// Only the actual Store receipt changes this retained comparison. Original
// forward context/scope, compilation, node proof and native owners stay intact.
func (s *XrayListRuntimeSource) acceptServiceModeComparison(ctx context.Context, receipt *config.ServiceModeCommitReview, plan dataplane.Plan, cleanup *operationgate.ExclusiveCleanupReview, restored bool) error {
	if s == nil || s.self != s || xrayListSourceContext(ctx) != nil || receipt == nil {
		return ErrXrayListSource
	}
	return s.app.Operations.WithExclusiveContext(ctx, func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.invalid || s.commitOwnersCurrent() != nil || !receipt.MatchesStore(s.store) || !restored && !receipt.PendingAcceptance() {
			return ErrXrayListSource
		}
		read := receipt.CommittedImages
		control := func() error { return s.control.Current(ctx) }
		if restored {
			if cleanup == nil {
				return ErrXrayListSource
			}
			read = receipt.RestoredImages
			control = func() error { return s.control.CurrentForCleanupOperation(ctx, cleanup) }
		}
		before, after, err := read(ctx)
		if err != nil || !reflect.DeepEqual(s.expected, before) && !(restored && reflect.DeepEqual(s.expected, after)) {
			return errors.Join(ErrXrayListSource, err)
		}
		if err := control(); err != nil {
			return err
		}
		if err := s.currentDestinations(ctx); err != nil {
			return err
		}
		wan, err := s.app.freshNetworkProfile(ctx)
		if err != nil || wan != s.wan {
			return errors.Join(ErrXrayListSource, err)
		}
		if err := s.scope.cleanupScopeCheck(ctx, plan.LAN); err != nil {
			return err
		}
		if err := s.registration.Current(ctx); err != nil {
			return err
		}
		if err := control(); err != nil {
			return err
		}
		closingBefore, closingAfter, err := read(ctx)
		if err != nil || !reflect.DeepEqual(before, closingBefore) || !reflect.DeepEqual(after, closingAfter) || !restored && !receipt.PendingAcceptance() {
			return errors.Join(ErrXrayListSource, err)
		}
		s.expected = closingAfter
		return nil
	})
}

func (a *App) updateManagedXrayServiceMode(parent context.Context, mode *string, schedule *config.ServiceCheckSchedule, revision uint64) (bool, error) {
	if a == nil || a.Store == nil || mode == nil || *mode != "auto" {
		return false, nil
	}
	before := a.Store.Get()
	if before.ServiceControl.Mode != "manual" {
		return false, nil
	}
	plan, exists, planErr := a.Dataplane.Committed()
	selected := autonomyManagedXraySelected(before, plan, "")
	for _, state := range before.AppliedServices {
		selected = selected || autonomyManagedXraySelected(before, plan, selectedRoute(state))
	}
	a.managedXraySelectedTCPListMu.Lock()
	r := a.managedXraySelectedTCPList
	a.managedXraySelectedTCPListMu.Unlock()
	if r != nil {
		r.mu.Lock()
		defer r.mu.Unlock()
		selected = selected || r.active != nil || r.pending != nil || r.stopped != nil
	}
	if !selected {
		return false, nil
	}
	if parent == nil || parent.Err() != nil || planErr != nil || !exists || r == nil || !r.original() || !r.policy.original() || r.policy.closed.Load() || r.pending != nil || r.preparing != nil || r.active == nil || before.Revision != revision ||
		before.SafeMode || before.ServiceControl.Stopped || schedule != nil && !reflect.DeepEqual(*schedule, before.ServiceControl.Schedule) {
		return true, ErrXrayListSource
	}
	e := r.active
	if e.source == nil || !r.autonomyCommittedMatches(before, plan, e.source.service, e.source.selected) {
		return true, ErrXrayListSource
	}
	ctx, cancel := context.WithTimeout(parent, defaultDataplaneApplyTimeout)
	defer cancel()
	c, release, err := a.privateExclusiveOperation(ctx)
	if err != nil {
		return true, err
	}
	owned := true
	defer func() {
		if owned {
			release()
		}
	}()
	cleanup, err := r.policy.control.ReviewExclusiveCleanup(c)
	if err != nil {
		return true, err
	}
	c, closeOperation, err := r.operation(c, e, cleanup)
	if err != nil {
		return true, err
	}
	defer func() {
		if owned {
			closeOperation()
		}
	}()
	health := func() error {
		check, end := context.WithTimeout(c, 8*time.Second)
		defer end()
		return r.manager.CheckRetainedManagedXraySelectedTCP(check)
	}
	if err := health(); err != nil {
		return true, err
	}
	store := e.source.store
	if a.Store != store || !reflect.DeepEqual(store.Get(), before) || !r.autonomyCommittedMatches(before, plan, e.source.service, e.source.selected) {
		return true, ErrXrayListSource
	}
	retain := func(cause error) (bool, error) {
		e.pendingStop = true
		e.pendingContext, e.pendingCloseOperation, e.pendingRelease = c, closeOperation, release
		r.pending = e
		owned = false
		a.Operations.FenceJournal()
		return true, cause
	}
	undo, receipt, err := store.UpdateManualToAutoReviewed(c, revision)
	if err != nil {
		if errors.Is(err, restorejournal.ErrRecovery) {
			return retain(err)
		}
		return true, err
	}
	compensate := func(cause error) (bool, error) {
		if undoErr := undo(); undoErr != nil {
			return retain(errors.Join(cause, undoErr))
		}
		check, end := context.WithTimeout(context.WithoutCancel(c), 8*time.Second)
		defer end()
		if restoreErr := e.source.acceptServiceModeComparison(check, receipt, plan, cleanup, true); restoreErr != nil {
			return retain(errors.Join(cause, restoreErr))
		}
		return true, cause
	}
	if err := e.source.acceptServiceModeComparison(c, receipt, plan, nil, false); err != nil {
		return compensate(err)
	}
	if err := health(); err != nil {
		return compensate(err)
	}
	if err := receipt.Accept(c); err != nil {
		return compensate(err)
	}
	_, after, err := receipt.CommittedImages(c)
	if err != nil || !r.autonomyCommittedMatches(after, plan, e.source.service, e.source.selected) {
		return compensate(errors.Join(ErrXrayListSource, err))
	}
	if err := r.policy.control.Current(c); err != nil {
		return compensate(err)
	}
	if err := c.Err(); err != nil {
		return compensate(err)
	}
	return true, nil
}
