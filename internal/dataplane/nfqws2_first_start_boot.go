package dataplane

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"time"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

// Only a trusted current applied-config review, bound by this actual Manager
// to its full committed journal, may start a new boot. Historical receipts are
// settled as stopped after independent absence, never adopted as live PIDs.
func (a *NFQWS2Adapter) reconcileFirstStart(ctx context.Context, plan Plan, lease *nfqws2Lease) (resultErr error) {
	if _, err := a.verifyOwnedLists(false); err != nil {
		return err
	}
	if (lease.FirstStart.Phase != nfqws2FirstRunning && lease.FirstStart.Phase != nfqws2FirstStopped) || lease.FirstStart.Process == nil {
		return errors.New("NFQWS2 recovery refuses an unsettled start or removal intent")
	}
	if lease.FirstStart.Phase == nfqws2FirstRunning {
		if err := a.verifyFirstStartRunning(ctx); err == nil {
			return a.Health(ctx, plan, "")
		}
	}
	if a.inactivity == nil || lease.FirstStart.Phase == nfqws2FirstRunning && a.inactivity.identity.BootID == lease.FirstStart.Process.BootID {
		return errors.New("NFQWS2 current-boot process is unknown; recovery cannot restart it")
	}
	if err := a.checkFirstStartBootReview(ctx, plan, lease); err != nil {
		return err
	}
	if err := a.firstStartRuntimeAbsent(ctx); err != nil {
		return err
	}
	config, exists, err := nfqws2Read(a.ConfigPath)
	if err != nil || !exists {
		return ErrReviewChanged
	}
	expected, err := a.firstStartConfig(plan, config)
	if err != nil || !bytes.Equal(config, expected) {
		return ErrReviewChanged
	}
	owner, err := a.owner()
	if err != nil {
		return err
	}
	effective, err := engineconfig.NFQWSFirstStartEffectiveConfig(config, owner)
	if err != nil {
		return err
	}
	arguments, err := engineconfig.NFQWSStartupArguments(effective, nil)
	if err != nil {
		return err
	}
	if a.stockNativeOwner == nil || a.firstStartReview != nil {
		return errors.New("NFQWS2 recovery has no original component writer review")
	}
	nativeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	review, err := a.stockNativeOwner.ReviewStockNFQWSNative(nativeCtx, arguments)
	if err != nil {
		cancel()
		return err
	}
	a.firstStartReview, a.firstStartReviewRoot = review, lease.Transaction
	defer func() {
		a.firstStartReview, a.firstStartReviewRoot = nil, ""
		resultErr = errors.Join(resultErr, review.Close())
	}()
	err = review.DryRun(nativeCtx)
	cancel()
	if err != nil {
		return err
	}
	if err := a.checkFirstStartBootReview(ctx, plan, lease); err != nil {
		return err
	}
	if _, err := a.verifyOwnedLists(false); err != nil {
		return err
	}
	if err := a.firstStartRuntimeAbsent(ctx); err != nil {
		return err
	}
	// Preserve the historical process identity in the existing same-lease
	// stopped phase. No Wait/ACK, successful rollback, or live adoption is made.
	if err := a.recordFirstStartStopped(lease); err != nil {
		return err
	}
	if err := a.deactivateFirstStart(ctx, lease); err != nil {
		return err
	}
	if err := a.checkFirstStartBootReview(ctx, plan, lease); err != nil {
		return err
	}
	if err := a.startFirstStart(ctx, lease.Transaction); err != nil {
		return a.cleanupNewFirstStartBoot(ctx, err, lease)
	}
	if err := CheckCommittedRecoveryReview(ctx, plan); err != nil {
		// The user may stop while a native start is in progress. Cleanup follows
		// exact new owned receipts; an ambiguous start remains fenced instead.
		return a.cleanupNewFirstStartBoot(ctx, err, lease)
	}
	if err := a.Health(ctx, plan, lease.Transaction); err != nil {
		return a.cleanupNewFirstStartBoot(ctx, err, lease)
	}
	return nil
}

func (a *NFQWS2Adapter) cleanupNewFirstStartBoot(ctx context.Context, cause error, previous *nfqws2Lease) error {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 60*time.Second)
	defer cancel()
	current, err := a.readLease()
	if err != nil {
		return errors.Join(cause, err)
	}
	if current == nil || current.FirstStart == nil || current.FirstStart.Phase != nfqws2FirstRunning || current.FirstStart.Process == nil {
		return cause
	}
	if previous == nil || previous.FirstStart == nil || previous.FirstStart.Process == nil || *current.FirstStart.Process == *previous.FirstStart.Process {
		return cause
	}
	return errors.Join(cause, a.deactivateFirstStart(cleanup, current))
}

func (a *NFQWS2Adapter) checkFirstStartBootReview(ctx context.Context, plan Plan, lease *nfqws2Lease) error {
	if err := CheckCommittedRecoveryReview(ctx, plan); err != nil {
		return err
	}
	review, ok := ctx.Value(committedRecoveryReviewKey{}).(*committedRecoveryReview)
	if !ok || review == nil || review.manager == nil {
		return ErrReviewChanged
	}
	actual, ok := review.manager.adapter(a.ID())
	if !ok || actual != a {
		return ErrReviewChanged
	}
	if plan.State != "committed" || !plan.Ready || plan.SafeMode || plan.Noop || lease.Transaction != filepath.Join(review.manager.StateRoot, "transactions", plan.PlanID, a.ID()) {
		return ErrReviewChanged
	}
	current, err := a.readLease()
	if err != nil || !reflect.DeepEqual(current, lease) {
		return ErrReviewChanged
	}
	staged, exists, err := nfqws2Read(filepath.Join(lease.Transaction, "nfqws2.conf.staged"))
	if err != nil || !exists || nfqws2Hash(staged) != lease.ConfigHash {
		return ErrReviewChanged
	}
	init, exists, err := nfqws2Read(filepath.Join(lease.Transaction, "S51nfqws2.staged"))
	if err != nil || !exists || nfqws2Hash(init) != lease.InitHash {
		return ErrReviewChanged
	}
	return nil
}
