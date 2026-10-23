package dataplane

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

// This is only an admission to repeat independent restoration checks. The
// strict rollback verifier still requires running metadata and a fresh exact
// process receipt. No historical PID is adopted or written back as live.
func nfqws2FirstStartRollbackResumeMatches(current *nfqws2Lease, snapshot nfqws2Snapshot) bool {
	before := snapshot.Lease
	if !snapshot.FirstStart || !snapshot.WasRunning || before == nil || before.FirstStart == nil || before.FirstStart.Phase != nfqws2FirstRunning || before.FirstStart.Process == nil ||
		current == nil || current.FirstStart == nil || current.FirstStart.Phase != nfqws2FirstStopped || current.FirstStart.Process == nil {
		return false
	}
	expected, first := *before, *before.FirstStart
	first.Phase = nfqws2FirstStopped
	expected.FirstStart = &first
	return reflect.DeepEqual(current, &expected)
}

// rollbackFirstStart restores the prior lease before restarting its runtime.
// A refusal between recordFirstStartStopped and Start leaves that exact prior
// lease stopped. A later explicit rollback retries only that unfinished start,
// under the same resource locks and a new finite native package review.
func (a *NFQWS2Adapter) resumeFirstStartRollback(ctx context.Context, root string, snapshot nfqws2Snapshot, expected *nfqws2Lease) (result error) {
	unlock, err := a.lockResources()
	if err != nil {
		return err
	}
	defer unlock()
	if !nfqws2InactiveFinite(ctx) || !nfqws2FirstStartRollbackResumeMatches(expected, snapshot) {
		return ErrReviewChanged
	}
	if a.stockNativeOwner == nil || a.firstStartReview != nil || filepath.Clean(a.InitPath) != filepath.Join(a.stockNativeOwner.InitDir, "S51nfqws2") ||
		filepath.Clean(a.ConfigPath) != filepath.Join(filepath.Dir(a.stockNativeOwner.InitDir), "nfqws2", "nfqws2.conf") {
		return components.ErrStockNFQWSNative
	}
	// The first rollback restores this exact saved overlay before restarting.
	// It is data only: independent absence is still required, and the ordinary
	// closed-config guard validates it again before any owned init invocation.
	running, runningExists, err := nfqws2Read(a.ConfigPath + ".run")
	if err != nil || runningExists && (!snapshot.RunningConfigExisted || !bytes.Equal(running, snapshot.RunningConfig)) {
		return ErrReviewChanged
	}
	current := func() error {
		if err := checkFirstStartReviewGuard(ctx); err != nil {
			return err
		}
		lease, err := a.readLease()
		if err != nil || !reflect.DeepEqual(lease, expected) {
			return ErrReviewChanged
		}
		data, existed := nfqws2SnapshotResources(snapshot)
		for i, path := range append(a.globalResources(), a.InitPath) {
			before, present := snapshot.Init, true
			if i < len(data) {
				before, present = data[i], existed[i]
			}
			actual, exists, err := nfqws2Read(path)
			if err != nil || exists != present || !bytes.Equal(actual, before) {
				return ErrReviewChanged
			}
		}
		actual, exists, err := nfqws2Read(a.ConfigPath + ".run")
		if err != nil || exists != runningExists || !bytes.Equal(actual, running) {
			return ErrReviewChanged
		}
		if _, exists, err := nfqws2Read(a.firstStartPIDPath()); err != nil || exists {
			return ErrReviewChanged
		}
		return ctx.Err()
	}
	if err := current(); err != nil {
		return err
	}
	if err := a.firstStartRuntimeAbsent(ctx); err != nil {
		return err
	}
	owner, err := a.owner()
	if err != nil {
		return err
	}
	effective, err := engineconfig.NFQWSFirstStartEffectiveConfig(snapshot.Config, owner)
	if err != nil {
		return err
	}
	arguments, err := engineconfig.NFQWSStartupArguments(effective, nil)
	if err != nil {
		return err
	}
	nativeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	review, err := a.stockNativeOwner.ReviewStockNFQWSNative(nativeCtx, arguments)
	if err != nil {
		return err
	}
	a.firstStartReview, a.firstStartReviewRoot = review, root
	defer func() {
		a.firstStartReview, a.firstStartReviewRoot = nil, ""
		result = errors.Join(result, review.Close())
	}()
	if err := current(); err != nil {
		return err
	}
	if err := review.DryRun(nativeCtx); err != nil {
		return err
	}
	if err := current(); err != nil {
		return err
	}
	return a.startFirstStart(ctx, expected.Transaction)
}
