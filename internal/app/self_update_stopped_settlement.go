package app

import (
	"context"
	"math"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

// Optional exact OPS methods; ordinary adapters cannot acquire settlement by
// implementing permissive defaults on the required file-effect interface.
type selfUpdateStoppedSettlementAdapter interface {
	StoppedSettlementEligibility(context.Context, string) (bool, error)
	SettleStoppedRollback(context.Context, string, updatecheck.SelfUpdateStoppedSettlementAuthority) error
}

func (f *SelfUpdateFiles) settleStoppedRollback(ctx context.Context, id string, revision uint64, guard selfupdatejournal.Check) error {
	provider, ok := f.Adapter.(selfUpdateStoppedSettlementAdapter)
	if !ok || ctx == nil || ctx.Err() != nil || f.ControlRoot == "" || f.JournalReadGuard == nil {
		return errSelfUpdateRecovery
	}
	controlRoot := f.ControlRoot
	frozen, present, err := operationgate.ReadSelfUpdateStop(ctx, controlRoot)
	if err != nil || !present || !frozen.Stopped || frozen.TransactionID != id || frozen.ConfigRevision != revision || frozen.Sequence < 2 {
		return operationgate.ErrSelfUpdateStopChanged
	}
	// No control writer is used: current and the canonical request stay exact.
	// CORE holds no config/control lock across callbacks; OPS retains its own
	// separate journal writer. A callback can revoke the reviewed config.
	current := func(c context.Context) error {
		if c == nil || c.Err() != nil || ctx.Err() != nil {
			return errSelfUpdateRecovery
		}
		read, present, err := operationgate.ReadSelfUpdateStop(c, controlRoot)
		if err != nil || !present || read != frozen {
			return operationgate.ErrSelfUpdateStopChanged
		}
		return nil
	}
	scope := func(c context.Context) error {
		if err := current(c); err != nil {
			return err
		}
		if err := guard(c); err != nil {
			return err
		}
		if f.RecoveryGuard != nil {
			if err := f.RecoveryGuard(c); err != nil {
				return err
			}
		}
		if err := guard(c); err != nil {
			return err
		}
		return current(c)
	}
	if err := scope(ctx); err != nil {
		return err
	}
	eligible, err := provider.StoppedSettlementEligibility(ctx, id)
	if err != nil {
		return err
	}
	if !eligible {
		return updatecheck.ErrStoppedSettlementIneligible
	}
	if err := scope(ctx); err != nil {
		return err
	}
	checked, readersChecked := false, false
	authority := updatecheck.SelfUpdateStoppedSettlementAuthority{
		Check: func(c context.Context, actualID, installationID string, preStop, reviewedRevision uint64) error {
			if actualID != id || installationID != frozen.InstallationID || preStop == 0 || preStop == math.MaxUint64 || preStop+1 != frozen.Sequence || reviewedRevision != revision {
				return operationgate.ErrSelfUpdateStopChanged
			}
			if err := scope(c); err != nil {
				return err
			}
			checked = true
			return nil
		},
		AdmitReaders: func(c context.Context, actualID string, required int) error {
			if actualID != id || required != selfupdatejournal.StoppedSchema {
				return errSelfUpdateRecovery
			}
			if err := scope(c); err != nil {
				return err
			}
			// OPS already checks its sealed fleet before this callback. Pass c,
			// including its active writerObservation, to the readonly scanner.
			if err := f.JournalReadGuard(c, required); err != nil {
				return err
			}
			if err := scope(c); err != nil {
				return err
			}
			readersChecked = true
			return nil
		},
	}
	// OPS owns the sole writer plus actual ECHILD/private/runtime proofs. Do
	// not open a CORE file Store while its retained writer lease is active.
	if err := provider.SettleStoppedRollback(ctx, id, authority); err != nil {
		return err
	}
	if !checked || !readersChecked {
		return errSelfUpdateRecovery
	}
	// Only after the provider returns, read the published terminal binding.
	receipt, present, err := f.Current()
	if err != nil || !present || receipt.ID != id || receipt.Schema != selfupdatejournal.StoppedSchema || receipt.Phase != "rolled-back-stopped" || receipt.Stopped == nil ||
		receipt.Stopped.InstallationID != frozen.InstallationID || receipt.Stopped.PreStopSequence+1 != frozen.Sequence || receipt.Stopped.StopSequence != frozen.Sequence || receipt.Stopped.Revision != revision || receipt.Stopped.RequiredReader != selfupdatejournal.StoppedSchema {
		return errSelfUpdateRecovery
	}
	return scope(ctx)
}
