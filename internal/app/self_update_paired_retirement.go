package app

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

type selfUpdatePairedRetirementProvider interface {
	RetireCompletedPairedState(context.Context, string, int, updatecheck.SelfUpdateRuntimeObservation) error
}

type appPairedRetirementStartupKey struct{}

type appPairedRetirementStartup struct {
	self        *appPairedRetirementStartup
	original    context.Context
	app         *App
	files       *SelfUpdateFiles
	adapter     SelfUpdateFileAdapter
	store       *config.Store
	helper      *updatecheck.Updater
	id          string
	workerPID   int
	revision    uint64
	fingerprint string
	controlRoot string
	pair        selfupdatejournal.PairedBinding
}

// CORE calls this once at actual candidate startup, after ExclusiveContext and
// before RetainHandoff. Only that exact finite operation may later retire the
// completed pair. A fresh lease on the same App cannot reconstruct the owner.
func (a *App) bindPairedSelfUpdateRetirement(ctx context.Context) (context.Context, error) {
	if a == nil || ctx == nil || ctx.Err() != nil || a.Store == nil || a.SelfUpdateFiles == nil || a.SelfUpdate == nil {
		return nil, updatecheck.ErrPairedRetirementOwner
	}
	if deadline, finite := ctx.Deadline(); !finite || !deadline.After(time.Now()) || ctx.Value(appPairedRetirementStartupKey{}) != nil {
		return nil, updatecheck.ErrPairedRetirementOwner
	}
	bound := ctx
	err := a.Operations.WithExclusiveContext(ctx, func() error {
		f := a.SelfUpdateFiles
		r, present, err := f.Current()
		if err != nil {
			return err
		}
		if !present || r.Schema != selfupdatejournal.PairedSchema {
			return nil
		}
		scope, ok := ctx.Value(selfUpdateFileAdmissionKey{}).(selfUpdateFileAdmission)
		if !ok || scope.inspect || scope.action != "" || scope.id != r.ID || r.Paired == nil || r.Rollback ||
			(r.Phase != "command-started" && r.Phase != "command-finished") || r.Command != "start-candidate-panel" ||
			f.Adapter == nil || !reflect.TypeOf(f.Adapter).Comparable() || f.Helper != a.SelfUpdate || f.ControlRoot == "" || f.RecoveryGuard == nil ||
			a.SelfUpdateStartupJobID != r.ID || a.SelfUpdateStartupHelperPID <= 1 || !a.SelfUpdate.StartupPending() {
			return updatecheck.ErrPairedRetirementOwner
		}
		if err := a.selfUpdateStartupAllowed(ctx, r.ID, a.SelfUpdateStartupHelperPID); err != nil {
			return err
		}
		cfg := a.Store.Get()
		if cfg.Revision != r.Paired.Revision || cfg.SafeMode || cfg.ServiceControl.Stopped {
			return updatecheck.ErrPairedRetirementOwner
		}
		p := &appPairedRetirementStartup{app: a, files: f, adapter: f.Adapter, store: a.Store, helper: a.SelfUpdate,
			id: r.ID, workerPID: a.SelfUpdateStartupHelperPID, revision: cfg.Revision, fingerprint: updatecheck.ConfigFingerprint(cfg), controlRoot: f.ControlRoot, pair: *r.Paired}
		p.self = p
		bound = context.WithValue(ctx, appPairedRetirementStartupKey{}, p)
		p.original = bound
		return nil
	})
	if err != nil {
		return nil, errors.Join(updatecheck.ErrPairedRetirementOwner, err)
	}
	return bound, nil
}

func (p *appPairedRetirementStartup) current(ctx context.Context, a *App, r selfupdatejournal.Receipt) error {
	if p == nil || p.self != p || p.original == nil || ctx != p.original || ctx.Err() != nil || p.app != a || a == nil ||
		a.Store != p.store || a.SelfUpdateFiles != p.files || a.SelfUpdate != p.helper || p.files == nil || p.files.Adapter != p.adapter ||
		p.files.Helper != p.helper || p.files.ControlRoot != p.controlRoot || a.SelfUpdateStartupJobID != p.id || a.SelfUpdateStartupHelperPID != p.workerPID ||
		r.ID != p.id || r.Paired == nil || *r.Paired != p.pair {
		return updatecheck.ErrPairedRetirementOwner
	}
	cfg := p.store.Get()
	if cfg.Revision != p.revision || cfg.SafeMode || cfg.ServiceControl.Stopped || updatecheck.ConfigFingerprint(cfg) != p.fingerprint {
		return updatecheck.ErrPairedRetirementOwner
	}
	return nil
}

// CORE's original startup handoff owns ctx and its exclusive lease until this
// synchronous call, node cleanup and installer settlement have all returned.
// This method creates no new admission, worker, deadline or recovery grant.
// Nonpaired updates return false. CORE must fence a paired refusal before
// releasing the lease, including a closing refusal after archive publication.
func (a *App) RetireCompletedPairedSelfUpdate(ctx context.Context) (bool, error) {
	if a == nil || ctx == nil || ctx.Err() != nil || a.Store == nil || a.SelfUpdateFiles == nil || a.SelfUpdate == nil {
		return false, updatecheck.ErrPairedRetirementOwner
	}
	if deadline, finite := ctx.Deadline(); !finite || !deadline.After(time.Now()) {
		return false, updatecheck.ErrPairedRetirementOwner
	}
	retired := false
	err := a.Operations.WithExclusiveContext(ctx, func() error {
		f := a.SelfUpdateFiles
		opening, present, err := f.Current()
		if err != nil {
			return err
		}
		if !present || opening.Schema != selfupdatejournal.PairedSchema {
			return nil
		}
		startup, _ := ctx.Value(appPairedRetirementStartupKey{}).(*appPairedRetirementStartup)
		if err := startup.current(ctx, a, opening); err != nil {
			return err
		}
		provider, ok := f.Adapter.(selfUpdatePairedRetirementProvider)
		if !ok || f.Adapter == nil || !reflect.TypeOf(f.Adapter).Comparable() || f.Helper != a.SelfUpdate || f.RecoveryGuard == nil || f.ControlRoot == "" ||
			a.SelfUpdateStartupJobID != opening.ID || a.SelfUpdateStartupHelperPID <= 1 || opening.Paired == nil || opening.Rollback ||
			(opening.Phase != "accepted" && opening.Phase != "archived") {
			return updatecheck.ErrPairedRetirementOwner
		}
		cfg := a.Store.Get()
		if cfg.Revision != opening.Paired.Revision || cfg.SafeMode || cfg.ServiceControl.Stopped {
			return updatecheck.ErrPairedRetirementOwner
		}
		epoch, err := a.Operations.ReviewControlEpoch(ctx, f.ControlRoot)
		if err != nil {
			return err
		}
		defer epoch.Close()
		reference := epoch.Reference()
		if reference.InstallationID != opening.Paired.InstallationID || reference.Sequence != opening.Paired.Sequence {
			return operationgate.ErrSelfUpdateStopChanged
		}
		p := &appPairedRetirementOwner{app: a, original: ctx, files: f, adapter: f.Adapter, store: a.Store, helper: a.SelfUpdate,
			id: opening.ID, workerPID: a.SelfUpdateStartupHelperPID, revision: cfg.Revision, fingerprint: updatecheck.ConfigFingerprint(cfg), epoch: epoch, startup: startup, pair: opening}
		p.self = p
		if err := p.current(ctx, p.id); err != nil {
			return err
		}
		observations := 0
		owner := func(c context.Context, id string) error {
			if err := p.current(c, id); err != nil {
				return err
			}
			observations++
			return nil
		}
		if err := provider.RetireCompletedPairedState(ctx, p.id, p.workerPID, owner); err != nil {
			return err
		}
		if observations < 2 {
			return updatecheck.ErrPairedRetirementOwner
		}
		closing, present, err := f.Current()
		if err != nil || !present || closing.ID != p.id || closing.Schema != selfupdatejournal.PairedSchema || closing.Phase != "archived" || closing.Retired == nil ||
			!reflect.DeepEqual(closing.Paired, opening.Paired) || closing.Rollback {
			return errors.Join(updatecheck.ErrPairedRetirementOwner, err)
		}
		if err := p.current(ctx, p.id); err != nil {
			return err
		}
		retired = true
		return nil
	})
	if err != nil {
		return false, errors.Join(updatecheck.ErrPairedRetirementOwner, err)
	}
	if err := ctx.Err(); err != nil {
		return false, errors.Join(updatecheck.ErrPairedRetirementOwner, err)
	}
	return retired, nil
}

type appPairedRetirementOwner struct {
	self        *appPairedRetirementOwner
	app         *App
	original    context.Context
	files       *SelfUpdateFiles
	adapter     SelfUpdateFileAdapter
	store       *config.Store
	helper      *updatecheck.Updater
	id          string
	workerPID   int
	revision    uint64
	fingerprint string
	epoch       *operationgate.ControlEpochReview
	startup     *appPairedRetirementStartup
	pair        selfupdatejournal.Receipt
}

func (p *appPairedRetirementOwner) current(ctx context.Context, id string) error {
	if p == nil || p.self != p || p.app == nil || p.original == nil || p.files == nil || p.store == nil || p.helper == nil || ctx == nil || ctx != p.original || ctx.Err() != nil || p.original.Err() != nil ||
		id != p.id || p.app.Store != p.store || p.app.SelfUpdateFiles != p.files || p.app.SelfUpdate != p.helper || p.files.Helper != p.helper ||
		p.files.Adapter != p.adapter || p.app.SelfUpdateStartupJobID != p.id || p.app.SelfUpdateStartupHelperPID != p.workerPID || p.epoch == nil {
		return updatecheck.ErrPairedRetirementOwner
	}
	return p.app.Operations.WithExclusiveContext(ctx, func() error {
		if err := p.startup.current(ctx, p.app, p.pair); err != nil {
			return err
		}
		if err := p.epoch.Current(ctx); err != nil {
			return err
		}
		cfg := p.store.Get()
		if cfg.Revision != p.revision || cfg.SafeMode || cfg.ServiceControl.Stopped || updatecheck.ConfigFingerprint(cfg) != p.fingerprint || p.app.PendingComponentRecovery() {
			return updatecheck.ErrPairedRetirementOwner
		}
		job := p.helper.Snapshot()
		if job.ID != p.id || job.State != "completed" || job.Stage != "completed" || job.CanApply || job.CanCancel || job.ReviewToken != "" {
			return updatecheck.ErrPairedRetirementOwner
		}
		if p.files.RecoveryGuard == nil {
			return updatecheck.ErrPairedRetirementOwner
		}
		if err := p.files.RecoveryGuard(ctx); err != nil {
			return err
		}
		return p.epoch.Current(ctx)
	})
}

// CORE adds this to SelfUpdateFiles.Pending. It is deliberately independent of
// healthy/status handling: acceptance alone cannot release ordinary writes.
func pairedSelfUpdateRetirementPending(receipt selfupdatejournal.Receipt) bool {
	return receipt.Schema == selfupdatejournal.PairedSchema && (receipt.Phase != "archived" || receipt.Retired == nil)
}
