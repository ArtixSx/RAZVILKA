package app

import (
	"context"
	"errors"
	"reflect"
	"sync"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Private concrete App issuer: no supplied guard, runner, DNS choice or
// evidence DTO can replace these original owners. CORE retains this binding
// through its actual Apply/compensation before releasing the App operation.
type listWGOperationBinding struct {
	self     *listWGOperationBinding
	mu       sync.Mutex
	app      *App
	store    *config.Store
	manager  *dataplane.Manager
	files    *SelfUpdateFiles
	root     string
	scope    *ListScopeBinding
	lan      *dataplane.LANPolicyRuntimePlan
	control  *operationgate.ControlEpochReview
	cleanup  *operationgate.ExclusiveCleanupReview
	material *dataplane.WGOperationMaterial
	closed   bool
}

func (a *App) reviewListWGOperation(ctx context.Context, scope *ListScopeBinding) (*listWGOperationBinding, error) {
	if a == nil || a.Store == nil || a.Dataplane == nil || a.SelfUpdateFiles == nil || scope == nil || scope.self != scope || scope.app != a || scope.store != a.Store {
		return nil, dataplane.ErrWGOperationOwner
	}
	scope.mu.Lock()
	lan := dataplane.CloneLANPolicyRuntime(scope.bound)
	scope.mu.Unlock()
	if err := scope.ScopeCheck(ctx, lan); err != nil {
		return nil, err
	}
	r := &listWGOperationBinding{app: a, store: a.Store, manager: a.Dataplane, files: a.SelfUpdateFiles, root: a.SelfUpdateFiles.ControlRoot, scope: scope, lan: lan}
	r.self = r
	var err error
	r.control, err = a.Operations.ReviewControlEpoch(ctx, r.root)
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = r.close()
		}
	}()
	r.cleanup, err = r.control.ReviewExclusiveCleanup(ctx)
	if err != nil {
		return nil, err
	}
	r.material, err = dataplane.ReviewWGOperationMaterial(ctx, r.manager, r.control, r.lan)
	if err != nil {
		return nil, err
	}
	if _, err = r.context(ctx); err != nil {
		return nil, err
	}
	keep = true
	return r, nil
}

func (r *listWGOperationBinding) original() error {
	if r == nil || r.self != r {
		return dataplane.ErrWGOperationOwner
	}
	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	if closed || r.app.Store != r.store || r.app.Dataplane != r.manager || r.app.SelfUpdateFiles != r.files || r.files.ControlRoot != r.root || r.control == nil || !r.control.MatchesControlRoot(r.root) || r.scope.app != r.app || r.scope.store != r.store {
		return dataplane.ErrWGOperationOwner
	}
	return nil
}

func (r *listWGOperationBinding) context(ctx context.Context) (context.Context, error) {
	if err := r.original(); err != nil {
		return nil, err
	}
	if err := r.scope.ScopeCheck(ctx, r.lan); err != nil {
		return nil, err
	}
	return r.material.Context(ctx)
}

// CORE calls this private method for joined Apply compensation only. The
// original cleanup review retains the real operation while exact original
// retained physics is checked; no forward Scope/Store/selection is consulted.
// action remains the existing manager cleanup, with its causal WG receipts.
func (r *listWGOperationBinding) withCleanup(ctx context.Context, lan *dataplane.LANPolicyRuntimePlan, action func(context.Context) error) error {
	if err := r.original(); err != nil {
		return err
	}
	if action == nil || !reflect.DeepEqual(lan, r.lan) {
		return dataplane.ErrWGOperationOwner
	}
	return r.cleanup.WithCurrent(ctx, func() error {
		if err := r.control.CurrentForCleanup(ctx); err != nil {
			return err
		}
		if err := r.scope.cleanupScopeCheck(ctx, r.lan); err != nil {
			return err
		}
		err := action(ctx) // ctx preserves the original material/Manager owner.
		return errors.Join(err, r.original(), r.scope.cleanupScopeCheck(ctx, r.lan), r.control.CurrentForCleanup(ctx))
	})
}

func (r *listWGOperationBinding) close() error {
	if r == nil || r.self != r {
		return dataplane.ErrWGOperationOwner
	}
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
	var err error
	if r.material != nil {
		err = r.material.Close()
	}
	if r.control != nil {
		err = errors.Join(err, r.control.Close())
	}
	return err
}
