package app

import (
	"context"
	"errors"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
)

// The legacy detector does not discover protected managed generation paths.
// Only the genuine Components current-receipt reader can make this saved
// route choice available. It proves installed assets, not native activation,
// service health or permission to execute a candidate/global init script.
func (a *App) prepareManagedNFQRouteOption(parent context.Context, option *routecatalog.Option) {
	if a == nil || a.Components == nil || parent == nil || option == nil || option.ID != "nfqws2" {
		return
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	a.managedNFQListMu.Lock()
	runtime := a.managedNFQList
	a.managedNFQListMu.Unlock()
	if handled, err := runtime.installedComponentCurrent(ctx); handled {
		if err == nil {
			managedNFQInstalledChoice(option)
		}
		return
	}
	lease, err := a.Components.AcquireCurrentManagedNFQWSRuntime(ctx)
	if err != nil {
		return
	}
	if err := errors.Join(lease.Check(ctx), lease.Close()); err != nil {
		return
	}
	managedNFQInstalledChoice(option)
}

// An active/pending execution already holds the actual component writer lease.
// Verify that SAME original lease under the runtime lock; reacquiring a second
// writer would incorrectly hide installed assets until Stop. No forward or
// health/effect permission is issued here and this does not close the lease.
func (r *ManagedNFQWSListRuntime) installedComponentCurrent(ctx context.Context) (bool, error) {
	if !r.original() {
		return false, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.active
	if r.pending != nil {
		e = r.pending
	}
	if e == nil {
		return false, nil
	}
	if r.closed || e.self != e || e.runtime != r || e.component == nil {
		return true, dataplane.ErrNFQWSScopedOwner
	}
	return true, e.component.Check(ctx)
}

func managedNFQInstalledChoice(option *routecatalog.Option) {
	option.Installed, option.Configured, option.Selectable = true, true, true
	// AUTO readiness must come from actual service/native evidence. A genuine
	// installation alone cannot authorize it or imply that this route is live.
	option.Ready = false
}
