package app

import (
	"context"
	"errors"
	"time"

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
	lease, err := a.Components.AcquireCurrentManagedNFQWSRuntime(ctx)
	if err != nil {
		return
	}
	if err := errors.Join(lease.Check(ctx), lease.Close()); err != nil {
		return
	}
	option.Installed, option.Configured, option.Selectable = true, true, true
	// AUTO readiness must come from actual service/native evidence. A genuine
	// installation alone cannot authorize it or imply that this route is live.
	option.Ready = false
}
