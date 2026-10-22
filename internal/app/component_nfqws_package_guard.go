package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/ArtixSx/razvilka/internal/components"
)

func (a *App) nfqwsPackageMutationGuard(id string) error {
	if id != "nfqws2" {
		return nil
	}
	if a == nil || a.Dataplane == nil || a.Components == nil {
		return components.ErrNFQWSPackageOwnershipUnknown
	}
	blocked, err := a.Dataplane.NFQWS2PackageMutationBlocked()
	if err != nil {
		return fmt.Errorf("%w: %v", components.ErrNFQWSPackageOwnershipUnknown, err)
	}
	if blocked {
		return components.ErrNFQWSOwnedPackageMutation
	}
	blocked, err = a.Components.NFQWSOwnedPackageInit()
	if err != nil {
		return err
	}
	if blocked {
		return components.ErrNFQWSOwnedPackageMutation
	}
	return nil
}

func nfqwsPackageMutationCode(err error) string {
	if errors.Is(err, components.ErrNFQWSOwnedPackageMutation) {
		return "NFQWS_OWNED_PROFILE_PACKAGE_UNSUPPORTED"
	}
	return "NFQWS_PACKAGE_OWNERSHIP_UNKNOWN"
}

func writeNFQWSPackageMutationFailure(w http.ResponseWriter, err error) bool {
	if errors.Is(err, components.ErrNFQWSInitialInstall) {
		writeJSON(w, http.StatusConflict, map[string]any{"code": "NFQWS_INITIAL_INSTALL_REVIEW_REQUIRED", "error": err.Error()})
		return true
	}
	if !errors.Is(err, components.ErrNFQWSOwnedPackageMutation) && !errors.Is(err, components.ErrNFQWSPackageOwnershipUnknown) {
		return false
	}
	writeJSON(w, http.StatusConflict, map[string]any{"code": nfqwsPackageMutationCode(err), "error": err.Error()})
	return true
}

func (a *App) nfqwsPackageUpdateGuard(id string, guard func(context.Context) error) func(context.Context) error {
	return func(ctx context.Context) error {
		if err := a.nfqwsPackageMutationGuard(id); err != nil {
			return err
		}
		if guard != nil {
			return guard(ctx)
		}
		return nil
	}
}

// Inventory is advisory only. Every actual mutation rechecks ownership.
func (a *App) enrichNFQWSPackageInventory(views []components.View) {
	for i := range views {
		if views[i].ID != "nfqws2" {
			continue
		}
		if err := a.nfqwsPackageMutationGuard("nfqws2"); err != nil {
			views[i].CanInstall, views[i].CanUpdate, views[i].CanRemove = false, false, false
			views[i].LifecycleBlockReason = err.Error()
		}
	}
}
