package dataplane

import (
	"context"
	"errors"
	"github.com/ArtixSx/razvilka/internal/components"
	"path/filepath"
)

// BindManagedHEVSidecar is startup-only: caller must not expose the freshly
// constructed adapter to any operation until this returns. Existing adapter
// lifetimes keep one backend; API setting changes never call this function.
func BindManagedHEVSidecar(ctx context.Context, a *ProxyTunnelAdapter, owner *components.Manager) error {
	if a == nil || owner == nil || a.SidecarKind != "" || a.SidecarBin != "" || a.hevInstalledCheck != nil {
		return errors.New("HEV requires a fresh adapter and original component owner")
	}
	path, err := owner.CheckInstalledHEV(ctx)
	if err != nil {
		return err
	}
	return bindHEVSidecarOwner(a, owner, path)
}

// BindHEVSidecarForRecovery reconstructs only original fixed coordinates. A
// deleted/broken executable must not prevent observation or owned cleanup.
// Any actual start still consults the same installed owner afresh.
func BindHEVSidecarForRecovery(ctx context.Context, a *ProxyTunnelAdapter, owner *components.Manager) error {
	if ctx == nil || a == nil || owner == nil || a.SidecarKind != "" || a.SidecarBin != "" || a.hevInstalledCheck != nil {
		return errors.New("HEV recovery requires fresh original owner coordinates")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	base := owner.BinDir
	if base == "" {
		base = "/opt/bin"
	}
	if !filepath.IsAbs(base) {
		return errors.New("HEV recovery binary root must be absolute")
	}
	path := filepath.Clean(filepath.Join(base, "hev-socks5-tunnel"))
	return bindHEVSidecarOwner(a, owner, path)
}

func bindHEVSidecarOwner(a *ProxyTunnelAdapter, owner *components.Manager, path string) error {
	check := func(c context.Context) error {
		current, err := owner.CheckInstalledHEV(c)
		if err != nil {
			return err
		}
		if current != path {
			return errors.New("HEV component binding changed")
		}
		return nil
	}
	a.SidecarKind, a.SidecarBin, a.hevInstalledCheck = "hev", path, check
	if err := a.checkSidecarIdentity(); err != nil {
		a.SidecarKind, a.SidecarBin, a.hevInstalledCheck = "", "", nil
		return err
	}
	return nil
}
