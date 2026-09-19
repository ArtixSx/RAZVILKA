package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/ArtixSx/razvilka/internal/backendprofile"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

// NewProxyTunnelAdapterWithHev is an opt-in integration point for controlled
// testing. Production initialization continues to use sing-box until a trusted
// HEV package, admission UI and hardware acceptance are supplied. Never change
// SidecarKind on an existing adapter: its lifetime and rollback use one backend.
func NewProxyTunnelAdapterWithHev(id string, configs *engineconfig.Manager, stateRoot, binary string) (*ProxyTunnelAdapter, error) {
	if !filepath.IsAbs(binary) || filepath.Clean(binary) != binary {
		return nil, errors.New("HEV requires an explicit absolute executable path")
	}
	a, e := NewProxyTunnelAdapter(id, configs, stateRoot)
	if e != nil {
		return nil, e
	}
	a.SidecarKind = "hev"
	a.SidecarBin = binary
	if e = a.checkSidecarIdentity(); e != nil {
		return nil, e
	}
	return a, nil
}
func (a *ProxyTunnelAdapter) effectiveSidecar() string {
	if a.SidecarKind == "" {
		return "sing-box"
	}
	return a.SidecarKind
}
func (a *ProxyTunnelAdapter) checkSidecarIdentity() error {
	kind := a.effectiveSidecar()
	if kind != "sing-box" && kind != "hev" {
		return errors.New("unsupported TUN sidecar")
	}
	info, err := os.Lstat(a.sidecarConfigPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > 128<<10 {
		return errors.New("sidecar runtime is not a regular bounded file")
	}
	data, err := readBoundedSidecar(a.sidecarConfigPath())
	if err != nil {
		return err
	}
	var doc map[string]any
	if json.Unmarshal(data, &doc) != nil {
		return errors.New("sidecar identity is unreadable")
	}
	_, hev := doc["socks5"]
	if (kind == "hev") != hev {
		return errors.New("TUN backend differs from retained runtime; stop and migrate explicitly")
	}
	if hev {
		expected, e := a.hevConfig()
		if e != nil {
			return e
		}
		// An edited runtime cannot add scripts/mapdns by hiding behind the HEV label.
		if !bytes.Equal(data, expected) {
			return errors.New("HEV runtime settings differ from the adapter")
		}
	}
	return nil
}
func (a *ProxyTunnelAdapter) hevConfig() ([]byte, error) {
	return backendprofile.HevJSON(backendprofile.HevOptions{Interface: a.Interface, Address: a.TunnelCIDR, SOCKSPort: a.SOCKSPort, MTU: 1400, MaxSessions: 128})
}
func (a *ProxyTunnelAdapter) buildSidecarConfig(ctx context.Context) ([]byte, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if e := a.checkSidecarIdentity(); e != nil {
		return nil, e
	}
	if a.effectiveSidecar() == "hev" {
		return a.hevConfig()
	}
	schema, e := a.detectSidecarSchema(ctx)
	if e != nil {
		return nil, preflightRefusalError{e}
	}
	return buildSOCKSTunnelConfigForSchema(a.Interface, a.TunnelCIDR, a.SOCKSPort, schema)
}
func (a *ProxyTunnelAdapter) validateSidecarConfig(ctx context.Context, path string) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := a.checkSidecarIdentity(); e != nil {
		return e
	}
	if a.effectiveSidecar() == "hev" {
		if e := ctx.Err(); e != nil {
			return e
		}
		expected, e := a.hevConfig()
		if e != nil {
			return e
		}
		info, e := os.Lstat(path)
		if e != nil {
			return e
		}
		if !info.Mode().IsRegular() || info.Size() > 128<<10 {
			return errors.New("invalid staged HEV file")
		}
		actual, e := readBoundedSidecar(path)
		if e != nil {
			return e
		}
		if !bytes.Equal(actual, expected) {
			return errors.New("staged HEV config was changed")
		}
		// Upstream has no native dry-run equivalent. Do not start a real TUN as a
		// syntax test; Activate+Health must prove the running sidecar on the test rig.
		return nil
	}
	output, e := a.run(ctx, a.sidecarBinary(), "check", "-c", path)
	if e != nil {
		return errors.New("sing-box TUN validation failed: " + shortOutput(output, e))
	}
	return nil
}
func (a *ProxyTunnelAdapter) checkSnapshotSidecar(snapshot proxySnapshot) error {
	kind := snapshot.SidecarKind
	if kind == "" {
		kind = "sing-box"
	}
	if kind != a.effectiveSidecar() {
		return errors.New("snapshot belongs to another TUN backend")
	}
	return nil
}

// Bounded descriptor read; a replaced symlink/file cannot supply different bytes
// between the identity check and validation. Caller owns the runtime operation.
func readBoundedSidecar(path string) ([]byte, error) {
	before, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !before.Mode().IsRegular() || before.Size() > 128<<10 {
		return nil, errors.New("invalid sidecar file")
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	after, e := f.Stat()
	if e != nil || !os.SameFile(before, after) {
		return nil, errors.New("sidecar replaced")
	}
	data, e := io.ReadAll(io.LimitReader(f, (128<<10)+1))
	if e != nil {
		return nil, e
	}
	if len(data) > 128<<10 {
		return nil, errors.New("sidecar grew beyond limit")
	}
	return data, nil
}
