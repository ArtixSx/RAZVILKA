package dataplane

import (
	"context"
	"errors"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"path/filepath"
)

type mihomoColdReadSource interface {
	MihomoColdReadTools() (any, SyntheticDNSCommandTools, string, error)
	RunMihomoColdRead(context.Context, string, ...string) ([]byte, error)
}
type mihomoColdReadRunner struct {
	original *RuntimeInactivitySourceReview
	source   mihomoColdReadSource
	tools    SyntheticDNSCommandTools
	ip6      string
}

func (r *mihomoColdReadRunner) current(ctx context.Context) error {
	if r == nil || r.original == nil || r.original.CheckCurrent(ctx) != nil || r.source == nil {
		return ErrMihomoLiveRetirement
	}
	original, tools, ip6, err := r.source.MihomoColdReadTools()
	inventory := r.original.source.inventory
	if err != nil || !sameNetworkPolicyDependency(original, inventory.reader.Runner) || !sameNetworkPolicyDependency(r.source, inventory.reader.Runner) ||
		tools.Provider != r.original.source.provider || tools.Provider != r.tools.Provider || tools.Identity != r.tools.Identity ||
		tools.ReviewSHA256 != inventory.review || tools.ReviewSHA256 != r.tools.ReviewSHA256 || tools.IP != r.tools.IP || tools.IPTables != r.tools.IPTables ||
		tools.IPTables != inventory.reader.IPTables || ip6 != r.ip6 || ip6 != inventory.reader.IP6Tables {
		return errors.Join(ErrMihomoLiveRetirement, err)
	}
	return ctx.Err()
}
func (r *mihomoColdReadRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if err := r.current(ctx); err != nil {
		return nil, err
	}
	if name != r.tools.IP && name != r.tools.IPTables && name != r.ip6 {
		return nil, ErrMihomoLiveRetirement
	}
	data, err := r.source.RunMihomoColdRead(ctx, name, args...)
	if closing := r.current(ctx); closing != nil {
		return nil, errors.Join(err, closing)
	}
	return data, err
}

// This private view is never registered and exposes no live owner or effect
// issuer. Coordinates come from the compiled adapter, tools from the ORIGINAL
// startup inventory lease; journal contents cannot choose executable paths.
func (m *Manager) mihomoColdProxy(ctx context.Context) (*ProxyTunnelAdapter, *netidentity.Provider, error) {
	if m == nil || xraySelectedTCPFinite(ctx) != nil {
		return nil, nil, ErrMihomoLiveRetirement
	}
	m.registryMu.RLock()
	original := m.runtimeSources
	m.registryMu.RUnlock()
	if original == nil || original.CheckCurrent(ctx) != nil {
		return nil, nil, ErrMihomoLiveRetirement
	}
	inventory := original.source.inventory
	source, ok := inventory.reader.Runner.(mihomoColdReadSource)
	if !ok {
		return nil, nil, ErrMihomoLiveRetirement
	}
	_, tools, ip6, err := source.MihomoColdReadTools()
	if err != nil || !tools.valid() || !filepath.IsAbs(tools.IP) || !filepath.IsAbs(ip6) {
		return nil, nil, ErrMihomoLiveRetirement
	}
	runner := &mihomoColdReadRunner{original: original, source: source, tools: tools, ip6: ip6}
	if err := runner.current(ctx); err != nil {
		return nil, nil, err
	}
	base, ok := m.adapter("sing-box")
	parent, typed := base.(*ProxyTunnelAdapter)
	if !ok || !typed || parent == nil || parent.StateRoot != filepath.Join(m.StateRoot, "sing-box") {
		return nil, nil, ErrMihomoLiveRetirement
	}
	proxy, err := NewProxyTunnelAdapter("mihomo", nil, m.StateRoot)
	if err != nil {
		return nil, nil, err
	}
	proxy.Runner, proxy.IP, proxy.IPTables, proxy.IP6Tables = runner, tools.IP, tools.IPTables, ip6
	proxy.EngineBin = "/opt/bin/mihomo"
	proxy.SidecarKind, proxy.SidecarBin = parent.SidecarKind, parent.SidecarBin
	return proxy, tools.Provider, nil
}
