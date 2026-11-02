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
	proxy                   *ProxyTunnelAdapter
	parent                  *ProxyTunnelAdapter
	sidecarKind, sidecarBin string
	engineSpec, sidecarSpec ProcessSpec

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
	if r.proxy != nil {
		registered, ok := r.original.manager.adapter("sing-box")
		if !ok || registered != r.parent || r.parent == nil || r.parent.SidecarKind != r.sidecarKind || r.parent.SidecarBin != r.sidecarBin ||
			r.proxy.Runner != r || r.proxy.mihomoOwner != nil || r.proxy.EngineBin != "/opt/bin/mihomo" || r.proxy.SidecarKind != r.sidecarKind || r.proxy.SidecarBin != r.sidecarBin ||
			r.proxy.IP != r.tools.IP || r.proxy.IPTables != r.tools.IPTables || r.proxy.IP6Tables != r.ip6 ||
			!sameMihomoLiveSpec(r.proxy.engineProcess(), r.engineSpec) || !sameMihomoLiveSpec(r.proxy.sidecarProcess(), r.sidecarSpec) {
			return ErrMihomoLiveRetirement
		}
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
	runner.proxy, runner.parent, runner.sidecarKind, runner.sidecarBin = proxy, parent, parent.SidecarKind, parent.SidecarBin
	runner.engineSpec, runner.sidecarSpec = proxy.engineProcess(), proxy.sidecarProcess()
	return proxy, tools.Provider, runner.current(ctx)
}

// Only the original private cold factory can supply this comparison binding.
// It exposes no effect runner or warm owner and is never in the registry.
func (a *ProxyTunnelAdapter) validateMihomoColdInactiveProcessScope(spec ProcessSpec) error {
	if a == nil || a.ID() != "mihomo" || a.mihomoOwner != nil {
		return ErrProxyRuntimeInactive
	}
	r, ok := a.Runner.(*mihomoColdReadRunner)
	if !ok || r == nil || r.proxy != a || r.original == nil || r.original.self != r.original || r.source == nil || r.parent == nil ||
		!sameMihomoLiveSpec(a.engineProcess(), r.engineSpec) || !sameMihomoLiveSpec(a.sidecarProcess(), r.sidecarSpec) ||
		!sameMihomoLiveSpec(spec, r.engineSpec) && !sameMihomoLiveSpec(spec, r.sidecarSpec) {
		return ErrProxyRuntimeInactive
	}
	return validateProxyInactiveProcessArgument(spec, "/proc/self/fd/4")
}
