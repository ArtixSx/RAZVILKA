package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"runtime"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

// Read-only original startup source comparison. It creates neither a tool
// lease nor a network identity and cannot make a route or process ready.
func (m *Manager) MihomoLiveStartupProvider() *netidentity.Provider {
	if m == nil {
		return nil
	}
	m.registryMu.RLock()
	sources := m.runtimeSources
	if sources != nil && sources.self == sources && sources.manager == m && sources.source != nil && sources.source.inventory != nil {
		provider := sources.source.inventory.reader.Provider
		m.registryMu.RUnlock()
		return provider
	}
	m.registryMu.RUnlock()
	registered, ok := m.adapter("sing-box")
	if !ok {
		return nil
	}
	base, ok := registered.(*ProxyTunnelAdapter)
	if !ok || base == nil {
		return nil
	}
	source, ok := base.Runner.(interface {
		DomainTCPCommandSource() (any, SyntheticDNSCommandTools, error)
	})
	if !ok {
		return nil
	}
	_, tools, err := source.DomainTCPCommandSource()
	if err != nil || !validPlanDigest(tools.ReviewSHA256) || tools.IP != base.IP || tools.IPTables != base.IPTables {
		return nil
	}
	return tools.Provider
}

// Trusted startup owners, never a request DTO. ResourceGuard adds only an
// exclusion boundary; it cannot grant a source, process, health or route.
type MihomoLiveOptions struct {
	Manager       *Manager
	Configs       *engineconfig.Manager
	Nodes         *nodestore.Store
	Gate          *operationgate.Gate
	ControlRoot   string
	History       *updatecheck.ExecutionHistoryAdmission
	FreshProfile  func(context.Context) (string, error)
	SidecarKind   string
	ResourceGuard func(context.Context, Plan, string, netip.Addr) error
}

func (a *MihomoProbeAdapter) ConfigureLiveRuntime(ctx context.Context, options MihomoLiveOptions) error {
	if runtime.GOOS != "linux" {
		return errMihomoLiveMaterial
	}
	if a == nil || a.self != a || a.components == nil || a.provider == nil || options.Manager == nil || !a.RegisteredWith(options.Manager) || options.Configs == nil || options.Nodes == nil || options.Gate == nil || options.History == nil || options.FreshProfile == nil || options.ResourceGuard == nil || !filepath.IsAbs(options.ControlRoot) || filepath.Clean(options.ControlRoot) != options.ControlRoot {
		return errMihomoLiveMaterial
	}
	if options.SidecarKind == "" {
		options.SidecarKind = "sing-box"
	}
	if options.SidecarKind != "sing-box" && options.SidecarKind != "hev" {
		return errMihomoLiveMaterial
	}
	parent, ok := options.Manager.adapter("sing-box")
	base, typed := parent.(*ProxyTunnelAdapter)
	if !ok || !typed || base == nil || base.Configs != options.Configs || base.StateRoot != filepath.Join(options.Manager.StateRoot, "sing-box") || base.Runner == nil {
		return errMihomoLiveMaterial
	}
	proxy, err := NewProxyTunnelAdapter("mihomo", options.Configs, options.Manager.StateRoot)
	if err != nil {
		return err
	}
	proxy.mihomoOwner = a
	proxy.EngineBin = filepath.Join(a.components.BinDir, "mihomo")
	proxy.Runner, proxy.IP, proxy.IPTables, proxy.IP6Tables = base.Runner, base.IP, base.IPTables, base.IP6Tables
	proxy.LANBridgeMembers = base.LANBridgeMembers
	proxy.FreshProfile = options.FreshProfile
	// Only the already-retained protected tool source may execute effects.
	// Its fixed images/environment and CORE admission cannot be replaced by a
	// bare path runner when live routing is enabled.
	toolRunner := base.Runner
	var originalGate *NetworkPolicyAdapter
	var originalGateRunner NFQWS2Runner
	if registered, found := options.Manager.adapter(NetworkPolicyAdapterID); found {
		gate, typed := registered.(*NetworkPolicyAdapter)
		if !typed || gate == nil || gate.Binding == nil || gate.Binding.Runtime == nil || gate.identity == nil || gate.identity.provider != a.provider {
			return errMihomoLiveMaterial
		}
		wrapped, typed := gate.Binding.Runtime.Runner.(networkPolicyIdentityRunner)
		if !typed || wrapped.identity != gate.identity || wrapped.runner == nil {
			return errMihomoLiveMaterial
		}
		toolRunner = wrapped.runner
		originalGate, originalGateRunner = gate, gate.Binding.Runtime.Runner
		proxy.IP, proxy.IPTables, proxy.IP6Tables = gate.Binding.Runtime.IP, gate.Binding.Runtime.IPTables, gate.Binding.Runtime.IP6Tables
	}
	toolSource, ok := toolRunner.(interface {
		DomainTCPCommandSource() (any, SyntheticDNSCommandTools, error)
	})
	if !ok {
		return errMihomoLiveMaterial
	}
	if _, ok := toolRunner.(mihomoLiveProtectedRunner); !ok {
		return errMihomoLiveMaterial
	}
	_, tools, err := toolSource.DomainTCPCommandSource()
	if err != nil || !validPlanDigest(tools.ReviewSHA256) || tools.Provider != a.provider || tools.IP != proxy.IP || tools.IPTables != proxy.IPTables {
		return errors.Join(errMihomoLiveMaterial, err)
	}
	proxy.Runner = &mihomoLiveCommandRunner{adapter: a, base: toolRunner, review: tools.ReviewSHA256, gate: originalGate, gateRunner: originalGateRunner}
	proxy.Processes = &mihomoLiveProcessController{adapter: a, proxy: proxy}
	if options.SidecarKind == "hev" {
		if err := BindHEVSidecarForRecovery(ctx, proxy, a.components); err != nil {
			return err
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.liveProxy != nil || a.liveOptions != nil || a.busy || a.pending != nil || a.livePending != nil || a.liveActive != nil {
		return errMihomoLiveMaterial
	}
	copy := options
	a.liveProxy, a.liveManager, a.liveOptions = proxy, options.Manager, &copy
	return nil
}

func (a *MihomoProbeAdapter) liveResource(ctx context.Context) (*mihomoLiveResource, error) {
	if a == nil || a.self != a || ctx == nil {
		return nil, errMihomoLiveMaterial
	}
	s, ok := ctx.Value(syntheticExecutionRegistrarKey{}).(*executionResourceScope)
	if !ok || s == nil || s.adapterOwner != a || s.adapter != "mihomo" || s.mihomoProof || s.mihomoLive == nil || s.mihomoLive.adapter != a {
		return nil, errMihomoLiveMaterial
	}
	r := s.mihomoLive
	if r.self != r || r.scope != s {
		return nil, errMihomoLiveMaterial
	}
	return r, nil
}

func (r *mihomoLiveResource) cleanupReview(ctx context.Context) (*operationgate.ExclusiveCleanupReview, error) {
	if op, ok := ctx.Value(mihomoLiveOperationKey{}).(*mihomoLiveOperation); ok {
		if op == nil || op.self != op || op.owner != r || !op.open.Load() || op.forward || op.cleanup == nil {
			return nil, errMihomoLiveMaterial
		}
		return op.cleanup, r.control.CurrentForCleanupOperation(ctx, op.cleanup)
	}
	r.mu.Lock()
	cleanup := r.cleanup
	r.mu.Unlock()
	if cleanup == nil {
		return nil, errMihomoLiveMaterial
	}
	return cleanup, r.control.CurrentForCleanupOperation(ctx, cleanup)
}

type mihomoLiveProcessController struct {
	adapter *MihomoProbeAdapter
	proxy   *ProxyTunnelAdapter
}

func (c *mihomoLiveProcessController) resource(ctx context.Context, spec ProcessSpec) (*mihomoLiveResource, bool, error) {
	if c == nil || c.adapter == nil || c.proxy == nil || c.proxy.mihomoOwner != c.adapter {
		return nil, false, errMihomoLiveMaterial
	}
	r, err := c.adapter.liveResource(ctx)
	if err != nil || r.proxy != c.proxy {
		return nil, false, errors.Join(errMihomoLiveMaterial, err)
	}
	engine := sameMihomoLiveSpec(spec, c.proxy.engineProcess())
	if !engine && !sameMihomoLiveSpec(spec, c.proxy.sidecarProcess()) {
		return nil, false, errMihomoLiveMaterial
	}
	return r, engine, nil
}
func (c *mihomoLiveProcessController) Start(ctx context.Context, spec ProcessSpec) error {
	r, engine, err := c.resource(ctx, spec)
	if err != nil {
		return err
	}
	if engine {
		r.mu.Lock()
		existing := r.child != nil
		r.mu.Unlock()
		if existing {
			return r.nativeCurrent(ctx)
		}
		cleanup, err := r.cleanupReview(ctx)
		if err != nil {
			return err
		}
		return r.startNative(ctx, cleanup)
	}
	return r.startSidecarNative(ctx)
}
func (c *mihomoLiveProcessController) Stop(ctx context.Context, spec ProcessSpec) error {
	r, engine, err := c.resource(ctx, spec)
	if err != nil {
		return err
	}
	cleanup, err := r.cleanupReview(ctx)
	if err != nil {
		return err
	}
	if engine {
		return r.cleanupNative(ctx, cleanup)
	}
	return r.cleanupSidecarNative(ctx, cleanup)
}
func (c *mihomoLiveProcessController) Running(spec ProcessSpec) bool {
	if c == nil || c.adapter == nil || c.proxy == nil {
		return false
	}
	c.adapter.mu.Lock()
	r := c.adapter.livePending
	if r == nil {
		r = c.adapter.liveActive
	}
	c.adapter.mu.Unlock()
	if r == nil || r.self != r || r.proxy != c.proxy {
		return false
	}
	r.mu.Lock()
	child, sidecar := r.child, r.sidecar
	r.mu.Unlock()
	if sameMihomoLiveSpec(spec, c.proxy.engineProcess()) {
		return child != nil && child.PID() > 0
	}
	if !sameMihomoLiveSpec(spec, c.proxy.sidecarProcess()) || sidecar == nil {
		return false
	}
	sidecar.mu.Lock()
	defer sidecar.mu.Unlock()
	if !sidecar.started || sidecar.joined || sidecar.closed {
		return false
	}
	select {
	case <-sidecar.done:
		return false
	default:
		return true
	}
}
