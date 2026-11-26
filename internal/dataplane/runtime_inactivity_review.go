package dataplane

import (
	"context"
	"errors"
	"path/filepath"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// This sentinel means no startup binding exists. A closed or changed binding
// is an error, never permission to construct replacement observation owners.
var ErrRuntimeInactivitySourcesMissing = errors.New("runtime inactivity sources were not bound")

// RuntimeInactivitySourceReview borrows the ORIGINAL startup association. Its
// provider and collector retain their original tool lease and lifetime. It
// neither owns Close nor certifies absence, and cannot be constructed by a DTO.
type RuntimeInactivitySourceReview struct {
	self           *RuntimeInactivitySourceReview
	manager        *Manager
	nfq            *NFQWS2Adapter
	dns            *ScopedDNSAdapter
	source         *NFQWSRuntimeInactiveSource
	root, settings string
	dnsManager     *dnscontrol.Manager
	kernel         func(context.Context, netidentity.Identity) error
}

func newRuntimeInactivitySourceReview(m *Manager, nfq *NFQWS2Adapter, dns *ScopedDNSAdapter, source *NFQWSRuntimeInactiveSource, settings string) *RuntimeInactivitySourceReview {
	r := &RuntimeInactivitySourceReview{manager: m, nfq: nfq, dns: dns, source: source, root: m.StateRoot, settings: settings, dnsManager: dns.DNS, kernel: NewScopedDNSInactivityKernelCheck(source.inventory)}
	r.self = r
	return r
}

// ReviewRuntimeInactivitySources returns only this manager's existing original
// association. In particular a caller cannot supply an alternative provider,
// inventory or callbacks and ask that a second binding be treated as current.
func (m *Manager) ReviewRuntimeInactivitySources(ctx context.Context, settings string) (*RuntimeInactivitySourceReview, error) {
	if m == nil || !nfqws2InactiveFinite(ctx) || !filepath.IsAbs(settings) || filepath.Clean(settings) != settings || settings == filepath.VolumeName(settings)+string(filepath.Separator) {
		return nil, ErrRuntimeInactivity
	}
	m.registryMu.RLock()
	r := m.runtimeSources
	if r == nil {
		nfq, nfqOK := m.Adapters["nfqws2"].(*NFQWS2Adapter)
		dns, dnsOK := m.Adapters[scopedDNSAdapterID].(*ScopedDNSAdapter)
		missing := nfqOK && dnsOK && nfq != nil && dns != nil && nfq.inactivity == nil && dns.InactivityIdentity == nil && dns.InactivityKernelCheck == nil && dns.inactivitySources == nil
		m.registryMu.RUnlock()
		if missing {
			return nil, ErrRuntimeInactivitySourcesMissing
		}
		return nil, ErrRuntimeInactivity
	}
	m.registryMu.RUnlock()
	if settings != r.settings {
		return nil, ErrRuntimeInactivity
	}
	if err := r.CheckCurrent(ctx); err != nil {
		return nil, err
	}
	return r, nil
}

// Sources returns the actual retained objects, not replacements or a cached
// successful observation. Every subsequent inventory Read checks original tools.
func (r *RuntimeInactivitySourceReview) Sources(ctx context.Context) (*netidentity.Provider, *BackendInventory, error) {
	if err := r.CheckCurrent(ctx); err != nil {
		return nil, nil, err
	}
	return r.source.provider, r.source.inventory, nil
}

func (r *RuntimeInactivitySourceReview) CheckCurrent(ctx context.Context) error {
	if r == nil || r.source == nil || r.source.provider == nil {
		return ErrRuntimeInactivity
	}
	return r.checkCurrentWith(ctx, r.source.provider.WithCurrent)
}

// Private source model seam. Public review always uses the original provider.
func (r *RuntimeInactivitySourceReview) checkCurrentWith(ctx context.Context, withCurrent func(context.Context, func(context.Context, netidentity.Identity) error) error) error {
	if !r.currentAssociation(ctx) || withCurrent == nil {
		return ErrRuntimeInactivity
	}
	uses := 0
	err := withCurrent(ctx, func(c context.Context, identity netidentity.Identity) error {
		uses++
		if uses != 1 || identity != r.source.identity || !r.currentAssociation(c) {
			return ErrRuntimeInactivity
		}
		if err := r.source.frozen.reader.CheckTools(c, backendInventoryScope{Network: identity, ToolReviewID: r.source.frozen.review}); err != nil {
			return err
		}
		if !r.currentAssociation(c) {
			return ErrRuntimeInactivity
		}
		return nil
	})
	if err != nil {
		return err
	}
	if uses != 1 || !r.currentAssociation(ctx) {
		return ErrRuntimeInactivity
	}
	return nil
}

func (r *RuntimeInactivitySourceReview) currentAssociation(ctx context.Context) bool {
	if r == nil || r.self != r || r.manager == nil || r.source == nil || r.nfq == nil || r.dns == nil || !nfqws2InactiveFinite(ctx) {
		return false
	}
	m := r.manager
	m.registryMu.RLock()
	valid := m.runtimeSources == r && m.StateRoot == r.root && m.Adapters["nfqws2"] == r.nfq && m.Adapters[scopedDNSAdapterID] == r.dns &&
		r.nfq.StateRoot == filepath.Join(r.root, "runtime", "nfqws2") && r.dns.StateRoot == filepath.Join(r.root, scopedDNSAdapterID) &&
		r.dnsCoordinates()
	m.registryMu.RUnlock()
	return valid && r.source.current(ctx) == nil
}

func (r *RuntimeInactivitySourceReview) dnsCoordinates() bool {
	return r != nil && r.self == r && r.dns != nil && r.source != nil && r.kernel != nil && r.dns.inactivitySources == r && r.dns.InactivityKernelCheck == nil &&
		r.dns.InactivitySettingsPath == r.settings && r.dns.InactivityIdentity == r.source.provider && r.dns.DNS == r.dnsManager && (r.dnsManager == nil || r.dnsManager.Path == r.settings)
}

func (a *ScopedDNSAdapter) runtimeInactivityKernel() func(context.Context, netidentity.Identity) error {
	if a == nil {
		return nil
	}
	if r := a.inactivitySources; r != nil {
		if !r.dnsCoordinates() {
			return nil
		}
		return r.readDNSKernel
	}
	return a.InactivityKernelCheck
}

func (r *RuntimeInactivitySourceReview) readDNSKernel(ctx context.Context, identity netidentity.Identity) error {
	if !r.currentAssociation(ctx) || identity != r.source.identity {
		return ErrScopedDNSRuntimeInactive
	}
	if err := r.kernel(ctx, identity); err != nil {
		return err
	}
	if !r.currentAssociation(ctx) {
		return ErrScopedDNSRuntimeInactive
	}
	return nil
}
