package dataplane

import (
	"context"
	"errors"
	"path/filepath"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// BindRuntimeInactivitySources is called once by the trusted startup assembly
// with its actual complete collector and provider. The assembly must keep the
// original admitted tool lease alive throughout every later observation.
// Construction authenticates the source; it does not prove runtime absence.
func (m *Manager) BindRuntimeInactivitySources(ctx context.Context, provider *netidentity.Provider, inventory *BackendInventory, settingsPath string) error {
	if m == nil || !nfqws2InactiveFinite(ctx) || provider == nil || inventory == nil || inventory.reader.Provider != provider ||
		!filepath.IsAbs(settingsPath) || filepath.Clean(settingsPath) != settingsPath || settingsPath == filepath.VolumeName(settingsPath)+string(filepath.Separator) {
		return ErrRuntimeInactivity
	}
	m.registryMu.RLock()
	defer m.registryMu.RUnlock()
	nfq, ok := m.Adapters["nfqws2"].(*NFQWS2Adapter)
	dns, dnsOK := m.Adapters[scopedDNSAdapterID].(*ScopedDNSAdapter)
	if !ok || !dnsOK || nfq == nil || dns == nil || nfq.StateRoot != filepath.Join(m.StateRoot, "runtime", "nfqws2") || dns.StateRoot != filepath.Join(m.StateRoot, scopedDNSAdapterID) ||
		dns.InactivityIdentity != nil || dns.InactivityKernelCheck != nil || dns.DNS != nil && dns.DNS.Path != settingsPath || dns.InactivitySettingsPath != "" && dns.InactivitySettingsPath != settingsPath {
		return ErrRuntimeInactivity
	}
	source, err := NewNFQWSRuntimeInactiveSource(ctx, nfq, inventory)
	if err != nil {
		return errors.Join(ErrRuntimeInactivity, err)
	}
	if err := source.Bind(nfq); err != nil {
		return errors.Join(ErrRuntimeInactivity, err)
	}
	dns.InactivitySettingsPath = settingsPath
	dns.InactivityIdentity = provider
	dns.InactivityKernelCheck = NewScopedDNSInactivityKernelCheck(inventory)
	return ctx.Err()
}
