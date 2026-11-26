package dataplane

import "sort"

// ManagedSidecarRegistration describes only the configured dependency of
// original registered parent adapters. HEV is not a standalone route engine.
// No installed asset, process, kernel state or admission is observed here.
type ManagedSidecarRegistration struct {
	Parents          []string
	RuntimePreflight bool
	Recovery         bool
}

func (m *Manager) ManagedSidecarLifecycleRegistration(id string) ManagedSidecarRegistration {
	var result ManagedSidecarRegistration
	if m == nil || id != "hev" {
		return result
	}
	m.registryMu.RLock()
	defer m.registryMu.RUnlock()
	for parent, registered := range m.Adapters {
		adapter, ok := registered.(*ProxyTunnelAdapter)
		// SidecarKind and the original component-owner closure are bound before
		// Register and stay immutable throughout the adapter lifetime. A binary
		// name or laboratory constructor without that owner proves nothing.
		if !ok || adapter == nil || parent != adapter.EngineID || (parent != "xray" && parent != "usque") || adapter.SidecarKind != "hev" || adapter.hevInstalledCheck == nil {
			continue
		}
		result.Parents = append(result.Parents, parent)
		result.RuntimePreflight = true
		_, recovery := registered.(RuntimeReconciler)
		result.Recovery = result.Recovery || recovery
	}
	sort.Strings(result.Parents)
	return result
}
