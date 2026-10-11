package dataplane

import "context"

// OriginalXraySelectedTCPDispatcher observes this Manager's actual factory
// registration. It returns no new adapter or runtime/Start permission; the
// independent original registration review and resource issuer remain required.
func (m *Manager) OriginalXraySelectedTCPDispatcher(ctx context.Context) (*ProxyTunnelAdapter, error) {
	if m == nil || xraySelectedTCPFinite(ctx) != nil {
		return nil, ErrXrayRegistration
	}
	m.registryMu.RLock()
	defer m.registryMu.RUnlock()
	a, ok := m.Adapters["xray"].(*ProxyTunnelAdapter)
	if !ok || a == nil || a.EngineID != "xray" || !a.xrayPlanDispatch || !a.nodeRouterVerifier || a.scopedXray || a.xrayOperation || a.Processes == nil {
		return nil, ErrXrayRegistration
	}
	return a, ctx.Err()
}
