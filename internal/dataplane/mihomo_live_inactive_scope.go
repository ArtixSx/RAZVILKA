package dataplane

// This only validates original startup comparison paths. The actual process
// observer independently checks executable bytes, birth, argv, FD contents and
// sockets; an FD spelling never supplies ownership or an inactivity result.
func (a *ProxyTunnelAdapter) validateMihomoInactiveProcessScope(spec ProcessSpec) error {
	if a == nil || a.ID() != "mihomo" || a.mihomoOwner == nil {
		return ErrProxyRuntimeInactive
	}
	owner := a.mihomoOwner
	owner.mu.Lock()
	bound := owner.self == owner && owner.liveProxy == a && owner.liveOptions != nil && owner.liveManager != nil
	owner.mu.Unlock()
	if !bound || !sameMihomoLiveSpec(spec, a.engineProcess()) && !sameMihomoLiveSpec(spec, a.sidecarProcess()) {
		return ErrProxyRuntimeInactive
	}
	return validateProxyInactiveProcessArgument(spec, "/proc/self/fd/4")
}
