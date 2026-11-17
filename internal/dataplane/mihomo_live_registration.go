package dataplane

// Registration is structural comparison only. It does not open assets, issue
// an operation, prove native health, or make this scope generally available.
func (m *Manager) MihomoLiveRuntimeRegistered() bool {
	if m == nil {
		return false
	}
	registered, ok := m.adapter("mihomo")
	if !ok {
		return false
	}
	a, ok := registered.(*MihomoProbeAdapter)
	if !ok || a == nil || a.self != a {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	proxy, options := a.liveProxy, a.liveOptions
	if proxy == nil || options == nil || a.liveManager != m || options.Manager != m || proxy.mihomoOwner != a || options.Configs != proxy.Configs || options.Gate == nil || options.History == nil || options.ResourceGuard == nil {
		return false
	}
	process, ok := proxy.Processes.(*mihomoLiveProcessController)
	if !ok || process.adapter != a || process.proxy != proxy {
		return false
	}
	commands, ok := proxy.Runner.(*mihomoLiveCommandRunner)
	return ok && commands.adapter == a && commands.base != nil && validPlanDigest(commands.review)
}

// MihomoLiveNodePlanSupported describes only the implemented explicit-node
// workflow. It is not live health, source ownership or a general AUTO grant;
// the ordinary transaction still earns every current source and route proof.
func (m *Manager) MihomoLiveNodePlanSupported(plan Plan) bool {
	if !m.MihomoLiveRuntimeRegistered() {
		return false
	}
	_, err := mihomoLiveIntentNode(plan)
	return err == nil
}
