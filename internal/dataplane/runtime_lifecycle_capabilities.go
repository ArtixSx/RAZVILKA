package dataplane

import "reflect"

// Read-only projection of the original Manager registration. No network,
// process, health, admission or lifecycle method is invoked to build it.
type AdapterLifecycleRegistration struct {
	Registered       bool
	StagedValidation bool
	IsolatedProbe    bool
	LiveApply        bool
	LiveHealth       bool
	Recovery         bool
	Rollback         bool
}

func (m *Manager) AdapterLifecycleRegistration(id string) AdapterLifecycleRegistration {
	if m == nil {
		return AdapterLifecycleRegistration{}
	}
	m.registryMu.RLock()
	defer m.registryMu.RUnlock()
	adapter := m.Adapters[id]
	if adapter == nil {
		return AdapterLifecycleRegistration{}
	}
	_, canary := adapter.(CanaryAdapter)
	_, recovery := adapter.(RuntimeReconciler)
	return AdapterLifecycleRegistration{Registered: true, StagedValidation: true, IsolatedProbe: canary, LiveApply: true, LiveHealth: true, Recovery: recovery, Rollback: true}
}

// The exact executor reports its configured pipeline, without testing a binary
// or granting readiness. Opaque plugin checkers cannot claim this registration.
type NodeCheckLifecycleRegistration struct {
	IsolatedProbe    bool
	NativeValidation bool
	Recovery         bool
}

func (c *ExactNodeChecker) NodeCheckLifecycleRegistration() NodeCheckLifecycleRegistration {
	if c == nil || c.gate == nil || c.prepare == nil {
		return NodeCheckLifecycleRegistration{}
	}
	expected := c.prepareSession
	native := reflect.ValueOf(c.prepare).Pointer() == reflect.ValueOf(expected).Pointer()
	return NodeCheckLifecycleRegistration{IsolatedProbe: true, NativeValidation: native, Recovery: true}
}
func (c *DispatchedNodeChecker) NodeCheckLifecycleRegistration() NodeCheckLifecycleRegistration {
	if c == nil || c.dispatcher == nil || c.checker == nil || c.dispatcher.checkers[c.checker.EngineID()] != c.checker {
		return NodeCheckLifecycleRegistration{}
	}
	return c.checker.NodeCheckLifecycleRegistration()
}
