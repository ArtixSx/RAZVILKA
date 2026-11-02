package strategylab

// LifecycleRegistration is advisory configuration readback. It neither probes
// assets nor grants native execution, publication, readiness or live Apply.
type LifecycleRegistration struct {
	NativeValidation      string
	ManagedCandidateProbe string
}

func (m *Manager) LifecycleRegistration() LifecycleRegistration {
	result := LifecycleRegistration{NativeValidation: "absent", ManagedCandidateProbe: "absent"}
	if m == nil {
		return result
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.Validator != nil {
		result.NativeValidation = "unknown"
		var configured CompatibleValidator
		recognized := false
		switch value := m.Validator.(type) {
		case CompatibleValidator:
			configured = value
			recognized = true
		case *CompatibleValidator:
			if value != nil {
				configured = *value
				recognized = true
			}
		}
		if recognized && configured.Provider == nil {
			result.NativeValidation = "absent"
		} else if recognized {
			if original, ok := configured.Provider.(*SupervisedCompatibilityProvider); ok && original != nil && original.self == original && original.manager == m {
				if _, err := adaptiveManagedValidatorLocked(m); err == nil {
					result.NativeValidation = "registered"
				}
			}
		}
	}
	// Legacy OUTPUT probes are not the production managed network consumer.
	// An opaque plugin cannot assert managed registration from a non-nil value.
	if m.Executor != nil {
		if _, legacy := m.Executor.(*SystemProbeExecutor); !legacy {
			result.ManagedCandidateProbe = "unknown"
		}
	}
	return result
}
