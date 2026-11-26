package strategylab

const (
	legacyStrategySchema                = 1
	legacyCompatibilitySupervisedSchema = 3
	managedStrategySchema               = 6
	managedSupervisedSchema             = 7
)

func ordinaryStrategySchema(version int) bool {
	return version == legacyStrategySchema || version == SchemaVersion || version == managedStrategySchema
}

func supervisedStrategySchema(version int) bool {
	return version == legacyCompatibilitySupervisedSchema || version == compatibilitySupervisedSchema || version == managedSupervisedSchema
}

func supportedStrategySchema(version int) bool {
	return ordinaryStrategySchema(version) || version == compatibilityUnknownSchema || supervisedStrategySchema(version)
}

// Schema 2 remains the durable unknown fence for ordinary state, including
// schema 4. Supervised state instead retains its exact session/receipt fence.
func retainUnknownStrategySchema(state *State) {
	if state.SchemaVersion == managedStrategySchema {
		state.ManagedProbeUnknown = true
		return
	}
	if !supervisedStrategySchema(state.SchemaVersion) {
		state.SchemaVersion = compatibilityUnknownSchema
	}
}

// Only a real ordinary writer upgrades a settled state. New/Snapshot and the
// exact helper receipt/cleanup CAS never migrate its image while observing it.
func promoteStrategyWriteSchema(state *State) {
	if state.SchemaVersion == managedStrategySchema || state.SchemaVersion == managedSupervisedSchema {
		return
	}
	if ordinaryStrategySchema(state.SchemaVersion) {
		state.SchemaVersion = SchemaVersion
	} else if supervisedStrategySchema(state.SchemaVersion) {
		state.SchemaVersion = compatibilitySupervisedSchema
	}
}

func supervisedWriteSchema(state State) int {
	if state.SchemaVersion == managedStrategySchema || state.SchemaVersion == managedSupervisedSchema || len(state.ManagedProbeEpochs) > 0 {
		return managedSupervisedSchema
	}
	return compatibilitySupervisedSchema
}
