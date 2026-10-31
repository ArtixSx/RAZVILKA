package strategylab

const (
	legacyStrategySchema                = 1
	legacyCompatibilitySupervisedSchema = 3
)

func ordinaryStrategySchema(version int) bool {
	return version == legacyStrategySchema || version == SchemaVersion
}

func supervisedStrategySchema(version int) bool {
	return version == legacyCompatibilitySupervisedSchema || version == compatibilitySupervisedSchema
}

func supportedStrategySchema(version int) bool {
	return ordinaryStrategySchema(version) || version == compatibilityUnknownSchema || supervisedStrategySchema(version)
}

// Schema 2 remains the durable unknown fence for ordinary state, including
// schema 4. Supervised state instead retains its exact session/receipt fence.
func retainUnknownStrategySchema(state *State) {
	if !supervisedStrategySchema(state.SchemaVersion) {
		state.SchemaVersion = compatibilityUnknownSchema
	}
}

// Only a real ordinary writer upgrades a settled state. New/Snapshot and the
// exact helper receipt/cleanup CAS never migrate its image while observing it.
func promoteStrategyWriteSchema(state *State) {
	if ordinaryStrategySchema(state.SchemaVersion) {
		state.SchemaVersion = SchemaVersion
	} else if supervisedStrategySchema(state.SchemaVersion) {
		state.SchemaVersion = compatibilitySupervisedSchema
	}
}
