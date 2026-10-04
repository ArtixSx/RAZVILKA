package dataplane

// NFQWSExecutionBinding is detached identity for the existing managed-process
// ownership session and private parent/helper channel. Serialized identity is
// never launch authority. Only the live Manager resource may admit Start.
// This binding sits outside the command digest to avoid a compiler/hash cycle.
type NFQWSExecutionBinding struct {
	ExecutionID        string `json:"execution_id"`
	PlanID             string `json:"plan_id"`
	PlanDigest         string `json:"plan_digest"`
	ResourceID         string `json:"resource_id"`
	ResourceGeneration string `json:"resource_generation"`
	EffectsDigest      string `json:"effects_digest"`
	SessionID          string `json:"session_id"`
	CommandSHA256      string `json:"command_sha256"`
}
