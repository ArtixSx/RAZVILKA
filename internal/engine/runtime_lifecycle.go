package engine

// Lifecycle describes registered server entry points, not successful probes or
// permission to execute them. Availability stays null until operation admission.
type LifecycleOperation struct {
	Registration string `json:"registration"` // registered, absent, unknown, lab-only
	Available    *bool  `json:"available"`
	Reason       string `json:"reason"`
}
type Lifecycle struct {
	Schema        int                           `json:"schema"`
	Operations    map[string]LifecycleOperation `json:"operations"`
	Prerequisites []string                      `json:"prerequisites"`
	Evidence      string                        `json:"evidence"`
}
