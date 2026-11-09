package dataplane

type mihomoLiveStopDiagnostic struct {
	phase string
	cause error
}

func (e *mihomoLiveStopDiagnostic) Error() string {
	return "original Mihomo Stop refused at " + mihomoLiveStopFixedPhase(e.phase)
}
func (e *mihomoLiveStopDiagnostic) Unwrap() error { return e.cause }
func mihomoLiveStopAt(phase string, err error) error {
	if err == nil {
		return nil
	}
	return &mihomoLiveStopDiagnostic{phase: phase, cause: err}
}

func mihomoLiveStopFixedPhase(phase string) string {
	switch phase {
	case "prepare", "record-pair", "settled-header", "inactive-recheck", "terminal-rows", "final-record-pair", "close-row", "transit-settlement", "sidecar-native", "engine-native", "persistent-policy", "process-absence", "compiled-remove", "full-absence", "removed-row":
		return phase
	default:
		return "unknown-step"
	}
}

// MihomoLiveStopFailurePhases reports only fixed internal step labels. It
// never formats a child error, pathname, command, network tuple or profile.
func MihomoLiveStopFailurePhases(err error) []string {
	var result []string
	seen := map[string]bool{}
	budget := 64
	var walk func(error, int)
	walk = func(err error, depth int) {
		if err == nil || depth > 16 || budget == 0 {
			return
		}
		budget--
		if e, ok := err.(*mihomoLiveStopDiagnostic); ok {
			if e == nil {
				return
			}
			phase := mihomoLiveStopFixedPhase(e.phase)
			if !seen[phase] {
				seen[phase] = true
				result = append(result, phase)
			}
			walk(e.cause, depth+1)
			return
		}
		if e, ok := err.(interface{ Unwrap() []error }); ok {
			for _, cause := range e.Unwrap() {
				walk(cause, depth+1)
			}
			return
		}
		if e, ok := err.(interface{ Unwrap() error }); ok {
			walk(e.Unwrap(), depth+1)
		}
	}
	walk(err, 0)
	return result
}
