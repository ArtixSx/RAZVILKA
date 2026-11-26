package startuptools

// Unlike at, this boundary preserves the original error categories without
// adding ErrUnknown to a dataplane/control refusal.
type wgInactivityStartupFailure struct {
	stage string
	cause error
}

func (e *wgInactivityStartupFailure) Error() string { return "WG startup refused" }
func (e *wgInactivityStartupFailure) Unwrap() error { return e.cause }

func wgInactivityStartupAt(stage string, err error) error {
	if err == nil {
		return nil
	}
	return &wgInactivityStartupFailure{stage: stage, cause: err}
}

func wgStartupDiagnosticStage(stage string) bool {
	switch stage {
	case "WG_STARTUP_CONTEXT", "WG_STARTUP_OWNER", "WG_STARTUP_OPEN_CURRENT", "WG_STARTUP_DESCRIPTORS", "WG_STARTUP_CLOSE_CURRENT", "WG_STARTUP_OBSERVATION",
		"WG_INACTIVITY_UNISSUED", "WG_INACTIVITY_DEADLINE", "WG_INACTIVITY_LOCK", "WG_INACTIVITY_ABSENCE", "WG_INACTIVITY_CURRENT", "WG_INACTIVITY_SOURCE":
		return true
	}
	return false
}

// WGStartupStage exposes only source-known private typed stages. It never
// reads Error text, paths, CLI data or free-form messages. The walk is bounded
// even for foreign errors whose Unwrap repeats itself or returns many children.
func WGStartupStage(err error) string {
	if err == nil {
		return "none"
	}
	pending := []error{err}
	for visited := 0; len(pending) > 0 && visited < 32; visited++ {
		current := pending[0]
		pending = pending[1:]
		if current == nil {
			continue
		}
		stage := ""
		switch f := current.(type) {
		case *failure:
			if f == nil {
				continue
			}
			stage = f.stage
		case *wgInactivityStartupFailure:
			if f == nil {
				continue
			}
			stage = f.stage
		}
		if wgStartupDiagnosticStage(stage) {
			return stage
		}
		remaining := 31 - visited - len(pending)
		if remaining <= 0 {
			continue
		}
		switch wrapped := current.(type) {
		case interface{ Unwrap() []error }:
			children := wrapped.Unwrap()
			pending = append(pending, children[:min(len(children), remaining)]...)
		case interface{ Unwrap() error }:
			pending = append(pending, wrapped.Unwrap())
		}
	}
	return "unclassified"
}
