package dataplane

import "context"

type wgInactivityReadFailure struct {
	stage string
	cause error
}

func (e *wgInactivityReadFailure) Error() string { return "WG inactivity read refused" }
func (e *wgInactivityReadFailure) Unwrap() error { return e.cause }

func wgInactivityReadAt(stage string, err error) error {
	if err == nil {
		return nil
	}
	return &wgInactivityReadFailure{stage: stage, cause: err}
}

func wgInactivityContextCause(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}

func wgInactivityDiagnosticStage(stage string) bool {
	switch stage {
	case "review-context", "review-lifetime", "review-input", "review-control", "review-adapter", "review-runner", "review-paths", "review-root", "review-source",
		"owner", "context", "lifetime", "adapter-shape", "bound-tools", "identity", "registry", "root", "control-opening", "tools", "control-closing":
		return true
	}
	return false
}

// WGInactivityReadStage returns only an actual private typed boundary label.
// It does not inspect error messages or expose paths/configuration/CLI data.
func WGInactivityReadStage(err error) string {
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
		if f, ok := current.(*wgInactivityReadFailure); ok {
			if f == nil {
				continue
			}
			if wgInactivityDiagnosticStage(f.stage) {
				return f.stage
			}
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
