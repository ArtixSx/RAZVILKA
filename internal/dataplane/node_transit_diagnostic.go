package dataplane

import "errors"

// A phase describes a source-level boundary, never a runtime value. The cause
// remains available to errors.Is/As, but its text can contain private paths or
// command output and must not enter the published diagnostic.
type nodeTransitPhaseError struct {
	phase string
	cause error
}

func (e *nodeTransitPhaseError) Error() string {
	message := "node transit phase=" + e.phase
	var inner *nodeTransitPhaseError
	if errors.As(e.cause, &inner) {
		message += "; " + inner.Error()
	}
	return message
}

func (e *nodeTransitPhaseError) Unwrap() error { return e.cause }

func nodeTransitPhase(phase string, cause error) error {
	if cause == nil {
		return nil
	}
	return &nodeTransitPhaseError{phase: phase, cause: cause}
}
