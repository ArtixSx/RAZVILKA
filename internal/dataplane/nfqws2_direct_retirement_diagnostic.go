package dataplane

import (
	"context"
	"errors"
)

// stage is issued only from the fixed proof sequence. No path, command,
// process identity, observation or wrapped error text enters the diagnostic.
type nfqwsDirectRetirementDiagnostic struct {
	stage string
	cause error
}

func (e *nfqwsDirectRetirementDiagnostic) Error() string {
	message := "NFQ direct preparation retirement " + e.stage
	if errors.Is(e.cause, context.DeadlineExceeded) {
		message += " deadline"
	}
	if errors.Is(e.cause, context.Canceled) {
		message += " canceled"
	}
	return message
}

func (e *nfqwsDirectRetirementDiagnostic) Unwrap() error { return e.cause }
