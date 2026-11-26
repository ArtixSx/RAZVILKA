package dataplane

import "errors"

// ConfirmedPreEffectRefusal classifies only an original read-only refusal in
// the returned Manager result. It is accounting data, never effect, retry or
// cleanup authority. Unknown phases/resources or additional error branches
// retain the switch charge, even if their journal resembles a refusal.
func ConfirmedPreEffectRefusal(execution Execution, err error) bool {
	if err == nil || errors.Is(err, ErrExecutionJournal) || execution.State != "canary-failed" ||
		execution.ResourcePlanID != "" || len(execution.Resources) != 0 || execution.RollbackVerified ||
		execution.StartedAt == "" || execution.FinishedAt == "" || len(execution.Steps) == 0 {
		return false
	}
	for index, step := range execution.Steps {
		if step.Adapter == "" || step.StartedAt == "" || step.FinishedAt == "" {
			return false
		}
		switch step.Phase {
		case "snapshot", "stage", "validate":
		default:
			return false
		}
		expected := "passed"
		if index == len(execution.Steps)-1 {
			expected = "failed"
		}
		if step.State != expected {
			return false
		}
	}
	// The private marker attests that this rejection preceded its own effects.
	// Require one original error chain, so a later unknown Close/journal error
	// joined by Manager's defers cannot borrow that attestation.
	for remaining := 64; err != nil && remaining > 0; remaining-- {
		if _, ok := err.(preflightRefusalError); ok {
			return true
		}
		switch wrapped := err.(type) {
		case interface{ Unwrap() []error }:
			causes := wrapped.Unwrap()
			if len(causes) != 1 {
				return false
			}
			err = causes[0]
		case interface{ Unwrap() error }:
			err = wrapped.Unwrap()
		default:
			return false
		}
	}
	return false
}
