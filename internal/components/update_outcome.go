package components

import (
	"errors"
	"fmt"
)

var (
	ErrRollbackUnconfirmed = errors.New("component rollback is not confirmed")
	ErrRollbackVerified    = errors.New("component update was rolled back and verified")
	ErrNoMutation          = errors.New("component update did not start")
)

// UpdateFailure carries machine-readable outcome independently of display text.
// Unknown errors after entering a package manager must never mean "old version
// preserved". errors.Is still exposes the underlying cause to diagnostics.
type UpdateFailure struct {
	Outcome error
	Version string
	Cause   error
}

func (e *UpdateFailure) Error() string {
	if e.Outcome == ErrRollbackVerified {
		return fmt.Sprintf("update was rolled back to %s: %v", e.Version, e.Cause)
	}
	if e.Outcome == ErrNoMutation {
		return fmt.Sprintf("update did not start: %v", e.Cause)
	}
	return fmt.Sprintf("update failed and rollback is not confirmed: %v", e.Cause)
}
func (e *UpdateFailure) Unwrap() []error { return []error{e.Outcome, e.Cause} }
func NoMutation(err error) error {
	if err == nil {
		return nil
	}
	return &UpdateFailure{Outcome: ErrNoMutation, Cause: err}
}
