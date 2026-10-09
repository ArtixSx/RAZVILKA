package dataplane

import "errors"

// Closed diagnostic coordinates only; error presentation and cause remain
// unchanged, and no native inventory, arguments or identifiers are retained.
type lanPolicyPreflightFailure struct {
	stage string
	cause error
}

func (e *lanPolicyPreflightFailure) Error() string { return e.cause.Error() }
func (e *lanPolicyPreflightFailure) Unwrap() error { return e.cause }

func lanPolicyPreflightAt(stage string, cause error) error {
	if cause == nil {
		return nil
	}
	return &lanPolicyPreflightFailure{stage: stage, cause: cause}
}

func LANPolicyPreflightFailureStage(err error) string {
	var failure *lanPolicyPreflightFailure
	if !errors.As(err, &failure) {
		return ""
	}
	switch failure.stage {
	case "scope-open", "scope-close", "rpdb-read", "rpdb-syntax", "rpdb-reserved-priority", "rpdb-goto-anchor", "rpdb-gate-mark", "rpdb-owned-table", "table-read", "table-owned-chain", "table-gate-mark", "table-connmark":
		return failure.stage
	}
	return ""
}
