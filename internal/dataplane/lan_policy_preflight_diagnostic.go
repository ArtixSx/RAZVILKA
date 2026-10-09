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
	if LANPolicyPreflightFailureStage(cause) != "" {
		return cause
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
	case "runtime-plan", "runtime-tools", "runtime-scope-missing", "boundary-identity", "boundary-plan", "boundary-physical", "boundary-apply", "boundary-cleanup", "boundary-retire", "boundary-inventory":
		return failure.stage
	case "inventory-mode", "inventory-coverage", "inventory-identity", "inventory-definition", "inventory-row-shape", "inventory-row-syntax", "inventory-row-key", "inventory-row-unallowed", "inventory-row-order", "inventory-consumer-required":
		return failure.stage
	case "inventory-boundary", "inventory-consumer-open", "inventory-consumer-close", "inventory-read-open", "inventory-read-close", "inventory-image-changed", "inventory-owner-current":
		return failure.stage
	}
	return ""
}
