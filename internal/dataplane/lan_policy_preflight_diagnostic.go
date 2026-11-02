package dataplane

import (
	"errors"
	"strings"
)

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
		return lanPolicyInventoryReadDiagnostic(failure.stage, failure.cause)
	case "inventory-xray-scope-open", "inventory-xray-prepared-open", "inventory-consumer-combination", "inventory-nfq-stock-open", "inventory-xray-stock-open", "inventory-proxy-consumer-open", "inventory-nfq-consumer-open", "inventory-xray-consumer-open":
		return failure.stage
	case "inventory-stock-source", "inventory-stock-owned", "inventory-stock-graph":
		return failure.stage
	case "inventory-stock-graph-parse", "inventory-stock-graph-shape", "inventory-stock-graph-reachability", "inventory-stock-graph-collision", "inventory-stock-graph-unknown-option", "inventory-stock-graph-coverage", "inventory-stock-graph-budget", "inventory-stock-graph-owned":
		return failure.stage
	}
	return ""
}

// The original capture issuer supplies a closed enum only. Never serialize a
// tool error, foreign row/table, path, command or supplied diagnostic string.
func lanPolicyInventoryReadDiagnostic(stage string, cause error) string {
	if stage != "inventory-read-open" && stage != "inventory-read-close" {
		return stage
	}
	var failure *backendInventoryFailure
	if errors.As(cause, &failure) {
		switch failure.stage {
		case "SCOPE", "TOOLS_A", "OPEN_A", "GETGEN_A", "GETTABLE", "TOOLS_B", "CLASSIC", "OPEN_B", "GETGEN_B", "CLOSE":
			return stage + "-" + strings.ToLower(failure.stage)
		}
	}
	return stage
}
