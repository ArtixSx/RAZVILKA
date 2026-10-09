package app

import (
	"context"
	"errors"
	"io/fs"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/strategylab"
)

// Original internal cause remains available to errors.Is/As. Presentation
// exposes fixed stage/reason codes only, never native argv, paths or secrets.
type managedNFQRuntimeFailure struct {
	stage string
	cause error
}

func (e *managedNFQRuntimeFailure) Error() string { return "managed NFQ runtime refused at " + e.stage }
func (e *managedNFQRuntimeFailure) Unwrap() error { return e.cause }

func managedNFQFailureAt(stage string, cause error) error {
	if cause == nil {
		return nil
	}
	var existing *managedNFQRuntimeFailure
	if errors.As(cause, &existing) {
		return cause
	}
	return &managedNFQRuntimeFailure{stage: stage, cause: cause}
}

func managedNFQFailureDiagnostic(err error) (stage, reason string) {
	stage, reason = "runtime-operation", "ORIGINAL_OWNER_REFUSED"
	var failure *managedNFQRuntimeFailure
	if errors.As(err, &failure) {
		stage = failure.stage
	}
	if lanStage := dataplane.LANPolicyPreflightFailureStage(err); lanStage != "" {
		stage = "lan-preflight-" + lanStage
		if failure != nil && failure.stage != "native-apply" {
			stage += "/" + failure.stage
		}
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		reason = "DEADLINE_EXCEEDED"
	case errors.Is(err, context.Canceled):
		reason = "CANCELED"
	case errors.Is(err, fs.ErrPermission):
		reason = "SOURCE_PERMISSION"
	case errors.Is(err, fs.ErrNotExist):
		reason = "SOURCE_MISSING"
	case errors.Is(err, operationgate.ErrRecovery):
		reason = "RECOVERY_REQUIRED"
	case errors.Is(err, operationgate.ErrBusy):
		reason = "OPERATION_BUSY"
	case errors.Is(err, ErrListScopeChanged):
		reason = "ORIGINAL_SCOPE_CHANGED"
	case errors.Is(err, components.ErrManagedNFQWSBundle):
		reason = "INSTALLED_BUNDLE_REFUSED"
	case errors.Is(err, strategylab.ErrSelectedCandidateChanged):
		reason = "SELECTED_SOURCE_CHANGED"
	case errors.Is(err, strategylab.ErrSelectedCandidateTraffic):
		reason = "SELECTED_TRAFFIC_REFUSED"
	case errors.Is(err, ErrDefaultRouteCapability):
		reason = "COMPILED_CAPABILITY_REFUSED"
	case errors.Is(err, dataplane.ErrReviewChanged):
		reason = "REVIEW_CHANGED"
	case errors.Is(err, dataplane.ErrNetworkPolicyConsumers):
		reason = "LAN_CONSUMER_REFUSED"
	case errors.Is(err, dataplane.ErrNFQWSScopedOwner):
		reason = "NATIVE_OWNER_REFUSED"
	case errors.Is(err, dataplane.ErrLANPolicyRuntime):
		reason = "LAN_GATE_REFUSED"
	}
	return
}
