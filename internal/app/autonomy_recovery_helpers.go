package app

import (
	"context"
	"errors"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/nodestore"
)

func canExploreUnconfirmedNode(r dataplane.NodeCheckResult) bool {
	if r.Available || r.Verdict != evidence.VerdictInconclusive {
		return false
	}
	switch r.Stage {
	case "transport", "egress", "service", "service_ip":
		return true
	}
	return false
}
func nodeCheckFailureCode(err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return "node-check-canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "node-check-deadline"
	case errors.Is(err, dataplane.ErrExactNodeNetworkChanged):
		return "node-network-changed"
	case errors.Is(err, dataplane.ErrExactNodeBusy):
		return "node-check-busy"
	case errors.Is(err, dataplane.ErrExactNodeRuntime):
		return "node-runtime-unavailable"
	case errors.Is(err, dataplane.ErrExactNodeUnavailable):
		return "node-checker-unavailable"
	case errors.Is(err, nodestore.ErrDisabled), errors.Is(err, nodestore.ErrNotFound):
		return "node-unavailable"
	default:
		return "node-check-unconfirmed"
	}
}
