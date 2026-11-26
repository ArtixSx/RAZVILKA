package updatecheck

import (
	"context"

	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

const fileProtocolNeedsReview = "file-protocol-needs-review"

// This annotation contains diagnostic labels only, never a role or proof.
type fileProtocolFailure struct {
	action, boundary string
	cause            error
}

func (e *fileProtocolFailure) Error() string { return "self update file protocol boundary failed" }
func (e *fileProtocolFailure) Unwrap() error { return e.cause }

// SelfUpdateFileFailureAt labels an actual returned error. Unknown labels and
// successful results pass through unchanged; the original cause remains joined.
func SelfUpdateFileFailureAt(action, boundary string, cause error) error {
	if cause == nil || fileProtocolAction(action) == "" || !fileProtocolBoundary(boundary) {
		return cause
	}
	return &fileProtocolFailure{action, boundary, cause}
}

// SelfUpdateFileFailureCode is data for the existing helper Code field. Only
// fixed labels from a causal annotation are accepted, never Error() text.
func SelfUpdateFileFailureCode(err error) string {
	remaining := 64
	failure, complete := findFileProtocolFailure(err, &remaining)
	if !complete || failure == nil {
		return fileProtocolNeedsReview
	}
	var cancelled, deadline, changed, protocol bool
	var mismatch, pending, unknown, retired bool
	remaining = 64
	if !walkFileProtocolCauses(failure.cause, &remaining, func(cause error) {
		cancelled = cancelled || cause == context.Canceled
		deadline = deadline || cause == context.DeadlineExceeded
		changed = changed || cause == ErrReviewChanged
		protocol = protocol || cause == ErrFileProtocol
		mismatch = mismatch || cause == selfupdatejournal.ErrMismatch
		pending = pending || cause == selfupdatejournal.ErrPending
		unknown = unknown || cause == selfupdatejournal.ErrUnknown
		retired = retired || cause == selfupdatejournal.ErrRetired
	}) {
		return fileProtocolNeedsReview
	}
	reason := ""
	switch {
	case deadline:
		reason = "deadline"
	case cancelled:
		reason = "cancelled"
	default:
		if stage := OrdinaryInstallerControllerFailureStage(failure.cause); stage != "" {
			reason = "ordinary-" + stage
		} else if changed {
			reason = "review-changed"
		} else if mismatch {
			reason = "mismatch"
		} else if pending {
			reason = "pending"
		} else if unknown {
			reason = "unknown-command"
		} else if retired {
			reason = "retired"
		} else if protocol {
			reason = "protocol"
		}
	}
	code := "file-protocol-" + fileProtocolAction(failure.action) + "-" + failure.boundary
	// Keep the existing <80-byte code convention. The boundary alone remains
	// exact if the optional, separately closed cause label would exceed it.
	if reason != "" && len(code)+1+len(reason) < 80 {
		code += "-" + reason
	}
	return code
}

// Prefer the inner boundary over an outer journal/action annotation, and the
// first causal branch over a later rollback error. Both traversals are bounded.
func findFileProtocolFailure(err error, remaining *int) (*fileProtocolFailure, bool) {
	if err == nil {
		return nil, true
	}
	if *remaining == 0 {
		return nil, false
	}
	*remaining -= 1
	if failure, ok := err.(*fileProtocolFailure); ok && failure == nil {
		return nil, false
	}
	if failure, ok := err.(*ordinaryInstallerRoleFailure); ok && failure == nil {
		return nil, false
	}
	switch e := err.(type) {
	case interface{ Unwrap() []error }:
		for _, cause := range e.Unwrap() {
			if *remaining == 0 {
				return nil, false
			}
			failure, complete := findFileProtocolFailure(cause, remaining)
			if !complete || failure != nil {
				return failure, complete
			}
		}
	case interface{ Unwrap() error }:
		failure, complete := findFileProtocolFailure(e.Unwrap(), remaining)
		if !complete || failure != nil {
			return failure, complete
		}
	}
	if failure, ok := err.(*fileProtocolFailure); ok && failure != nil && fileProtocolAction(failure.action) != "" && fileProtocolBoundary(failure.boundary) {
		return failure, true
	}
	return nil, true
}

func walkFileProtocolCauses(err error, remaining *int, visit func(error)) bool {
	if err == nil {
		return true
	}
	if *remaining == 0 {
		return false
	}
	*remaining -= 1
	if failure, ok := err.(*fileProtocolFailure); ok && failure == nil {
		return false
	}
	if failure, ok := err.(*ordinaryInstallerRoleFailure); ok && failure == nil {
		return false
	}
	visit(err)
	switch e := err.(type) {
	case interface{ Unwrap() []error }:
		for _, cause := range e.Unwrap() {
			if *remaining == 0 || !walkFileProtocolCauses(cause, remaining, visit) {
				return false
			}
		}
	case interface{ Unwrap() error }:
		return walkFileProtocolCauses(e.Unwrap(), remaining, visit)
	}
	return true
}

func fileProtocolAction(action string) string {
	switch action {
	case "helper", "prepare", "install", "restore", "accept-live", "accept-rollback":
		return action
	case "stop-old-panel":
		return "stop-old"
	case "prepare-private-state":
		return "prepare-private"
	case "quiesce-old-runtime":
		return "quiesce"
	case "start-candidate-panel":
		return "start-candidate"
	case "stop-candidate-panel":
		return "stop-candidate"
	case "restore-private-state":
		return "restore-private"
	case "start-rollback-panel":
		return "start-rollback"
	case "resolve-unknown":
		return "resolve"
	case "settle-stopped-rollback":
		return "settle-stopped"
	}
	return ""
}

func fileProtocolBoundary(boundary string) bool {
	switch boundary {
	case "action", "source", "review", "previous-review", "journal-open", "journal-current", "journal-order", "install-journal", "file-admission", "quiescence",
		"authority-control", "authority-guard", "authority-recovery", "authority-provider",
		"post-authority-control", "post-authority-guard", "post-authority-recovery", "post-authority-provider":
		return true
	}
	return false
}
