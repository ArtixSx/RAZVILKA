package app

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// Only the original review boundary issues these labels. The retained cause
// remains available to errors.Is/As; presentation never reads its Error text.
type managedXrayReviewFailure struct {
	stage string
	cause error
}

func (*managedXrayReviewFailure) Error() string   { return "managed Xray review refused" }
func (e *managedXrayReviewFailure) Unwrap() error { return e.cause }

func managedXrayReviewStageAllowed(stage string) bool {
	switch stage {
	case "target", "admission", "control", "prepare", "final-check", "cleanup":
		return true
	}
	return false
}

func managedXrayReviewAt(stage string, ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if !managedXrayReviewStageAllowed(stage) {
		stage = "admission"
	}
	if ctx != nil {
		err = errors.Join(err, ctx.Err())
	}
	return &managedXrayReviewFailure{stage: stage, cause: err}
}

// Bound traversal even for unknown/cyclic errors. Only private typed stages
// and the actual context sentinels are recognized, including joined cleanup.
func managedXrayReviewDiagnostic(err error, boundary string) (stage, cause string) {
	stage, cause = boundary, "none"
	if !managedXrayReviewStageAllowed(stage) {
		stage = "admission"
	}
	if err == nil {
		return
	}
	cause = "refused"
	haveStage, deadline, canceled := false, false, false
	pending := []error{err}
	for visited := 0; len(pending) > 0 && visited < 32; visited++ {
		current := pending[0]
		pending = pending[1:]
		if current == nil {
			continue
		}
		if failure, ok := current.(*managedXrayReviewFailure); ok {
			if failure == nil {
				continue
			}
			if managedXrayReviewStageAllowed(failure.stage) && (!haveStage || failure.stage == "cleanup") {
				stage, haveStage = failure.stage, true
			}
		}
		switch current {
		case context.DeadlineExceeded:
			deadline = true
		case context.Canceled:
			canceled = true
		}
		remaining := 31 - visited - len(pending)
		if remaining <= 0 {
			continue
		}
		switch wrapped := current.(type) {
		case interface{ Unwrap() []error }:
			children := wrapped.Unwrap()
			pending = append(pending, children[:min(len(children), remaining)]...)
		case interface{ Unwrap() error }:
			pending = append(pending, wrapped.Unwrap())
		}
	}
	if deadline {
		cause = "deadline"
	} else if canceled {
		cause = "canceled"
	}
	return
}

func writeManagedXrayReviewError(w http.ResponseWriter, err error, started time.Time) {
	stage, cause := managedXrayReviewDiagnostic(err, "target")
	writeJSON(w, http.StatusConflict, map[string]any{
		"ok": false, "code": "XRAY_SELECTED_TCP_REVIEW_REFUSED",
		"error":          "Проверка исходного Xray TCP пути не завершена. Проверьте журнал и состояние маршрута.",
		"service_health": "unverified", "review_stage": stage, "cause": cause,
		"elapsed_ms": max(int64(0), min(time.Since(started).Milliseconds(), int64(120000))),
	})
}
