package app

import (
	"context"
	"errors"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// Historical compensation harness retained solely to test the individual
// guarded undo APIs. Production private import must never fall back to this.
type privateRestoreStep struct {
	phase string
	apply func() (func() error, error)
}

func runPrivateRestore(ctx context.Context, steps []privateRestoreStep) error {
	undos := make([]func() error, 0, len(steps))
	fail := func(phase string, cause error) error {
		incomplete := errors.Is(cause, engineconfig.ErrStageRollback) || errors.Is(cause, restorejournal.ErrRecovery)
		for i := len(undos) - 1; i >= 0; i-- {
			if undos[i]() != nil {
				incomplete = true
			}
		}
		return &privateRestoreFailure{phase: phase, recoveryRequired: incomplete}
	}
	for _, step := range steps {
		if err := ctx.Err(); err != nil {
			return fail(step.phase, err)
		}
		undo, err := step.apply()
		if err != nil {
			return fail(step.phase, err)
		}
		if undo != nil {
			undos = append(undos, undo)
		}
	}
	return nil
}
