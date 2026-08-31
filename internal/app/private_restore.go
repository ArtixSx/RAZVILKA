package app

import (
	"context"
	"errors"
	"net/http"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/privatebackup"
)

type privateRestoreStep struct {
	phase string // Fixed internal label, never archive-provided text.
	apply func() (func() error, error)
}

// No cause is retained here: private input and filesystem error paths must not
// accidentally reach the HTTP response, logs or audit through formatting.
type privateRestoreFailure struct {
	phase            string
	recoveryRequired bool
}

func (e *privateRestoreFailure) Error() string { return "private backup import failed" }

// runPrivateRestore compensates only completed steps in reverse order. A
// guarded undo may refuse a concurrent edit; remaining undos still run and the
// caller must report incomplete recovery. This is not a durable crash journal.
func runPrivateRestore(ctx context.Context, steps []privateRestoreStep) error {
	undos := make([]func() error, 0, len(steps))
	fail := func(phase string, cause error) error {
		incomplete := errors.Is(cause, engineconfig.ErrStageRollback)
		for i := len(undos) - 1; i >= 0; i-- {
			if err := undos[i](); err != nil {
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
	// If the final step committed, a late disconnect does not turn success into
	// rollback. The client may have to refresh to learn the committed result.
	return nil
}

func (a *App) restorePrivateDraft(ctx context.Context, payload privatebackup.Payload) error {
	if len(payload.ProviderSnapshots) != 0 || a.Store == nil || a.CustomServices == nil || a.EngineConfigs == nil || len(payload.Devices) != 0 && a.Devices == nil {
		return &privateRestoreFailure{phase: "preflight"}
	}
	steps := []privateRestoreStep{{"custom_services", func() (func() error, error) {
		return a.CustomServices.MergeWithRollback(payload.CustomServices, a.reservedServiceIDs(), true)
	}}}
	if a.Devices != nil {
		steps = append(steps, privateRestoreStep{"devices", func() (func() error, error) {
			return a.Devices.MergeMetadataWithRollback(payload.Devices)
		}})
	}
	steps = append(steps, privateRestoreStep{"services", func() (func() error, error) {
		return a.Store.ReplaceDraftWithRollback(payload.Services)
	}})
	items := make([]engineconfig.StageItem, 0, len(payload.EngineFiles))
	for _, file := range payload.EngineFiles {
		items = append(items, engineconfig.StageItem{EngineID: file.EngineID, FileID: file.FileID, Content: file.Content})
	}
	// Engine staging is last: it already rolls its own batch back on failure,
	// and now reports if that rollback itself failed. No later step may be
	// appended without adding a guarded undo for successful engine staging.
	steps = append(steps, privateRestoreStep{"engine_files", func() (func() error, error) {
		_, err := a.EngineConfigs.StagePrivate(items)
		return nil, err
	}})
	return runPrivateRestore(ctx, steps)
}

func writePrivateRestoreFailure(w http.ResponseWriter, err error) {
	var failure *privateRestoreFailure
	if !errors.As(err, &failure) {
		failure = &privateRestoreFailure{phase: "unknown", recoveryRequired: true}
	}
	message := "Восстановление не завершено. Изменения этой операции отменены."
	code := "PRIVATE_BACKUP_IMPORT_ROLLED_BACK"
	if failure.recoveryRequired {
		message = "Восстановление не завершено, и не все изменения удалось отменить. Возможна параллельная правка или ошибка записи. Проверьте черновики перед применением."
		code = "PRIVATE_BACKUP_RECOVERY_REQUIRED"
	}
	writeJSON(w, http.StatusInternalServerError, map[string]any{
		"ok": false, "error": message, "code": code, "phase": failure.phase,
		"recovery_required": failure.recoveryRequired, "rolled_back": !failure.recoveryRequired,
		"live_applied": false,
	})
}
