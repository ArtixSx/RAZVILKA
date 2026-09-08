package app

import (
	"context"
	"errors"
	"net/http"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/privatebackup"
	"github.com/ArtixSx/razvilka/internal/privaterestore"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// No cause is retained here: private input and filesystem error paths must not
// accidentally reach the HTTP response, logs or audit through formatting.
type privateRestoreFailure struct {
	phase            string
	recoveryRequired bool
	notStarted       bool
}

func (e *privateRestoreFailure) Error() string { return "private backup import failed" }

func (a *App) restorePrivateDraft(ctx context.Context, payload privatebackup.Payload) error {
	release, err := a.privateRestoreAdmission(ctx)
	if err != nil {
		return err
	}
	defer release()
	// Revalidate under exclusive admission too, including internal callers.
	if _, err := a.previewPrivateBackup(payload); err != nil {
		return &privateRestoreFailure{phase: "preflight", notStarted: true}
	}
	if len(payload.ProviderSnapshots) != 0 || a.PrivateRestore == nil || a.Store == nil || a.CustomServices == nil || a.EngineConfigs == nil || a.Devices == nil || payload.NodeSnapshot != nil && a.Nodes == nil || payload.NativeEnrollment != nil && a.Warp == nil || payload.SubscriptionSnapshot != nil && a.NodeFeeds == nil {
		return &privateRestoreFailure{phase: "preflight", notStarted: true}
	}
	finished := false
	defer func() {
		if !finished {
			a.Operations.Fence()
		} // Unexpected panic: release only a fenced gate.
	}()
	out, err := a.PrivateRestore.RestoreOnline(ctx, payload, a.reservedServiceIDs(), privaterestore.Stores{
		Config: a.Store, Custom: a.CustomServices, Devices: a.Devices, Engines: a.EngineConfigs, Nodes: a.Nodes, Warp: a.Warp, Feeds: a.NodeFeeds,
	})
	finished = true
	if out == restorejournal.Blocked {
		a.Operations.Fence() // Before releasing this request's exclusive admission.
		return &privateRestoreFailure{phase: "recovery", recoveryRequired: true}
	}
	if err == nil {
		return nil
	}
	if out == restorejournal.Clean {
		if errors.Is(err, restorejournal.ErrBusy) {
			return operationgate.ErrBusy
		}
		return &privateRestoreFailure{phase: "preflight", notStarted: true}
	}
	return &privateRestoreFailure{phase: "restore"}
}

func writePrivateRestoreFailure(w http.ResponseWriter, err error) {
	if errors.Is(err, operationgate.ErrBusy) || errors.Is(err, operationgate.ErrRecovery) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		writeOperationFailure(w, err)
		return
	}
	var failure *privateRestoreFailure
	if !errors.As(err, &failure) {
		failure = &privateRestoreFailure{phase: "unknown", recoveryRequired: true}
	}
	message := "Восстановление не завершено. Изменения этой операции отменены."
	code := "PRIVATE_BACKUP_IMPORT_ROLLED_BACK"
	status := http.StatusInternalServerError
	if failure.notStarted {
		message = "Импорт не начат: не удалось подготовить хранилища или проверить архив. Настройки не изменены."
		code = "PRIVATE_BACKUP_IMPORT_NOT_STARTED"
		status = http.StatusConflict
	}
	if failure.recoveryRequired {
		message = "Восстановление не завершено. Изменения приостановлены до проверки журнала при следующем запуске. Не удаляйте журнал и не применяйте черновики вручную."
		code = "PRIVATE_BACKUP_RECOVERY_REQUIRED"
	}
	writeJSON(w, status, map[string]any{
		"ok": false, "error": message, "code": code, "phase": failure.phase,
		"recovery_required": failure.recoveryRequired, "rolled_back": !failure.recoveryRequired && !failure.notStarted, "not_started": failure.notStarted,
		"live_applied": false,
	})
}
