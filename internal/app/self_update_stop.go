package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func (f *SelfUpdateFiles) controlAuthority(ctx context.Context, allowMissing bool) error {
	if f == nil || f.ControlRoot == "" {
		return nil // Legacy fixtures have no persistent authority protocol.
	}
	r, present, err := operationgate.ReadSelfUpdateStop(ctx, f.ControlRoot)
	if err != nil {
		return err
	}
	if !present && !allowMissing {
		return operationgate.ErrSelfUpdateStopJournal
	}
	if r.Stopped {
		return operationgate.ErrSelfUpdateStopped
	}
	return nil
}

func (f *SelfUpdateFiles) controlAction(ctx context.Context, id string, revision uint64, action string) error {
	if f == nil || f.ControlRoot == "" {
		return nil
	}
	r, present, err := operationgate.ReadSelfUpdateStop(ctx, f.ControlRoot)
	if err != nil {
		return err
	}
	if !present {
		if action == "prepare" {
			return nil
		}
		return operationgate.ErrSelfUpdateStopJournal
	}
	if !r.Stopped {
		return nil
	}
	if r.TransactionID != id || r.ConfigRevision != revision {
		return operationgate.ErrSelfUpdateStopChanged
	}
	switch selfUpdateActionAuthority(action) {
	case "stop-owned", "replace-to-rollback", "read/observe":
		return nil
	default:
		return operationgate.ErrSelfUpdateStopped
	}
}

func (f *SelfUpdateFiles) controlPending() bool {
	if f == nil || f.ControlRoot == "" {
		return false
	}
	r, _, err := operationgate.ReadSelfUpdateStop(context.Background(), f.ControlRoot)
	return err != nil || r.Stopped
}

func (f *SelfUpdateFiles) controlView(ctx context.Context) map[string]any {
	view := map[string]any{"stop_requested": false, "authority_revoked": false, "stopped_confirmed": false, "cleanup_pending": false}
	if f == nil || f.ControlRoot == "" {
		return view
	}
	r, present, err := operationgate.ReadSelfUpdateStop(ctx, f.ControlRoot)
	if err != nil {
		view["authority_unknown"], view["cleanup_pending"] = true, true
		return view
	}
	if present && r.Stopped {
		view["stop_requested"], view["authority_revoked"], view["cleanup_pending"] = true, true, true
		view["sequence"], view["cleanup_state"] = r.Sequence, r.State
		// A retained observation alone is not a fresh owned absence proof.
	}
	return view
}

// This is durable revocation only. It neither writes a third config image nor
// borrows the installer's Exclusive lease. Owned cleanup remains separately
// fenced until the real supervisor and concrete adapters have joined/observed.
func (a *App) requestSelfUpdateRuntimeStop(w http.ResponseWriter, r *http.Request, revision uint64) {
	if a.Security == nil || !a.Security.Authenticated(r) {
		http.Error(w, "administrator login is required", http.StatusUnauthorized)
		return
	}
	if a.Store == nil || a.SelfUpdateFiles == nil || a.SelfUpdateFiles.ControlRoot == "" {
		a.writeOperationFailure(w, errSelfUpdateRecovery)
		return
	}
	f := a.SelfUpdateFiles
	var receipt operationgate.SelfUpdateStop
	var newlyRequested bool
	err := a.Store.WithRevisionObservation(r.Context(), revision, func() error {
		current, present, readErr := operationgate.ReadSelfUpdateStop(r.Context(), f.ControlRoot)
		// Matching retry may finish the missing immutable intent after a crash.
		// Other damage is never treated as an absent/new installation.
		if readErr != nil && !(present && current.Stopped && errors.Is(readErr, operationgate.ErrSelfUpdateStopJournal)) {
			return readErr
		}
		id := current.TransactionID
		if !current.Stopped {
			state, exists, fileErr := f.Current()
			if fileErr == nil && exists && selfUpdateID.MatchString(state.ID) {
				id = state.ID
			} else if f.Helper != nil && selfUpdateID.MatchString(f.Helper.Snapshot().ID) {
				id = f.Helper.Snapshot().ID
			} else {
				// Stop is global even when the other journals are unreadable.
				// Its ID is generated here, never supplied through HTTP.
				var value [16]byte
				if _, err := rand.Read(value[:]); err != nil {
					return err
				}
				id = hex.EncodeToString(value[:])
			}
		}
		newlyRequested = !current.Stopped || readErr != nil
		var err error
		receipt, err = operationgate.RequestSelfUpdateStop(r.Context(), f.ControlRoot, id, revision)
		return err
	})
	if newlyRequested && receipt.Stopped {
		// External config replacement may invalidate the acknowledgement after
		// the independent revocation was already persisted. Cancel owned work
		// even then; uncertainty never restores its authority.
		a.preemptForRuntimeStop(0)
	}
	if err != nil {
		status, code := http.StatusServiceUnavailable, "SELF_UPDATE_STOP_UNCONFIRMED"
		if errors.Is(err, config.ErrRevisionChanged) || errors.Is(err, operationgate.ErrSelfUpdateStopChanged) {
			status, code = http.StatusConflict, "SERVICE_CONTROL_CHANGED"
		}
		writeJSON(w, status, map[string]any{"code": code, "error": "Остановка требует проверки. Сохраните журналы; очистка маршрутов не подтверждена.", "recovery_required": true, "stopped_confirmed": false})
		return
	}
	a.wakePanelSnapshot()
	writeJSON(w, http.StatusAccepted, map[string]any{"stop_requested": true, "authority_revoked": true, "stopped_confirmed": false, "cleanup_pending": true, "sequence": receipt.Sequence, "cleanup_state": receipt.State, "recovery_required": true})
}
