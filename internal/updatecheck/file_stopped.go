package updatecheck

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

const stoppedRollbackState = "rolled-back-stopped"

func terminalHelperState(state string) bool {
	return state == "completed" || state == "rolled-back" || state == stoppedRollbackState
}

// Mandatory trusted CORE bindings; no HTTP DTO can provide these callbacks.
// Check observes the preserved exact Stop. AdmitReaders checks the proof
// sealed before Stop and must not start any controller during settlement.
type SelfUpdateStoppedSettlementAuthority struct {
	Check        func(ctx context.Context, id, installationID string, preStopSequence, reviewedRevision uint64) error
	AdmitReaders func(ctx context.Context, id string, requiredReader int) error
}

func (a *SelfUpdateFileAdapter) SettleStoppedRollback(ctx context.Context, id string, authority SelfUpdateStoppedSettlementAuthority) error {
	return a.withCandidateStoppedRead(ctx, id, func(held context.Context) error {
		return a.settleStoppedRollback(held, id, authority)
	})
}

func (a *SelfUpdateFileAdapter) settleStoppedRollback(ctx context.Context, id string, authority SelfUpdateStoppedSettlementAuthority) error {
	if authority.Check == nil || authority.AdmitReaders == nil {
		return ErrFileProtocol
	}
	record, review, err := a.load(ctx, id)
	if err != nil {
		return err
	}
	if terminalHelperState(record.Job.State) && record.Job.State != stoppedRollbackState {
		return ErrFileProtocol
	}
	binding := selfupdatejournal.StoppedBinding{InstallationID: review.AuthorityInstallationID, PreStopSequence: review.AuthoritySequence, StopSequence: review.AuthoritySequence + 1, Revision: review.Revision, RequiredReader: selfupdatejournal.StoppedSchema}
	check := func(ctx context.Context) error {
		if a.stopCheck == nil {
			return ErrFileProtocol
		}
		stopped, err := a.stopCheck(ctx, id)
		if err != nil || !stopped {
			return errors.Join(ErrFileProtocol, err)
		}
		if err := a.AuthorityAction(ctx, id, review.Revision, "replace-to-rollback"); err != nil {
			return err
		}
		return authority.Check(ctx, id, review.AuthorityInstallationID, review.AuthoritySequence, review.Revision)
	}
	readers := func(ctx context.Context) error {
		if err := a.CheckRetainedJournalReaders(ctx, id, selfupdatejournal.StoppedSchema); err != nil {
			return err
		}
		return authority.AdmitReaders(ctx, id, selfupdatejournal.StoppedSchema)
	}
	store, err := a.OpenFileJournal()
	if err != nil {
		return err
	}
	defer store.Close()
	inactive := func(ctx context.Context) error { return a.stoppedSettlementInactive(ctx, id, review, store) }
	if err := store.SettleStoppedRollback(ctx, id, binding, check, readers, inactive); err != nil {
		return err
	}
	// The file receipt is the authoritative terminal transition. A crash here
	// leaves helper review pending; retry performs every fresh check again.
	if err := check(ctx); err != nil {
		return err
	}
	if err := readers(ctx); err != nil {
		return err
	}
	if err := inactive(ctx); err != nil {
		return err
	}
	fresh, freshReview, err := a.load(ctx, id)
	if err != nil || fresh.FileReviewSHA256 != record.FileReviewSHA256 || freshReview.Revision != review.Revision {
		return errors.Join(ErrFileProtocol, err)
	}
	if terminalHelperState(fresh.Job.State) && fresh.Job.State != stoppedRollbackState {
		return ErrFileProtocol
	}
	fresh.Job.State, fresh.Job.Stage = stoppedRollbackState, stoppedRollbackState
	fresh.Job.Code, fresh.Job.ReviewToken = "", ""
	fresh.Job.Message = "Данные приложения восстановлены. Приложение остановлено."
	fresh.Job.CanApply, fresh.Job.CanCancel = false, false
	fresh.Job.UpdatedAt = time.Now().UTC()
	if err := archiveHelperRecord(a.directory, fresh); err != nil {
		return err
	}
	if err := check(ctx); err != nil {
		return err
	}
	root, err := ownedfs.Open(a.directory)
	if err != nil {
		return err
	}
	defer root.Close()
	data, err := json.Marshal(fresh)
	if err != nil {
		return err
	}
	if err := writeSelfUpdateRecord(root, data); err != nil {
		return err
	}
	if err := check(ctx); err != nil {
		return err
	}
	if err := readers(ctx); err != nil {
		return err
	}
	return inactive(ctx)
}

func (a *SelfUpdateFileAdapter) stoppedSettlementInactive(ctx context.Context, id string, review fileReview, store *selfupdatejournal.Store) error {
	r, present, err := store.Current()
	if err != nil || !present || r.ID != id {
		return errors.Join(ErrFileProtocol, err)
	}
	if r.Phase == "command-started" {
		return selfupdatejournal.ErrUnknown
	}
	if err := store.VerifyReviewedImages(ctx, id, review.Files, review.OldExecutableSHA256, review.OldInitSHA256, review.OldConfigSHA256); err != nil {
		return err
	}
	identity, err := a.helperIdentity(id, review)
	if err != nil {
		return err
	}
	observe := a.processInactive
	if observe == nil {
		observe = fileProcessInactive
	}
	if err := observe(ctx, identity.OldPanel); err != nil {
		return err
	}
	root, err := a.commandRoot(id)
	if err != nil {
		return err
	}
	defer root.Close()
	seen := map[string]bool{}
	for _, command := range r.Commands {
		if !validFileCommand(command) {
			return ErrFileProtocol
		}
		seen[command] = true
	}
	for _, command := range []string{"stop-old-panel", "prepare-private-state", "quiesce-old-runtime", "start-candidate-panel", "stop-candidate-panel", "restore-private-state", "start-rollback-panel"} {
		commandReceipt, err := readFileCommand(root, id, command)
		if errors.Is(err, os.ErrNotExist) && !seen[command] {
			continue
		}
		if errors.Is(err, os.ErrNotExist) && seen[command] && command == "stop-candidate-panel" && ctx.Value(candidateStoppedReadKey{}) != nil {
			s, sourceErr := candidateStoppedReadFor(ctx, a, id)
			if sourceErr != nil {
				return sourceErr
			}
			if err := s.completion.receipt(r); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		// A durable ECHILD is mandatory even across reboot. Merely finding a
		// dead helper or a different boot cannot clear command uncertainty.
		if !seen[command] || !commandReceipt.WaitECHILD || (commandReceipt.State != "reaped" && commandReceipt.State != "not-started") || commandReceipt.Parent != identity.Process || commandReceipt.Supervisor.ExecutableSHA256 != review.OldExecutableSHA256 {
			return ErrFileCommandUnsettled
		}
		if err := observe(ctx, commandReceipt.Supervisor); err != nil {
			return err
		}
		if commandReceipt.Runtime != (fileProcess{}) {
			wanted := review.OldExecutableSHA256
			if command == "start-candidate-panel" {
				for _, file := range review.Files {
					if file.Target == "bin/razvilka" {
						wanted = file.SHA256
					}
				}
			} else if command != "start-rollback-panel" {
				return ErrFileProtocol
			}
			if commandReceipt.Runtime.ExecutableSHA256 != wanted {
				return ErrFileProtocol
			}
			if err := observe(ctx, commandReceipt.Runtime); err != nil {
				return err
			}
		}
		if command == "prepare-private-state" || command == "restore-private-state" {
			if commandReceipt.State != "reaped" || commandReceipt.Cancelled || commandReceipt.ExitCode != 0 {
				return ErrFileProtocol
			}
		}
	}
	for _, required := range []string{"stop-old-panel", "prepare-private-state", "quiesce-old-runtime", "restore-private-state"} {
		if !seen[required] {
			return ErrFileProtocol
		}
	}
	if err := a.verifyPrivateRestore(ctx, id); err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(a.installation, "razvilka/run/razvilka.pid")); !errors.Is(err, os.ErrNotExist) {
		return ErrFileProtocol
	}
	if a.runtimeInactive == nil {
		return ErrFileProtocol
	}
	if err := a.runtimeInactive(ctx, id); err != nil {
		return err
	}
	return ctx.Err()
}
