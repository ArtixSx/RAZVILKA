package updatecheck

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

func pairedFileEffect(effect string) bool {
	return effect == pairedPriorManifestEffect || effect == "paired-seal-paired-receipt" || effect == "paired-seal-paired-current" || effect == "paired-retire-paired-receipt"
}

// OpenFileJournal installs the same fixed private evidence reader used by
// inventory, settlement and paired publication. A bare Store refuses paired
// evidence; neither a digest nor Receipt.Pending supplies this reader.
func (a *SelfUpdateFileAdapter) OpenFileJournal() (*selfupdatejournal.Store, error) {
	if a == nil || a.owned == nil || a.owned(a.installation) != nil || a.owned(a.fileJournal) != nil {
		return nil, ErrFileProtocol
	}
	return selfupdatejournal.OpenWithPairedEvidence(a.installation, a.fileJournal, a.verifyPairedState)
}

func (a *SelfUpdateFileAdapter) verifyPairedState(ctx context.Context, receipt selfupdatejournal.Receipt, pendingID string, formatOnly bool) error {
	if receipt.Schema != selfupdatejournal.PairedSchema || receipt.Paired == nil {
		return ErrFileProtocol
	}
	b := receipt.Paired
	if err := a.pairedHelperNamespace(ctx, receipt, pendingID, formatOnly); err != nil {
		return err
	}
	path := filepath.Join(a.installation, filepath.FromSlash(pairedPriorArchiveDirectory), receipt.ID)
	if a.owned(path) != nil {
		return ErrFileProtocol
	}
	root, err := ownedfs.Open(path)
	if err != nil {
		return err
	}
	defer root.Close()
	fs, err := os.OpenRoot(path)
	if err != nil {
		return err
	}
	defer fs.Close()
	binding := pairedPriorBinding{ID: receipt.ID, ReviewSHA256: b.ReviewSHA256, ReceiptSHA256: b.PreparedSHA256, InstallationID: b.InstallationID, Sequence: b.Sequence, Revision: b.Revision}
	doc, data, err := readPairedPriorArchive(ctx, root, fs, binding)
	if err != nil || digestBytes(data) != b.ManifestSHA256 || priorArchiveMatchesReceipt(doc, receipt) != nil {
		return ErrPairedPriorArchive
	}
	held, heldErr := root.RootInfo()
	current, currentErr := os.Lstat(path)
	base, baseErr := os.Lstat(filepath.Dir(path))
	if heldErr != nil || currentErr != nil || baseErr != nil || !os.SameFile(held, current) || !privatePriorArchiveInfo(current, true) || !privatePriorArchiveInfo(base, true) || a.owned(path) != nil {
		return ErrPairedPriorArchive
	}
	job, err := a.commandRoot(receipt.ID)
	if err != nil {
		return err
	}
	_, retainedErr := job.Stat("retained-helper.json")
	job.Close()
	retained := retainedErr == nil
	if retainedErr != nil && !errors.Is(retainedErr, os.ErrNotExist) || receipt.Phase == "archived" && !retained {
		return ErrFileProtocol
	}
	record, review, err := a.loadBoundReview(ctx, receipt.ID, true, retained)
	if err != nil || record.FileReviewSHA256 != b.ReviewSHA256 || review.AuthorityInstallationID != b.InstallationID || review.AuthoritySequence != b.Sequence || review.Revision != b.Revision {
		return ErrFileProtocol
	}
	if receipt.Phase == "archived" {
		if record.Job.State != "completed" || receipt.Retired == nil {
			return ErrFileProtocol
		}
		data, _ := json.Marshal(record)
		if digestBytes(data) != receipt.Retired.HelperSHA256 {
			return ErrFileProtocol
		}
		return a.pairedSettledFormats(ctx, record, review, receipt)
	}
	return ctx.Err()
}

// Every retained helper must still have its file-journal counterpart. Checking
// the namespace cannot silently hide an orphan behind one retired transaction.
// The file inventory validates all receipts/images; this check does not recurse
// through a second paired verifier or grant another job retirement.
func (a *SelfUpdateFileAdapter) pairedHelperNamespace(ctx context.Context, receipt selfupdatejournal.Receipt, pendingID string, formatOnly bool) error {
	entries, err := boundedJobDirectories(a.directory)
	if err != nil {
		return err
	}
	files, err := boundedJobDirectories(a.fileJournal)
	if err != nil {
		return err
	}
	fileIDs := map[string]bool{}
	stagedPointer := 0
	for _, entry := range files {
		if entry.Name() == ".writer.lock" || entry.Name() == "current.json" {
			continue
		}
		// ownedfs stages the pointer in this directory before its guarded
		// rename. This is namespace inspection of a pending receipt only.
		// The full file inventory and pairedCurrentReady still fence any
		// uncommitted entry; accepted/archived evidence never permits one.
		if receipt.Phase == "paired-prepared" && strings.HasPrefix(entry.Name(), ".transaction-") && jobIDPattern.MatchString(strings.TrimPrefix(entry.Name(), ".transaction-")) && !entry.IsDir() && entry.Type()&os.ModeSymlink == 0 {
			stagedPointer++
			if stagedPointer > 1 {
				return ErrFileProtocol
			}
			continue
		}
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !jobIDPattern.MatchString(entry.Name()) {
			return ErrFileProtocol
		}
		fileIDs[entry.Name()] = true
	}
	currentRoot, err := ownedfs.Open(a.directory)
	if err != nil {
		return err
	}
	currentData, readErr := currentRoot.ReadLimited("current.json", 64<<10)
	currentRoot.Close()
	var current updateRecord
	if readErr != nil || decodeFileProtocol(currentData, &current) != nil || current.Owner != updaterOwner || !jobIDPattern.MatchString(current.Job.ID) {
		return ErrFileProtocol
	}
	preparing, err := a.preparingHelper(ctx, current)
	if err != nil {
		return err
	}
	if !terminalHelperState(current.Job.State) && !formatOnly && current.Job.ID != pendingID {
		return selfupdatejournal.ErrPending
	}
	found := false
	foundCurrent := preparing && current.Job.Stage == "metadata"
	for _, entry := range entries {
		if entry.Name() == "current.json" {
			continue
		}
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !jobIDPattern.MatchString(entry.Name()) {
			return ErrFileProtocol
		}
		isCurrent := entry.Name() == current.Job.ID
		if !fileIDs[entry.Name()] && !(isCurrent && (current.Job.State == "ready" || current.Job.State == "installing" || preparing) && (formatOnly || pendingID == current.Job.ID)) {
			return ErrFileProtocol
		}
		if isCurrent {
			foundCurrent = true
			if preparing {
				continue
			}
		}
		if entry.Name() == receipt.ID {
			found = true
			continue
		}
		record, review, err := a.loadBoundReview(ctx, entry.Name(), true, !isCurrent)
		if err != nil || a.checkHelperProcessFormats(ctx, record, review) != nil {
			return ErrFileProtocol
		}
	}
	if !found || !foundCurrent {
		return ErrFileProtocol
	}
	return ctx.Err()
}

func (a *SelfUpdateFileAdapter) priorCaptureCheck(id string, review fileReview) func(context.Context) error {
	return func(ctx context.Context) error {
		if err := a.Authority(ctx, id, review.Revision); err != nil {
			return err
		}
		if err := a.fileQuiescence(ctx, id); err != nil {
			return err
		}
		if err := a.filePanelAbsent(ctx); err != nil {
			return err
		}
		return a.runtimeInactive(ctx, id)
	}
}

// SealPairedPriorState attaches the verified copy before replacement. It is
// deliberately unwired until the actual bootstrap has full offline rollback.
func (a *SelfUpdateFileAdapter) SealPairedPriorState(ctx context.Context, id string) error {
	if runtime.GOOS != "linux" || a == nil || ctx == nil || a.runtimeInactive == nil || a.admission == nil {
		return ErrFileProtocol
	}
	record, review, err := a.load(ctx, id)
	if err != nil {
		return err
	}
	store, err := a.OpenFileJournal()
	if err != nil {
		return err
	}
	defer store.Close()
	check := a.priorCaptureCheck(id, review)
	return store.SealPairedPriorState(ctx, id, check, check, func(ctx context.Context, receipt selfupdatejournal.Receipt) (selfupdatejournal.PairedBinding, error) {
		if err := store.VerifyReviewedImages(ctx, id, review.Files, review.OldExecutableSHA256, review.OldInitSHA256, review.OldConfigSHA256); err != nil {
			return selfupdatejournal.PairedBinding{}, err
		}
		data, _ := json.Marshal(receipt)
		binding := pairedPriorBinding{ID: id, ReviewSHA256: record.FileReviewSHA256, ReceiptSHA256: digestBytes(data), InstallationID: review.AuthorityInstallationID, Sequence: review.AuthoritySequence, Revision: review.Revision}
		digest, err := capturePairedPriorState(ctx, a.installation, binding, receipt, a.owned, check, func(rename func() error) error {
			return a.EffectAdmission(ctx, id, "start/live", pairedPriorManifestEffect, rename)
		}, nil)
		return selfupdatejournal.PairedBinding{ManifestSHA256: digest, PreparedSHA256: binding.ReceiptSHA256, ReviewSHA256: binding.ReviewSHA256, InstallationID: binding.InstallationID, Sequence: binding.Sequence, Revision: binding.Revision}, err
	}, func(ctx context.Context, effect string, rename func() error) error {
		return a.EffectAdmission(ctx, id, "start/live", "paired-seal-"+effect, rename)
	})
}

// The mandatory owner observes the actual current App operation/runtime. It
// is supplied by trusted CORE wiring, never a client result or a copy checksum.
func (a *SelfUpdateFileAdapter) RetirePairedPriorState(ctx context.Context, id string, owner SelfUpdateRuntimeObservation) error {
	if runtime.GOOS != "linux" || a == nil || ctx == nil || owner == nil || a.admission == nil {
		return ErrFileProtocol
	}
	record, review, err := a.loadBoundReview(ctx, id, true, true)
	if err != nil || record.Job.State != "completed" {
		return ErrFileProtocol
	}
	current, err := readAdapterRecord(a.directory, id)
	if err != nil {
		return err
	}
	data, _ := json.Marshal(record)
	currentData, _ := json.Marshal(current)
	if digestBytes(data) != digestBytes(currentData) {
		return ErrFileProtocol
	}
	store, err := a.OpenFileJournal()
	if err != nil {
		return err
	}
	defer store.Close()
	check := func(ctx context.Context) error { return a.Authority(ctx, id, review.Revision) }
	terminal := func(ctx context.Context) error {
		fresh, err := readAdapterRecord(a.directory, id)
		if err != nil {
			return err
		}
		freshData, _ := json.Marshal(fresh)
		if digestBytes(freshData) != digestBytes(data) {
			return ErrFileProtocol
		}
		receipt, err := store.RetainedReceipt(ctx, id)
		if err != nil || a.pairedSettledFormats(ctx, record, review, receipt) != nil {
			return ErrFileProtocol
		}
		identity, err := a.helperIdentity(id, review)
		if err != nil {
			return err
		}
		observe := a.processInactive
		if observe == nil {
			observe = fileProcessInactive
		}
		for _, process := range []fileProcess{identity.Process, identity.OldPanel} {
			if err := observe(ctx, process); err != nil {
				return err
			}
		}
		root, err := a.commandRoot(id)
		if err != nil {
			return err
		}
		defer root.Close()
		for _, command := range receipt.Commands {
			r, err := readFileCommand(root, id, command)
			if err != nil || observe(ctx, r.Supervisor) != nil {
				return ErrFileCommandUnsettled
			}
		}
		return owner(ctx, id)
	}
	return store.RetirePairedPriorState(ctx, id, digestBytes(data), check, terminal, func(ctx context.Context, effect string, rename func() error) error {
		return a.EffectAdmission(ctx, id, "start/live", "paired-retire-"+effect, rename)
	})
}

func (a *SelfUpdateFileAdapter) pairedSettledFormats(ctx context.Context, record updateRecord, review fileReview, receipt selfupdatejournal.Receipt) error {
	if err := a.checkHelperProcessFormats(ctx, record, review); err != nil {
		return err
	}
	identity, err := a.helperIdentityForRecord(review.ID, review, record)
	if err != nil {
		return err
	}
	root, err := a.commandRoot(review.ID)
	if err != nil {
		return err
	}
	defer root.Close()
	seen := map[string]bool{}
	for _, command := range receipt.Commands {
		r, err := readFileCommand(root, review.ID, command)
		if err != nil || r.Parent != identity.Process || r.Supervisor.ExecutableSHA256 != reviewedHelperSHA(review) || r.Cancelled || r.ExitCode != 0 {
			return ErrFileCommandUnsettled
		}
		if command == "start-candidate-panel" {
			if r.State != "runtime-handed-off" || r.Runtime == (fileProcess{}) {
				return ErrFileCommandUnsettled
			}
			candidate := ""
			for _, file := range review.Files {
				if file.Target == "bin/razvilka" {
					candidate = file.SHA256
				}
			}
			if r.Runtime.ExecutableSHA256 != candidate {
				return ErrFileProtocol
			}
		} else if (command != "stop-old-panel" && command != "prepare-private-state" && command != "quiesce-old-runtime") || r.State != "reaped" || !r.WaitECHILD {
			return ErrFileCommandUnsettled
		}
		seen[command] = true
	}
	if len(seen) != 4 || !seen["start-candidate-panel"] {
		return ErrFileProtocol
	}
	entries, err := boundedJobDirectories(filepath.Join(a.directory, review.ID))
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".json" {
			for _, command := range []string{"stop-candidate-panel", "restore-private-state", "start-rollback-panel"} {
				if entry.Name() == command+".process.json" {
					return ErrFileCommandUnsettled
				}
			}
		}
	}
	return a.verifyPrivateSnapshot(ctx, review.ID)
}
