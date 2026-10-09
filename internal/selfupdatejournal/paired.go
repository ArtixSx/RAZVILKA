package selfupdatejournal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"slices"
)

// PairedSchema is a distinct active format. Ordinary replacements still write
// Schema; a schema2/3 reader must refuse paired state rather than replay it.
const PairedSchema = 4

type PairedBinding struct {
	ManifestSHA256 string `json:"manifest_sha256"`
	PreparedSHA256 string `json:"prepared_sha256"`
	ReviewSHA256   string `json:"review_sha256"`
	InstallationID string `json:"installation_id"`
	Sequence       uint64 `json:"sequence"`
	Revision       uint64 `json:"revision"`
}

type RetirementBinding struct {
	AcceptedSHA256 string `json:"accepted_sha256"`
	HelperSHA256   string `json:"helper_sha256"`
}

// PairedEvidence is an installed trusted reader of the fixed private archive
// and matching helper evidence. Receipt metadata alone never supplies it.
type PairedEvidence func(ctx context.Context, receipt Receipt, pendingID string, formatOnly bool) error

func OpenWithPairedEvidence(installation, journal string, evidence PairedEvidence) (*Store, error) {
	if evidence == nil {
		return nil, ErrMismatch
	}
	s, err := Open(installation, journal)
	if err == nil {
		s.pairedEvidence = evidence
	}
	return s, err
}

func receiptSHA(r Receipt) string {
	data, _ := json.Marshal(r)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func preparedPairReceipt(r Receipt) Receipt {
	r.Schema, r.Phase, r.Index, r.Command, r.Rollback, r.BeforeFiles = Schema, "prepared", 0, "", false, false
	r.Paired, r.Retired = nil, nil
	r.Commands = slices.Clone(r.Commands[:3])
	return r
}

func validPairedReceipt(r Receipt) bool {
	if r.Paired == nil || r.Stopped != nil || r.Rollback || len(r.Files) != 6 || len(r.Commands) < 3 || !slices.Equal(r.Commands[:3], []string{"stop-old-panel", "prepare-private-state", "quiesce-old-runtime"}) {
		return false
	}
	b := r.Paired
	if !digest(b.ManifestSHA256) || !digest(b.PreparedSHA256) || !digest(b.ReviewSHA256) || !idPattern.MatchString(b.InstallationID) || b.Sequence == 0 || b.PreparedSHA256 != receiptSHA(preparedPairReceipt(r)) {
		return false
	}
	for _, file := range r.Files {
		if (file.Target == "bin/razvilka" || file.Target == "etc/init.d/S99razvilka" || file.Target == "etc/razvilka/config.json") && !file.OldPresent {
			return false
		}
	}
	if r.Phase == "paired-prepared" {
		return r.Index == 0 && r.Command == "" && len(r.Commands) == 3 && !r.BeforeFiles && r.Retired == nil
	}
	if r.Phase == "archived" {
		if r.Retired == nil || !digest(r.Retired.AcceptedSHA256) || !digest(r.Retired.HelperSHA256) {
			return false
		}
		accepted := r
		accepted.Phase, accepted.Retired = "accepted", nil
		return r.Retired.AcceptedSHA256 == receiptSHA(accepted)
	}
	return r.Retired == nil && (r.Phase == "installing" || r.Phase == "installed" || r.Phase == "command-started" || r.Phase == "command-finished" || r.Phase == "accepted")
}

func (s *Store) verifyPairedEvidence(ctx context.Context, r Receipt) error {
	if r.Schema != PairedSchema {
		return nil
	}
	if s.pairedEvidence == nil || !valid(r) {
		return ErrMismatch
	}
	return s.pairedEvidence(ctx, r, "", true)
}

func (s *Store) verifyPairedInventory(ctx context.Context, r Receipt, pendingID string, formatOnly bool) error {
	if r.Schema != PairedSchema {
		return nil
	}
	if s.pairedEvidence == nil || !valid(r) {
		return ErrMismatch
	}
	return s.pairedEvidence(ctx, r, pendingID, formatOnly)
}

func (s *Store) pairedCurrentReady(id string) error {
	data, err := s.journal.ReadLimited("current.json", 1024)
	var pointer struct {
		Schema int    `json:"schema"`
		ID     string `json:"id"`
	}
	if err != nil || decode(data, &pointer) != nil || pointer.Schema != PairedSchema || pointer.ID != id {
		return ErrMismatch
	}
	canonical, _ := json.Marshal(pointer)
	if string(data) != string(canonical) {
		return ErrMismatch
	}
	directory, err := s.journalFiles.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	entries, err := directory.ReadDir(258)
	if err != nil && err != io.EOF || len(entries) > 257 {
		return ErrMismatch
	}
	for _, entry := range entries {
		if entry.Name() != ".writer.lock" && entry.Name() != "current.json" && (!entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !idPattern.MatchString(entry.Name())) {
			return ErrMismatch
		}
	}
	return nil
}

// WithPairedOfflineRestore retains the existing writer while a trusted current
// owner restores the complete offline pair. It does not replay the six-file
// rollback, change receipts, clear Stop, or issue a retirement grant. The
// callback must keep all control/helper evidence in its current location.
func (s *Store) WithPairedOfflineRestore(ctx context.Context, id string, authority, quiescence Check, restore func(context.Context, Receipt, Check) error) error {
	if s == nil || ctx == nil || authority == nil || quiescence == nil || restore == nil || s.pairedEvidence == nil || !idPattern.MatchString(id) {
		return ErrMismatch
	}
	if _, finite := ctx.Deadline(); !finite {
		return ErrMismatch
	}
	if err := checks(ctx, authority, quiescence); err != nil {
		return err
	}
	var writer os.FileInfo
	unlock, err := lockExistingWriter(s.journal, func(info os.FileInfo) { writer = info })
	if err != nil {
		return err
	}
	defer unlock()
	r, err := s.matching(id)
	if err != nil || r.Schema != PairedSchema || r.Phase == "command-started" || s.pairedCurrentReady(id) != nil {
		return ErrMismatch
	}
	before := receiptSHA(r)
	check := func(c context.Context) error {
		if c != ctx {
			return ErrMismatch
		}
		current, err := s.journal.Stat(".writer.lock")
		if err != nil || !os.SameFile(writer, current) {
			return ErrMismatch
		}
		fresh, err := s.matching(id)
		if err != nil || receiptSHA(fresh) != before || s.pairedCurrentReady(id) != nil || s.verifyImages(fresh) != nil {
			return ErrMismatch
		}
		return checks(c, authority, quiescence)
	}
	if err := check(ctx); err != nil {
		return err
	}
	if err := s.verifyPairedEvidence(ctx, r); err != nil {
		return err
	}
	copy := r
	copy.Files, copy.Commands = slices.Clone(r.Files), slices.Clone(r.Commands)
	if err := restore(ctx, copy, check); err != nil {
		return err
	}
	return check(ctx)
}

// SealPairedPriorState binds capture to the current prepared source before
// replacement. capture is the trusted whole-source copier, not a supplied DTO.
// A cut after publication remains pending; it cannot supply retirement.
func (s *Store) SealPairedPriorState(ctx context.Context, id string, authority, quiescence Check, capture func(context.Context, Receipt) (PairedBinding, error), admission Admission) error {
	if s == nil || ctx == nil || authority == nil || quiescence == nil || capture == nil || admission == nil || s.pairedEvidence == nil || !idPattern.MatchString(id) {
		return ErrMismatch
	}
	if _, finite := ctx.Deadline(); !finite {
		return ErrMismatch
	}
	var writer os.FileInfo
	unlock, err := lockExistingWriter(s.journal, func(info os.FileInfo) { writer = info })
	if err != nil {
		return err
	}
	defer unlock()
	check := func(c context.Context) error {
		current, err := s.journal.Stat(".writer.lock")
		if err != nil || !os.SameFile(writer, current) {
			return ErrMismatch
		}
		return checks(c, authority, quiescence)
	}
	r, err := s.preparedPriorState(ctx, id, check, check)
	if err != nil {
		return err
	}
	binding, err := capture(ctx, r)
	if err != nil {
		return err
	}
	fresh, err := s.preparedPriorState(ctx, id, check, check)
	if err != nil || receiptSHA(fresh) != receiptSHA(r) || binding.PreparedSHA256 != receiptSHA(r) {
		return ErrMismatch
	}
	r.Schema, r.Phase, r.Paired = PairedSchema, "paired-prepared", &binding
	if !valid(r) {
		return ErrMismatch
	}
	prepared := func() error {
		if err := check(ctx); err != nil {
			return err
		}
		return s.verifyPairedEvidence(ctx, r)
	}
	if err := s.writePairedReceipt(ctx, r, admission, prepared); err != nil {
		return err
	}
	pointer, _ := json.Marshal(struct {
		Schema int    `json:"schema"`
		ID     string `json:"id"`
	}{PairedSchema, id})
	if err := s.boundary("before:paired-current"); err != nil {
		return err
	}
	if _, err := s.journal.WriteAtomicWithRenameAdmission("current.json", pointer, 0600, func(rename func() error) error { return admission(ctx, "paired-current", rename) }, prepared); err != nil {
		return err
	}
	if err := syncDirectory(s.journalFiles, "."); err != nil {
		return err
	}
	if err := s.boundary("after:paired-current"); err != nil {
		return err
	}
	return prepared()
}

// RetirePairedPriorState is a single receipt transition. It keeps every frozen
// byte and requires independently settled matching helper/process evidence.
// Pending, unknown, stopped and rolled-back receipts cannot enter this state.
func (s *Store) RetirePairedPriorState(ctx context.Context, id string, helperSHA string, authority, terminal Check, admission Admission) error {
	if s == nil || ctx == nil || authority == nil || terminal == nil || admission == nil || !digest(helperSHA) || !idPattern.MatchString(id) {
		return ErrMismatch
	}
	if _, finite := ctx.Deadline(); !finite {
		return ErrMismatch
	}
	var writer os.FileInfo
	unlock, err := lockExistingWriter(s.journal, func(info os.FileInfo) { writer = info })
	if err != nil {
		return err
	}
	defer unlock()
	r, err := s.matching(id)
	if err != nil || r.Schema != PairedSchema || (r.Phase != "accepted" && r.Phase != "archived") || r.Rollback {
		return ErrPending
	}
	if r.Phase == "archived" && r.Retired.HelperSHA256 != helperSHA {
		return ErrMismatch
	}
	check := func() error {
		current, err := s.journal.Stat(".writer.lock")
		if err != nil || !os.SameFile(writer, current) {
			return ErrMismatch
		}
		if err := checks(ctx, authority, terminal); err != nil {
			return err
		}
		if err := s.VerifyInstallation(ctx, id, false); err != nil {
			return err
		}
		return s.verifyPairedEvidence(ctx, r)
	}
	if err := check(); err != nil {
		return err
	}
	if r.Phase == "accepted" {
		r.Retired = &RetirementBinding{receiptSHA(r), helperSHA}
		r.Phase = "archived"
		if err := s.writePairedReceipt(ctx, r, admission, check); err != nil {
			return err
		}
	}
	return check()
}

func (s *Store) writePairedReceipt(ctx context.Context, r Receipt, admission Admission, prepared func() error) error {
	if !valid(r) || admission == nil || prepared == nil {
		return ErrMismatch
	}
	if err := s.boundary("before:receipt:" + r.Phase); err != nil {
		return err
	}
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if _, err := s.journal.WriteAtomicWithRenameAdmission(r.ID+"/receipt.json", data, 0600, func(rename func() error) error { return admission(ctx, "paired-receipt", rename) }, prepared); err != nil {
		return err
	}
	if err := syncDirectory(s.journalFiles, r.ID); err != nil {
		return err
	}
	return s.boundary("after:receipt:" + r.Phase)
}
