package selfupdatejournal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
)

// Only unresolved offline restoration uses this format. The current pointer
// stays at 4: readers <=4 reject the receipt, and successful verification can
// atomically put back the exact original receipt without a second pointer cut.
const OfflineRetrySchema = 5
const OfflineRetryReadVersion = OfflineRetrySchema
const MaximumOfflinePlanBytes = 16 << 20

type OfflineRetryBinding struct {
	PlanSHA256     string `json:"plan_sha256"`
	OriginalSHA256 string `json:"original_sha256"`
	OriginalPhase  string `json:"original_phase"`
}

func originalOfflineReceipt(r Receipt) (Receipt, bool) {
	if r.Schema != OfflineRetrySchema || r.Phase != "offline-restoring" || r.Offline == nil || !digest(r.Offline.PlanSHA256) || !digest(r.Offline.OriginalSHA256) || r.Offline.OriginalPhase == "command-started" {
		return Receipt{}, false
	}
	binding := *r.Offline
	r.Schema, r.Phase, r.Offline = PairedSchema, binding.OriginalPhase, nil
	return r, valid(r) && receiptSHA(r) == binding.OriginalSHA256
}

func offlinePlanSHA(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// WithPairedOfflineRetry owns the existing writer for the entire callback.
// bind publishes one bounded immutable plan and the schema5 fence BEFORE any
// installation effect. A cold retry receives only that exact bound plan.
// Success is legal only after the callback verifies the entire post-image;
// only then is the original schema4 receipt restored atomically. All ordinary
// mutation entry points reject schema5 through matching().
func (s *Store) WithPairedOfflineRetry(ctx context.Context, id string, authority, quiescence Check, admission Admission, restore func(context.Context, Receipt, []byte, bool, Check, func([]byte, Check) error) error) error {
	if s == nil || ctx == nil || authority == nil || quiescence == nil || admission == nil || restore == nil || s.pairedEvidence == nil || !idPattern.MatchString(id) {
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
	current, present, err := s.Current()
	if err != nil || !present || current.ID != id || s.pairedCurrentReady(id) != nil {
		return ErrMismatch
	}
	original := current
	var plan []byte
	bound := current.Schema == OfflineRetrySchema
	verifyOnly := false
	planName := id + "/offline-retry-v1.json"
	if bound {
		var ok bool
		original, ok = originalOfflineReceipt(current)
		if !ok {
			return ErrMismatch
		}
		plan, err = s.journal.ReadLimited(planName, MaximumOfflinePlanBytes)
		if err != nil || len(plan) == 0 || offlinePlanSHA(plan) != current.Offline.PlanSHA256 {
			return ErrMismatch
		}
	} else {
		if current.Schema != PairedSchema || current.Phase == "command-started" {
			return ErrMismatch
		}
		if _, err := s.journal.Stat(planName); err == nil {
			plan, err = s.journal.ReadLimited(planName, MaximumOfflinePlanBytes)
			if err != nil || len(plan) == 0 {
				return ErrMismatch
			}
			// A schema4 receipt supplies NO direct resume authority. A completed
			// attempt may prove all post-images without effects. A plan-only cut
			// needs a fresh independently rederived prepared proof before bind
			// may publish the missing schema5 fence and permit installation.
			verifyOnly = true
		} else if !errors.Is(err, os.ErrNotExist) {
			return ErrMismatch
		}
	}
	expected := receiptSHA(current)
	check := func(c context.Context) error {
		if c != ctx {
			return ErrMismatch
		}
		actual, err := s.journal.Stat(".writer.lock")
		fresh, has, readErr := s.Current()
		if err != nil || !os.SameFile(writer, actual) || readErr != nil || !has || receiptSHA(fresh) != expected || s.pairedCurrentReady(id) != nil || s.verifyImages(fresh) != nil {
			return ErrMismatch
		}
		if bound || verifyOnly {
			data, err := s.journal.ReadLimited(planName, MaximumOfflinePlanBytes)
			if err != nil || !bytes.Equal(data, plan) {
				return ErrMismatch
			}
		}
		return checks(c, authority, quiescence)
	}
	if err := check(ctx); err != nil {
		return err
	}
	if err := s.verifyPairedEvidence(ctx, original); err != nil {
		return err
	}
	publish := func(receipt Receipt, effect string, ready Check) error {
		data, err := json.Marshal(receipt)
		if err != nil || !valid(receipt) {
			return ErrMismatch
		}
		_, err = s.journal.WriteAtomicWithRenameAdmission(id+"/receipt.json", data, 0600, func(rename func() error) error { return admission(ctx, effect, rename) }, func() error {
			if err := check(ctx); err != nil {
				return err
			}
			if ready != nil {
				return ready(ctx)
			}
			return nil
		})
		if err != nil {
			return err
		}
		expected = receiptSHA(receipt)
		return syncDirectory(s.journalFiles, id)
	}
	bind := func(data []byte, ready Check) error {
		if bound || len(data) == 0 || len(data) > MaximumOfflinePlanBytes || verifyOnly && (ready == nil || !bytes.Equal(data, plan)) {
			return ErrMismatch
		}
		if err := check(ctx); err != nil {
			return err
		}
		if !verifyOnly {
			if _, err := s.journal.Stat(planName); !errors.Is(err, os.ErrNotExist) {
				return ErrMismatch
			}
			if _, err := s.journal.WriteAtomicWithRenameAdmission(planName, data, 0600, func(rename func() error) error { return admission(ctx, "paired-offline-plan", rename) }, func() error { return check(ctx) }); err != nil {
				return err
			}
			if err := syncDirectory(s.journalFiles, id); err != nil {
				return err
			}
		}
		next := original
		next.Schema, next.Phase = OfflineRetrySchema, "offline-restoring"
		next.Offline = &OfflineRetryBinding{offlinePlanSHA(data), receiptSHA(original), original.Phase}
		if err := publish(next, "paired-offline-pending", ready); err != nil {
			return err
		}
		plan, bound, verifyOnly = bytes.Clone(data), true, false
		return check(ctx)
	}
	// The DTO passed to the callback is a copy; its slices cannot rewrite the
	// exact original receipt retained for final publication.
	encoded, _ := json.Marshal(original)
	var callbackReceipt Receipt
	if decode(encoded, &callbackReceipt) != nil {
		return ErrMismatch
	}
	if err := restore(ctx, callbackReceipt, bytes.Clone(plan), verifyOnly, check, bind); err != nil {
		return err
	}
	if verifyOnly {
		return check(ctx)
	}
	if !bound {
		return ErrMismatch
	}
	if err := check(ctx); err != nil {
		return err
	}
	if err := s.verifyPairedEvidence(ctx, original); err != nil {
		return err
	}
	if err := publish(original, "paired-offline-complete", nil); err != nil {
		return err
	}
	return check(ctx)
}
