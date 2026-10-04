package selfupdatejournal

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sync/atomic"
)

type writerObservationKey struct{}
type writerObservation struct {
	directory string
	info      os.FileInfo
	active    atomic.Bool
}

// StoppedBinding comes only from the immutable reviewed authority. It records
// the exact preserved Stop epoch, not a claim that any runtime started.
type StoppedBinding struct {
	InstallationID  string `json:"installation_id"`
	PreStopSequence uint64 `json:"pre_stop_sequence"`
	StopSequence    uint64 `json:"stop_sequence"`
	Revision        uint64 `json:"revision"`
	RequiredReader  int    `json:"required_reader"`
}

func validStoppedBinding(b StoppedBinding) bool {
	return idPattern.MatchString(b.InstallationID) && b.PreStopSequence > 0 && b.PreStopSequence < math.MaxUint64 && b.StopSequence == b.PreStopSequence+1 && b.Revision > 0 && b.RequiredReader == StoppedSchema
}

// SettleStoppedRollback is a data-only terminal transition under the existing
// writer lease. All checks are trusted callbacks: preserved matching Stop,
// sealed reader admission, and actual process/private-state inactivity. It
// never runs a command or invokes live acceptance. A cut after receipt write
// is retried with fresh checks and exact bindings, without replaying effects.
func (s *Store) SettleStoppedRollback(ctx context.Context, id string, binding StoppedBinding, authority, readers, inactive Check) error {
	var writerInfo os.FileInfo
	unlock, err := lockWriter(s.journal, func(info os.FileInfo) { writerInfo = info })
	if err != nil {
		return err
	}
	defer unlock()
	// Windows byte locks prohibit a second descriptor reading the marker.
	// This context carries only the same already validated kernel lease;
	// callers cannot manufacture it, and all receipts/images are read afresh.
	observation := &writerObservation{directory: s.journalFiles.Name(), info: writerInfo}
	observation.active.Store(true)
	defer observation.active.Store(false)
	ctx = context.WithValue(ctx, writerObservationKey{}, observation)
	r, err := s.matching(id)
	if err != nil {
		return err
	}
	if r.Phase == "command-started" {
		return ErrUnknown
	}
	if !validStoppedBinding(binding) || authority == nil || readers == nil || inactive == nil || len(r.Files) != 6 || !r.Rollback || r.Index != len(r.Files) {
		return ErrPending
	}
	terminal := r.Phase == "rolled-back-stopped"
	if terminal {
		if r.Stopped == nil || *r.Stopped != binding {
			return ErrMismatch
		}
	} else if r.Schema != Schema || (r.Phase != "restored" && r.Phase != "command-finished") {
		return ErrPending
	}
	check := func() error {
		if err := checks(ctx, authority, readers); err != nil {
			return fmt.Errorf("stopped authority/readers: %w", err)
		}
		if err := inactive(ctx); err != nil {
			return fmt.Errorf("stopped inactivity: %w", err)
		}
		if err := s.VerifyInstallation(ctx, id, true); err != nil {
			return fmt.Errorf("stopped restored files: %w", err)
		}
		return authority(ctx)
	}
	if err := check(); err != nil {
		return err
	}
	if !terminal {
		r.Schema, r.Phase, r.Command, r.BeforeFiles = StoppedSchema, "rolled-back-stopped", "", false
		r.Stopped = &binding
		if err := s.writeReceipt(r); err != nil {
			return err
		}
	}
	if err := check(); err != nil {
		return err
	}
	data, _ := json.Marshal(struct {
		Schema int    `json:"schema"`
		ID     string `json:"id"`
	}{StoppedSchema, id})
	if err := s.boundary("before:stopped-current"); err != nil {
		return err
	}
	if err := s.journal.WriteAtomic("current.json", data, 0600); err != nil {
		return err
	}
	if err := syncDirectory(s.journalFiles, "."); err != nil {
		return err
	}
	if err := s.boundary("after:stopped-current"); err != nil {
		return err
	}
	return check()
}
