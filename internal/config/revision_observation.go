package config

import (
	"bytes"
	"context"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// WithRevisionObservation binds a bounded independent receipt to the current
// in-process revision without writing config or borrowing its writer lease.
// External replacement is detected before/after the callback; a changed image
// returns unknown even if the independent receipt was already persisted.
// observe must not call this Store or acquire the application operation gate.
func (s *Store) WithRevisionObservation(ctx context.Context, revision uint64, observe func() error) error {
	if observe == nil {
		return ErrRevisionChanged
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if s.writeUncertain || s.cfg.Revision != revision {
			return ErrRevisionChanged
		}
		image, err := restorejournal.ReadFileImage(ctx, s.path)
		if err != nil {
			return err
		}
		if image.Exists != s.diskImage.Exists || !bytes.Equal(image.Data, s.diskImage.Data) {
			return ErrRevisionChanged
		}
		return nil
	}
	if err := check(); err != nil {
		return err
	}
	if err := observe(); err != nil {
		return err
	}
	return check()
}

// WithAutonomyEnrollmentRevision holds the same file lease as a config writer
// until the first-run wizard has published its separate permission journal.
// publish must write only that journal and must not call this Store.
func (s *Store) WithAutonomyEnrollmentRevision(ctx context.Context, revision uint64, publish func() error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.writeUncertain || s.cfg.Revision != revision || publish == nil {
		return ErrRevisionChanged
	}
	target, err := restorejournal.OpenFileTarget(s.path)
	if err != nil {
		return err
	}
	defer target.Close()
	current, err := target.Read(ctx)
	if err != nil {
		return err
	}
	if current.Exists != s.diskImage.Exists || !bytes.Equal(current.Data, s.diskImage.Data) {
		return ErrRevisionChanged
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return publish()
}
