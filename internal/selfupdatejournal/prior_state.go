package selfupdatejournal

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"slices"
)

// WithPreparedPriorState holds the existing writer lease while the trusted
// update owner copies its still-installed prior state. It neither publishes a
// receipt nor grants rollback/retirement authority. The original finite context
// and both owner checks survive the entire callback. inspect must not reenter a
// writer method or perform application/network effects.
func (s *Store) WithPreparedPriorState(ctx context.Context, id string, authority, quiescence Check, inspect func(context.Context, Receipt) error) error {
	if s == nil || ctx == nil || authority == nil || quiescence == nil || inspect == nil || !idPattern.MatchString(id) {
		return ErrMismatch
	}
	if _, finite := ctx.Deadline(); !finite {
		return ErrMismatch
	}
	if err := checks(ctx, authority, quiescence); err != nil {
		return err
	}
	// Prepare already created this permanent marker. A read/copy operation must
	// not initialize a journal or manufacture a new source writer identity.
	var writer os.FileInfo
	unlock, err := lockExistingWriter(s.journal, func(info os.FileInfo) { writer = info })
	if err != nil {
		return err
	}
	defer unlock()
	heldAuthority := func(c context.Context) error {
		current, err := s.journal.Stat(".writer.lock")
		if err != nil || !os.SameFile(writer, current) {
			return ErrMismatch
		}
		return authority(c)
	}
	r, err := s.preparedPriorState(ctx, id, heldAuthority, quiescence)
	if err != nil {
		return err
	}
	before, _ := json.Marshal(r)
	copy := r
	copy.Files = slices.Clone(r.Files)
	copy.Commands = slices.Clone(r.Commands)
	if err := inspect(ctx, copy); err != nil {
		return err
	}
	fresh, err := s.preparedPriorState(ctx, id, heldAuthority, quiescence)
	if err != nil {
		return err
	}
	after, _ := json.Marshal(fresh)
	if !bytes.Equal(before, after) {
		return ErrMismatch
	}
	return ctx.Err()
}

func (s *Store) preparedPriorState(ctx context.Context, id string, authority, quiescence Check) (Receipt, error) {
	r, err := s.matching(id)
	if err != nil {
		return r, err
	}
	if r.Schema != Schema || r.Phase != "prepared" || r.Rollback || r.BeforeFiles || r.Index != 0 || r.Command != "" || len(r.Files) != 6 || !slices.Equal(r.Commands, []string{"stop-old-panel", "prepare-private-state", "quiesce-old-runtime"}) {
		return r, ErrMismatch
	}
	if err := s.verifyImages(r); err != nil {
		return r, err
	}
	for _, file := range r.Files {
		hash, present, err := hashFile(s.installation, file.Target)
		if err != nil || present != file.OldPresent || present && hash != file.OldHash {
			return r, ErrMismatch
		}
		if present {
			info, err := s.installation.Stat(file.Target)
			if err != nil || uint32(info.Mode().Perm()) != file.OldMode {
				return r, ErrMismatch
			}
		}
	}
	for _, root := range []*os.Root{s.files, s.journalFiles} {
		held, err := root.Stat(".")
		current, currentErr := os.Lstat(root.Name())
		if err != nil || currentErr != nil || !current.IsDir() || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(held, current) {
			return r, ErrMismatch
		}
	}
	return r, checks(ctx, authority, quiescence)
}
