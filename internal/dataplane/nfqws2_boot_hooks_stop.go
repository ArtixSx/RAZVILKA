package dataplane

import (
	"context"
	"errors"
	"os"
	"reflect"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// ReviewNFQWS2BootHookStop retains the original journal and observation sources
// for the installed offline Stop command. It never repairs or deletes rules.
// An ambiguous present graph is refused before Stop may touch it.
func (m *Manager) ReviewNFQWS2BootHookStop(ctx context.Context, settings string) (func() error, func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	r, err := ownedfs.Open(m.StateRoot)
	if errors.Is(err, os.ErrNotExist) {
		return func() error { return nil }, func() {}, nil
	}
	if err != nil {
		return nil, nil, err
	}
	closeRoot := func() { _ = r.Close() }
	raw, record, err := readNFQWS2BootHookEvidence(r)
	if err != nil {
		closeRoot()
		return nil, nil, errors.Join(ErrExecutionJournal, err)
	}
	if record == nil || record.State == "settled" || record.State == "stopped" {
		closeRoot()
		return func() error { return nil }, func() {}, nil
	}
	plan, exists, err := m.Committed()
	if err != nil || !exists || plan.PlanID != record.PlanID || plan.Digest != record.Digest {
		closeRoot()
		return nil, nil, errors.Join(ErrExecutionJournal, err)
	}
	review, err := m.ReviewRuntimeInactivitySources(ctx, settings)
	if err != nil {
		closeRoot()
		return nil, nil, err
	}
	if err = review.VerifyNFQWS2Inactive(ctx); err != nil && review.VerifyNFQWS2RebootStop(ctx, plan, record.Instance) != nil {
		observed, observeErr := m.ObserveCommittedNFQWS2Hooks(ctx, plan)
		if observeErr != nil || observed.Class != NFQWS2HooksLoss || observed.Instance != record.Instance || len(observed.Families) < 1 || len(observed.Families) > 2 {
			closeRoot()
			return nil, nil, errors.Join(ErrExecutionJournal, observeErr)
		}
		for i, family := range observed.Families {
			if family.Class != NFQWS2HooksLoss || i == 0 && family.Family != 4 || i == 1 && family.Family != 6 {
				closeRoot()
				return nil, nil, ErrExecutionJournal
			}
		}
	}
	j := &nfqws2BootHookWAL{root: r, path: m.StateRoot, image: raw, record: *record}
	if err := j.current(); err != nil {
		closeRoot()
		return nil, nil, err
	}
	return func() error {
		return m.settleNFQWS2BootHookStop(ctx, plan, j, func() error { return review.VerifyNFQWS2Inactive(ctx) })
	}, closeRoot, nil
}

// A Stop may take long enough for its committed intent to be replaced. The
// original plan must still match on both sides of the fresh absence check;
// inactivity alone cannot settle evidence belonging to another plan.
func (m *Manager) settleNFQWS2BootHookStop(ctx context.Context, plan Plan, j *nfqws2BootHookWAL, verify func() error) error {
	current := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if m.StateRoot != j.path {
			return ErrReviewChanged
		}
		actual, exists, err := m.Committed()
		if err != nil || !exists || !reflect.DeepEqual(actual, plan) {
			return errors.Join(ErrReviewChanged, err)
		}
		return ctx.Err()
	}
	return j.settleStopped(func() error {
		if err := current(); err != nil {
			return err
		}
		if err := verify(); err != nil {
			return err
		}
		return current()
	})
}

// The caller retains its exact source review across Stop. A fresh observation
// is required even if admission already found the runtime inactive. Original
// effect states remain evidence; unknown does not become acknowledged.
func (j *nfqws2BootHookWAL) settleStopped(verify func() error) error {
	if err := j.current(); err != nil {
		return err
	}
	if err := verify(); err != nil {
		return err
	}
	if err := j.current(); err != nil {
		return err
	}
	j.record.State = "stopped"
	return j.save()
}
