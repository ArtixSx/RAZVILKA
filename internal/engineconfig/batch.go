package engineconfig

import (
	"context"
	"errors"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

var ErrStageFailed = errors.New("engine draft import failed; original draft files preserved")

// wrap is a package-private fault-injection seam around the REAL CAS targets.
// No alternate production file writer or rollback implementation is used.
func (m *Manager) stageBatch(items []StageItem, validate func(string, string, string) Validation, wrap func(string, restorejournal.Target) restorejournal.Target) ([]Content, func() error, error) {
	if len(items) == 0 {
		return []Content{}, func() error { return nil }, nil
	}
	refs := make([]DraftRef, 0, len(items))
	seen := map[string]bool{}
	after := map[string]restorejournal.Image{}
	for _, item := range items {
		ref := DraftRef{item.EngineID, item.FileID}
		if _, _, err := lookup(ref.EngineID, ref.FileID); err != nil {
			return nil, nil, restorejournal.ErrInvalid
		}
		id := draftID(ref)
		if seen[id] || !validate(ref.EngineID, ref.FileID, item.Content).OK {
			return nil, nil, restorejournal.ErrInvalid
		}
		seen[id] = true
		refs = append(refs, ref)
		after[id] = restorejournal.Image{Exists: true, Data: []byte(item.Content)}
	}
	ctx := context.Background()
	s, err := m.BeginRestore(ctx, refs)
	if err != nil {
		return nil, nil, err
	}
	defer s.Close()
	targets := s.Targets()
	if wrap != nil {
		for id, target := range targets {
			targets[id] = wrap(id, target)
		}
	}
	before := map[string]restorejournal.Image{}
	planBytes := 0
	for _, id := range s.order {
		image, err := targets[id].Read(ctx)
		if err != nil {
			return nil, nil, err
		}
		before[id] = image
		planBytes += len(image.Data) + len(after[id].Data)
		if planBytes > restorejournal.MaxPlanBytes {
			return nil, nil, restorejournal.ErrInvalid
		}
	}
	for _, id := range s.order {
		if err := targets[id].CompareAndSwap(ctx, before[id], after[id]); err != nil {
			// Include the failed target: rename may already have committed.
			if rollbackDraftImages(targets, s.order, before, after) != nil {
				return nil, nil, ErrStageRollback
			}
			return nil, nil, ErrStageFailed
		}
	}
	out := make([]Content, 0, len(items))
	for _, item := range items {
		_, file, _ := lookup(item.EngineID, item.FileID)
		value := Content{EngineID: item.EngineID, FileID: item.FileID, Path: choosePath(file.Paths), Source: "staged", Sensitive: file.Sensitive, SHA256: sum([]byte(item.Content))}
		if !file.Sensitive {
			value.Content = item.Content
		}
		out = append(out, value)
	}
	// Reacquire ALL selected leases for a later guarded undo. Check the entire
	// set before any write; unrelated drafts remain outside this transaction.
	binding := s.Binding()
	used := false
	undo := func() error {
		current, err := m.BeginRestore(ctx, refs)
		if err != nil {
			return ErrStageRollback
		}
		defer current.Close()
		if current.Binding() != binding {
			return ErrStageRollback
		}
		if used {
			return nil
		}
		if err := rollbackDraftImages(current.Targets(), current.order, before, after); err != nil {
			return ErrStageRollback
		}
		used = true
		return nil
	}
	return out, undo, nil
}

func rollbackDraftImages(targets map[string]restorejournal.Target, order []string, before, after map[string]restorejournal.Image) error {
	ctx := context.Background()
	for _, id := range order {
		current, err := targets[id].Read(ctx)
		if err != nil || !sameImage(current, before[id]) && !sameImage(current, after[id]) {
			return ErrStageRollback
		}
	}
	var result error
	for i := len(order) - 1; i >= 0; i-- {
		id := order[i]
		current, err := targets[id].Read(ctx)
		if err != nil {
			result = ErrStageRollback
			continue
		}
		if sameImage(current, before[id]) {
			continue
		}
		if !sameImage(current, after[id]) {
			result = ErrStageRollback
			continue
		}
		if err := targets[id].CompareAndSwap(ctx, after[id], before[id]); err != nil {
			// A rollback write may also fail AFTER committing. Trust observed bytes,
			// not the error alone, but never blindly overwrite an unknown third state.
			actual, readErr := targets[id].Read(ctx)
			if readErr != nil || !sameImage(actual, before[id]) {
				result = ErrStageRollback
			}
		}
	}
	for _, id := range order {
		actual, err := targets[id].Read(ctx)
		if err != nil || !sameImage(actual, before[id]) {
			result = ErrStageRollback
		}
	}
	return result
}
