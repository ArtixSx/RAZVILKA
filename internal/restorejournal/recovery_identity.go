package restorejournal

import (
	"context"
	"encoding/json"
)

// RecoveryIdentity observes the actual canonical protocol document under this
// original journal lease. It exposes no images, paths or replay authority.
// Callers retaining this same private Journal can compare the identity before
// Recover; a separately opened later journal must compare again under its lease.
func (j *Journal) RecoveryIdentity(ctx context.Context) (identity string, pending bool, err error) {
	if j == nil || ctx == nil || ctx.Err() != nil {
		return "", false, ErrUnavailable
	}
	if !j.mu.TryLock() {
		return "", false, ErrBusy
	}
	defer j.mu.Unlock()
	if j.closed {
		return "", false, ErrUnavailable
	}
	doc, err := j.load()
	if err != nil {
		return "", false, err
	}
	if ctx.Err() != nil {
		return "", false, ctx.Err()
	}
	canonical, err := json.Marshal(doc)
	if err != nil {
		return "", false, ErrInvalid
	}
	return sum(canonical), doc.State != "idle", nil
}
