package restorejournal

import "context"

// RequireIdle observes the original journal while its lifetime lease remains
// held. It never opens a target or replays/finalizes a transaction. A caller
// with another pending protocol must not let ordinary Recover change that
// protocol's retained before images before checking them.
func (j *Journal) RequireIdle(ctx context.Context) error {
	if j == nil {
		return ErrUnavailable
	}
	if ctx == nil || ctx.Err() != nil {
		return ErrAborted
	}
	if !j.mu.TryLock() {
		return ErrBusy
	}
	defer j.mu.Unlock()
	if j.closed || j.root == nil || j.release == nil {
		return ErrUnavailable
	}
	doc, err := j.load()
	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ErrAborted
	}
	if doc.State != "idle" {
		return ErrRecovery
	}
	return nil
}
