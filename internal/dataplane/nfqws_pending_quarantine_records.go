package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
)

// All three files are handed over by this actual writer, never opened by
// pathname to manufacture a completion witness. Publication uncertainty is
// sticky here; COMMON's separately retained retryable intent is unrelated.
func (q *NFQWSPendingQuarantine) publishExecution(data []byte) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.self != q || q.closed || q.records == nil {
		return ErrExecutionJournal
	}
	if err := q.records.beforePublication(); err != nil {
		q.revokeLocked(err)
		return err
	}
	var err error
	for i := range 2 {
		err = errors.Join(err, q.records.publishOriginalDurable(i, data, syncDataplaneJournalDirectory))
	}
	if err != nil {
		q.revokeLocked(err)
	}
	return err
}

func (q *NFQWSPendingQuarantine) publishPlan(plan Plan) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.self != q || q.closed || q.records == nil || plan.PlanID != q.plan.PlanID || plan.Digest != q.plan.Digest || plan.Revision != q.plan.Revision || plan.State == "committed" || !nfqws2ActiveSamePlan(q.plan, plan) {
		q.revokeLocked(ErrExecutionJournal)
		return ErrExecutionJournal
	}
	if err := q.planCurrentLocked(false); err != nil {
		q.revokeLocked(err)
		return err
	}
	if err := q.records.beforePublication(); err != nil {
		q.revokeLocked(err)
		return err
	}
	data, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		q.revokeLocked(err)
		return err
	}
	file, err := q.records.root.WriteAtomicRetained("latest-plan.json", data, 0600)
	if err != nil {
		q.revokeLocked(err)
		return err
	}
	// Own the actual new FD before any stat, Sync or old-FD close can fail.
	old := q.planFile
	q.planFile, q.planRaw, q.planInfo = file, bytes.Clone(data), nil
	q.planInfo, err = file.Stat()
	err = errors.Join(err, syncDataplaneJournalDirectory(q.records.root))
	if old != nil {
		err = errors.Join(err, old.Close())
	}
	err = errors.Join(err, q.planCurrentLocked(true))
	if err != nil {
		q.revokeLocked(err)
	}
	return err
}

func (q *NFQWSPendingQuarantine) planCurrentLocked(required bool) error {
	if q.records == nil || q.records.root == nil {
		return ErrExecutionJournal
	}
	if q.planFile == nil && q.planInfo == nil && len(q.planRaw) == 0 && !required {
		return nil // Before this writer's first actual publication only.
	}
	if q.planFile == nil || q.planInfo == nil || len(q.planRaw) == 0 || len(q.planRaw) > 16<<20 {
		return ErrExecutionJournal
	}
	before, err := q.planFile.Stat()
	named, namedErr := q.records.root.Stat("latest-plan.json")
	if err != nil || namedErr != nil || !validNetworkPolicyReceiptFile(before) || !os.SameFile(before, q.planInfo) || !os.SameFile(before, named) || before.Size() != int64(len(q.planRaw)) || before.Mode() != q.planInfo.Mode() || !before.ModTime().Equal(q.planInfo.ModTime()) {
		return ErrExecutionJournal
	}
	data := make([]byte, len(q.planRaw))
	defer clear(data)
	n, readErr := q.planFile.ReadAt(data, 0)
	after, afterErr := q.planFile.Stat()
	namedAfter, pathErr := q.records.root.Stat("latest-plan.json")
	if readErr != nil || n != len(data) || !bytes.Equal(data, q.planRaw) || afterErr != nil || pathErr != nil || !os.SameFile(before, after) || !os.SameFile(before, namedAfter) || before.Size() != after.Size() || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) {
		return ErrExecutionJournal
	}
	return nil
}

func (q *NFQWSPendingQuarantine) recordsCurrentLocked(ctx context.Context) error {
	return errors.Join(q.records.current(ctx, true), q.planCurrentLocked(true), q.records.current(ctx, true), ctx.Err())
}

func (q *NFQWSPendingQuarantine) closeLocked() error {
	if q.closed {
		return q.closeErr
	}
	q.closed = true
	if q.planFile != nil {
		q.closeErr = errors.Join(q.closeErr, q.planFile.Close())
	}
	q.closeErr = errors.Join(q.closeErr, q.records.close())
	return q.closeErr
}

func (q *NFQWSPendingQuarantine) scopeClosing() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.claimed {
		return nil // SAME App keeps all authored FDs through final source close.
	}
	return q.closeLocked()
}
