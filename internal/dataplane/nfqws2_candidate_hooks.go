package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

const nfqws2CandidateHooksJournal = "candidate-hooks.json"

// This journal records forward write intent before each command. It is evidence
// within the already-running Manager transaction, never standalone repair or
// cleanup authority. Interrupted attempts remain subject to canonical rollback.
type nfqws2CandidateHookEffect struct {
	Command NFQWS2HookCommand `json:"command"`
	State   string            `json:"state"`
}
type nfqws2CandidateHookRecord struct {
	Version  int                         `json:"version"`
	PlanID   string                      `json:"plan_id"`
	Digest   string                      `json:"digest"`
	Instance string                      `json:"instance"`
	State    string                      `json:"state"`
	Effects  []nfqws2CandidateHookEffect `json:"effects"`
}
type nfqws2CandidateHookJournal struct {
	root   *ownedfs.Root
	path   string
	image  []byte
	record nfqws2CandidateHookRecord
}

func newNFQWS2CandidateHookJournal(root string, plan Plan, instance string) (*nfqws2CandidateHookJournal, error) {
	r, err := ownedfs.Open(root)
	if err != nil {
		return nil, err
	}
	j := &nfqws2CandidateHookJournal{root: r, path: root, record: nfqws2CandidateHookRecord{Version: 1, PlanID: plan.PlanID, Digest: plan.Digest, Instance: instance, State: "pending"}}
	if _, err = r.Stat(nfqws2CandidateHooksJournal); !errors.Is(err, os.ErrNotExist) {
		r.Close()
		return nil, ErrReviewChanged
	}
	if err = j.save(); err != nil {
		r.Close()
		return nil, err
	}
	return j, nil
}
func (j *nfqws2CandidateHookJournal) current() error {
	first, err := j.root.RootInfo()
	if err != nil {
		return err
	}
	r, err := ownedfs.Open(j.path)
	if err != nil {
		return err
	}
	defer r.Close()
	second, err := r.RootInfo()
	if err != nil || !os.SameFile(first, second) {
		return errors.Join(ErrReviewChanged, err)
	}
	raw, err := j.root.ReadLimited(nfqws2CandidateHooksJournal, 1<<20)
	if err != nil || !bytes.Equal(raw, j.image) {
		return errors.Join(ErrReviewChanged, err)
	}
	return nil
}
func (j *nfqws2CandidateHookJournal) save() error {
	return j.saveWithSync(func() error { return syncDataplaneJournalDirectory(j.root) })
}

func (j *nfqws2CandidateHookJournal) saveWithSync(syncDirectory func() error) error {
	raw, err := json.Marshal(j.record)
	if err != nil {
		return err
	}
	if len(raw) > 1<<20 {
		return ErrReviewChanged
	}
	if err = j.root.WriteAtomic(nfqws2CandidateHooksJournal, raw, 0600); err != nil {
		return err
	}
	if err = syncDirectory(); err != nil {
		return err
	}
	j.image = raw
	return nil
}
func (j *nfqws2CandidateHookJournal) effect(command NFQWS2HookCommand, state string) error {
	if err := j.current(); err != nil {
		return err
	}
	if state == "pending" {
		if len(j.record.Effects) > 0 && j.record.Effects[len(j.record.Effects)-1].State != "acknowledged" {
			return ErrReviewChanged
		}
		command.Args = append([]string(nil), command.Args...)
		j.record.Effects = append(j.record.Effects, nfqws2CandidateHookEffect{Command: command, State: state})
	} else {
		n := len(j.record.Effects)
		if n == 0 || (state != "acknowledged" && state != "unknown") || j.record.Effects[n-1].State != "pending" || !reflect.DeepEqual(j.record.Effects[n-1].Command, command) {
			return ErrReviewChanged
		}
		j.record.Effects[n-1].State = state
	}
	return j.save()
}
func (j *nfqws2CandidateHookJournal) finish(state string) error {
	if err := j.current(); err != nil {
		return err
	}
	if state == "settled" {
		for _, effect := range j.record.Effects {
			if effect.State != "acknowledged" {
				return ErrReviewChanged
			}
		}
	}
	j.record.State = state
	return j.save()
}

// Manager calls this only between candidate Activate and unchanged Health,
// while holding its original operation admission. No public committed-plan API
// is reused: that API would bind the previous plan and re-enter the Manager gate.
func (a *NFQWS2Adapter) settleCandidateHooks(ctx context.Context, plan Plan, root string, review func(context.Context) error) error {
	if ctx == nil || review == nil || plan.LAN != nil || !plan.Ready || plan.SafeMode || plan.Noop || !validPlanID(plan.PlanID) || !validPlanDigest(plan.Digest) || a.activeOwner() {
		return ErrReviewChanged
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if err := review(ctx); err != nil {
		return err
	}
	unlock, err := a.lockResources()
	if err != nil {
		return err
	}
	defer unlock()
	lease, err := a.readLease()
	if err != nil {
		return err
	}
	// Legacy expert stock rules retain their original Health-only contract.
	if lease == nil || lease.FirstStart == nil {
		return nil
	}
	expected, ok := a.firstStartTransaction(plan)
	if !ok || root != expected || !filepath.IsAbs(root) || filepath.Clean(root) != root || lease.Transaction != root {
		return ErrReviewChanged
	}
	t := &nfqws2HookAttempt{a: a, plan: plan, lease: lease, review: review, attempted: map[int][]BackendInventoryRow{}}
	reason, err := t.admit(ctx)
	if err != nil {
		return t.fail(reason, err)
	}
	if t.result.Class == NFQWS2HooksFull {
		return review(ctx)
	}
	// admit refuses partial/foreign graphs. Only complete LOSS reaches here.
	if t.result.Class != NFQWS2HooksLoss {
		return ErrReviewChanged
	}
	j, err := newNFQWS2CandidateHookJournal(root, plan, t.result.Instance)
	if err != nil {
		return err
	}
	defer j.root.Close()
	originalReview := t.review
	t.review = func(c context.Context) error { return errors.Join(originalReview(c), j.current()) }
	t.effect = j.effect
	// Validate retained this exact native review for this candidate. Borrow it
	// without re-entering its component lock or releasing its original owner.
	if a.firstStartReview != nil {
		if a.firstStartReviewRoot != root {
			return ErrReviewChanged
		}
		t.native, t.borrowedNative = a.firstStartReview, true
	}
	reason, err = t.prepare(ctx)
	if err == nil {
		reason, err = t.write(ctx)
	}
	if t.native != nil && !t.borrowedNative {
		err = errors.Join(err, t.native.Close())
	}
	if err == nil {
		return j.finish("settled")
	}
	cleanupErr := error(nil)
	if len(t.order) > 0 {
		cleanupErr = t.rollback(ctx)
	}
	state := "reverted"
	if cleanupErr != nil || t.result.Uncertain {
		state = "uncertain"
	}
	journalErr := j.finish(state)
	return errors.Join(t.fail(reason, err), cleanupErr, journalErr)
}
