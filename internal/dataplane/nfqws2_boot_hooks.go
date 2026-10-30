package dataplane

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

const nfqws2BootHookJournal = "nfqws2-boot-hooks.json"

// One manager-owned boot repair, separate from application/candidate journals.
// An interrupted effect is never replayed, including when the kernel now looks
// complete. Only an acknowledged repair or an explicitly verified stopped
// image may be superseded.
func readNFQWS2BootHookJournal(root *ownedfs.Root) ([]byte, *nfqws2CandidateHookRecord, error) {
	raw, r, err := readNFQWS2BootHookEvidence(root)
	if err == nil && r != nil && r.State != "settled" && r.State != "stopped" {
		err = ErrExecutionJournal
	}
	return raw, r, err
}

// Pending evidence is readable only for the explicit Stop review. Reading it
// never authorizes replay of an uncertain command.
func readNFQWS2BootHookEvidence(root *ownedfs.Root) ([]byte, *nfqws2CandidateHookRecord, error) {
	raw, err := root.ReadLimited(nfqws2BootHookJournal, 1<<20)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var r nfqws2CandidateHookRecord
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF || r.Version != 1 || !validPlanID(r.PlanID) || !validPlanDigest(r.Digest) || !validNFQWS2BootHookInstance(r.Instance) {
		return nil, nil, ErrExecutionJournal
	}
	if r.State != "pending" && r.State != "uncertain" && r.State != "settled" && r.State != "stopped" || r.State == "settled" && len(r.Effects) == 0 {
		return nil, nil, ErrExecutionJournal
	}
	canonical, _ := json.Marshal(r)
	if !bytes.Equal(raw, canonical) {
		return nil, nil, ErrExecutionJournal
	}
	for i, e := range r.Effects {
		if !validNFQWS2BootHookCommand(e.Command) || e.State != "acknowledged" && (r.State == "settled" || i != len(r.Effects)-1 || e.State != "pending" && e.State != "unknown") {
			return nil, nil, ErrExecutionJournal
		}
	}
	return raw, &r, nil
}

func validNFQWS2BootHookInstance(s string) bool {
	raw, err := hex.DecodeString(s)
	return err == nil && len(raw) == 12 && strings.ToLower(s) == s
}

// A terminal acknowledgement must still belong to the closed writer vocabulary,
// never an arbitrary shell/xtables command disguised as completed history.
func validNFQWS2BootHookCommand(c NFQWS2HookCommand) bool {
	a := c.Args
	if (c.Family != 4 && c.Family != 6) || len(a) < 4 || a[0] != "-t" {
		return false
	}
	if a[1] == "nat" {
		return c.Family == 4 && (slices.Equal(a, []string{"-t", "nat", "-N", nfqws2HookNATChain}) || slices.Equal(a, []string{"-t", "nat", "-A", "POSTROUTING", "-j", nfqws2HookNATChain}))
	}
	if a[1] != "mangle" {
		return false
	}
	for _, chain := range []string{nfqws2HookPostChain, nfqws2HookPreChain} {
		if slices.Equal(a, []string{"-t", "mangle", "-N", chain}) {
			return true
		}
	}
	for _, r := range [][]string{{"POSTROUTING", nfqws2HookPostChain}, {"PREROUTING", nfqws2HookPreChain}} {
		if slices.Equal(a, []string{"-t", "mangle", "-A", r[0], "-j", r[1]}) {
			return true
		}
	}
	if a[2] != "-A" || (a[3] != nfqws2HookPostChain && a[3] != nfqws2HookPreChain) {
		return false
	}
	iface := ""
	queue := 300
	for i := 4; i+1 < len(a); i++ {
		if a[i] == "-i" || a[i] == "-o" {
			iface = a[i+1]
		}
		if a[i] == "--queue-num" {
			var err error
			queue, err = strconv.Atoi(a[i+1])
			if err != nil || queue < 1 || queue > 65535 {
				return false
			}
		}
	}
	if !nfqws2HealthInterface.MatchString(iface) {
		return false
	}
	scope := nfqws2StockHookScope{interfaces: []string{iface}, queue: queue, tcp: "443"}
	rules := scope.postRules()
	if a[3] == nfqws2HookPreChain {
		rules = scope.preRules()
	}
	for _, rule := range rules {
		if slices.Equal(a[4:], strings.Fields(rule)) {
			return true
		}
	}
	return false
}

// CheckNFQWS2BootHookRecovery only reads the manager-owned boot WAL. Startup
// must call it before choosing a read-only preserved recovery record as well.
func (m *Manager) CheckNFQWS2BootHookRecovery() error {
	return executionJournalError(m.checkNFQWS2BootHookJournal())
}

func (m *Manager) checkNFQWS2BootHookJournal() error {
	r, err := ownedfs.Open(m.StateRoot)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer r.Close()
	_, _, err = readNFQWS2BootHookJournal(r)
	return err
}

type nfqws2BootHookWAL struct {
	root   *ownedfs.Root
	path   string
	image  []byte
	record nfqws2CandidateHookRecord
}

func (j *nfqws2BootHookWAL) current() error {
	before, err := j.root.RootInfo()
	if err != nil {
		return err
	}
	reopened, err := ownedfs.Open(j.path)
	if err != nil {
		return err
	}
	defer reopened.Close()
	after, err := reopened.RootInfo()
	if err != nil || !os.SameFile(before, after) {
		return errors.Join(ErrReviewChanged, err)
	}
	raw, err := j.root.ReadLimited(nfqws2BootHookJournal, 1<<20)
	if err != nil || !bytes.Equal(raw, j.image) {
		return errors.Join(ErrReviewChanged, err)
	}
	return nil
}
func (j *nfqws2BootHookWAL) save() error {
	return j.saveWithSync(func() error { return syncDataplaneJournalDirectory(j.root) })
}

func (j *nfqws2BootHookWAL) saveWithSync(syncDirectory func() error) error {
	raw, err := json.Marshal(j.record)
	if err != nil {
		return err
	}
	if len(raw) > 1<<20 {
		return ErrExecutionJournal
	}
	if err = j.root.WriteAtomic(nfqws2BootHookJournal, raw, 0600); err != nil {
		return err
	}
	// File fsync precedes rename inside WriteAtomic. The directory entry must
	// also be durable before the caller may execute a recorded firewall effect.
	if err = syncDirectory(); err != nil {
		return err
	}
	j.image = raw
	return nil
}
func (j *nfqws2BootHookWAL) effect(c NFQWS2HookCommand, state string) error {
	if err := j.current(); err != nil {
		return err
	}
	n := len(j.record.Effects)
	if state == "pending" {
		if n > 0 && j.record.Effects[n-1].State != "acknowledged" {
			return ErrExecutionJournal
		}
		c.Args = append([]string(nil), c.Args...)
		j.record.Effects = append(j.record.Effects, nfqws2CandidateHookEffect{Command: c, State: state})
	} else {
		if n == 0 || (state != "acknowledged" && state != "unknown") || j.record.Effects[n-1].State != "pending" || !reflect.DeepEqual(j.record.Effects[n-1].Command, c) {
			return ErrExecutionJournal
		}
		j.record.Effects[n-1].State = state
	}
	return j.save()
}

// Reconcile already owns both the manager operation and NFQ resources. Never
// re-enter the public restoration API. FULL has no effects; LOSS needs this
// boot writer before the first command and unchanged committed-intent reviews.
func (a *NFQWS2Adapter) settleBootHooks(ctx context.Context, plan Plan, lease *nfqws2Lease) error {
	if err := CheckCommittedRecoveryReview(ctx, plan); err != nil {
		return err
	}
	bound, _ := ctx.Value(committedRecoveryReviewKey{}).(*committedRecoveryReview)
	if bound == nil || bound.manager == nil || bound.manager.StateRoot != filepath.Dir(filepath.Dir(a.StateRoot)) {
		return ErrReviewChanged
	}
	registered, ok := bound.manager.adapter(a.ID())
	if !ok || registered != a {
		return ErrReviewChanged
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	review := func(c context.Context) error { return CheckCommittedRecoveryReview(c, plan) }
	t := &nfqws2HookAttempt{a: a, plan: plan, lease: lease, review: review, attempted: map[int][]BackendInventoryRow{}}
	reason, err := t.admit(ctx)
	if err != nil {
		return t.fail(reason, err)
	}
	if t.result.Class == NFQWS2HooksFull {
		return review(ctx)
	}
	if t.result.Class != NFQWS2HooksLoss {
		return ErrReviewChanged
	}
	r, err := ownedfs.Open(bound.manager.StateRoot)
	if err != nil {
		return err
	}
	defer r.Close()
	prior, _, err := readNFQWS2BootHookJournal(r)
	if err != nil {
		return errors.Join(ErrExecutionJournal, err)
	}
	// Re-read the old terminal image immediately before publishing this intent.
	if current, readErr := r.ReadLimited(nfqws2BootHookJournal, 1<<20); !(errors.Is(readErr, os.ErrNotExist) && prior == nil) && (readErr != nil || !bytes.Equal(current, prior)) {
		return ErrReviewChanged
	}
	if err = review(ctx); err != nil {
		return err
	}
	j := &nfqws2BootHookWAL{root: r, path: bound.manager.StateRoot, record: nfqws2CandidateHookRecord{Version: 1, PlanID: plan.PlanID, Digest: plan.Digest, Instance: t.result.Instance, State: "pending"}}
	if err = j.save(); err != nil {
		return err
	}
	t.review = func(c context.Context) error { return errors.Join(review(c), j.current()) }
	t.effect = j.effect
	reason, err = t.prepare(ctx)
	if err == nil {
		reason, err = t.write(ctx)
	}
	if err == nil {
		err = t.review(ctx)
	}
	if err != nil {
		var rollbackErr error
		if len(t.order) > 0 {
			rollbackErr = t.rollback(ctx)
		}
		if t.native != nil {
			rollbackErr = errors.Join(rollbackErr, t.native.Close())
		}
		// Preserve any concurrently replaced journal, never overwrite it with
		// an uncertainty report belonging to this older writer.
		if currentErr := j.current(); currentErr != nil {
			return errors.Join(t.fail(reason, err), rollbackErr, currentErr)
		}
		j.record.State = "uncertain"
		return errors.Join(t.fail(reason, err), rollbackErr, j.save())
	}
	if t.native != nil {
		if err = t.native.Close(); err != nil {
			return err
		}
	}
	if err = j.current(); err != nil {
		return err
	}
	for _, e := range j.record.Effects {
		if e.State != "acknowledged" {
			return ErrExecutionJournal
		}
	}
	j.record.State = "settled"
	return j.save()
}
