package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

const nfqws2HookJournalName = "nfqws2-hooks-recovery.json"

var ErrNFQWS2HookRecovery = errors.New("NFQWS2 hook recovery is unfinished: stop the panel; for an owned first-start NFQWS2-only route plan, run the installed CLI -stop-owned-routes with its original config/state paths, then start the panel and use Resume; other scopes and unknown or foreign kernel objects require review")

type nfqws2HookJournal struct {
	Version  int            `json:"version"`
	State    string         `json:"state"`
	Reason   string         `json:"reason"`
	Plan     dataplane.Plan `json:"plan"`
	Instance string         `json:"instance"`
	Started  time.Time      `json:"started"`
	Finished time.Time      `json:"finished,omitempty"`
}

type nfqws2HookJournalContextKey struct{}

type nfqws2HookJournalOwner struct {
	path   string
	root   *ownedfs.Root
	image  []byte
	record nfqws2HookJournal
}

func openNFQWS2HookJournal(root string) (*ownedfs.Root, error) {
	return openNFQWS2HookJournalAt(root, "/opt")
}

// Only the fixed installation alias may resolve through Entware's mount link.
// Every descendant is checked beneath its anchored canonical installation root.
func openNFQWS2HookJournalAt(root, alias string) (*ownedfs.Root, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, ErrNFQWS2HookRecovery
	}
	resolved := root
	rel, err := filepath.Rel(alias, root)
	if err == nil && filepath.IsLocal(rel) && rel != "." {
		canonical, err := filepath.EvalSymlinks(alias)
		if err != nil {
			return nil, err
		}
		base, err := ownedfs.Open(canonical)
		if err != nil {
			return nil, err
		}
		defer base.Close()
		// A shared /opt is not an installation owner before its first
		// application subtree exists. Prove only that absence beneath the
		// held canonical descriptor without following the child symlink.
		// Once the subtree exists, all original owner checks remain required,
		// even when a deeper state directory has not been created.
		first, _, _ := strings.Cut(rel, string(filepath.Separator))
		if _, err := base.LstatChild(first); err != nil {
			if errors.Is(err, os.ErrNotExist) && nfqws2HookAbsentInstallationCurrent(base, alias, canonical, first) != nil {
				return nil, ErrNFQWS2HookRecovery
			}
			return nil, err
		}
		info, err := base.RootInfo()
		if err == nil {
			err = nfqws2HookInstallationOwner(info)
		}
		if err != nil {
			return nil, err
		}
		if err = base.Check(rel); err != nil {
			return nil, err
		}
		resolved = filepath.Join(canonical, rel)
	} else {
		for path := root; ; path = filepath.Dir(path) {
			info, err := os.Lstat(path)
			if err != nil {
				return nil, err
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return nil, ErrNFQWS2HookRecovery
			}
			if filepath.Dir(path) == path {
				break
			}
		}
	}
	r, err := ownedfs.Open(resolved)
	if err != nil {
		return nil, err
	}
	info, err := r.RootInfo()
	if err == nil {
		err = nfqws2HookPrivateOwner(info)
	}
	if err != nil {
		r.Close()
		return nil, err
	}
	return r, nil
}

// An absent child of a detached old mount is not absence at the configured
// installation alias. Changed/missing owners deliberately return a fixed
// refusal: callers interpret any wrapped ErrNotExist as a fresh installation.
func nfqws2HookAbsentInstallationCurrent(base *ownedfs.Root, alias, canonical, first string) error {
	if base == nil {
		return ErrNFQWS2HookRecovery
	}
	held, heldErr := base.RootInfo()
	resolved, resolveErr := filepath.EvalSymlinks(alias)
	current, statErr := os.Lstat(canonical)
	if heldErr != nil || resolveErr != nil || statErr != nil || resolved != canonical || !os.SameFile(held, current) || current.Mode()&os.ModeSymlink != 0 {
		return ErrNFQWS2HookRecovery
	}
	if _, err := base.LstatChild(first); !errors.Is(err, os.ErrNotExist) {
		return ErrNFQWS2HookRecovery
	}
	return nil
}

func readNFQWS2HookJournal(r *ownedfs.Root) (nfqws2HookJournal, []byte, error) {
	var j nfqws2HookJournal
	f, err := openNFQWS2HookFile(r)
	if err != nil {
		return j, nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err == nil && !info.Mode().IsRegular() {
		err = ErrNFQWS2HookRecovery
	}
	if err == nil {
		err = nfqws2HookPrivateOwner(info)
	}
	if err != nil {
		return j, nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return j, nil, err
	}
	if len(data) > 1<<20 {
		return j, nil, ErrNFQWS2HookRecovery
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err = d.Decode(&j); err != nil {
		return j, nil, err
	}
	if j.Version != 1 || (j.State != "pending" && j.State != "settled") || j.Plan.PlanID == "" || j.Plan.Digest == "" || j.Instance == "" || j.Started.IsZero() {
		return j, nil, ErrNFQWS2HookRecovery
	}
	canonical, _ := json.Marshal(j)
	if !bytes.Equal(canonical, data) {
		return j, nil, ErrNFQWS2HookRecovery
	}
	return j, data, nil
}

// CheckNFQWS2HookRecovery performs bounded, descriptor-anchored reads only.
// Missing state is a fresh installation; malformed or pending state fails closed.
func CheckNFQWS2HookRecovery(root string) error {
	r, err := openNFQWS2HookJournal(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.Join(ErrNFQWS2HookRecovery, err)
	}
	defer r.Close()
	j, _, err := readNFQWS2HookJournal(r)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || j.State != "settled" {
		return errors.Join(ErrNFQWS2HookRecovery, err)
	}
	return nil
}
func writeNFQWS2HookJournal(r *ownedfs.Root, j nfqws2HookJournal) ([]byte, error) {
	return writeNFQWS2HookJournalWithSync(r, j, func() error {
		if runtime.GOOS == "windows" {
			return nil
		}
		return r.Sync()
	})
}
func writeNFQWS2HookJournalWithSync(r *ownedfs.Root, j nfqws2HookJournal, syncDirectory func() error) ([]byte, error) {
	data, err := json.Marshal(j)
	if len(data) > 1<<20 {
		return nil, ErrNFQWS2HookRecovery
	}
	if err != nil {
		return nil, err
	}
	if err = r.WriteAtomic(nfqws2HookJournalName, data, 0600); err != nil {
		return nil, err
	}
	if err = syncDirectory(); err != nil {
		return nil, err
	}
	return data, nil
}
func beginNFQWS2HookJournal(root string, plan dataplane.Plan, instance string) (*nfqws2HookJournalOwner, error) {
	if instance == "" {
		return nil, ErrNFQWS2HookRecovery
	}
	r, err := openNFQWS2HookJournal(root)
	if err != nil {
		return nil, err
	}
	j, _, err := readNFQWS2HookJournal(r)
	if !errors.Is(err, os.ErrNotExist) && (err != nil || j.State != "settled") {
		r.Close()
		return nil, errors.Join(ErrNFQWS2HookRecovery, err)
	}
	j = nfqws2HookJournal{Version: 1, State: "pending", Reason: "repair-in-progress", Plan: plan, Instance: instance, Started: time.Now().UTC()}
	data, err := writeNFQWS2HookJournal(r, j)
	if err != nil {
		r.Close()
		return nil, err
	}
	return &nfqws2HookJournalOwner{path: root, root: r, image: data, record: j}, nil
}
func (o *nfqws2HookJournalOwner) current() error {
	before, err := o.root.RootInfo()
	if err != nil {
		return err
	}
	r, err := openNFQWS2HookJournal(o.path)
	if err != nil {
		return err
	}
	defer r.Close()
	after, err := r.RootInfo()
	if err != nil {
		return err
	}
	if !os.SameFile(before, after) {
		return ErrNFQWS2HookRecovery
	}
	_, data, err := readNFQWS2HookJournal(r)
	if err != nil {
		return err
	}
	if !bytes.Equal(data, o.image) {
		return ErrNFQWS2HookRecovery
	}
	return nil
}
func (o *nfqws2HookJournalOwner) settle() error {
	return o.settleAt(time.Now().UTC())
}

func (o *nfqws2HookJournalOwner) settleAt(finished time.Time) error {
	if err := o.current(); err != nil {
		return err
	}
	_, data, err := readNFQWS2HookJournal(o.root)
	if err != nil {
		return err
	}
	if !bytes.Equal(data, o.image) {
		return ErrNFQWS2HookRecovery
	}
	j := o.record
	j.State = "settled"
	j.Reason = "verified-settlement"
	j.Finished = finished
	_, err = writeNFQWS2HookJournal(o.root, j)
	return err
}

// ReviewNFQWS2HookStop is used only by the existing offline CLI. It refuses
// ambiguous graphs before Stop can touch them and retains the exact journal
// owner through fresh inactivity verification after the original Stop.
func ReviewNFQWS2HookStop(ctx context.Context, m *dataplane.Manager, settings string) (func() error, func(), error) {
	bootSettle, bootClose, err := m.ReviewNFQWS2BootHookStop(ctx, settings)
	if err != nil {
		return nil, nil, err
	}
	settle, closeReview, err := reviewNFQWS2AppHookStop(ctx, m, settings)
	if err != nil {
		bootClose()
		return nil, nil, err
	}
	return func() error {
		if err := settle(); err != nil {
			return err
		}
		return bootSettle()
	}, func() { closeReview(); bootClose() }, nil
}

func reviewNFQWS2AppHookStop(ctx context.Context, m *dataplane.Manager, settings string) (func() error, func(), error) {
	return reviewNFQWS2AppHookStopAt(ctx, m, settings, time.Time{})
}

func reviewNFQWS2AppHookStopAt(ctx context.Context, m *dataplane.Manager, settings string, finished time.Time) (func() error, func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	r, err := openNFQWS2HookJournal(m.StateRoot)
	if errors.Is(err, os.ErrNotExist) {
		return func() error { return nil }, func() {}, nil
	}
	if err != nil {
		return nil, nil, err
	}
	closeRoot := func() { _ = r.Close() }
	j, data, err := readNFQWS2HookJournal(r)
	if errors.Is(err, os.ErrNotExist) || err == nil && j.State == "settled" {
		closeRoot()
		return func() error { return nil }, func() {}, nil
	}
	if err != nil {
		closeRoot()
		return nil, nil, errors.Join(ErrNFQWS2HookRecovery, err)
	}
	current, exists, err := m.Committed()
	if err != nil || !exists || !reflect.DeepEqual(current, j.Plan) {
		closeRoot()
		return nil, nil, errors.Join(ErrNFQWS2HookRecovery, err)
	}
	review, err := m.ReviewRuntimeInactivitySources(ctx, settings)
	if err != nil {
		closeRoot()
		return nil, nil, err
	}
	if err = nfqws2HookStopAdmission(j,
		func() error {
			if err := review.VerifyNFQWS2Inactive(ctx); err == nil {
				return nil
			}
			return review.VerifyNFQWS2RebootStop(ctx, j.Plan, j.Instance)
		},
		func() (dataplane.NFQWS2HookRestore, error) { return m.ObserveCommittedNFQWS2Hooks(ctx, j.Plan) }); err != nil {
		closeRoot()
		return nil, nil, err
	}

	o := &nfqws2HookJournalOwner{path: m.StateRoot, root: r, image: data, record: j}
	return nfqws2HookStopSettlementAt(ctx, m, o, func() error { return review.VerifyNFQWS2Inactive(ctx) }, finished), closeRoot, nil
}

func nfqws2HookStopSettlement(ctx context.Context, m *dataplane.Manager, o *nfqws2HookJournalOwner, verify func() error) func() error {
	return nfqws2HookStopSettlementAt(ctx, m, o, verify, time.Time{})
}

func nfqws2HookStopSettlementAt(ctx context.Context, m *dataplane.Manager, o *nfqws2HookJournalOwner, verify func() error, finished time.Time) func() error {
	current := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if m.StateRoot != o.path {
			return dataplane.ErrReviewChanged
		}
		plan, exists, err := m.Committed()
		if err != nil || !exists || !reflect.DeepEqual(plan, o.record.Plan) {
			return errors.Join(dataplane.ErrReviewChanged, err)
		}
		return ctx.Err()
	}
	return func() error {
		// The admitted plan and journal still belong to this Stop. A fresh
		// absence observation cannot grant settlement of a changed intent.
		if err := current(); err != nil {
			return errors.Join(ErrNFQWS2HookRecovery, err)
		}
		if err := o.current(); err != nil {
			return errors.Join(ErrNFQWS2HookRecovery, err)
		}
		if err := verify(); err != nil {
			return fmt.Errorf("%w: inactivity: %v", ErrNFQWS2HookRecovery, err)
		}
		if err := current(); err != nil {
			return errors.Join(ErrNFQWS2HookRecovery, err)
		}
		if finished.IsZero() {
			return o.settle()
		}
		return o.settleAt(finished)
	}
}

// retain improves diagnostics without weakening the already durable pending
// intent. On write/sync failure the original intent still blocks restart.
func (o *nfqws2HookJournalOwner) retain(reason string) error {
	if err := o.current(); err != nil {
		return err
	}
	j := o.record
	j.Reason = reason
	data, err := writeNFQWS2HookJournal(o.root, j)
	if err == nil {
		o.record = j
		o.image = data
	}
	return err
}

// LOSS proves all owned mangle rows absent, while the original live receipt,
// lease, NAT and committed plan checks still belong to the Manager/Stop. FULL
// cannot establish provenance of an identical timeout/EEXIST row and refuses.
func nfqws2HookStopAdmission(j nfqws2HookJournal, inactive func() error, observe func() (dataplane.NFQWS2HookRestore, error)) error {
	if err := inactive(); err == nil {
		return nil
	}
	observed, err := observe()
	if err != nil || observed.Class != dataplane.NFQWS2HooksLoss || observed.Instance != j.Instance {
		return errors.Join(ErrNFQWS2HookRecovery, err)
	}
	if len(observed.Families) < 1 || len(observed.Families) > 2 || observed.Families[0].Family != 4 {
		return ErrNFQWS2HookRecovery
	}
	for i, family := range observed.Families {
		if family.Class != dataplane.NFQWS2HooksLoss || (i == 1 && family.Family != 6) {
			return ErrNFQWS2HookRecovery
		}
	}
	return nil
}
