package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

type mihomoStoppedPlanFile struct {
	file *os.File
	info os.FileInfo
	ack  bool
}

// This issuer publishes documents only after genuine joined retirement. It
// never replaces the original execution journals or creates an effect scope.
type mihomoStoppedPlanPublication struct {
	terminal *MihomoLiveTerminal
	manager  *Manager
	root     *ownedfs.Root
	path     string
	anchor   os.FileInfo
	before   Plan
	plan     Plan
	data     []byte
	files    [2]mihomoStoppedPlanFile
	failure  error
	closed   bool
	closeErr error
}

var mihomoStoppedPlanNames = [2]string{"latest-plan.json", "latest-committed-plan.json"}

// CommitRetiredMihomo settles the documentary half of the
// SAME-App Stop/CAS. The original terminal and fresh cleanup capability supply
// authority; revision supplies comparison metadata, never a route or issuer.
func (m *Manager) CommitRetiredMihomo(ctx context.Context, terminal *MihomoLiveTerminal, cleanup *operationgate.ExclusiveCleanupReview, revision uint64) (Plan, error) {
	if m == nil || terminal == nil || terminal.self != terminal || terminal.owner == nil || terminal.owner.scope == nil || terminal.owner.scope.manager != m || cleanup == nil || revision == 0 || xraySelectedTCPFinite(ctx) != nil {
		return Plan{}, errMihomoLiveMaterial
	}
	if err := terminal.ObserveRetired(ctx, cleanup); err != nil {
		return Plan{}, err
	}
	plan, err := m.publishRetiredMihomoPlan(ctx, terminal, cleanup, revision)
	if err != nil {
		return Plan{}, err
	}
	// ObserveRetired owns its own Manager/provider boundaries. Call it outside
	// the publication locks, retaining the caller's same original admission.
	if err := terminal.ObserveRetired(ctx, cleanup); err != nil {
		return Plan{}, err
	}
	return cloneExecutionResourcePlan(plan), nil
}

func (m *Manager) publishRetiredMihomoPlan(ctx context.Context, terminal *MihomoLiveTerminal, cleanup *operationgate.ExclusiveCleanupReview, revision uint64) (Plan, error) {
	if err := m.beginOperation(ctx); err != nil {
		return Plan{}, err
	}
	defer m.endOperation()
	c, end, err := terminal.owner.operation(ctx, cleanup, false)
	if err != nil {
		return Plan{}, err
	}
	defer end()
	ctx = c
	terminal.mu.Lock()
	defer terminal.mu.Unlock()
	if err := terminal.current(ctx); err != nil {
		return Plan{}, err
	}
	e := terminal.owner
	if e == nil || e.scope == nil || e.scope.manager != m || revision <= e.definition.Plan.Revision {
		return Plan{}, errMihomoLiveMaterial
	}
	if err := e.control.CurrentForCleanupOperation(ctx, cleanup); err != nil {
		return Plan{}, err
	}
	current, found, err := m.Committed()
	if err != nil || !found {
		return Plan{}, errors.Join(ErrExecutionJournal, err)
	}
	p := terminal.stopped
	if p == nil {
		if current.State != "committed" || !mihomoStoppedOriginalPlanMatches(e.definition.Plan, current) {
			return Plan{}, ErrReviewChanged
		}
		plan, err := BuildAt(Input{Revision: revision, NetworkProfileID: e.definition.Plan.NetworkProfileID}, time.Now().UTC())
		if err != nil || !plan.Noop || !plan.Ready || len(plan.Routes) != 0 || plan.LAN != nil || plan.DNS != nil {
			return Plan{}, errors.Join(ErrExecutionJournal, err)
		}
		plan.State = "committed"
		plan.Note = "Original Mihomo runtime retired; owned routes are stopped."
		data, err := json.MarshalIndent(plan, "", "  ")
		if err != nil {
			return Plan{}, err
		}
		// Freeze the exact shape of OUR encoded target, not an independently
		// canonicalized compiler value. Committed will decode these same bytes
		// after the first ACK, including omitempty nil/empty slice semantics.
		var published Plan
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&published) != nil || decoder.Decode(new(any)) != io.EOF {
			return Plan{}, ErrExecutionJournal
		}
		root, anchor, err := openNetworkPolicyObservationRoot(m.StateRoot)
		if err != nil {
			return Plan{}, err
		}
		// Committed decoded this independent document for this caller. Keep its
		// exact nil/empty wire shape: the general compiler clone canonicalizes
		// some service slices, which would fail the immediate exact comparison.
		// This private before image is neither mutated nor returned to callers.
		p = &mihomoStoppedPlanPublication{terminal: terminal, manager: m, root: root, path: m.StateRoot, anchor: anchor, before: current, plan: published, data: data}
		terminal.stopped = p
	}
	if p.terminal != terminal || p.manager != m || p.plan.Revision != revision {
		return Plan{}, errMihomoLiveMaterial
	}
	wanted := p.before
	if p.files[1].file != nil {
		wanted = p.plan
	}
	if !reflect.DeepEqual(current, wanted) {
		return Plan{}, ErrReviewChanged
	}
	m.journalMu.Lock()
	defer m.journalMu.Unlock()
	if err := p.publish(ctx); err != nil {
		return Plan{}, err
	}
	if err := terminal.current(ctx); err != nil {
		return Plan{}, err
	}
	return cloneExecutionResourcePlan(p.plan), e.control.CurrentForCleanupOperation(ctx, cleanup)
}

// Committed decodes the Manager's published plan. Derive its expected wire
// shape only from this terminal owner's original frozen compiler intent:
// omitempty drops empty compiler slices. Neither incoming documents nor the
// retained before/target images are rewritten, and the ordinary exact intent
// comparison still permits only its existing result-bookkeeping differences.
func mihomoStoppedOriginalPlanMatches(original, current Plan) bool {
	data, err := json.Marshal(original)
	if err != nil {
		return false
	}
	var expected Plan
	if json.Unmarshal(data, &expected) != nil {
		return false
	}
	return xraySelectedTCPSamePlan(cloneExecutionResourcePlan(expected), current)
}

func (p *mihomoStoppedPlanPublication) current(ctx context.Context) error {
	if p == nil || p.closed || p.root == nil || p.manager == nil || ctx == nil {
		return ErrExecutionJournal
	}
	if ctx.Err() != nil {
		return errors.Join(ErrExecutionJournal, ctx.Err())
	}
	if p.failure != nil {
		return p.failure
	}
	refuse := func(cause error) error {
		p.failure = errors.Join(ErrExecutionJournal, cause)
		return p.failure
	}
	if p.manager.StateRoot != p.path {
		return refuse(nil)
	}
	rootCurrent := func() error {
		named, err := os.Lstat(p.path)
		held, heldErr := p.root.RootInfo()
		if err != nil || heldErr != nil || !networkPolicyPrivateDirectory(named) || !networkPolicyPrivateDirectory(held) || !os.SameFile(p.anchor, named) || !os.SameFile(p.anchor, held) {
			return refuse(errors.Join(err, heldErr))
		}
		return nil
	}
	if err := rootCurrent(); err != nil {
		return err
	}
	for index, held := range p.files {
		if held.file == nil {
			continue
		}
		matches := func(info os.FileInfo) bool {
			return held.info != nil && validNetworkPolicyReceiptFile(info) && os.SameFile(held.info, info) && info.Size() == int64(len(p.data)) && info.Size() == held.info.Size() && info.Mode() == held.info.Mode() && info.ModTime().Equal(held.info.ModTime())
		}
		before, err := held.file.Stat()
		named, namedErr := p.root.Stat(mihomoStoppedPlanNames[index])
		if err != nil || namedErr != nil || !matches(before) || !matches(named) {
			return refuse(errors.Join(err, namedErr))
		}
		data := make([]byte, len(p.data))
		n, readErr := held.file.ReadAt(data, 0)
		after, afterErr := held.file.Stat()
		closing, closingErr := p.root.Stat(mihomoStoppedPlanNames[index])
		if readErr != nil || n != len(data) || !bytes.Equal(data, p.data) || afterErr != nil || closingErr != nil || !matches(after) || !matches(closing) {
			return refuse(errors.Join(readErr, afterErr, closingErr))
		}
	}
	if err := rootCurrent(); err != nil {
		return err
	}
	return ctx.Err()
}

func (p *mihomoStoppedPlanPublication) publish(ctx context.Context) error {
	return p.publishDurable(ctx, syncDataplaneJournalDirectory)
}

func (p *mihomoStoppedPlanPublication) publishDurable(ctx context.Context, syncDirectory func(*ownedfs.Root) error) error {
	if err := p.current(ctx); err != nil {
		return err
	}
	for index := range p.files {
		held := &p.files[index]
		if held.file == nil {
			file, err := p.root.WriteAtomicRetained(mihomoStoppedPlanNames[index], p.data, 0600)
			if err != nil {
				// A failed writer cannot be reconstructed from its named bytes.
				p.failure = errors.Join(ErrExecutionJournal, err)
				return p.failure
			}
			held.file = file
			held.info, err = file.Stat()
			if err != nil {
				p.failure = errors.Join(ErrExecutionJournal, err)
				return p.failure
			}
		}
		if err := p.current(ctx); err != nil {
			return err
		}
		if !held.ack {
			if err := syncDirectory(p.root); err != nil {
				return errors.Join(ErrExecutionJournal, err) // Keep this original FD for retry.
			}
			held.ack = true
		}
	}
	return p.current(ctx)
}

func (p *mihomoStoppedPlanPublication) close() error {
	if p == nil {
		return nil
	}
	if p.closed {
		return p.closeErr
	}
	if p.failure != nil || !p.files[0].ack || !p.files[1].ack {
		return ErrExecutionJournal // Preserve the original pending publication.
	}
	p.closed = true
	for _, held := range p.files {
		p.closeErr = errors.Join(p.closeErr, held.file.Close())
	}
	p.closeErr = errors.Join(p.closeErr, p.root.Close())
	return p.closeErr
}
