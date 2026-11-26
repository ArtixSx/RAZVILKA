package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

type xrayStoppedPlanFile struct {
	file *os.File
	info os.FileInfo
	ack  bool
}

// This issuer publishes documents only after genuine joined retirement. It
// never replaces the original execution journals or creates an effect scope.
type xrayStoppedPlanPublication struct {
	terminal *XraySelectedTCPTerminal
	manager  *Manager
	root     *ownedfs.Root
	path     string
	anchor   os.FileInfo
	before   Plan
	plan     Plan
	data     []byte
	files    [2]xrayStoppedPlanFile
	failure  error
	closed   bool
	closeErr error
}

var xrayStoppedPlanNames = [2]string{"latest-plan.json", "latest-committed-plan.json"}

// CommitRetiredManagedXraySelectedTCP settles the documentary half of the
// SAME-App Stop/CAS. The original terminal and fresh cleanup capability supply
// authority; revision supplies comparison metadata, never a route or issuer.
func (m *Manager) CommitRetiredManagedXraySelectedTCP(ctx context.Context, terminal *XraySelectedTCPTerminal, cleanup *operationgate.ExclusiveCleanupReview, revision uint64) (Plan, error) {
	if m == nil || terminal == nil || terminal.self != terminal || terminal.owner == nil || terminal.owner.scope == nil || terminal.owner.scope.manager != m || cleanup == nil || revision == 0 || xraySelectedTCPFinite(ctx) != nil {
		return Plan{}, ErrXrayOperationOwner
	}
	if err := terminal.ObserveRetired(ctx, cleanup); err != nil {
		return Plan{}, err
	}
	plan, err := m.publishRetiredXrayPlan(ctx, terminal, revision)
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

func (m *Manager) publishRetiredXrayPlan(ctx context.Context, terminal *XraySelectedTCPTerminal, revision uint64) (Plan, error) {
	if err := m.beginOperation(ctx); err != nil {
		return Plan{}, err
	}
	defer m.endOperation()
	terminal.mu.Lock()
	defer terminal.mu.Unlock()
	if err := terminal.current(ctx); err != nil {
		return Plan{}, err
	}
	e := terminal.owner.execution
	if e == nil || e.material == nil || e.material.manager != m || e.cleanupGuard == nil || revision <= e.plan.Revision {
		return Plan{}, ErrXrayOperationOwner
	}
	if err := e.cleanupGuard(ctx, e.plan); err != nil {
		return Plan{}, err
	}
	current, found, err := m.Committed()
	if err != nil || !found {
		return Plan{}, errors.Join(ErrExecutionJournal, err)
	}
	p := terminal.stopped
	if p == nil {
		if current.State != "committed" || !xraySelectedTCPSamePlan(e.plan, current) {
			return Plan{}, ErrReviewChanged
		}
		plan, err := BuildAt(Input{Revision: revision, NetworkProfileID: e.plan.NetworkProfileID}, time.Now().UTC())
		if err != nil || !plan.Noop || !plan.Ready || len(plan.Routes) != 0 || plan.LAN != nil || plan.DNS != nil {
			return Plan{}, errors.Join(ErrExecutionJournal, err)
		}
		plan.State = "committed"
		plan.Note = "Original selected Xray TCP runtime retired; owned routes are stopped."
		data, err := json.MarshalIndent(plan, "", "  ")
		if err != nil {
			return Plan{}, err
		}
		root, anchor, err := openNetworkPolicyObservationRoot(m.StateRoot)
		if err != nil {
			return Plan{}, err
		}
		p = &xrayStoppedPlanPublication{terminal: terminal, manager: m, root: root, path: m.StateRoot, anchor: anchor, before: cloneExecutionResourcePlan(current), plan: plan, data: data}
		terminal.stopped = p
	}
	if p.terminal != terminal || p.manager != m || p.plan.Revision != revision {
		return Plan{}, ErrXrayOperationOwner
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
	return cloneExecutionResourcePlan(p.plan), e.cleanupGuard(ctx, e.plan)
}

func (p *xrayStoppedPlanPublication) current(ctx context.Context) error {
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
	named, err := os.Lstat(p.path)
	if err != nil || !networkPolicyPrivateDirectory(named) || !os.SameFile(p.anchor, named) {
		return refuse(err)
	}
	for index, held := range p.files {
		if held.file == nil {
			continue
		}
		before, err := held.file.Stat()
		named, namedErr := p.root.Stat(xrayStoppedPlanNames[index])
		if err != nil || namedErr != nil || !validNetworkPolicyReceiptFile(before) || !os.SameFile(held.info, before) || !os.SameFile(before, named) || before.Size() != int64(len(p.data)) {
			return refuse(errors.Join(err, namedErr))
		}
		data := make([]byte, len(p.data))
		n, readErr := held.file.ReadAt(data, 0)
		closing, closingErr := p.root.Stat(xrayStoppedPlanNames[index])
		if readErr != nil || n != len(data) || !bytes.Equal(data, p.data) || closingErr != nil || !os.SameFile(before, closing) {
			return refuse(errors.Join(readErr, closingErr))
		}
	}
	return ctx.Err()
}

func (p *xrayStoppedPlanPublication) publish(ctx context.Context) error {
	if err := p.current(ctx); err != nil {
		return err
	}
	for index := range p.files {
		held := &p.files[index]
		if held.file == nil {
			file, err := p.root.WriteAtomicRetained(xrayStoppedPlanNames[index], p.data, 0600)
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
			if err := syncDataplaneJournalDirectory(p.root); err != nil {
				return errors.Join(ErrExecutionJournal, err) // Keep this original FD for retry.
			}
			held.ack = true
		}
	}
	return p.current(ctx)
}

func (p *xrayStoppedPlanPublication) close() error {
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
