package dataplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"sync"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

// Original DNS-only handoff cursor. The baseline, its COMMON receipt and all
// addresses remain owned; no client-cache, process or routing grant is issued.
type DomainTCPDetachedStandby struct {
	self            *DomainTCPDetachedStandby
	mu              sync.Mutex
	original        *DomainTCPOriginalScope
	owner           *domainTCPStandbyOwner
	session         *scopedDNSSession
	mode            *scopedDNSSyntheticMode
	definition      ExecutionDomainDNSDetachedDefinition
	continuation    *dnscontrol.SyntheticDNSLedgerContinuation
	before          Execution
	globalPublished bool // Manager serializes publication/retry.
	metadataDone    bool
	registryDone    bool               // mu: readonly observers can compare the same joined source.
	finished        bool               // mu
	failure         error              // Sticky ambiguous actual descriptor close; Manager serializes.
	fault           func(string) error // Only private durability/registry ACK fault injection.
	initialFault    func(string) error // CI-only refusal after original successor durability ACK.
}

func (*DomainTCPDetachedStandby) String() string   { return "[original detached DNS standby]" }
func (*DomainTCPDetachedStandby) GoString() string { return "[original detached DNS standby]" }

// DetachPublishedStandby releases only the joined DNS registry coordinate.
// This does not release the Manager's retained baseline slot or permit a new
// Apply. A subsequent original factory must independently prove disjointness.
func (o *DomainTCPOriginalScope) DetachPublishedStandby(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview, history *updatecheck.ExecutionHistoryAdmission) (*DomainTCPDetachedStandby, error) {
	if o == nil || o.self != o || cleanup == nil || history == nil || xraySelectedTCPFinite(ctx) != nil {
		return nil, ErrDomainPolicyTCPConsumer
	}
	o.mu.Lock()
	owner, existing, retiring := o.standbyOwner, o.dnsDetachment, o.standbyRetirement
	o.mu.Unlock()
	if owner == nil || owner.self != owner || owner.original != o || owner.process == nil || owner.process.scope == nil || owner.process.material == nil || owner.process.material.control == nil || owner.process.material.binding == nil || owner.process.material.binding.adapter == nil || retiring != nil {
		return nil, ErrDomainPolicyTCPConsumer
	}
	p, s := owner.process, owner.process.scope
	m := s.manager
	if m == nil {
		return nil, ErrDomainPolicyTCPConsumer
	}
	if err := m.beginOperation(ctx); err != nil {
		return nil, err
	}
	defer m.endOperation()
	if err := history.CheckWrite(ctx, 7); err != nil {
		return nil, err
	}
	if err := p.material.control.CurrentForCleanupOperation(ctx, cleanup); err != nil {
		return nil, err
	}
	if existing != nil {
		if existing.self != existing || existing.owner != owner || existing.original != o {
			return nil, ErrPolicyAdditionUnknown
		}
		if err := existing.resume(ctx, cleanup, history); err != nil {
			return nil, err
		}
		return existing, nil
	}
	if err := owner.current(); err != nil {
		return nil, err
	}
	row, err := owner.baseline.retirement.ObserveClosed(ctx)
	if err != nil || !row.PossiblyIssued {
		return nil, errors.Join(ErrDomainPolicyTCPCaptureRetirementPending, err)
	}
	token, err := owner.baseline.retirement.ReviewContinuation(ctx)
	if err != nil {
		return nil, err
	}
	material := p.material
	a := material.binding.adapter
	a.mu.Lock()
	session := material.session
	if a.live != session || session == nil || session.synthetic == nil || session.synthetic.source != material.dnsSource || session.synthetic.binding != material.binding || session.synthetic.control != material.control || session.inactiveJoined() != nil {
		a.mu.Unlock()
		return nil, ErrDomainPolicyTCPConsumer
	}
	mode := session.synthetic
	if mode.ownerRecord == nil || mode.ownerRecord.current("owner.json") != nil {
		a.mu.Unlock()
		return nil, ErrDomainPolicyTCPConsumer
	}
	hash := sha256.Sum256(mode.ownerRecord.canonical)
	ref := token.Reference()
	definition := ExecutionDomainDNSDetachedDefinition{Schema: 1, OwnerName: mode.ownerRecord.destination, OwnerSHA256: hex.EncodeToString(hash[:]), LedgerPrefixSHA256: ref.PrefixSHA256, LedgerCount: ref.Count, ClosedMapping: row}
	a.mu.Unlock()
	s.mu.Lock()
	retained := s.retainedXrayOwner
	valid := s.retained && retained != nil && retained.standby == owner && !retained.pending && m.retainedXrayOwner() == retained
	var baseline *ExecutionSyntheticBaselineDefinition
	for _, resource := range s.execution.Resources {
		if resource.ID == filepath.Base(owner.baseline.relative) {
			baseline = resource.SyntheticBaseline
		}
	}
	if !valid || definition.validate(s.execution.PlanID, baseline) != nil {
		s.mu.Unlock()
		return nil, ErrPolicyAdditionUnknown
	}
	beforeWire, err := json.Marshal(s.execution)
	var before Execution
	if err == nil {
		err = json.Unmarshal(beforeWire, &before)
	}
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	d := &DomainTCPDetachedStandby{original: o, owner: owner, session: session, mode: mode, definition: definition.Clone(), continuation: token, before: before}
	d.self = d
	// Reserve unknown custody before either original name or journal changes.
	retained.pending = true
	s.mu.Unlock()
	o.mu.Lock()
	d.fault = o.dnsDetachmentFault
	o.dnsDetachment = d
	o.mu.Unlock()
	if err := d.resume(ctx, cleanup, history); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *DomainTCPDetachedStandby) registryDetached() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.registryDone
}

// Read only the SAME captured, joined session after its registry entry left.
// A different live session can neither replace nor resurrect this source.
func (d *DomainTCPDetachedStandby) originalClosedSession(ctx context.Context) (*scopedDNSSession, error) {
	if d == nil || d.self != d || !d.registryDetached() || d.original == nil || d.owner == nil || d.mode == nil || d.session == nil {
		return nil, ErrDomainPolicyTCPConsumer
	}
	a := d.owner.process.material.binding.adapter
	a.mu.Lock()
	defer a.mu.Unlock()
	if d.session.synthetic != d.mode || d.mode.source != d.owner.process.material.dnsSource || d.session.inactiveJoined() != nil || d.mode.ownerRecord == nil || !d.mode.ownerRecord.moved || !d.mode.ownerRecord.synced || d.mode.ownerRecord.closeErr != nil {
		return nil, ErrDomainPolicyTCPConsumer
	}
	if err := d.mode.ownerRecord.current(d.definition.OwnerName); err != nil {
		return nil, err
	}
	return d.session, ctx.Err()
}

func (d *DomainTCPDetachedStandby) guard(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview) error {
	if d == nil || d.self != d || d.original == nil || d.owner == nil || d.owner.original != d.original || d.owner.process == nil || d.continuation == nil || d.mode == nil || d.session == nil {
		return ErrDomainPolicyTCPConsumer
	}
	if d.failure != nil {
		return d.failure
	}
	p := d.owner.process
	if err := p.material.control.CurrentForCleanupOperation(ctx, cleanup); err != nil {
		return err
	}
	d.original.mu.Lock()
	same := d.original.dnsDetachment == d && d.original.standbyOwner == d.owner
	d.original.mu.Unlock()
	if !same {
		return ErrPolicyAdditionUnknown
	}
	s := p.scope
	s.mu.Lock()
	retained := s.retainedXrayOwner
	same = s.retained && retained != nil && retained.standby == d.owner && s.manager.retainedXrayOwner() == retained
	s.mu.Unlock()
	if !same {
		return ErrPolicyAdditionUnknown
	}
	if err := d.original.compareStandbyForDetachment(ctx, false, d); err != nil {
		return err
	}
	row, err := d.owner.baseline.retirement.ObserveClosed(ctx)
	if err != nil || !reflect.DeepEqual(row, d.definition.ClosedMapping) {
		return errors.Join(ErrDomainPolicyTCPConsumer, err)
	}
	return p.material.control.CurrentForCleanupOperation(ctx, cleanup)
}

func (d *DomainTCPDetachedStandby) resume(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview, history *updatecheck.ExecutionHistoryAdmission) error {
	if err := d.guard(ctx, cleanup); err != nil {
		return err
	}
	if err := history.CheckWrite(ctx, 7); err != nil {
		return err
	}
	d.mu.Lock()
	finished := d.finished
	d.mu.Unlock()
	if finished {
		return nil // Readonly reobservation; a successor may now own owner.json.
	}
	p, s := d.owner.process, d.owner.process.scope
	a := p.material.binding.adapter
	a.mu.Lock()
	if d.session.synthetic != d.mode || d.mode.source != p.material.dnsSource || d.mode.ownerRecord == nil {
		a.mu.Unlock()
		return ErrDomainPolicyTCPConsumer
	}
	// The SAME no-replace owner cursor retains its exact inode on an uncertain
	// rename/sync. A foreign owner or reserved history is never overwritten.
	err := d.mode.ownerRecord.retire(ctx)
	a.mu.Unlock()
	if err != nil {
		return err
	}
	if !d.metadataDone {
		if err := d.publish(ctx, cleanup, history); err != nil {
			return err
		}
	}
	if err := d.guard(ctx, cleanup); err != nil {
		return err
	}
	if !d.registryDetached() {
		a.mu.Lock()
		if a.live != d.session || d.mode.ownerRecord.current(d.definition.OwnerName) != nil {
			a.mu.Unlock()
			return ErrPolicyAdditionUnknown
		}
		if err := scopedDNSInactiveRetire(a.StateRoot, d.session); err != nil {
			a.mu.Unlock()
			return err
		}
		a.live = nil
		d.mu.Lock()
		d.registryDone = true
		d.mu.Unlock()
		a.mu.Unlock()
		if d.fault != nil {
			if err := d.fault("registry"); err != nil {
				return err
			}
		}
	}
	if err := d.guard(ctx, cleanup); err != nil {
		return err
	}
	s.mu.Lock()
	retained := s.retainedXrayOwner
	if !s.retained || retained == nil || retained.standby != d.owner || s.manager.retainedXrayOwner() != retained {
		s.mu.Unlock()
		return ErrPolicyAdditionUnknown
	}
	retained.pending = false
	s.mu.Unlock()
	d.mu.Lock()
	d.finished = true
	d.mu.Unlock()
	return nil
}

func (d *DomainTCPDetachedStandby) publish(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview, history *updatecheck.ExecutionHistoryAdmission) error {
	s := d.owner.process.scope
	s.mu.Lock()
	found := false
	for i := range s.execution.Resources {
		row := &s.execution.Resources[i]
		if row.ID == filepath.Base(d.owner.baseline.relative) {
			definition := d.definition.Clone()
			row.DomainDNSDetached = &definition
			row.Phase = "standby-detached"
			found = true
		}
	}
	data, err := json.Marshal(s.execution)
	if !found || validateExecutionResources(*s.execution, false) != nil {
		s.mu.Unlock()
		return ErrExecutionJournal
	}
	s.mu.Unlock()
	if err != nil {
		return err
	}
	records := d.owner.process.records
	if err := records.beforePublication(); err != nil {
		return err
	}
	for i := range 2 {
		if err := d.guard(ctx, cleanup); err != nil {
			return err
		}
		if err := history.CheckWrite(ctx, 7); err != nil {
			return err
		}
		if err := records.publishOriginalDurable(i, data, func(root *ownedfs.Root) error {
			if err := syncDataplaneJournalDirectory(root); err != nil {
				return err
			}
			if d.fault != nil {
				return d.fault([]string{"alias0", "alias1"}[i])
			}
			return nil
		}); err != nil {
			return err
		}
	}
	if err := history.CheckWrite(ctx, 7); err != nil {
		return err
	}
	if err := d.guard(ctx, cleanup); err != nil {
		return err
	}
	expected := d.before
	if d.globalPublished {
		expected = *s.execution
	}
	if err := d.owner.globalRecordCurrent(s.managerRoot, expected); err != nil {
		return err
	}
	if !d.globalPublished {
		file, err := records.root.WriteAtomicRetained("latest-execution.json", data, 0600)
		if err != nil {
			return err
		}
		info, err := file.Stat()
		if err != nil {
			return errors.Join(err, file.Close())
		}
		closeErr := d.owner.replaceGlobalRecord(file, info)
		d.globalPublished = true
		if closeErr != nil {
			d.failure = errors.Join(ErrPolicyAdditionUnknown, closeErr)
			return d.failure
		}
	}
	if err := syncDataplaneJournalDirectory(records.root); err != nil {
		return err
	}
	if d.fault != nil {
		if err := d.fault("global"); err != nil {
			return err
		}
	}
	if err := d.owner.globalRecordCurrent(s.managerRoot, *s.execution); err != nil {
		return err
	}
	if err := records.current(ctx, true); err != nil {
		return err
	}
	d.metadataDone = true
	return nil
}
