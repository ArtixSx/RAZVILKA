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

	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

// This original owner holds only an already acknowledged restorative footprint.
// It cannot start a child, publish DNS, select a route, or expire a client cache.
type domainTCPStandbyOwner struct {
	self       *domainTCPStandbyOwner
	original   *DomainTCPOriginalScope
	process    *XrayDomainTCPExecutionResource
	baseline   *syntheticBaselineExecutionResource
	latest     *os.File // SAME original global writer inode, retained across alias handoff.
	latestInfo os.FileInfo
}

// RetainStandby requests handoff of the SAME acknowledged standby after Run
// joined its process. The Manager completes the handoff after the callback,
// through its existing two original journal writers. All other errors remain
// errors; retaining a baseline does not turn a failed probe into a pass.
func (o *DomainTCPOriginalScope) RetainStandby(ctx context.Context, history *updatecheck.ExecutionHistoryAdmission) error {
	if o == nil || o.self != o || history == nil || xraySelectedTCPFinite(ctx) != nil {
		return ErrDomainPolicyTCPConsumer
	}
	if err := history.CheckWrite(ctx, 4); err != nil {
		return err
	}
	if err := o.standbyCurrent(ctx); err != nil {
		return err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.standbyHistory != nil || o.standbyOwner != nil {
		return ErrDomainPolicyTCPConsumer
	}
	o.standbyHistory = history
	return nil
}

// Requires the actual finalizer, source, process, handlers and COMMON receipts.
// Neither a terminal record nor an equal tuple can manufacture these objects.
func (o *DomainTCPOriginalScope) standbyCurrent(ctx context.Context) error {
	return o.compareStandby(ctx, true)
}

func (o *DomainTCPOriginalScope) compareStandby(ctx context.Context, transferring bool) error {
	if o == nil || o.self != o || xraySelectedTCPFinite(ctx) != nil {
		return ErrDomainPolicyTCPConsumer
	}
	o.mu.Lock()
	p, baseline, capture, kernel := o.process, o.baseline, o.captureResource, o.kernel
	ready, closed := o.standbyReady, o.closed
	o.mu.Unlock()
	if !ready || !closed || p == nil || p.self != p || p.scope != o.binding.scope || p.material == nil || baseline == nil || baseline.self != baseline || capture == nil || capture.self != capture || capture.process != p || capture.mapping != baseline.mapping || kernel == nil || kernel.flow.Load() != nil {
		return ErrDomainPolicyTCPConsumer
	}
	ctx = p.scope.contextWith(ctx)
	if transferring {
		if _, err := p.originalContext(ctx, true); err != nil {
			return err
		}
	} else {
		p.scope.mu.Lock()
		err := p.scope.checkOriginalOwner(ctx, nil, false, false)
		p.scope.mu.Unlock()
		if err != nil {
			return err
		}
		if err := p.records.current(ctx, true); err != nil {
			return err
		}
		if err := p.filesCurrent(ctx); err != nil {
			return err
		}
	}
	if p.child == nil || p.birth == nil {
		return ErrXrayDomainTCPOriginal
	}
	select {
	case <-p.child.done:
	default:
		return ErrXrayDomainTCPOriginal
	}
	if err := p.observeDomainListenerAbsent(ctx); err != nil {
		return err
	}
	session, err := o.binding.originalSyntheticSession(p.material.control)
	if err != nil || session != p.material.session || session.inactiveJoined() != nil {
		return errors.Join(ErrDomainPolicyTCPConsumer, err)
	}
	if _, err := baseline.retirement.ObserveClosed(ctx); err != nil {
		return err
	}
	if err := capture.capture.retirement.Joined(ctx); err != nil {
		return err
	}
	s := p.scope
	s.mu.Lock()
	standbyFound := false
	for _, r := range s.execution.Resources {
		if r.ID == filepath.Base(baseline.relative) && s.syntheticBaselines[r.ID] == baseline && r.SyntheticBaseline != nil && r.State == "prepared" && (r.Phase == "capture-ready" || r.Phase == "standby-retained") {
			standbyFound = true
			continue
		}
		if r.State != "removed" && r.State != "unused" {
			s.mu.Unlock()
			return ErrDomainPolicyTCPConsumer
		}
	}
	s.mu.Unlock()
	if !standbyFound {
		return ErrDomainPolicyTCPConsumer
	}
	if err := capture.closedStandbyLocal(ctx); err != nil {
		return err
	}
	if err := capture.tools.Runner.CheckSyntheticDNS(ctx, capture.tools.Identity); err != nil {
		return err
	}
	if err := s.networkIdentity.check(ctx); err != nil {
		return err
	}
	receipt, err := observeNetworkPolicyEffects(ctx, baseline.effects, baseline.root, policyAdditionOptions{})
	defer receipt.close()
	status := receipt.status
	if err != nil || !status.Complete || status.Unknown || status.Removed || status.Promoted || status.Pending != 0 || status.Cleaned != 0 || status.Added != len(baseline.effects.Effects) {
		return errors.Join(ErrSyntheticBaselineTransition, err)
	}
	view, err := capture.backend.Read(ctx, capture.tools.Identity)
	if err != nil {
		return err
	}
	if err := view.requireLANBackendCoverage(); err != nil || view.Scope.Network != capture.tools.Identity {
		return errors.Join(ErrDomainPolicyTCPConsumer, err)
	}
	for i := range baseline.effects.Effects {
		count, err := syntheticBaselineExactPresence(view.Rows, baseline.effects, i)
		if err != nil || count != 1 {
			return errors.Join(ErrSyntheticBaselineTransition, err)
		}
	}
	for i := range capture.effects.Effects {
		count, err := domainTCPCapturePresence(view.Rows, capture.effects, i)
		if err != nil || count != 0 {
			return errors.Join(ErrDomainPolicyTCPConsumer, err)
		}
	}
	return receipt.current()
}

// Read-only comparison after the actual listener and handlers joined. The
// live local() predicate correctly refuses a closed socket and remains used
// by every preparation/forward path. This leaf grants no cleanup admission.
func (r *domainTCPCaptureExecutionResource) closedStandbyLocal(ctx context.Context) error {
	if r == nil || r.self != r || xraySelectedTCPFinite(ctx) != nil || r.process == nil || r.process.self != r.process || r.process.material == nil || r.capture == nil || r.capture.self != r.capture || r.capture.xray == nil || r.capture.xray.resource != r.process || r.capture.spec != r.definition.Process.Capture || r.mapping != r.process.material.mapping || r.tools == nil || !r.tools.valid() || !reflect.DeepEqual(*r.tools, r.toolsFrozen) || r.backend == nil || r.process.scope == nil || r.process.scope.networkIdentity == nil {
		return ErrDomainPolicyTCPConsumer
	}
	s := r.process.scope
	if ctx.Value(syntheticExecutionRegistrarKey{}) != s || r.tools.Provider != s.networkIdentity.provider || r.tools.Identity != s.networkIdentity.value || r.backend.reader.Provider != r.tools.Provider || r.backend.review != r.tools.ReviewSHA256 || r.backend.reader.IPTables != r.tools.IPTables || r.root != filepath.Join(s.root, r.relative) || r.anchor == nil || r.relative == "" || !reflect.DeepEqual(r.definition.Process, r.process.definition) {
		return ErrDomainPolicyTCPConsumer
	}
	endpoint, err := r.capture.retirement.Endpoint(ctx)
	if err != nil || endpoint != r.capture.spec.Listen {
		return errors.Join(ErrDomainPolicyTCPConsumer, err)
	}
	s.mu.Lock()
	original := s.domainTCPCaptures[filepath.Base(r.relative)] == r && s.owned != nil
	var info os.FileInfo
	if original {
		info, err = s.owned.Stat(r.relative)
	}
	s.mu.Unlock()
	if !original || err != nil || !networkPolicyPrivateDirectory(info) || !os.SameFile(r.anchor, info) {
		return errors.Join(ErrDomainPolicyTCPConsumer, err)
	}
	plan, err := compileDomainTCPCaptureEffects(r.definition.Process.Capture, r.definition.Process.Mapping)
	if err != nil || !reflect.DeepEqual(plan, r.effects) {
		return errors.Join(ErrDomainPolicyTCPConsumer, err)
	}
	digest, err := PolicyEffectPlanDigest(plan)
	if err != nil || digest != r.digest {
		return errors.Join(ErrDomainPolicyTCPConsumer, err)
	}
	return ctx.Err()
}

func (o *domainTCPStandbyOwner) current() error {
	if o == nil || o.self != o || o.original == nil || o.original.standbyOwner != o || o.process != o.original.process || o.baseline != o.original.baseline {
		return ErrDomainPolicyTCPConsumer
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	return o.original.compareStandby(ctx, false)
}

// RetainedStandbyCurrent compares only this original restorative owner. It
// grants no process, publication, selection, cleanup or address reuse.
func (o *DomainTCPOriginalScope) RetainedStandbyCurrent(ctx context.Context) error {
	if o == nil || o.self != o || xraySelectedTCPFinite(ctx) != nil {
		return ErrDomainPolicyTCPConsumer
	}
	o.mu.Lock()
	owner := o.standbyOwner
	o.mu.Unlock()
	if owner == nil || owner.self != owner || owner.original != o {
		return ErrDomainPolicyTCPConsumer
	}
	s := o.binding.scope
	s.mu.Lock()
	retained := s.retained && s.retainedXrayOwner != nil && s.retainedXrayOwner.standby == owner
	pending := !retained || s.retainedXrayOwner.pending
	s.mu.Unlock()
	if !retained {
		return ErrDomainPolicyTCPConsumer
	}
	if pending {
		return ErrPolicyAdditionUnknown
	}
	return o.compareStandby(ctx, false)
}

// Called only by the SAME Manager wrapper after its actual action returned.
// All non-restorative resources must already be joined and terminal.
func (o *DomainTCPOriginalScope) finishStandbyHandoff(ctx context.Context, actionErr error) (bool, error) {
	if o == nil || o.self != o {
		return false, nil
	}
	o.mu.Lock()
	history, existing := o.standbyHistory, o.standbyOwner
	o.mu.Unlock()
	if history == nil {
		return false, nil
	}
	if existing != nil {
		return true, ErrDomainPolicyTCPConsumer
	}
	if err := history.CheckWrite(ctx, 4); err != nil {
		return true, err
	}
	if err := o.standbyCurrent(ctx); err != nil {
		return true, err
	}
	p, baseline := o.process, o.baseline
	s, m := p.scope, p.scope.manager
	m.retainedXrayMu.Lock()
	defer m.retainedXrayMu.Unlock()
	if m.retainedXray != nil || m.replacementXray != nil {
		return true, ErrDomainPolicyTCPConsumer
	}
	owner := &domainTCPStandbyOwner{original: o, process: p, baseline: baseline}
	owner.self = owner
	retained := &retainedXrayExecution{scope: s, records: p.records, standby: owner, pending: true}
	retained.self = retained
	// Custody precedes the first changed publication. Any later failed write,
	// alias handoff or closing proof retains these exact anchors cleanup-only.
	o.mu.Lock()
	o.standbyOwner = owner
	o.mu.Unlock()
	s.mu.Lock()
	s.retained, s.retainedXrayOwner = true, retained
	s.mu.Unlock()
	m.retainedXray = retained
	s.mu.Lock()
	if !s.open || s.failure != nil || s.domainTCPOwner != o {
		s.mu.Unlock()
		return true, ErrDomainPolicyTCPConsumer
	}
	for i := range s.execution.Resources {
		if s.execution.Resources[i].ID == filepath.Base(baseline.relative) {
			s.execution.Resources[i].Phase = "standby-retained"
		}
	}
	// This is a known retained resource, not a successful service/apply result.
	s.execution.State = "resource-failed"
	s.execution.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	s.execution.Steps[0].State, s.execution.Steps[0].FinishedAt = "failed", s.execution.FinishedAt
	if actionErr != nil {
		s.execution.Error, s.execution.Steps[0].Detail = actionErr.Error(), actionErr.Error()
	}
	err := s.persist()
	s.mu.Unlock()
	if err != nil {
		return true, err
	}
	if err := o.standbyCurrent(ctx); err != nil {
		return true, err
	}
	if err := p.records.detachStandbyAlias(ctx, owner); err != nil {
		return true, err
	}
	if err := owner.current(); err != nil {
		return true, err
	}
	s.mu.Lock()
	retained.pending = false
	s.observationOpen.Store(false)
	s.cancel() // No forward borrower or callback survives the transfer.
	s.mu.Unlock()
	m.retainedXray = retained
	if err := owner.current(); err != nil {
		s.mu.Lock()
		retained.pending = true
		s.mu.Unlock()
		return true, err
	}
	return true, nil
}

// Author a separate second record before relinquishing the global latest
// coordinate. Its FD comes from this exact writer, never a pathname read.
func (d *xraySelectedTCPExecutionRecords) detachStandbyAlias(ctx context.Context, owner *domainTCPStandbyOwner) error {
	if d == nil || d.scope == nil || d.standbyAlias.Load() {
		return ErrExecutionJournal
	}
	if err := d.current(ctx, true); err != nil {
		return err
	}
	data, err := json.Marshal(d.scope.execution)
	if err != nil {
		return err
	}
	file, err := writeDataplaneJournalRetained(filepath.Join(d.scope.root, "standby-execution.json"), data)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err == nil {
		d.mu.Lock()
		if owner == nil || owner.self != owner || owner.process.records != d || owner.latest != nil || d.files[1] == nil {
			d.mu.Unlock()
			return errors.Join(ErrExecutionJournal, file.Close())
		}
		owner.latest, owner.latestInfo = d.files[1], d.infos[1]
		d.files[1], d.infos[1], d.images[1] = nil, nil, nil
		d.mu.Unlock()
		err = d.captureOriginalRecord(1, file, info, data, d.transactionRoot, "standby-execution.json")
	}
	if err != nil {
		return errors.Join(err, file.Close())
	}
	d.standbyAlias.Store(true)
	return d.current(ctx, true)
}

// The known-owner exception is scoped to this SAME last global publication.
// Any later/foreign publication, even equal bytes on a replaced inode, cannot
// hide an unknown transaction behind the retained baseline's older document.
func (m *Manager) checkKnownDomainStandbyRecord(record Execution) error {
	owner := m.retainedXrayOwner()
	if owner == nil || owner.self != owner || owner.standby == nil || owner.pending || owner.scope == nil || owner.scope.manager != m {
		return ErrPolicyAdditionUnknown
	}
	standby := owner.standby
	if standby.self != standby || standby.latest == nil || standby.latestInfo == nil {
		return ErrExecutionJournal
	}
	check := func() error {
		if err := standby.globalRecordCurrent(m.StateRoot, record); err != nil {
			return err
		}
		owner.scope.mu.Lock()
		same := owner.scope.retained && owner.scope.retainedXrayOwner == owner && reflect.DeepEqual(*owner.scope.execution, record)
		owner.scope.mu.Unlock()
		if !same {
			return ErrExecutionJournal
		}
		return nil
	}
	if err := check(); err != nil {
		return err
	}
	if err := standby.current(); err != nil {
		return err
	}
	return check()
}

// Original FD and bytes only. This comparison cannot issue a standby owner.
func (standby *domainTCPStandbyOwner) globalRecordCurrent(root string, record Execution) error {
	if standby == nil || standby.self != standby || standby.latest == nil || standby.latestInfo == nil {
		return ErrExecutionJournal
	}
	held, err := standby.latest.Stat()
	named, statErr := os.Lstat(filepath.Join(root, "latest-execution.json"))
	matches := func(info os.FileInfo) bool {
		return info != nil && validNetworkPolicyReceiptFile(info) && os.SameFile(standby.latestInfo, info) && info.Mode() == standby.latestInfo.Mode() && info.Size() == standby.latestInfo.Size() && info.ModTime().Equal(standby.latestInfo.ModTime())
	}
	if err != nil || statErr != nil || !matches(held) || !matches(named) || held.Size() < 1 || held.Size() > 16<<20 {
		return errors.Join(ErrExecutionJournal, err, statErr)
	}
	data := make([]byte, int(held.Size()))
	n, readErr := standby.latest.ReadAt(data, 0)
	var canonical bytes.Buffer
	expected, marshalErr := json.Marshal(record)
	if readErr != nil || n != len(data) || marshalErr != nil || json.Compact(&canonical, data) != nil || !bytes.Equal(canonical.Bytes(), expected) {
		return errors.Join(ErrExecutionJournal, readErr, marshalErr)
	}
	after, afterErr := standby.latest.Stat()
	closing, closingErr := os.Lstat(filepath.Join(root, "latest-execution.json"))
	if afterErr != nil || closingErr != nil || !matches(after) || !matches(closing) {
		return errors.Join(ErrExecutionJournal, afterErr, closingErr)
	}
	return nil
}
