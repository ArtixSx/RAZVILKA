package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Custody observation only. It does not mint a cleanup context or claim that
// the live native runtime has been stopped; Stop must still perform that work.
func (m *Manager) HasPendingMihomoTransitHistory() bool {
	if m == nil {
		return false
	}
	r := m.originalMihomoLive()
	if r == nil || r.self != r || r.scope == nil {
		return false
	}
	s := r.scope
	s.mu.Lock()
	defer s.mu.Unlock()
	c := r.transitHistory
	return s.open && s.retained && s.pending && s.mihomoLive == r && c != nil && c.self == c && c.owner == r && !c.complete
}

// Rotation only occurs in an original retained runtime, never the initial
// Apply, a reopened journal, a copied resource or an unfinished native probe.
func (r *mihomoLiveResource) rotateMihomoTransit(ctx context.Context) error {
	if r == nil || r.self != r || r.scope == nil || r.scope.mihomoLive != r {
		return errMihomoLiveMaterial
	}
	s := r.scope
	s.mu.Lock()
	if !s.retained {
		s.mu.Unlock()
		return nil
	}
	if s.pending || s.failure != nil || r.transitHistory != nil || r.historyAdmission == nil {
		failure := s.failure
		s.mu.Unlock()
		return errors.Join(ErrExecutionJournal, failure)
	}
	if err := r.localRecord(ctx, true); err != nil {
		s.mu.Unlock()
		return errors.Join(ErrExecutionJournal, err)
	}
	cursor, err := r.prepareTransitArchiveLocked()
	s.mu.Unlock()
	if err != nil || cursor == nil {
		return err
	}
	if err := r.historyAdmission.CheckWrite(ctx, 8); err != nil {
		return err
	}
	if err := r.records.current(ctx, true); err != nil {
		return err
	}
	if err := r.transitArchivePeakBudget(ctx, len(cursor.image)); err != nil {
		return err
	}
	cleanup, err := r.control.ReviewExclusiveCleanup(ctx)
	if err != nil {
		return err
	}
	c, end, err := r.operation(ctx, cleanup, false)
	if err != nil {
		return err
	}
	defer end()
	s.mu.Lock()
	current, marshalErr := json.Marshal(s.execution)
	if marshalErr != nil || !bytes.Equal(current, cursor.before) || s.pending || s.failure != nil || r.transitHistory != nil {
		s.mu.Unlock()
		return ErrExecutionJournal
	}
	r.transitHistory = cursor
	s.pending = true // Only this original cursor may settle this metadata fence.
	s.mu.Unlock()
	if err := cursor.create(c); err != nil {
		return err
	}
	return cursor.finish(c, cleanup)
}

// Scope.mu is held; no sources, observers or native commands are called here.
func (r *mihomoLiveResource) prepareTransitArchiveLocked() (*mihomoTransitArchiveCursor, error) {
	s := r.scope
	if s.execution == nil || s.execution.State != "committed" || s.execution.MihomoTransitHistoryArchive != nil || s.execution.DomainDNSCoexistence != nil {
		return nil, ErrExecutionJournal
	}
	type cohortKey struct {
		generation string
		index      int
		source     netip.Addr
	}
	groups := map[cohortKey][]ExecutionResource{}
	var order []cohortKey
	for _, row := range s.execution.Resources {
		if row.Kind != "node-transit" || row.State != "removed" && row.State != "unused" {
			continue
		}
		owner := s.issued[row.ID]
		if owner == nil || row.NodeTransit == nil || *row.NodeTransit != owner.spec || row.Generation != owner.digest || row.EffectsDigest != owner.effects {
			return nil, ErrExecutionJournal
		}
		if !mihomoTransitJoinedRow(owner, row) {
			continue
		} // Retain unjoined owners, never retire their callbacks.
		key := cohortKey{row.NodeTransit.PolicyGeneration, row.NodeTransit.IfIndex, row.NodeTransit.Source}
		if _, found := groups[key]; !found {
			order = append(order, key)
		}
		groups[key] = append(groups[key], row)
	}
	var rows []ExecutionResource
	for _, key := range order {
		if len(groups[key]) >= mihomoTransitArchiveRows {
			rows = groups[key]
			break
		}
	}
	if len(rows) < mihomoTransitArchiveRows {
		return nil, nil
	}
	selected := map[string]*executionTransitResource{}
	for _, row := range rows {
		selected[row.ID] = s.issued[row.ID]
	}
	before, err := json.Marshal(s.execution)
	if err != nil {
		return nil, err
	}
	after := *s.execution
	after.Resources = nil
	for _, row := range s.execution.Resources {
		if selected[row.ID] == nil {
			after.Resources = append(after.Resources, row)
		}
	}
	after.Resources = cloneExecutionResources(after.Resources)
	afterImage, err := json.Marshal(after)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	archive := Execution{PlanID: "dp-check-" + strings.Repeat("0", 32), ResourcePlanID: s.execution.PlanID, Digest: s.execution.Digest, State: "temporary-complete", StartedAt: now, FinishedAt: now, Resources: cloneExecutionResources(rows), Steps: []ExecutionStep{{Adapter: "mihomo", Phase: "archive-joined-transit", State: "passed", StartedAt: now, FinishedAt: now}}}
	marker := &MihomoTransitHistoryArchive{Schema: 1, OriginExecutionID: s.execution.PlanID, OriginPlanID: s.execution.PlanID, OriginDigest: s.execution.Digest, OriginBefore: bytes.Clone(before), OriginBeforeSHA256: nodeDefaultSourceMaterialHash(before), OriginAfterSHA256: nodeDefaultSourceMaterialHash(afterImage)}
	archive.MihomoTransitHistoryArchive = marker
	if err := marker.validate(archive); err != nil {
		return nil, err
	}
	image, err := json.Marshal(archive)
	if err != nil {
		return nil, err
	}
	cursor := &mihomoTransitArchiveCursor{owner: r, before: before, after: afterImage, archive: archive, image: image, selected: selected}
	cursor.self = cursor
	return cursor, nil
}

func (r *mihomoLiveResource) resumeTransitArchive(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview) error {
	if r == nil || r.self != r || r.scope == nil {
		return ErrExecutionJournal
	}
	if r.transitHistory == nil {
		return nil
	}
	c, end, err := r.operation(ctx, cleanup, false)
	if err != nil {
		return err
	}
	defer end()
	return r.transitHistory.finish(c, cleanup)
}

func (c *mihomoTransitArchiveCursor) finish(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview) error {
	if c == nil || c.self != c || c.owner == nil || c.owner.transitHistory != c || c.complete || cleanup == nil {
		return ErrExecutionJournal
	}
	if c.closeErr != nil {
		return errors.Join(ErrExecutionJournal, c.closeErr)
	}
	r, s := c.owner, c.owner.scope
	if r.control == nil || s == nil || r.records == nil {
		return ErrExecutionJournal
	}
	if err := r.control.CurrentForCleanupOperation(ctx, cleanup); err != nil {
		return err
	}
	if !c.durable {
		if c.file == nil {
			if err := c.create(ctx); err != nil {
				return err
			}
		}
		if err := c.publish(ctx); err != nil {
			return err
		}
	}
	if err := c.archiveCurrent(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	if !s.open || !s.retained || !s.pending || s.failure != nil || s.mihomoLive != r {
		failure := s.failure
		s.mu.Unlock()
		return errors.Join(ErrExecutionJournal, failure)
	}
	for _, row := range c.archive.Resources {
		id, owner := row.ID, c.selected[row.ID]
		if owner == nil || s.issued[id] != owner || !mihomoTransitJoinedRow(owner, row) {
			s.mu.Unlock()
			return ErrExecutionJournal
		}
	}
	current, err := json.Marshal(s.execution)
	if err != nil || !bytes.Equal(current, c.before) && !bytes.Equal(current, c.after) {
		s.mu.Unlock()
		return ErrExecutionJournal
	}
	if err := c.originalImages(ctx); err != nil {
		s.mu.Unlock()
		return err
	}
	if !c.originACK {
		var after Execution
		if json.Unmarshal(c.after, &after) != nil || validateExecutionResources(after, true) != nil {
			s.mu.Unlock()
			return ErrExecutionJournal
		}
		s.execution = &after
		// This metadata cursor owns its recoverable publication fence. Generic
		// persist would poison unrelated scope.failure on a partial writer ACK.
		// The SAME validated Manager writer and two original retained sinks run;
		// no prior/foreign failure is cleared or ignored.
		c.publishing = true
		err = func() error {
			defer func() { c.publishing = false }()
			return s.manager.writeExecutionOwned(s.root, *s.execution, s)
		}()
		if err == nil {
			err = r.records.current(ctx, true)
		}
		if err != nil {
			s.mu.Unlock()
			return err
		}
		c.originACK = true
	}
	s.mu.Unlock()
	if err := errors.Join(r.control.CurrentForCleanupOperation(ctx, cleanup), c.closeArchive(ctx)); err != nil {
		return err
	}
	if err := c.archiveCurrent(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.pending || s.failure != nil || r.transitHistory != c || !c.originACK || !c.fileClosed || !c.rootClosed || c.closeErr != nil {
		return errors.Join(ErrExecutionJournal, s.failure, c.closeErr)
	}
	if err := r.records.current(ctx, true); err != nil {
		return err
	}
	r.records.mu.Lock()
	afterMatches := bytes.Equal(r.records.images[0], c.after) && bytes.Equal(r.records.images[1], c.after)
	r.records.mu.Unlock()
	if !afterMatches {
		return ErrExecutionJournal
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.historyIDs == nil {
		r.historyIDs = map[string]struct{}{}
	}
	for id, owner := range c.selected {
		if s.issued[id] != owner || !owner.finished {
			return ErrExecutionJournal
		}
	}
	for id, owner := range c.selected {
		// Maps lose callbacks only after durable archive + both writer ACKs and
		// actual archive descriptor close ACK. Old closures still fail identity.
		delete(s.issued, id)
		owner.readback = nil
		r.historyIDs[id] = struct{}{}
	}
	c.complete, s.pending, r.transitHistory = true, false, nil
	return nil
}

func mihomoTransitJoinedRow(owner *executionTransitResource, row ExecutionResource) bool {
	return owner != nil && owner.finished && (row.State == "removed" && owner.admitted || row.State == "unused" && owner.unusedSettled)
}

func (c *mihomoTransitArchiveCursor) originalImages(ctx context.Context) error {
	d := c.owner.records
	if err := d.current(ctx, false); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, image := range d.images {
		if !bytes.Equal(image, c.before) && !bytes.Equal(image, c.after) {
			return ErrExecutionJournal
		}
	}
	return nil
}
