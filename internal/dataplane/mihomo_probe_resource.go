package dataplane

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"reflect"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

type mihomoProbeResource struct {
	self            *mihomoProbeResource
	adapter         *MihomoProbeAdapter
	scope           *executionResourceScope
	source          *components.MihomoProbeSource
	control         *operationgate.ControlEpochReview
	cleanup         *operationgate.ExclusiveCleanupReview
	definition      ExecutionMihomoProbeDefinition
	id              string
	records         *xraySelectedTCPExecutionRecords // Existing two-original-writer reader, no engine authority.
	child           *components.MihomoProbeProcess
	attempted       bool
	settled         bool
	actionErr       error
	terminalWritten bool
	closeAttempted  bool
	closeErr        error
	result          MihomoServiceProbe
}

func (a *MihomoProbeAdapter) issueProbe(ctx context.Context, source *components.MihomoProbeSource, control *operationgate.ControlEpochReview, cleanup *operationgate.ExclusiveCleanupReview, d ExecutionMihomoProbeDefinition) (*mihomoProbeResource, error) {
	s, ok := ctx.Value(syntheticExecutionRegistrarKey{}).(*executionResourceScope)
	if !ok || s == nil || !s.mihomoProof || s.adapterOwner != a || s.adapter != "mihomo" || s.mihomo != nil || d.validate() != nil || !reflect.DeepEqual(s.plan, mihomoProbePlan(d)) || !source.OwnedBy(a.components) {
		return nil, ErrMihomoProbe
	}
	if err := source.Current(ctx); err != nil {
		return nil, err
	}
	if source.Reference() != d.Source {
		return nil, ErrMihomoProbe
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	records, err := newXraySelectedTCPRecords(s)
	if err != nil {
		return nil, err
	}
	r := &mihomoProbeResource{adapter: a, scope: s, source: source, control: control, cleanup: cleanup, definition: d.Clone(), id: "mp-" + hex.EncodeToString(nonce[:]), records: records}
	r.self = r
	s.startMu.RLock()
	defer s.startMu.RUnlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mihomo != nil || s.checkOriginalOwner(ctx, nil, true, false) != nil || s.resourceCount() != 0 {
		_ = records.close()
		return nil, ErrMihomoProbe
	}
	a.mu.Lock()
	if !a.busy || a.pending != nil {
		a.mu.Unlock()
		_ = records.close()
		return nil, ErrMihomoProbe
	}
	a.pending = r
	a.mu.Unlock()
	s.mihomo = r
	copy := d.Clone()
	s.execution.Resources = append(s.execution.Resources, ExecutionResource{ID: r.id, Kind: "mihomo-probe", State: "prepared", Phase: "planned", Generation: d.Source.ConfigSHA256, EffectsDigest: d.Source.ConfigSHA256, MihomoProbe: &copy})
	return r, s.persist()
}

// Caller holds scope.mu. Serialized equality supplements original pointer
// ownership; it never creates a resource or permits a second launch.
func (r *mihomoProbeResource) local(ctx context.Context, forward bool) error {
	if r == nil || r.self != r || r.scope == nil || r.scope.mihomo != r || !r.scope.mihomoProof || r.scope.adapterOwner != r.adapter || r.source == nil || !r.source.OwnedBy(r.adapter.components) || ctx.Value(syntheticExecutionRegistrarKey{}) != r.scope || r.source.Reference() != r.definition.Source {
		return ErrMihomoProbe
	}
	r.adapter.mu.Lock()
	original := r.adapter.pending == r
	r.adapter.mu.Unlock()
	if !original || len(r.scope.execution.Resources) != 1 {
		return ErrMihomoProbe
	}
	row := r.scope.execution.Resources[0]
	if row.ID != r.id || validateMihomoProbeExecutionResource(*r.scope.execution, row, false) != nil || !reflect.DeepEqual(row.MihomoProbe, &r.definition) {
		return ErrMihomoProbe
	}
	return r.scope.checkOriginalOwner(ctx, nil, forward, !forward)
}

func (r *mihomoProbeResource) current(ctx context.Context) error {
	if r == nil || r.self != r || xraySelectedTCPFinite(ctx) != nil {
		return ErrMihomoProbe
	}
	if err := r.source.Current(ctx); err != nil {
		return err
	}
	if err := r.control.Current(ctx); err != nil {
		return err
	}
	if err := r.records.current(ctx, true); err != nil {
		return err
	}
	if err := r.scope.manager.checkPlanNetwork(ctx, r.scope.plan); err != nil {
		return err
	}
	if err := verifyNetworkProfile(ctx, r.definition.NetworkProfile, r.scope.manager.FreshProfile); err != nil {
		return err
	}
	if err := checkNodeResource(ctx, r.definition.Source.ServerHost, r.definition.Source.Endpoint); err != nil {
		return err
	}
	identity, err := r.adapter.provider.Observe(ctx)
	if err != nil || identity != r.definition.NetworkIdentity {
		return errors.Join(err, ErrMihomoProbe)
	}
	r.scope.mu.Lock()
	defer r.scope.mu.Unlock()
	return r.local(ctx, true)
}

func (r *mihomoProbeResource) phase(ctx context.Context, phase string, forward bool) error {
	r.scope.mu.Lock()
	defer r.scope.mu.Unlock()
	if err := r.local(ctx, forward); err != nil {
		return err
	}
	row := &r.scope.execution.Resources[0]
	row.Phase = phase
	if phase == "removed" || phase == "unused" {
		row.State = phase
	}
	return r.scope.persist()
}

func (r *mihomoProbeResource) start(ctx context.Context, begin func() error) error {
	if begin == nil || r.attempted {
		return ErrMihomoProbe
	}
	if err := r.current(ctx); err != nil {
		return err
	}
	if err := r.phase(ctx, "process-pending", true); err != nil {
		return err
	}
	r.scope.startMu.RLock()
	defer r.scope.startMu.RUnlock()
	r.scope.mu.Lock()
	err := r.local(ctx, true)
	r.scope.mu.Unlock()
	if err != nil {
		return err
	}
	r.attempted = true
	return begin() // Components enters its actual original control.WithStart.
}

func (r *mihomoProbeResource) publishRecords(data []byte) error {
	if r == nil || r.self != r || r.records == nil || r.records.scope != r.scope || r.scope.mihomo != r {
		return ErrExecutionJournal
	}
	d := r.records
	if r.attempted {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		if err := d.current(ctx, false); err != nil {
			return err
		}
	} else if err := d.beforePublication(); err != nil {
		return err
	}
	var result error
	for i := range 2 {
		result = errors.Join(result, d.publishOriginalDurable(i, data, syncDataplaneJournalDirectory))
	}
	return result
}

func (r *mihomoProbeResource) finish(ctx context.Context, actionErr error) error {
	r.actionErr = errors.Join(r.actionErr, actionErr)
	if !r.settled {
		r.scope.cancel()
		return errors.Join(actionErr, components.ErrMihomoProbePending)
	}
	s := r.scope
	s.cancel()
	s.observationOpen.Store(false)
	if r.closeAttempted {
		return r.closeErr
	}
	if !r.terminalWritten {
		s.mu.Lock()
		e := s.execution
		e.State = "temporary-complete"
		e.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		e.Steps[0].State, e.Steps[0].FinishedAt = "passed", e.FinishedAt
		if r.actionErr != nil {
			e.Error, e.Steps[0].Detail, e.Steps[0].State = r.actionErr.Error(), r.actionErr.Error(), "failed"
		}
		err := s.persist()
		s.mu.Unlock()
		if err != nil {
			return errors.Join(actionErr, err)
		}
		if err := r.records.current(ctx, true); err != nil {
			return errors.Join(actionErr, err)
		}
	}
	r.terminalWritten = true
	// Descriptors are never adopted/reopened after partial close. Keep the
	// exact close failure fenced, rather than calling a closed FD a proof.
	r.closeAttempted = true
	r.closeErr = errors.Join(r.source.Close(), r.records.close(), s.owned.Close())
	if r.closeErr != nil {
		return errors.Join(actionErr, r.closeErr)
	}
	s.mu.Lock()
	s.open = false
	s.closedErr = nil
	s.mu.Unlock()
	r.adapter.mu.Lock()
	if r.adapter.pending == r {
		r.adapter.pending = nil
	}
	r.adapter.mu.Unlock()
	return actionErr
}
