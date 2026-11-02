package dataplane

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

// This issuer is reachable only through the actual Manager operation. The
// definition is comparison data; source, node, profile and control retain their
// original owners independently of both journal files.
func (a *MihomoProbeAdapter) issueLive(ctx context.Context, source *components.MihomoLiveSource, node *NodeDefaultSourceReview, profile *components.MihomoLiveProfile, history *updatecheck.ExecutionHistoryAdmission, control, childControl *operationgate.ControlEpochReview, definition ExecutionMihomoLiveDefinition) (*mihomoLiveResource, error) {
	if a == nil || a.self != a || xraySelectedTCPFinite(ctx) != nil || source == nil || node == nil || profile == nil || history == nil || control == nil || childControl == nil || control == childControl || control.Reference() != childControl.Reference() {
		return nil, fmt.Errorf("live issuer argument/control binding: %w", errMihomoLiveMaterial)
	}
	s, ok := ctx.Value(syntheticExecutionRegistrarKey{}).(*executionResourceScope)
	if !ok || s == nil || s.mihomoProof || s.adapterOwner != a || s.adapter != "mihomo" {
		return nil, fmt.Errorf("live issuer original scope binding: %w", errMihomoLiveMaterial)
	}
	if definition.validate() != nil || definition.Observation != nil || definition.NativeHome != nil {
		return nil, fmt.Errorf("live issuer frozen definition: %w", errMihomoLiveMaterial)
	}
	if !reflect.DeepEqual(s.plan, definition.Plan) {
		return nil, fmt.Errorf("live issuer frozen plan comparison: %w", errMihomoLiveMaterial)
	}
	if !source.OwnedBy(a.components) || source.Reference() != definition.Source || node.Reference() != definition.Node {
		return nil, fmt.Errorf("live issuer original source references: %w", errMihomoLiveMaterial)
	}
	// Admit the typed reader before the first journal containing its intent.
	if err := history.CheckWrite(ctx, 6); err != nil {
		return nil, err
	}
	if err := errors.Join(source.Current(ctx), node.Current(ctx), control.Current(ctx), childControl.Current(ctx)); err != nil {
		return nil, err
	}
	ref, err := source.ReviewProfileReference(ctx, profile)
	if err != nil || ref != definition.Profile {
		return nil, errors.Join(errMihomoLiveMaterial, err)
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	digest, err := definition.FrozenDigest()
	if err != nil {
		return nil, err
	}
	records, err := newXraySelectedTCPRecords(s)
	if err != nil {
		return nil, err
	}
	r := &mihomoLiveResource{adapter: a, scope: s, source: source, node: node, profile: profile, control: control, childControl: childControl, definition: definition.Clone(), id: "ml-" + hex.EncodeToString(nonce[:]), records: records}
	r.self = r
	s.startMu.RLock()
	defer s.startMu.RUnlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mihomoLive != nil || s.mihomo != nil || s.resourceCount() != 0 {
		return nil, fmt.Errorf("live issuer existing scope slot: %w", errors.Join(errMihomoLiveMaterial, records.close()))
	}
	if s.checkOriginalOwner(ctx, nil, true, false) != nil {
		return nil, fmt.Errorf("live issuer closing original scope: %w", errors.Join(errMihomoLiveMaterial, records.close()))
	}
	a.mu.Lock()
	if a.pending != nil || a.livePending != nil || a.liveActive != nil {
		a.mu.Unlock()
		return nil, fmt.Errorf("live issuer existing adapter slot: %w", errors.Join(errMihomoLiveMaterial, records.close()))
	}
	a.livePending = r
	a.mu.Unlock()
	s.mihomoLive = r
	d := definition.Clone()
	s.execution.Resources = append(s.execution.Resources, ExecutionResource{ID: r.id, Kind: "mihomo-live", State: "prepared", Phase: "reserved", Generation: d.Profile.ConfigSHA256, EffectsDigest: digest, MihomoLive: &d})
	// A partial publication must return the SAME retained owner for cleanup.
	return r, s.persist()
}

// Caller holds scope.mu. This does not observe expensive sources while holding
// that lock; every forward caller bookends it with actual original checks.
func (r *mihomoLiveResource) localRecord(ctx context.Context, forward bool) error {
	if r == nil || r.self != r || r.scope == nil || r.scope.mihomoLive != r || r.scope.adapterOwner != r.adapter || ctx == nil || ctx.Value(syntheticExecutionRegistrarKey{}) != r.scope || r.records == nil || r.records.scope != r.scope {
		return errMihomoLiveMaterial
	}
	r.adapter.mu.Lock()
	original := r.adapter.livePending == r || r.adapter.liveActive == r
	r.adapter.mu.Unlock()
	if !original {
		return errMihomoLiveMaterial
	}
	if _, err := r.recordIndex(); err != nil {
		return err
	}
	if r.scope.retained {
		if err := r.scope.checkRetainedMihomoOperation(ctx, forward); err != nil {
			return err
		}
	}
	return r.scope.checkOriginalOwner(ctx, nil, forward, !forward)
}

func (r *mihomoLiveResource) currentBeforeStart(ctx context.Context) error {
	if r == nil || r.self != r || xraySelectedTCPFinite(ctx) != nil || r.source == nil || r.node == nil || r.control == nil || r.scope == nil || r.adapter == nil {
		return errMihomoLiveMaterial
	}
	if err := errors.Join(r.source.Current(ctx), r.node.Current(ctx), r.control.Current(ctx), r.records.current(ctx, true)); err != nil {
		return err
	}
	ref, err := r.source.ReviewProfileReference(ctx, r.profile)
	if err != nil || ref != r.definition.Profile || r.source.Reference() != r.definition.Source || r.node.Reference() != r.definition.Node {
		return errors.Join(errMihomoLiveMaterial, err)
	}
	if err := r.scope.manager.checkPlanNetwork(ctx, r.scope.plan); err != nil {
		return err
	}
	if err := r.scope.guard(ctx); err != nil {
		return err
	}
	identity, err := r.adapter.provider.Observe(ctx)
	if err != nil || identity != r.definition.NetworkIdentity {
		return errors.Join(errMihomoLiveMaterial, err)
	}
	if err := r.resourceBoundary(ctx, "", netip.Addr{}); err != nil {
		return err
	}
	if err := r.liveEndpointsCurrent(ctx); err != nil {
		return err
	}
	r.scope.mu.Lock()
	defer r.scope.mu.Unlock()
	return r.localRecord(ctx, true)
}

func (r *mihomoLiveResource) beforeValidation(ctx context.Context, child *components.MihomoLiveProcess) error {
	if child == nil || r == nil {
		return errMihomoLiveMaterial
	}
	if err := r.currentBeforeStart(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	original := r.child == child && r.reserveAttempted && !r.closed && r.closeErr == nil
	r.mu.Unlock()
	if !original {
		return errMihomoLiveMaterial
	}
	home, err := child.NativeHomeReference(ctx)
	if err != nil || home.Validate() != nil {
		return errors.Join(errMihomoLiveMaterial, err)
	}
	r.scope.mu.Lock()
	defer r.scope.mu.Unlock()
	if r.validationUsed || r.localRecord(ctx, true) != nil {
		return errMihomoLiveMaterial
	}
	r.validationUsed = true
	index, err := r.recordIndex()
	if err != nil {
		return err
	}
	r.definition.NativeHome = &home
	d := r.definition.Clone()
	r.scope.execution.Resources[index].MihomoLive = &d
	r.scope.execution.Resources[index].Phase = "validation-pending"
	return r.scope.persist()
}

func (r *mihomoLiveResource) admitNativeStart(ctx context.Context, begin func() error) error {
	if begin == nil || r == nil {
		return errMihomoLiveMaterial
	}
	if err := r.currentBeforeStart(ctx); err != nil {
		return err
	}
	r.scope.startMu.RLock()
	defer r.scope.startMu.RUnlock()
	r.scope.mu.Lock()
	if !r.validationUsed || r.startUsed || r.localRecord(ctx, true) != nil {
		r.scope.mu.Unlock()
		return errMihomoLiveMaterial
	}
	r.startUsed = true
	index, err := r.recordIndex()
	if err != nil {
		r.scope.mu.Unlock()
		return err
	}
	r.scope.execution.Resources[index].Phase = "process-pending"
	err = r.scope.persist()
	r.scope.mu.Unlock()
	if err != nil {
		return err
	}
	if err := r.currentBeforeStart(ctx); err != nil {
		return err
	}
	// Components permits this synchronous call only on its pinned creator
	// thread, once, under its original control.WithStart barrier.
	err = begin()
	return errors.Join(err, r.currentBeforeStart(ctx))
}

// Called by the existing writer while scope.mu is held. No pathname read can
// synthesize these two retained FDs; partial writes retain the first real ACK.
func (r *mihomoLiveResource) publishRecords(data []byte) error {
	if r == nil || r.self != r || r.scope == nil || r.scope.mihomoLive != r || r.records == nil || r.records.scope != r.scope {
		return ErrExecutionJournal
	}
	d := r.records
	if r.validationUsed || r.startUsed {
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

func validateMihomoLiveExecutionResource(execution Execution, r ExecutionResource, terminal bool) error {
	d := r.MihomoLive
	planID := execution.PlanID
	if execution.ResourcePlanID != "" {
		planID = execution.ResourcePlanID
	}
	if d == nil || r.Kind != "mihomo-live" || d.validate() != nil || d.Plan.PlanID != planID || d.Plan.Digest != execution.Digest || r.Generation != d.Profile.ConfigSHA256 || r.NodeTransit != nil || r.NFQWS != nil || r.SyntheticBaseline != nil || r.XraySelectedTCP != nil || r.XrayDomainTCP != nil || r.DomainTCPCapture != nil || r.DomainTCPBaseline != nil || r.MihomoProbe != nil {
		return ErrExecutionJournal
	}
	if (r.Phase == "sidecar-bound" || r.Phase == "policy-pending") && d.Observation == nil {
		return ErrExecutionJournal
	}
	if r.Phase != "reserved" && r.Phase != "closed" && r.Phase != "removed" && r.Phase != "unused" && d.NativeHome == nil {
		return ErrExecutionJournal
	}
	digest, err := d.FrozenDigest()
	if err != nil || digest != r.EffectsDigest {
		return ErrExecutionJournal
	}
	switch r.Phase {
	case "reserved", "validation-pending", "process-pending", "listener-bound", "sidecar-pending", "sidecar-bound", "policy-pending", "closed":
		if r.State != "prepared" || terminal {
			return ErrExecutionJournal
		}
	case "active":
		if r.State != "active" || d.validateActive() != nil || execution.State != "committing" && execution.State != "committed" && execution.State != "rolling-back" && execution.State != "rollback-failed" {
			return ErrExecutionJournal
		}
	case "removed":
		if r.State != "removed" {
			return ErrExecutionJournal
		}
	case "unused":
		if r.State != "unused" || d.Observation != nil || d.NativeHome != nil {
			return ErrExecutionJournal
		}
	default:
		return ErrExecutionJournal
	}
	return nil
}

// Called with scope.mu held. TUN service checks may append temporary transit
// rows, but only the same scope's originally issued owners may coexist here.
func (r *mihomoLiveResource) recordIndex() (int, error) {
	if r == nil || r.scope == nil || r.scope.execution == nil || validateExecutionResources(*r.scope.execution, false) != nil {
		return -1, ErrExecutionJournal
	}
	index := -1
	for i, row := range r.scope.execution.Resources {
		if row.ID == r.id {
			if index != -1 || validateMihomoLiveExecutionResource(*r.scope.execution, row, false) != nil || !reflect.DeepEqual(row.MihomoLive, &r.definition) {
				return -1, ErrExecutionJournal
			}
			index = i
			continue
		}
		owner := r.scope.issued[row.ID]
		if row.Kind != "node-transit" || owner == nil || row.NodeTransit == nil || *row.NodeTransit != owner.spec || row.Generation != owner.digest || row.EffectsDigest != owner.effects || owner.spec.PlanID != r.definition.Plan.PlanID || owner.spec.PlanDigest != r.definition.Plan.Digest {
			return -1, ErrExecutionJournal
		}
	}
	if index < 0 {
		return -1, ErrExecutionJournal
	}
	return index, nil
}
