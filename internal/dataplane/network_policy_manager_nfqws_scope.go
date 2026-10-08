package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"time"
)

type nfqwsExecutionReadbackMode string

const (
	nfqwsExecutionBeforeStart nfqwsExecutionReadbackMode = "before-start"
	nfqwsExecutionPrepared    nfqwsExecutionReadbackMode = "prepared"
	nfqwsExecutionRemoved     nfqwsExecutionReadbackMode = "removed"
)

// Only the actual owner installs this private read-only producer. The
// registrar supplies full immutable compiler input and its anchored childroot.
type nfqwsExecutionReadback func(context.Context, *NFQWSScopedPlan, string, nfqwsExecutionReadbackMode) error
type nfqwsExecutionReadbackKey struct{}
type nfqwsExecutionRegistrar func(context.Context, NFQWSScopedSpec) (*NFQWSExecutionResource, error)
type nfqwsExecutionRegistrarKey struct{}

// NFQWSExecutionResource is a borrowed live capability, never a saved launch
// permission. Its lifetime is the existing Manager operation. The managed
// owner must use the private parent/helper channel for the real Start ACK.
type NFQWSExecutionResource struct {
	scope             *executionResourceScope
	plan              *NFQWSScopedPlan
	binding           NFQWSExecutionBinding
	root              string
	relative          string
	anchor            os.FileInfo
	readback          nfqwsExecutionReadback
	beforeUsed        bool
	startReady        bool
	startUsed         bool
	startACK          bool
	preparedUsed      bool
	activeCommand     *nfqws2ActiveProcessCommand
	activeReadback    nfqwsExecutionActiveReadback
	activeObservation *NFQWSActiveObservation
	transferUsed      bool
	preparedOwner     *NFQWSPreparedHandle
	transferGuards    *nfqwsExecutionTransferGuards
	transferEntered   bool
	transferACK       bool
	finalOwner        *NFQWSActiveHandle
}

// AcquireNFQWSExecutionResource requires the private issuer and actual owner
// readback in this Manager's context. A spec or persisted binding cannot issue.
func AcquireNFQWSExecutionResource(ctx context.Context, spec NFQWSScopedSpec) (*NFQWSExecutionResource, error) {
	if ctx == nil {
		return nil, ErrNFQWSScopedOwner
	}
	issue, ok := ctx.Value(nfqwsExecutionRegistrarKey{}).(nfqwsExecutionRegistrar)
	if !ok || issue == nil {
		return nil, ErrNFQWSScopedOwner
	}
	return issue(ctx, spec)
}

func (r *NFQWSExecutionResource) Binding() NFQWSExecutionBinding {
	if r == nil {
		return NFQWSExecutionBinding{}
	}
	return r.binding
}

func (r *NFQWSExecutionResource) Plan() *NFQWSScopedPlan {
	if r == nil {
		return nil
	}
	return r.plan // The compiler's public accessors return detached values.
}

func (r *NFQWSExecutionResource) Root() string {
	if r == nil {
		return ""
	}
	return r.root
}

func (s *executionResourceScope) issueNFQWS(ctx context.Context, spec NFQWSScopedSpec) (*NFQWSExecutionResource, error) {
	if ctx == nil {
		return nil, ErrNFQWSScopedOwner
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	readback, ok := ctx.Value(nfqwsExecutionReadbackKey{}).(nfqwsExecutionReadback)
	if !ok || readback == nil || s.adapter != "nfqws2" || s.resourceCount() >= maxExecutionResources {
		return nil, ErrNFQWSScopedOwner
	}
	if err := s.check(ctx, nil, true); err != nil {
		return nil, err
	}
	if (s.networkIdentity != nil) != (spec.NetworkIdentity != nil) {
		return nil, ErrNetworkPolicyIdentity
	}
	if s.networkIdentity != nil {
		if err := nfqwsExecutionNetworkMatches(s.networkIdentity.value, spec); err != nil {
			return nil, err
		}
	}
	if _, err := s.plan.FrozenLAN(); err != nil {
		return nil, err
	}
	compiled, err := CompileNFQWSScopedPlan(s.plan, spec)
	if err != nil {
		return nil, err
	}
	for _, existing := range s.execution.Resources {
		if existing.NFQWS != nil && (existing.NFQWS.Spec.SessionID == spec.SessionID || existing.State == "prepared" && existing.NFQWS.Spec.Queue == spec.Queue && existing.NFQWS.Spec.NetNamespace == spec.NetNamespace) {
			return nil, ErrNFQWSScopedOwner
		}
	}
	if err := s.owned.MkdirAll("execution-resources", 0700); err != nil {
		return nil, executionJournalError(err)
	}
	relative, err := s.owned.MkdirTemp("execution-resources", "nq-")
	if err != nil {
		return nil, executionJournalError(err)
	}
	anchor, err := s.owned.Stat(relative)
	if err != nil {
		return nil, executionJournalError(err)
	}
	metadata := compiled.Resources()
	r := &NFQWSExecutionResource{scope: s, plan: compiled, root: filepath.Join(s.root, relative), relative: relative, anchor: anchor, readback: readback,
		binding: NFQWSExecutionBinding{ExecutionID: s.execution.PlanID, PlanID: s.plan.PlanID, PlanDigest: s.plan.Digest, ResourceID: filepath.Base(relative),
			ResourceGeneration: metadata.Generation, EffectsDigest: compiled.Digest(), SessionID: spec.SessionID, CommandSHA256: spec.CommandSHA256}}
	for _, path := range []string{r.root, filepath.Dir(r.root), s.root} {
		opened, err := openJournalDirectory(path)
		if err != nil {
			return nil, executionJournalError(err)
		}
		err = syncDataplaneJournalDirectory(opened)
		_ = opened.Close()
		if err != nil {
			return nil, executionJournalError(err)
		}
	}
	s.nfqws[r.binding.ResourceID] = r
	s.execution.Resources = append(s.execution.Resources, ExecutionResource{ID: r.binding.ResourceID, Kind: "nfqws-scoped", State: "prepared", Phase: "planned",
		Generation: metadata.Generation, EffectsDigest: compiled.Digest(), NFQWS: &ExecutionNFQWSDefinition{Plan: cloneExecutionResourcePlan(s.plan), Spec: compiled.Spec()}})
	if s.networkIdentity != nil {
		identity := s.networkIdentity.value
		s.execution.Resources[len(s.execution.Resources)-1].NFQWS.NetworkIdentity = &identity
	}
	// Retain the entire reservation BEFORE any ownership intent/helper process.
	if err := s.persist(); err != nil {
		return nil, err
	}
	return r, nil
}

// Called with metadata mutex held; owner proofs always run outside it.
func (r *NFQWSExecutionResource) matching(binding NFQWSExecutionBinding) (int, error) {
	if r == nil || r.scope == nil || binding != r.binding || r.scope.nfqws[binding.ResourceID] != r {
		return -1, ErrNFQWSScopedOwner
	}
	for i, recorded := range r.scope.execution.Resources {
		if recorded.ID == binding.ResourceID {
			if recorded.Kind != "nfqws-scoped" || recorded.State != "prepared" || recorded.NFQWS == nil || recorded.NodeTransit != nil ||
				recorded.Generation != binding.ResourceGeneration || recorded.EffectsDigest != binding.EffectsDigest ||
				!reflect.DeepEqual(recorded.NFQWS.Plan, r.scope.plan) || !reflect.DeepEqual(recorded.NFQWS.Spec, r.plan.Spec()) {
				return -1, ErrNFQWSScopedOwner
			}
			identity := r.scope.networkIdentity
			if identity == nil && recorded.NFQWS.NetworkIdentity != nil || identity != nil && (recorded.NFQWS.NetworkIdentity == nil || *recorded.NFQWS.NetworkIdentity != identity.value) {
				return -1, ErrNFQWSScopedOwner
			}
			if identity == nil && recorded.NFQWS.Spec.NetworkIdentity != nil || identity != nil && nfqwsExecutionNetworkMatches(identity.value, recorded.NFQWS.Spec) != nil {
				return -1, ErrNFQWSScopedOwner
			}
			if r.activeCommand == nil && (recorded.NFQWS.Mode != "" || recorded.NFQWS.Observation != nil) ||
				r.activeCommand != nil && (recorded.NFQWS.Mode != nfqws2ActiveProcessMode || nfqws2ActiveCommandMatchesSpec(*r.activeCommand, recorded.NFQWS.Spec) != nil) {
				return -1, ErrNFQWSScopedOwner
			}
			switch recorded.Phase {
			case "planned", "process-pending", "capture-ready", "transfer-intent", "transfer-ack", "closed":
			default:
				return -1, ErrNFQWSScopedOwner
			}
			return i, nil
		}
	}
	return -1, ErrNFQWSScopedOwner
}

func (r *NFQWSExecutionResource) check(ctx context.Context, forward bool) error {
	if !forward && r.activeCommand != nil {
		return r.checkOriginalCleanup(ctx)
	}
	if err := r.scope.check(ctx, &executionTransitResource{relative: r.relative, anchor: r.anchor}, forward); err != nil {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	return nil
}

// Current is read-only admission for private pre/post-start owner proofs.
// Actual capture writers MUST use ApplyGuard, which requires capture-ready.
func (r *NFQWSExecutionResource) Current(ctx context.Context, binding NFQWSExecutionBinding) error {
	if r == nil || r.scope == nil {
		return ErrNFQWSScopedOwner
	}
	r.scope.mu.Lock()
	defer r.scope.mu.Unlock()
	if _, err := r.matching(binding); err != nil {
		return err
	}
	return r.check(ctx, true)
}

// BeforeStart is one-shot: process-pending is durable before the independent
// empty-queue/all-capture/LAN readback and BEFORE process ownership intent.
func (r *NFQWSExecutionResource) BeforeStart(ctx context.Context, binding NFQWSExecutionBinding) error {
	if r == nil || r.scope == nil {
		return ErrNFQWSScopedOwner
	}
	if err := func() error {
		r.scope.mu.Lock()
		defer r.scope.mu.Unlock()
		i, err := r.matching(binding)
		if err != nil || r.beforeUsed || r.scope.execution.Resources[i].Phase != "planned" {
			return errors.Join(ErrNFQWSScopedOwner, err)
		}
		if err := r.check(ctx, true); err != nil {
			return err
		}
		r.beforeUsed = true
		r.scope.execution.Resources[i].Phase = "process-pending"
		return r.scope.persist()
	}(); err != nil {
		return err
	}
	if err := r.readback(ctx, r.plan, r.root, nfqwsExecutionBeforeStart); err != nil {
		return err
	}
	r.scope.mu.Lock()
	defer r.scope.mu.Unlock()
	if _, err := r.matching(binding); err != nil {
		return err
	}
	if err := r.check(ctx, true); err != nil {
		return err
	}
	r.startReady = true
	return nil
}

// WithStart holds the separate close barrier until the actual child Start ACK
// or bounded failure. begin must include the private live helper handshake;
// its owner bounds all I/O by the managed command deadline. CORE admission
// surrounds ONLY each Cmd.Start, never this whole callback or metadata/probes.
func (r *NFQWSExecutionResource) WithStart(ctx context.Context, binding NFQWSExecutionBinding, begin func() error) error {
	if r == nil || r.scope == nil || ctx == nil || begin == nil {
		return ErrNFQWSScopedOwner
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || deadline.After(time.Now().Add(15*time.Second)) {
		return ErrNFQWSScopedOwner
	}
	r.scope.startMu.RLock()
	defer r.scope.startMu.RUnlock()
	if err := func() error {
		r.scope.mu.Lock()
		defer r.scope.mu.Unlock()
		i, err := r.matching(binding)
		if err != nil || !r.startReady || r.startUsed || r.scope.execution.Resources[i].Phase != "process-pending" {
			return errors.Join(ErrNFQWSScopedOwner, err)
		}
		if err := r.check(ctx, true); err != nil {
			return err
		}
		r.startUsed = true // Never replay even when helper/child ACK is lost.
		return nil
	}(); err != nil {
		return err
	}
	if err := begin(); err != nil {
		return err
	}
	r.scope.mu.Lock()
	defer r.scope.mu.Unlock()
	if _, err := r.matching(binding); err != nil {
		return err
	}
	r.startACK = true
	return r.check(ctx, true)
}

// Prepared requires actual running child/queue, unchanged LAN and zero
// capture before publishing capture-ready. An ACK alone never grants capture.
func (r *NFQWSExecutionResource) Prepared(ctx context.Context, binding NFQWSExecutionBinding) error {
	if r == nil || r.scope == nil || r.activeCommand != nil {
		return ErrNFQWSScopedOwner
	}
	if err := func() error {
		r.scope.mu.Lock()
		defer r.scope.mu.Unlock()
		i, err := r.matching(binding)
		if err != nil || !r.startACK || r.preparedUsed || r.scope.execution.Resources[i].Phase != "process-pending" {
			return errors.Join(ErrNFQWSScopedOwner, err)
		}
		if err := r.check(ctx, true); err != nil {
			return err
		}
		r.preparedUsed = true
		return nil
	}(); err != nil {
		return err
	}
	if err := r.readback(ctx, r.plan, r.root, nfqwsExecutionPrepared); err != nil {
		return err
	}
	r.scope.mu.Lock()
	defer r.scope.mu.Unlock()
	i, err := r.matching(binding)
	if err != nil {
		return err
	}
	if err := r.check(ctx, true); err != nil {
		return err
	}
	r.scope.execution.Resources[i].Phase = "capture-ready"
	return r.scope.persist()
}

func (r *NFQWSExecutionResource) effectGuard(ctx context.Context, plan *NFQWSScopedPlan, effect PolicyEffect, cleanup bool) error {
	if r == nil || r.scope == nil || plan != r.plan {
		return ErrNFQWSScopedOwner
	}
	r.scope.mu.Lock()
	defer r.scope.mu.Unlock()
	i, err := r.matching(r.binding)
	if err != nil {
		return err
	}
	if !cleanup && (!r.startACK || r.scope.execution.Resources[i].Phase != "capture-ready") {
		return ErrNFQWSScopedOwner
	}
	effects, err := r.plan.Effects()
	if err != nil {
		return err
	}
	known := false
	for _, expected := range effects.Effects {
		known = known || reflect.DeepEqual(effect, expected)
	}
	if !known {
		return ErrNFQWSScopedOwner
	}
	return r.check(ctx, !cleanup)
}

func (r *NFQWSExecutionResource) ApplyGuard(ctx context.Context, plan *NFQWSScopedPlan, effect PolicyEffect) error {
	return r.effectGuard(ctx, plan, effect, false)
}

func (r *NFQWSExecutionResource) CleanupGuard(ctx context.Context, plan *NFQWSScopedPlan, effect PolicyEffect) error {
	return r.effectGuard(ctx, plan, effect, true)
}

// SettleRemoved uses the actual owner's fresh independent mixed receipt,
// ECHILD/parent ACK, queue and complete both-family capture/reference absence.
func (r *NFQWSExecutionResource) SettleRemoved(ctx context.Context) error {
	if r == nil || r.scope == nil {
		return ErrNFQWSScopedOwner
	}
	if err := func() error {
		r.scope.mu.Lock()
		defer r.scope.mu.Unlock()
		if _, err := r.matching(r.binding); err != nil {
			return err
		}
		return r.check(ctx, false)
	}(); err != nil {
		return err
	}
	if err := r.readback(ctx, r.plan, r.root, nfqwsExecutionRemoved); err != nil {
		return err
	}
	r.scope.mu.Lock()
	defer r.scope.mu.Unlock()
	i, err := r.matching(r.binding)
	if err != nil {
		return err
	}
	if err := r.check(ctx, false); err != nil {
		return err
	}
	r.scope.execution.Resources[i].State = "removed"
	r.scope.execution.Resources[i].Phase = "removed"
	return r.scope.persist()
}
