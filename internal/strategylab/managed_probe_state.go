package strategylab

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/netip"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// Persisted comparison data only. A record cannot recreate its original App,
// managed component, control, network or source owner after a restart.
type ManagedProbeEpochRecord struct {
	Scope                string `json:"scope"`
	PinnedAddress        string `json:"pinned_address"`
	ID                   string `json:"id"`
	ServiceID            string `json:"service_id"`
	CandidateID          string `json:"candidate_id"`
	Incarnation          string `json:"incarnation"`
	ValidationGeneration string `json:"validation_generation"`
	NetworkID            string `json:"network_id"`
	PolicyDigest         string `json:"policy_digest"`
	RuntimeDigest        string `json:"runtime_digest"`
	CriteriaDigest       string `json:"criteria_digest"`
}

// Implemented by the original App's held policy/WAN/catalog owner. It is a
// closing observation, never a process factory, effect admission or DTO grant.
type ManagedProbeEnvironment interface{ Current(context.Context) error }

var ErrManagedProbeContextRequired = errors.New("automatic managed selection requires its original current probe context")

func requireManagedSelectionEpoch(state State, selection Selection, epoch *ManagedProbeEpoch) error {
	if (state.SchemaVersion == managedStrategySchema || state.SchemaVersion == managedSupervisedSchema) && selection.Mode != ModeManual && epoch == nil {
		return ErrManagedProbeContextRequired
	}
	return nil
}

type ManagedProbeEpoch struct {
	self                      *ManagedProbeEpoch
	mu                        sync.Mutex
	manager                   *Manager
	source                    *CandidateProbeReview
	environment               ManagedProbeEnvironment
	record                    ManagedProbeEpochRecord
	running, complete, failed bool
	nativeSession             *compatibilitySession
}

func managedProbeKey(serviceID, candidateID string) string {
	return selectionKey(serviceID, "tcp", "ipv4") + "|" + candidateID
}

func (m *Manager) currentManagedProbeEpoch(ctx context.Context, candidateID, serviceID string) (*ManagedProbeEpoch, error) {
	key := managedProbeKey(serviceID, candidateID)
	m.mu.RLock()
	_, exists := m.state.ManagedProbeEpochs[key]
	owner := m.managedEpochs[key]
	m.mu.RUnlock()
	if !exists {
		return nil, nil
	}
	if owner == nil {
		return nil, ErrSelectedCandidateChanged
	}
	if err := owner.Current(ctx); err != nil {
		return nil, err
	}
	return owner, nil
}

func validateManagedProbeState(state State) error {
	strong := state.SchemaVersion == managedStrategySchema || state.SchemaVersion == managedSupervisedSchema
	if !strong && (len(state.ManagedProbeEpochs) > 0 || state.ManagedProbeUnknown) {
		return restorejournal.ErrInvalid
	}
	if len(state.ManagedProbeEpochs) > MaxAdaptiveScopes {
		return restorejournal.ErrInvalid
	}
	for key, record := range state.ManagedProbeEpochs {
		pin, pinErr := netip.ParseAddr(record.PinnedAddress)
		if record.Scope != "router-output-https-tcp443-ipv4" || pinErr != nil || !pin.Is4() || !pin.IsGlobalUnicast() || pin.IsPrivate() || pin.IsLoopback() || pin.IsLinkLocalUnicast() {
			return restorejournal.ErrInvalid
		}
		if !strong || key != managedProbeKey(record.ServiceID, record.CandidateID) || !selectedReviewKeyValid(record.ServiceID, "tcp", "ipv4") || !compatibilityHex(record.ID, 32) || !compatibilityHex(record.Incarnation, 32) || !compatibilityHex(record.ValidationGeneration, 32) || record.CandidateID == "" || len(record.CandidateID) > 128 || record.NetworkID == "" || len(record.NetworkID) > 128 || !compatibilityHex(record.PolicyDigest, 64) || !compatibilityHex(record.RuntimeDigest, 64) || !compatibilityHex(record.CriteriaDigest, 64) {
			return restorejournal.ErrInvalid
		}
	}
	for _, evidence := range state.Evidence {
		if evidence.ManagedEpoch != "" && (!strong || !compatibilityHex(evidence.ManagedEpoch, 32)) {
			return restorejournal.ErrInvalid
		}
	}
	return nil
}

func managedEvidenceCurrent(state State, evidence Evidence) bool {
	key := managedProbeKey(evidence.ServiceID, evidence.CandidateID)
	if evidence.ManagedEpoch == "" {
		return state.SchemaVersion != managedStrategySchema && state.SchemaVersion != managedSupervisedSchema
	}
	record, exists := state.ManagedProbeEpochs[key]
	return exists && state.managedCurrent[key] == evidence.ManagedEpoch && record.ID == evidence.ManagedEpoch && record.CandidateID == evidence.CandidateID && record.Incarnation == evidence.CandidateIncarnation && record.ValidationGeneration == evidence.ValidationGeneration && !state.ManagedProbeUnknown
}

func (m *Manager) BeginManagedProbe(ctx context.Context, source *CandidateProbeReview, environment ManagedProbeEnvironment, networkID, policyDigest string) (*ManagedProbeEpoch, error) {
	if m == nil || source == nil || source.self != source || source.material == nil || source.material.binding.manager != m || environment == nil || networkID == "" || len(networkID) > 128 || !compatibilityHex(policyDigest, 64) || selectedReviewContext(ctx) != nil {
		return nil, ErrSelectedCandidateChanged
	}
	if err := environment.Current(ctx); err != nil {
		return nil, err
	}
	reference, err := source.Reference(ctx)
	if err != nil {
		return nil, err
	}
	runtimeDigest, err := selectedReferenceDigest(source.material.descriptor)
	if err != nil {
		return nil, err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	r := &ManagedProbeEpoch{manager: m, source: source, environment: environment, record: ManagedProbeEpochRecord{ID: hex.EncodeToString(nonce[:]), ServiceID: reference.Scope.Target.ServiceID, CandidateID: reference.Material.CandidateID, Incarnation: reference.Material.Incarnation, ValidationGeneration: reference.ValidationGeneration, NetworkID: networkID, PolicyDigest: policyDigest, RuntimeDigest: runtimeDigest, CriteriaDigest: reference.Scope.CriteriaDigest}}
	r.self = r
	r.record.Scope = "router-output-https-tcp443-ipv4"
	r.record.PinnedAddress = reference.Scope.Address.String()
	// Repeated actual probes may accumulate RequiredPasses only under the SAME
	// still-current original context. Restart, revalidation or any changed
	// environment always gets a new ID; persisted strings alone cannot reuse it.
	key := managedProbeKey(r.record.ServiceID, r.record.CandidateID)
	m.mu.RLock()
	previous := m.managedEpochs[key]
	m.mu.RUnlock()
	reuseID := ""
	if previous != nil && previous.Current(ctx) == nil {
		old := previous.record
		old.ID = r.record.ID
		if reflect.DeepEqual(old, r.record) {
			reuseID = previous.record.ID
		}
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	if source.closed || m.nativeRunning || m.managedProbe != nil || m.compatibilityUnknownLocked() || m.writeBlocked {
		return nil, errCompatibilityBusy
	}
	if err := source.material.materialCurrentLocked(ctx); err != nil {
		return nil, err
	}
	retained, err := compatibilityStateCopy(m.state)
	if err != nil || retained.CompatibilitySession == nil {
		return nil, ErrSelectedCandidateChanged
	}
	r.nativeSession = retained.CompatibilitySession
	if source.material.managedEpoch != nil {
		r.nativeSession = source.material.managedEpoch.nativeSession
	}
	if reuseID != "" && m.managedEpochs[key] == previous && m.state.ManagedProbeEpochs[key].ID == reuseID {
		r.record.ID = reuseID
	}
	source.material.probe = r
	m.nativeRunning, m.managedProbe, r.running = true, r, true
	return r, nil
}

func (r *ManagedProbeEpoch) Current(ctx context.Context) error {
	if r == nil || r.self != r || r.source == nil || r.manager == nil || r.environment == nil || selectedReviewContext(ctx) != nil {
		return ErrSelectedCandidateChanged
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failed || !r.running && !r.complete {
		return ErrSelectedCandidateChanged
	}
	if err := r.environment.Current(ctx); err != nil {
		return err
	}
	if r.complete {
		if err := r.completedSourceCurrent(ctx); err != nil {
			return err
		}
		r.manager.mu.RLock()
		stored, exists := r.manager.state.ManagedProbeEpochs[managedProbeKey(r.record.ServiceID, r.record.CandidateID)]
		original := r.manager.managedEpochs[managedProbeKey(r.record.ServiceID, r.record.CandidateID)] == r
		r.manager.mu.RUnlock()
		if !exists || !original || !reflect.DeepEqual(stored, r.record) {
			return ErrSelectedCandidateChanged
		}
	} else {
		reference, err := r.source.Reference(ctx)
		if err != nil || reference.Material.CandidateID != r.record.CandidateID || reference.Material.Incarnation != r.record.Incarnation || reference.ValidationGeneration != r.record.ValidationGeneration || reference.Scope.CriteriaDigest != r.record.CriteriaDigest {
			return errors.Join(ErrSelectedCandidateChanged, err)
		}
	}
	return errors.Join(r.environment.Current(ctx), selectedReviewContext(ctx))
}

func (r *ManagedProbeEpoch) Reference(ctx context.Context) (ManagedProbeEpochRecord, error) {
	if err := r.Current(ctx); err != nil {
		return ManagedProbeEpochRecord{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.record, nil
}

// Read-only completed evidence observes Manager's acknowledged CAS lineage,
// not the old live writer lease or global latest compatibility session. The
// original native receipt remains private in this owner; restart cannot issue
// it. Every effect still needs a newly acquired genuine runtime/source lease.
func (r *ManagedProbeEpoch) completedSourceCurrent(ctx context.Context) error {
	m := r.manager
	m.mu.RLock()
	defer m.mu.RUnlock()
	return r.completedSourceCurrentLocked(ctx)
}

func (r *ManagedProbeEpoch) completedSourceCurrentLocked(ctx context.Context) error {
	m := r.manager
	material := r.source.material
	if material == nil || material.binding.manager != m || m.Path != material.path || m.compatibilityUnknownLocked() || m.writeBlocked || m.nativeRunning && m.managedProbe == nil || r.nativeSession == nil {
		return ErrSelectedCandidateChanged
	}
	candidate, exists := m.state.Candidates[r.record.CandidateID]
	if !exists || !adaptiveCandidateIdentityEqual(candidate, material.binding.candidate) || !compatibilityJSONEqual(candidate.Validation, material.binding.candidate.Validation) {
		return ErrSelectedCandidateChanged
	}
	validator, err := adaptiveManagedValidatorLocked(m)
	if err != nil || validator.(CompatibleValidator).Provider != material.provider {
		return ErrSelectedCandidateChanged
	}
	material.provider.mu.Lock()
	settled := !material.provider.running && !material.provider.unknown
	material.provider.mu.Unlock()
	view := m.state
	view.CompatibilitySession = r.nativeSession
	if !settled || selectedReviewCompatibility(view, candidate, material.selection, material.review) != nil || compatibilityProtectedReview(m.Path, material.review) != nil || compatibilityFilesUnchanged(material.review) != nil {
		return ErrSelectedCandidateChanged
	}
	image, err := restorejournal.ReadFileImage(ctx, m.Path)
	if err != nil || !image.Exists || !m.image.Exists || !bytes.Equal(image.Data, m.image.Data) {
		return ErrSelectedCandidateChanged
	}
	return ctx.Err()
}

// Finish is called only by the managed consumer after its actual flow has
// joined and both rule/process cleanup have been confirmed. A cleanup error
// retains the original native slot and persists unknown; it never records PASS.
func (r *ManagedProbeEpoch) Finish(ctx context.Context, evidence *Evidence, cleanupErr error) (result error) {
	if r == nil || r.self != r || r.source == nil || r.manager == nil {
		return ErrSelectedCandidateChanged
	}
	published := false
	defer func() {
		if published {
			result = errors.Join(result, r.Current(ctx))
		}
	}()
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.running || r.failed {
		return ErrSelectedCandidateChanged
	}
	var currentErr error
	if cleanupErr == nil && evidence != nil {
		currentErr = r.environment.Current(ctx)
		if currentErr == nil {
			currentErr = r.source.Current(ctx)
		}
	}
	r.source.mu.Lock()
	defer r.source.mu.Unlock()
	m := r.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.managedProbe != r || !m.nativeRunning {
		return ErrSelectedCandidateChanged
	}
	if cleanupErr != nil {
		r.failed = true
		m.compatibilityUnknown = true
		return errors.Join(cleanupErr, m.retainAdaptiveValidationUnknownLocked())
	}
	// Known physical cleanup releases the serial slot even after Stop/cancel;
	// those conditions still refuse publication of a delayed result below.
	defer func() { m.nativeRunning = false; m.managedProbe = nil; r.running = false }()
	if evidence == nil {
		return currentErr
	}
	if currentErr != nil {
		return currentErr
	}
	if err := r.source.material.materialCurrentLocked(ctx); err != nil {
		return err
	}
	e := *evidence
	if e.CandidateID != r.record.CandidateID || e.ServiceID != r.record.ServiceID || e.Protocol != "tcp" || e.IPFamily != "ipv4" || len(e.Stages) == 0 {
		return errEvidenceBinding
	}
	e.ManagedEpoch = r.record.ID
	e.CandidateIncarnation = r.record.Incarnation
	e.ValidationGeneration = r.record.ValidationGeneration
	if err := m.publishManagedEvidenceLocked(r.record, e); err != nil {
		return err
	}
	// Only this acknowledged CAS can advance this original comparison reader.
	r.source.material.image = compatibilityImageCopy(m.image)
	var err error
	r.source.material.file, err = selectedReviewFileIdentity(m.Path)
	if err != nil {
		m.writeBlocked = true
		return err
	}
	if m.managedEpochs == nil {
		m.managedEpochs = map[string]*ManagedProbeEpoch{}
	}
	m.managedEpochs[managedProbeKey(r.record.ServiceID, r.record.CandidateID)] = r
	r.complete = true
	// Retain only bounded original validation/material metadata for read-only
	// evidence. The completed source cannot authorize another live invocation;
	// its large whole-file image and predecessor-epoch chain are released.
	r.source.closed = true
	r.source.material.image = restorejournal.Image{}
	r.source.material.managedEpoch = nil
	published = true
	return nil
}

// Caller holds Manager.mu after observing the actual original context/source.
// All proposed evidence is validated before even the in-memory schema/epoch
// changes; one CAS publishes the entire new context and its observation.
func (m *Manager) publishManagedEvidenceLocked(record ManagedProbeEpochRecord, e Evidence) error {
	if _, err := prepareRecordedEvidence(e, m.state.Candidates[e.CandidateID], m.now()); err != nil {
		return err
	}
	next, err := compatibilityStateCopy(m.state)
	if err != nil {
		return err
	}
	if next.ManagedProbeEpochs == nil {
		next.ManagedProbeEpochs = map[string]ManagedProbeEpochRecord{}
	}
	next.ManagedProbeEpochs[managedProbeKey(record.ServiceID, record.CandidateID)] = record
	if supervisedStrategySchema(next.SchemaVersion) {
		next.SchemaVersion = managedSupervisedSchema
	} else {
		next.SchemaVersion = managedStrategySchema
	}
	if err := validateManagedProbeState(next); err != nil {
		return err
	}
	previousState := m.state
	m.state = next
	m.state.managedCurrent = map[string]string{managedProbeKey(record.ServiceID, record.CandidateID): record.ID}
	if err := m.recordLocked(e); err != nil {
		m.state = previousState
		return err
	}
	m.state.managedCurrent = nil
	return nil
}

func (m *Manager) observeManagedProbeEpochs(contexts ...context.Context) map[string]string {
	m.mu.RLock()
	owners := make(map[string]*ManagedProbeEpoch, len(m.managedEpochs))
	for key, owner := range m.managedEpochs {
		owners[key] = owner
	}
	m.mu.RUnlock()
	current := map[string]string{}
	parent := context.Background()
	if len(contexts) == 1 && contexts[0] != nil {
		parent = contexts[0]
	}
	ctx, cancel := context.WithTimeout(parent, 250*time.Millisecond)
	defer cancel()
	keys := make([]string, 0, len(owners))
	for key := range owners {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if ctx.Err() != nil {
			break
		}
		owner := owners[key]
		if owner.Current(ctx) == nil {
			current[key] = owner.record.ID
		}
	}
	return current
}

// Select is the managed-only selection consumer. Legacy Select cannot turn
// persisted epoch strings into eligibility; this original owner must still
// match its App/network/runtime/source on both sides of the state CAS.
func (r *ManagedProbeEpoch) Select(ctx context.Context, frozen bool) (Selection, error) {
	return r.SelectForMode(ctx, ModePreferred, frozen)
}

func (r *ManagedProbeEpoch) SelectForMode(ctx context.Context, mode AdaptiveMode, frozen bool) (Selection, error) {
	if mode != ModePreferred && mode != ModeOnly {
		return Selection{}, errors.New("explicit managed automatic selection mode required")
	}
	if err := r.Current(ctx); err != nil {
		return Selection{}, err
	}
	r.mu.Lock()
	r.source.mu.Lock()
	m := r.manager
	m.mu.Lock()
	var selected Selection
	selectErr := func() error {
		if !r.complete || r.failed || m.managedEpochs[managedProbeKey(r.record.ServiceID, r.record.CandidateID)] != r {
			return ErrSelectedCandidateChanged
		}
		if err := r.completedSourceCurrentLocked(ctx); err != nil {
			return err
		}
		view := m.state
		view.managedCurrent = map[string]string{managedProbeKey(r.record.ServiceID, r.record.CandidateID): r.record.ID}
		for _, summary := range summarize(view, m.now()) {
			if summary.CandidateID != r.record.CandidateID || summary.ServiceID != r.record.ServiceID || summary.Protocol != "tcp" || summary.IPFamily != "ipv4" {
				continue
			}
			if !summary.Eligible {
				return errors.New(summary.Reason)
			}
			now := m.now().UTC().Format(time.RFC3339)
			selected = Selection{ServiceID: r.record.ServiceID, Protocol: "tcp", IPFamily: "ipv4", CandidateID: r.record.CandidateID, Mode: mode, Frozen: frozen, SelectedAt: now, LastHealthyAt: summary.LastCheckedAt, Healthy: true, Confidence: summary.Confidence, Status: "healthy", Reason: summary.Reason}
			key := selectionKey(r.record.ServiceID, "tcp", "ipv4")
			if previous, exists := m.state.Selections[key]; exists {
				if previous.Mode == ModeManual || previous.Frozen && previous.CandidateID != selected.CandidateID {
					return errors.New("manual or frozen selection prevents automatic replacement")
				}
				selected.Frozen = selected.Frozen || previous.Frozen
				if previous.CandidateID != selected.CandidateID {
					selected.PreviousCandidateID = previous.CandidateID
				}
			}
			next, err := compatibilityStateCopy(m.state)
			if err != nil {
				return err
			}
			next.Selections[key] = selected
			previousState := m.state
			m.state = next
			if err := m.saveLocked(); err != nil {
				m.state = previousState
				return err
			}
			return nil
		}
		return errors.New("managed candidate has no current evidence for the requested scope")
	}()
	m.mu.Unlock()
	r.source.mu.Unlock()
	r.mu.Unlock()
	if selectErr != nil {
		return Selection{}, selectErr
	}
	if err := r.Current(ctx); err != nil {
		return selected, err
	}
	return selected, nil
}
