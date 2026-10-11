package dataplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sync"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

type xraySelectedTCPRegistrarKey struct{}
type xraySelectedTCPRegistrar func(context.Context, *XrayOperationMaterial, XraySelectedTCPRedirectSpec) (*XraySelectedTCPExecutionResource, error)

// Only the SAME Manager's actual executionResourceScope can issue this owner.
// A journal definition, native observation, config/path, process handle or
// detached operation cannot construct it. The issuer retains actual config
// and executable descriptors BEFORE any native process or COMMON invocation.
type XraySelectedTCPExecutionResource struct {
	self                                               *XraySelectedTCPExecutionResource
	mu                                                 sync.Mutex
	observationMu                                      sync.RWMutex
	commonMu                                           sync.Mutex
	common                                             *xraySelectedTCPCommonPublication
	records                                            *xraySelectedTCPExecutionRecords
	scope                                              *executionResourceScope
	owner                                              *xrayOperationOwner
	material                                           *XrayOperationMaterial
	definition                                         ExecutionXraySelectedTCPDefinition
	effects                                            PolicyEffectPlan
	root                                               *ownedfs.Root
	rootPath, relative, id                             string
	anchor                                             os.FileInfo
	config                                             *os.File
	configInfo                                         os.FileInfo
	executable                                         *xraySelectedTCPExecutable
	child                                              *xraySelectedTCPProcess
	versionChild                                       *xraySelectedTCPProcess
	log                                                *os.File
	birth                                              *xraySelectedTCPProcessObservation
	versionUsed, versionVerified, startFailed          bool
	startUsed, startACK, selectorUsed, active, stopped bool
	descriptorsClosed                                  bool
	descriptorsErr                                     error
}

func (*XraySelectedTCPExecutionResource) String() string {
	return "[private original Xray execution resource]"
}
func (*XraySelectedTCPExecutionResource) GoString() string {
	return "[private original Xray execution resource]"
}

func AcquireXraySelectedTCPExecutionResource(ctx context.Context, material *XrayOperationMaterial, spec XraySelectedTCPRedirectSpec) (*XraySelectedTCPExecutionResource, error) {
	if xraySelectedTCPFinite(ctx) != nil || material == nil || material.self != material || ctx.Value(xrayOperationMaterialKey{}) != material {
		return nil, errXraySelectedTCPRuntime
	}
	issue, ok := ctx.Value(xraySelectedTCPRegistrarKey{}).(xraySelectedTCPRegistrar)
	if !ok || issue == nil {
		return nil, errXraySelectedTCPRuntime
	}
	return issue(ctx, material, spec)
}

// Structural metadata only. Actual map/root/config/source/process/COMMON
// ownership and terminal producers remain independent original live checks.
func validateXraySelectedTCPExecutionResource(resource ExecutionResource, terminal bool) error {
	d := resource.XraySelectedTCP
	if resource.Kind != "xray-selected-tcp" || resource.NodeTransit != nil || resource.NFQWS != nil || resource.SyntheticBaseline != nil || d == nil {
		return ErrExecutionJournal
	}
	compiled, err := d.validate()
	if err != nil || resource.Generation != compiled.Generation || resource.EffectsDigest != d.EffectsSHA256 {
		return errors.Join(ErrExecutionJournal, err)
	}
	switch resource.Phase {
	case "planned", "process-pending", "listener-ready", "applied", "transfer-intent", "transfer-ack", "closed":
		if resource.State != "prepared" {
			return ErrExecutionJournal
		}
		if terminal {
			return errors.Join(ErrExecutionJournal, ErrPolicyAdditionUnknown)
		}
	case "active":
		if resource.State != "active" || d.Observation == nil {
			return ErrExecutionJournal
		}
	case "removed":
		if resource.State != "removed" {
			return ErrExecutionJournal
		}
	case "unused":
		if resource.State != "unused" || d.Observation != nil {
			return ErrExecutionJournal
		}
	default:
		return ErrExecutionJournal
	}
	if (resource.Phase == "listener-ready" || resource.Phase == "applied" || resource.Phase == "transfer-intent" || resource.Phase == "transfer-ack") && d.Observation == nil {
		return ErrExecutionJournal
	}
	return nil
}

func (s *executionResourceScope) issueXraySelectedTCP(ctx context.Context, material *XrayOperationMaterial, spec XraySelectedTCPRedirectSpec) (result *XraySelectedTCPExecutionResource, resultErr error) {
	if s == nil || xraySelectedTCPFinite(ctx) != nil || material == nil || material.self != material || ctx.Value(xrayOperationMaterialKey{}) != material {
		return nil, errXraySelectedTCPRuntime
	}
	// Close joins this issuer's original file publication. Source/provider
	// readers and file I/O remain outside the scope metadata mutex.
	s.startMu.RLock()
	defer s.startMu.RUnlock()
	owner, err := newXrayOperationOwner(ctx, s)
	if err != nil {
		return nil, err
	}
	bound, err := owner.context(ctx)
	if err != nil {
		return nil, err
	}
	material.barrier.RLock()
	defer material.barrier.RUnlock()
	if material.current(bound, false) != nil || !reflect.DeepEqual(spec, material.material.spec) {
		return nil, errXraySelectedTCPRuntime
	}
	compiled, err := CompileXraySelectedTCPRedirect(spec)
	if err != nil {
		return nil, err
	}
	effectsHash, err := PolicyEffectPlanDigest(compiled)
	if err != nil {
		return nil, err
	}
	if s.networkIdentity == nil || s.networkIdentity.value.Validate() != nil {
		return nil, ErrNetworkPolicyIdentity
	}
	image := slices.Clone(material.material.config)
	defer clear(image)
	if len(image) == 0 || len(image) > 1<<20 {
		return nil, errXraySelectedTCPRuntime
	}
	configHash := sha256.Sum256(image)
	d := ExecutionXraySelectedTCPDefinition{Schema: 1, PlanID: s.plan.PlanID, PlanDigest: s.plan.Digest, NetworkProfile: s.plan.NetworkProfileID,
		Match: spec.Clone(), Service: cloneXraySelectedTCPService(material.material.proof.service), Proof: material.material.ref,
		ConfigSHA256: hex.EncodeToString(configHash[:]), EffectsSHA256: effectsHash, Process: xraySelectedTCPProcessShape(), NetworkIdentity: s.networkIdentity.value}
	if _, err := d.validate(); err != nil {
		return nil, err
	}
	if err := func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.adapter != "xray" || s.adapterOwner != material.adapter || s.xraySelectedTCP == nil || len(s.xraySelectedTCP) != 0 || s.resourceCount() >= maxExecutionResources {
			return errXraySelectedTCPRuntime
		}
		return s.checkOriginalOwner(bound, nil, true, false)
	}(); err != nil {
		return nil, err
	}
	if err := s.owned.MkdirAll("execution-resources", 0700); err != nil {
		return nil, executionJournalError(err)
	}
	relative, err := s.owned.MkdirTemp("execution-resources", "xr-")
	if err != nil {
		return nil, executionJournalError(err)
	}
	anchor, err := s.owned.Stat(relative)
	if err != nil {
		return nil, executionJournalError(err)
	}
	r := &XraySelectedTCPExecutionResource{scope: s, owner: owner, material: material, definition: d.Clone(), effects: compiled, rootPath: filepath.Join(s.root, relative), relative: relative, id: filepath.Base(relative), anchor: anchor}
	r.self = r
	published := false
	ownRecords := false
	defer func() {
		if !published {
			if ownRecords {
				_ = r.records.close()
			}
			if r.config != nil {
				_ = r.config.Close()
			}
			if r.executable != nil {
				_ = r.executable.close()
			}
			if r.root != nil {
				_ = r.root.Close()
			}
		}
	}()
	r.root, err = ownedfs.Open(r.rootPath)
	if err != nil {
		return nil, executionJournalError(err)
	}
	if err = r.root.WriteAtomic(d.Process.ConfigName, image, 0600); err != nil {
		return nil, executionJournalError(err)
	}
	if err = r.root.Sync(); err != nil {
		return nil, executionJournalError(err)
	}
	r.config, err = r.root.OpenFile(d.Process.ConfigName, os.O_RDONLY, 0)
	if err != nil {
		return nil, executionJournalError(err)
	}
	r.configInfo, err = r.config.Stat()
	if err != nil || r.configCurrent(bound) != nil {
		return nil, errXraySelectedTCPRuntime
	}
	// This accepts only original dispatcher material; it opens no caller path.
	// Native version and actual Start remain later one-shot lifecycle steps.
	r.executable, err = holdXraySelectedTCPExecutableLocked(bound, material)
	if err != nil {
		return nil, err
	}
	for _, path := range []string{r.rootPath, filepath.Dir(r.rootPath), s.root} {
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
	if err = owner.checkHeld(bound, false); err != nil {
		return nil, err
	}
	if p, ok := ctx.Value(xraySelectedTCPReplacementKey{}).(*xraySelectedTCPReplacement); ok && p != nil {
		if p.self != p || p.scope != s || p.manager != s.manager || p.records == nil || p.records.scope != s || p.candidate == nil || p.candidate.material != material || p.records.current(bound, true) != nil {
			return nil, ErrXrayOperationOwner
		}
		r.records = p.records
	} else {
		r.records, err = newXraySelectedTCPRecords(s)
		ownRecords = err == nil
	}
	if err != nil || !os.SameFile(s.anchor, r.records.transactionAnchor) {
		return nil, errors.Join(ErrExecutionJournal, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.xraySelectedTCP == nil || len(s.xraySelectedTCP) != 0 || s.resourceCount() >= maxExecutionResources || s.checkOriginalOwner(bound, nil, true, false) != nil {
		return nil, errXraySelectedTCPRuntime
	}
	named, err := s.owned.Stat(relative)
	if err != nil || !os.SameFile(anchor, named) {
		return nil, errXraySelectedTCPRuntime
	}
	s.xraySelectedTCP[r.id] = r
	definition := r.definition.Clone()
	s.execution.Resources = append(s.execution.Resources, ExecutionResource{ID: r.id, Kind: "xray-selected-tcp", State: "prepared", Phase: "planned",
		Generation: compiled.Generation, EffectsDigest: effectsHash, XraySelectedTCP: &definition})
	published = true
	// A failed ACK retains the SAME owner and planned record for original
	// compensation. Returning the pointer is not a forward/native grant.
	return r, s.persist()
}

// Called only with the original scope metadata lock held. No external read,
// callback, process action or receipt mutation is hidden in this comparison.
func (r *XraySelectedTCPExecutionResource) matching() (int, error) {
	if r == nil || r.self != r || r.scope == nil || r.scope.xraySelectedTCP[r.id] != r || r.owner == nil || r.owner.scope != r.scope || r.owner.material != r.material {
		return -1, errXraySelectedTCPRuntime
	}
	for i, record := range r.scope.execution.Resources {
		if record.ID != r.id {
			continue
		}
		if record.Kind != "xray-selected-tcp" || record.XraySelectedTCP == nil || record.NodeTransit != nil || record.NFQWS != nil || record.SyntheticBaseline != nil || record.Generation != r.effects.Generation || record.EffectsDigest != r.definition.EffectsSHA256 {
			return -1, errXraySelectedTCPRuntime
		}
		expected, actual := r.definition.Clone(), record.XraySelectedTCP.Clone()
		expected.Observation = nil
		actual.Observation = nil
		if !reflect.DeepEqual(expected, actual) || validateXraySelectedTCPExecutionResource(record, false) != nil {
			return -1, errXraySelectedTCPRuntime
		}
		return i, nil
	}
	return -1, errXraySelectedTCPRuntime
}

func (r *XraySelectedTCPExecutionResource) configCurrent(ctx context.Context) error {
	if r == nil || r.self != r || xraySelectedTCPFinite(ctx) != nil || r.root == nil || r.config == nil || r.configInfo == nil || r.material == nil || r.material.self != r.material {
		return errXraySelectedTCPRuntime
	}
	held, err := r.config.Stat()
	named, namedErr := r.root.Stat(r.definition.Process.ConfigName)
	directory, dirErr := os.Lstat(r.rootPath)
	if err != nil || namedErr != nil || dirErr != nil || !networkPolicyPrivateDirectory(directory) || !os.SameFile(r.anchor, directory) || !validNetworkPolicyReceiptFile(held) || !validNetworkPolicyReceiptFile(named) ||
		!os.SameFile(r.configInfo, held) || !os.SameFile(held, named) || held.Size() != r.configInfo.Size() || named.Size() != held.Size() || !held.ModTime().Equal(r.configInfo.ModTime()) || !named.ModTime().Equal(held.ModTime()) {
		return errXraySelectedTCPRuntime
	}
	if held.Size() <= 0 || held.Size() > 1<<20 {
		return errXraySelectedTCPRuntime
	}
	data := make([]byte, int(held.Size()))
	defer clear(data)
	n, readErr := r.config.ReadAt(data, 0)
	if readErr != nil || n != len(data) {
		return errXraySelectedTCPRuntime
	}
	hash := sha256.Sum256(data)
	after, statErr := r.root.Stat(r.definition.Process.ConfigName)
	if statErr != nil || !validNetworkPolicyReceiptFile(after) || !os.SameFile(named, after) || after.Mode() != held.Mode() || after.Size() != held.Size() || !after.ModTime().Equal(held.ModTime()) || hex.EncodeToString(hash[:]) != r.definition.ConfigSHA256 {
		return errXraySelectedTCPRuntime
	}
	return ctx.Err()
}
