package dataplane

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"sync"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/strategylab"
)

// NFQWSActiveMaterial binds the original selected source, current component
// lease and provider control to a private real argv. It is read-only prepared
// material, not an ACTIVE handle or a Start/scope/queue/transfer capability.
// Only the actual NFQ participant may consume its command inside SAME Apply.
type NFQWSActiveMaterial struct {
	self               *NFQWSActiveMaterial
	mu                 sync.Mutex
	closed             bool
	manager            *Manager
	managerRoot        string
	registryGeneration uint64
	adapter            *NFQWS2Adapter
	source             *strategylab.SelectedCandidateReview
	runtime            *components.ManagedNFQWSRuntimeLease
	control            *operationgate.ControlEpochReview
	provider           *netidentity.Provider
	descriptor         components.NFQWSRuntimeDescriptor
	reference          strategylab.SelectedCandidateReference
	intent             nfqws2ActiveProcessIntent
	command            nfqws2ActiveProcessCommand
	queue              uint16
	executionBound     bool
	execution          *nfqws2ActiveExecution
	issuedSelection    *NFQWSScopedSelection
}

// ReviewManagedNFQWSActiveMaterial observes configured original owners only.
// Caller retains all of them through real Stop/sole Wait and COMMON cleanup.
// The explicit queue is intent, never a claim that its kernel slot is free.
// No runner, caller argv, executable path, helper prefix or metadata issuer is
// accepted. Source/Scope review creation remains with their actual owners.
func ReviewManagedNFQWSActiveMaterial(ctx context.Context, manager *Manager, adapter *NFQWS2Adapter, source *strategylab.SelectedCandidateReview, runtime *components.ManagedNFQWSRuntimeLease, control *operationgate.ControlEpochReview, controlRoot string, provider *netidentity.Provider, queue uint16) (*NFQWSActiveMaterial, error) {
	if nfqws2ActiveOperation(ctx) != nil || manager == nil || adapter == nil || source == nil || runtime == nil || control == nil || provider == nil || queue == 0 || !control.MatchesControlRoot(controlRoot) {
		return nil, ErrNFQWSScopedOwner
	}
	if err := control.Current(ctx); err != nil {
		return nil, errors.Join(ErrNFQWSScopedOwner, err)
	}
	if err := source.ManagedOwnersCurrent(ctx, runtime, control); err != nil {
		return nil, errors.Join(ErrNFQWSScopedOwner, err)
	}
	reference, err := source.Reference(ctx)
	if err != nil {
		return nil, errors.Join(ErrNFQWSScopedOwner, err)
	}
	descriptor := runtime.Descriptor()
	if len(descriptor.Lua) != 3 || len(descriptor.Blobs) != 2 || descriptor.ReceiptID != reference.ReceiptID || descriptor.ManifestSHA256 != reference.ManifestSHA256 {
		return nil, ErrNFQWSScopedOwner
	}
	manager.registryMu.RLock()
	registered, generation := manager.Adapters["nfqws2"], manager.registryGeneration
	manager.registryMu.RUnlock()
	if registered != adapter || adapter.StateRoot != filepath.Join(manager.StateRoot, "runtime", "nfqws2") {
		return nil, ErrNFQWSScopedOwner
	}
	owner, err := adapter.owner()
	if err != nil {
		return nil, ErrNFQWSScopedOwner
	}
	parent, err := components.ReadNFQWSSupervisionIdentity()
	if err != nil {
		return nil, ErrNFQWSScopedOwner
	}
	identity, err := provider.Observe(ctx)
	if err != nil || identity.BootID != parent.BootID {
		return nil, errors.Join(ErrNFQWSScopedOwner, err)
	}
	epoch := control.Reference()
	intent := nfqws2ActiveProcessIntent{StateRoot: adapter.StateRoot,
		Owner: owner, ControlRoot: controlRoot, InstallationID: epoch.InstallationID, Sequence: epoch.Sequence,
		Program: nfqws2ManagedFile{Path: descriptor.Executable.Path, SHA256: descriptor.Executable.SHA256}, Parent: parent,
		NetworkIdentity: identity, Args: []string{"--intercept=1", "--qnum=" + strconv.Itoa(int(queue))}}
	for _, asset := range descriptor.Lua {
		intent.Assets = append(intent.Assets, nfqws2ManagedFile{Path: asset.Path, SHA256: asset.SHA256})
		intent.Args = append(intent.Args, "--lua-init=@"+asset.Path)
	}
	for _, blob := range descriptor.Blobs {
		intent.Assets = append(intent.Assets, nfqws2ManagedFile{Path: blob.Path, SHA256: blob.SHA256})
		intent.Args = append(intent.Args, "--blob="+blob.Alias+":@"+blob.Path)
	}
	intent.Args = append(intent.Args, slices.Clone(reference.Arguments)...)
	r := &NFQWSActiveMaterial{manager: manager, managerRoot: manager.StateRoot, registryGeneration: generation, adapter: adapter, source: source, runtime: runtime,
		control: control, provider: provider, descriptor: descriptor, reference: reference, intent: intent, queue: queue}
	r.self = r
	if err := r.Current(ctx); err != nil {
		return nil, err
	}
	if err := control.Current(ctx); err != nil {
		return nil, errors.Join(ErrNFQWSScopedOwner, err)
	}
	if ctx.Err() != nil {
		return nil, ErrNFQWSScopedOwner
	}
	return r, nil
}

// spec contains no argv; real executable+all ordered arguments determine its
// comparison hash. SAME actual private command is retained by this producer.
func (r *NFQWSActiveMaterial) spec() NFQWSScopedSpec {
	if r.command.ID == "" {
		return NFQWSScopedSpec{}
	}
	identity := r.command.NetworkIdentity
	result := NFQWSScopedSpec{Queue: r.queue, BootID: identity.BootID, SessionID: r.command.ID, CommandSHA256: nfqws2ActiveCommandDigest(r.command),
		NetworkIdentity: &identity, Candidate: NFQWSScopedCandidate{ID: r.reference.CandidateID, Incarnation: r.reference.Incarnation,
			ArgumentsSHA256: components.NFQWSRuntimeArgumentsSHA256(r.command.Program.Path, r.command.Args)}}
	if identity.Kind == netidentity.ProcNetInode {
		result.NetNamespace = "net:[" + strconv.FormatUint(identity.Inode, 10) + "]"
	}
	return result
}

// ReviewScope consumes the full DEFAULT reference/rules beside their projected
// Plan. Both opening and closing material reads precede any native effect.
// Prepared intent has no activation ID/deadline. SAME Activate issues the
// one-use native command after the original LAN participant is installed.
func (r *NFQWSActiveMaterial) ReviewScope(ctx context.Context, expectedReference strategylab.SelectedCandidateReference, expected Plan, matches []NFQWSScopedMatch) (*NFQWSScopedSelection, error) {
	if r == nil || r.self != r {
		return nil, ErrNFQWSScopedOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.executionBound || r.command.ID != "" || !reflect.DeepEqual(expectedReference, r.reference) {
		return nil, ErrNFQWSScopedOwner
	}
	if err := r.currentLocked(ctx); err != nil {
		return nil, err
	}
	selection, err := reviewNFQWSScopedPreparedSelection(ctx, r, expectedReference, expected, matches)
	if err != nil {
		return nil, err
	}
	if err := r.currentLocked(ctx); err != nil {
		_ = selection.Close()
		return nil, err
	}
	return selection, nil
}

func (r *NFQWSActiveMaterial) Current(ctx context.Context) error {
	if r == nil || r.self != r {
		return ErrNFQWSScopedOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.currentLocked(ctx)
}

// Read-only current material observation intentionally does not call Gate
// Current/WithStart, so the shared owner may use it under Store observation.
// Activation expiry is enforced at preparation/actual Start, never promoted
// into active-lifetime permission by this fresh finite observer.
func (r *NFQWSActiveMaterial) currentLocked(ctx context.Context) error {
	if r.closed || nfqws2ActiveOperation(ctx) != nil || r.manager == nil || r.adapter == nil || r.manager.StateRoot != r.managerRoot ||
		r.adapter.StateRoot != r.intent.StateRoot || r.control == nil || !r.control.MatchesControlRoot(r.intent.ControlRoot) ||
		r.command.ID != "" && !reflect.DeepEqual(nfqws2ActiveIntentFromCommand(r.command), r.intent) {
		return ErrNFQWSScopedOwner
	}
	r.manager.registryMu.RLock()
	registered, generation := r.manager.Adapters["nfqws2"], r.manager.registryGeneration
	r.manager.registryMu.RUnlock()
	if registered != r.adapter || generation != r.registryGeneration || r.source == nil || r.runtime == nil || r.provider == nil {
		return ErrNFQWSScopedOwner
	}
	reference, err := r.source.ManagedReference(ctx, r.runtime, r.control)
	if err != nil || !reflect.DeepEqual(reference, r.reference) || !reflect.DeepEqual(r.runtime.Descriptor(), r.descriptor) {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	if err := r.provider.WithCurrent(ctx, func(_ context.Context, identity netidentity.Identity) error {
		if identity != r.intent.NetworkIdentity {
			return ErrNFQWSScopedOwner
		}
		return nil
	}); err != nil {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	state, present, err := operationgate.ReadSelfUpdateStop(ctx, r.intent.ControlRoot)
	if err != nil || !present || state.Stopped || state.InstallationID != r.intent.InstallationID || state.Sequence != r.intent.Sequence {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	if err := r.source.ManagedOwnersCurrent(ctx, r.runtime, r.control); err != nil {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	r.manager.registryMu.RLock()
	registered, generation = r.manager.Adapters["nfqws2"], r.manager.registryGeneration
	r.manager.registryMu.RUnlock()
	if registered != r.adapter || generation != r.registryGeneration || r.manager.StateRoot != r.managerRoot || r.adapter.StateRoot != r.intent.StateRoot || !r.control.MatchesControlRoot(r.intent.ControlRoot) || !reflect.DeepEqual(r.runtime.Descriptor(), r.descriptor) {
		return ErrNFQWSScopedOwner
	}
	return ctx.Err()
}

// Close retires this reader only; it cannot release the caller's actual
// component/control/source leases or remove a physical process/COMMON receipt.
func (r *NFQWSActiveMaterial) Close() error {
	if r == nil || r.self != r {
		return ErrNFQWSScopedOwner
	}
	r.mu.Lock()
	r.closed = true
	e := r.execution
	selection := r.issuedSelection
	r.mu.Unlock()
	var err error
	if selection != nil {
		err = selection.Close()
	}
	if e != nil {
		err = errors.Join(err, e.closePreEffectLAN())
		// Read-only descriptors of already published files. A close error
		// changes no file and must not keep a completed owner retained.
		_ = e.closeDirectPreparation()
	}
	return err
}
