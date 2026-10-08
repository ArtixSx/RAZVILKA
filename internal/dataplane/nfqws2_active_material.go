package dataplane

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"sync"
	"time"

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
	command            nfqws2ActiveProcessCommand
	queue              uint16
	executionBound     bool
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
	deadline, _ := ctx.Deadline()
	if ceiling := time.Now().Add(15 * time.Second); deadline.After(ceiling) {
		deadline = ceiling
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, ErrNFQWSScopedOwner
	}
	epoch := control.Reference()
	command := nfqws2ActiveProcessCommand{Version: 1, Mode: nfqws2ActiveProcessMode, ID: hex.EncodeToString(nonce[:]), StateRoot: adapter.StateRoot,
		Owner: owner, ControlRoot: controlRoot, InstallationID: epoch.InstallationID, Sequence: epoch.Sequence,
		Program: nfqws2ManagedFile{Path: descriptor.Executable.Path, SHA256: descriptor.Executable.SHA256}, Parent: parent,
		NetworkIdentity: identity, ActivationDeadline: deadline.UTC(), Args: []string{"--intercept=1", "--qnum=" + strconv.Itoa(int(queue))}}
	for _, asset := range descriptor.Lua {
		command.Assets = append(command.Assets, nfqws2ManagedFile{Path: asset.Path, SHA256: asset.SHA256})
		command.Args = append(command.Args, "--lua-init=@"+asset.Path)
	}
	for _, blob := range descriptor.Blobs {
		command.Assets = append(command.Assets, nfqws2ManagedFile{Path: blob.Path, SHA256: blob.SHA256})
		command.Args = append(command.Args, "--blob="+blob.Alias+":@"+blob.Path)
	}
	command.Args = append(command.Args, slices.Clone(reference.Arguments)...)
	r := &NFQWSActiveMaterial{manager: manager, managerRoot: manager.StateRoot, registryGeneration: generation, adapter: adapter, source: source, runtime: runtime,
		control: control, provider: provider, descriptor: descriptor, reference: reference, command: command, queue: queue}
	r.self = r
	if nfqws2ActiveCommandMatchesSpec(command, r.spec()) != nil {
		return nil, ErrNFQWSScopedOwner
	}
	if err := r.Current(ctx); err != nil {
		return nil, err
	}
	if err := control.Current(ctx); err != nil {
		return nil, errors.Join(ErrNFQWSScopedOwner, err)
	}
	if ctx.Err() != nil || !time.Now().Before(command.ActivationDeadline) {
		return nil, ErrNFQWSScopedOwner
	}
	return r, nil
}

// spec contains no argv; real executable+all ordered arguments determine its
// comparison hash. SAME actual private command is retained by this producer.
func (r *NFQWSActiveMaterial) spec() NFQWSScopedSpec {
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
// Expired material cannot prepare another activation, even with fresh ctx.
func (r *NFQWSActiveMaterial) ReviewScope(ctx context.Context, expectedReference strategylab.SelectedCandidateReference, expected Plan, matches []NFQWSScopedMatch) (*NFQWSScopedSelection, error) {
	if r == nil || r.self != r {
		return nil, ErrNFQWSScopedOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || !time.Now().Before(r.command.ActivationDeadline) || !reflect.DeepEqual(expectedReference, r.reference) {
		return nil, ErrNFQWSScopedOwner
	}
	if err := r.currentLocked(ctx); err != nil {
		return nil, err
	}
	selection, err := ReviewNFQWSScopedSelection(ctx, r.source, expectedReference, expected, r.spec(), matches)
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
		r.adapter.StateRoot != r.command.StateRoot || r.control == nil || !r.control.MatchesControlRoot(r.command.ControlRoot) {
		return ErrNFQWSScopedOwner
	}
	r.manager.registryMu.RLock()
	registered, generation := r.manager.Adapters["nfqws2"], r.manager.registryGeneration
	r.manager.registryMu.RUnlock()
	if registered != r.adapter || generation != r.registryGeneration || r.source == nil || r.runtime == nil || r.provider == nil {
		return ErrNFQWSScopedOwner
	}
	if err := r.source.ManagedOwnersCurrent(ctx, r.runtime, r.control); err != nil {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	reference, err := r.source.Reference(ctx)
	if err != nil || !reflect.DeepEqual(reference, r.reference) || !reflect.DeepEqual(r.runtime.Descriptor(), r.descriptor) {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	if err := r.provider.WithCurrent(ctx, func(_ context.Context, identity netidentity.Identity) error {
		if identity != r.command.NetworkIdentity {
			return ErrNFQWSScopedOwner
		}
		return nil
	}); err != nil {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	state, present, err := operationgate.ReadSelfUpdateStop(ctx, r.command.ControlRoot)
	if err != nil || !present || state.Stopped || state.InstallationID != r.command.InstallationID || state.Sequence != r.command.Sequence {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	if err := r.source.ManagedOwnersCurrent(ctx, r.runtime, r.control); err != nil {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	r.manager.registryMu.RLock()
	registered, generation = r.manager.Adapters["nfqws2"], r.manager.registryGeneration
	r.manager.registryMu.RUnlock()
	if registered != r.adapter || generation != r.registryGeneration || r.manager.StateRoot != r.managerRoot || r.adapter.StateRoot != r.command.StateRoot || !r.control.MatchesControlRoot(r.command.ControlRoot) || !reflect.DeepEqual(r.runtime.Descriptor(), r.descriptor) {
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
	defer r.mu.Unlock()
	r.closed = true
	return nil
}
