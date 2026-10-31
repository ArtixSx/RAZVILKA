package dataplane

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
	"github.com/ArtixSx/razvilka/internal/strategylab"
)

// ManagedNFQWSProbeConsumer borrows the original startup Manager and tool
// owners. It is a single synchronous candidate probe, never another queue
// scheduler or an owner recovered from serialized metadata.
type ManagedNFQWSProbeConsumer struct {
	self          *ManagedNFQWSProbeConsumer
	mu            sync.Mutex
	cleanupMu     sync.Mutex
	manager       *Manager
	adapter       *NFQWS2Adapter
	gate          *NetworkPolicyAdapter
	inventory     BackendInventory
	control       *operationgate.ControlEpochReview
	controlRoot   string
	provider      *netidentity.Provider
	panel         context.Context
	registry      uint64
	runtimeOwner  *LANPolicyRuntime
	runtimeRunner NFQWS2Runner
	active        *nfqwsProbeExecution
}

type nfqwsProbeExecution struct {
	self            *nfqwsProbeExecution
	consumer        *ManagedNFQWSProbeConsumer
	source          *strategylab.CandidateProbeReview
	epoch           *strategylab.ManagedProbeEpoch
	consumption     *strategylab.ManagedProbeConsumption
	runtime         *components.ManagedNFQWSRuntimeLease
	reference       strategylab.CandidateProbeReference
	record          strategylab.ManagedProbeEpochRecord
	descriptor      components.NFQWSRuntimeDescriptor
	cleanup         *operationgate.ExclusiveCleanupReview
	guard           func(context.Context) error
	socket          *nfqwsProbeSocketOwner
	command         nfqws2ManagedProcessCommand
	spec            NFQWSScopedSpec
	plan            Plan
	resource        *NFQWSExecutionResource
	binding         *NFQWSScopedBinding
	open            atomic.Bool
	executing       atomic.Bool
	entered         atomic.Bool
	settled         atomic.Bool
	processResult   *nfqws2ManagedProcessLease
	processWait     *nfqwsProbeProcessWait
	records         *xraySelectedTCPExecutionRecords // Same original authored-record primitive.
	finishing       atomic.Bool
	receiptUnlinked atomic.Bool
	connect         chan struct{}
	flow            chan nfqwsProbeDialResult
	service         catalog.Service
	evidence        strategylab.Evidence
}

type nfqwsProbeDialResult struct {
	conn net.Conn
	err  error
}
type nfqwsProbeExecutionKey struct{}
type nfqwsProbeCleanupKey struct{}

var errNFQWSProbeScopeRetained = errors.New("original NFQWS probe scope retained for final completion")

// ManagedNFQWSProbeCompletion is issued only before any potential effect, or
// after the actual process ACK and COMMON removed settlement. Copies refuse.
type ManagedNFQWSProbeCompletion struct {
	self    *ManagedNFQWSProbeCompletion
	mu      sync.Mutex
	runtime *components.ManagedNFQWSRuntimeLease
	closed  bool
}

func (r *ManagedNFQWSProbeCompletion) CloseRuntime() error {
	if r == nil || r.self != r {
		return ErrNFQWSScopedOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	if r.runtime == nil {
		return ErrNFQWSScopedOwner
	}
	if err := r.runtime.Close(); err != nil {
		return err
	}
	r.closed = true
	return nil
}

func newManagedNFQWSProbeCompletion(runtime *components.ManagedNFQWSRuntimeLease) *ManagedNFQWSProbeCompletion {
	r := &ManagedNFQWSProbeCompletion{runtime: runtime}
	r.self = r
	return r
}

func NewManagedNFQWSProbeConsumer(manager *Manager, gate *NetworkPolicyAdapter, inventory *BackendInventory, control *operationgate.ControlEpochReview, controlRoot string, provider *netidentity.Provider, panel context.Context) (*ManagedNFQWSProbeConsumer, error) {
	if manager == nil || gate == nil || inventory == nil || control == nil || provider == nil || panel == nil || panel.Err() != nil || !control.MatchesControlRoot(controlRoot) || inventory.reader.Provider != provider || inventory.reader.CheckTools == nil || gate.Binding == nil || gate.Binding.Runtime == nil || gate.Binding.Runtime.Runner == nil || gate.identity == nil || gate.identity.provider != provider || gate.Binding.Runtime.IPTables != inventory.reader.IPTables || gate.Binding.Runtime.IP6Tables != inventory.reader.IP6Tables {
		return nil, ErrNFQWSScopedOwner
	}
	if _, ok := inventory.reader.Runner.(backendInventoryBoundedRunner); !ok {
		return nil, ErrNFQWSScopedOwner
	}
	manager.registryMu.RLock()
	registered, generation := manager.Adapters["nfqws2"], manager.registryGeneration
	registeredGate := manager.Adapters[NetworkPolicyAdapterID]
	manager.registryMu.RUnlock()
	actual, ok := registered.(*NFQWS2Adapter)
	if !ok || actual == nil || registeredGate != gate || actual.StateRoot != filepath.Join(manager.StateRoot, "runtime", "nfqws2") {
		return nil, ErrNFQWSScopedOwner
	}
	r := &ManagedNFQWSProbeConsumer{manager: manager, adapter: actual, gate: gate, inventory: *inventory, control: control, controlRoot: controlRoot, provider: provider, panel: panel, registry: generation, runtimeOwner: gate.Binding.Runtime, runtimeRunner: gate.Binding.Runtime.Runner}
	r.self = r
	return r, nil
}

func (r *ManagedNFQWSProbeConsumer) OwnsContext(ctx context.Context) bool {
	if r == nil || r.self != r || ctx == nil {
		return false
	}
	e, ok := ctx.Value(nfqwsProbeExecutionKey{}).(*nfqwsProbeExecution)
	return ok && e != nil && e.self == e && e.consumer == r && e.open.Load()
}

// Pending reports this original consumer's retained lifetime only. It issues
// neither cleanup nor a process owner and cannot recreate one after restart.
func (r *ManagedNFQWSProbeConsumer) Pending() bool {
	if r == nil || r.self != r {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.active != nil
}

func (r *ManagedNFQWSProbeConsumer) ScopeCurrent(ctx context.Context, generation string) error {
	if !r.OwnsContext(ctx) {
		return ErrNFQWSScopedOwner
	}
	e := ctx.Value(nfqwsProbeExecutionKey{}).(*nfqwsProbeExecution)
	if e.resource == nil || generation != "" && generation != e.resource.plan.Resources().Generation {
		return ErrNFQWSScopedOwner
	}
	if ctx.Value(nfqwsProbeCleanupKey{}) == e {
		return e.cleanupCurrent(ctx)
	}
	return e.current(ctx)
}

func (e *nfqwsProbeExecution) owners(ctx context.Context) error {
	if e == nil || e.self != e || !e.open.Load() || ctx == nil || ctx.Err() != nil || e.consumer == nil || e.consumer.self != e.consumer {
		return ErrNFQWSScopedOwner
	}
	c := e.consumer
	if c.panel.Err() != nil && ctx.Value(nfqwsProbeCleanupKey{}) != e || c.gate.Binding == nil || c.gate.Binding.Runtime != c.runtimeOwner || !sameNetworkPolicyDependency(c.gate.Binding.Runtime.Runner, c.runtimeRunner) || c.gate.identity == nil || c.gate.identity.provider != c.provider || c.inventory.reader.Provider != c.provider || c.gate.Binding.Runtime.IPTables != c.inventory.reader.IPTables || c.gate.Binding.Runtime.IP6Tables != c.inventory.reader.IP6Tables {
		return ErrNFQWSScopedOwner
	}
	c.manager.registryMu.RLock()
	same := c.manager.registryGeneration == c.registry && c.manager.Adapters["nfqws2"] == c.adapter && c.manager.Adapters[NetworkPolicyAdapterID] == c.gate
	c.manager.registryMu.RUnlock()
	if !same {
		return ErrNFQWSScopedOwner
	}
	if e.records != nil {
		if err := e.records.current(ctx, true); err != nil {
			return err
		}
	}
	if e.processWait != nil && e.processWait.root != nil {
		if err := e.processWait.root.current(ctx); err != nil {
			return err
		}
	}
	return c.provider.WithCurrent(ctx, func(cctx context.Context, id netidentity.Identity) error {
		if e.socket == nil || id != e.socket.identity {
			return ErrNFQWSScopedOwner
		}
		return c.inventory.reader.CheckTools(cctx, backendInventoryScope{Network: id, ToolReviewID: c.inventory.review})
	})
}

func (e *nfqwsProbeExecution) current(ctx context.Context) error {
	if err := e.owners(ctx); err != nil {
		return err
	}
	if err := e.consumer.control.Current(ctx); err != nil {
		return err
	}
	if err := e.guard(ctx); err != nil {
		return err
	}
	if err := e.epoch.ProbeOwnersCurrent(ctx, e.source, e.runtime, e.consumer.control); err != nil {
		return err
	}
	ref, err := e.source.ManagedReference(ctx, e.runtime, e.consumer.control)
	if err != nil || !reflect.DeepEqual(ref, e.reference) || !reflect.DeepEqual(e.runtime.Descriptor(), e.descriptor) {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	return e.socket.current(ctx)
}

func (e *nfqwsProbeExecution) cleanupCurrent(ctx context.Context) error {
	if e == nil || e.cleanup == nil || e.socket == nil {
		return ErrNFQWSScopedOwner
	}
	return e.cleanup.WithCurrent(ctx, func() error {
		if err := e.owners(ctx); err != nil {
			return err
		}
		if err := e.consumer.control.CurrentForCleanupOperation(ctx, e.cleanup); err != nil {
			return err
		}
		// The original held descriptor remains reserved after cancellation.
		e.socket.mu.Lock()
		defer e.socket.mu.Unlock()
		if e.socket.closed && e.settled.Load() {
			return nil
		}
		if e.socket.closed || e.socket.bound == nil {
			return ErrNFQWSScopedOwner
		}
		return e.socket.bound.retainedCurrent(ctx)
	})
}

func (r *ManagedNFQWSProbeConsumer) Execute(ctx context.Context, source *strategylab.CandidateProbeReview, epoch *strategylab.ManagedProbeEpoch, runtime *components.ManagedNFQWSRuntimeLease, service catalog.Service, revision uint64, guard func(context.Context) error) (strategylab.Evidence, *ManagedNFQWSProbeCompletion, error) {
	var zero strategylab.Evidence
	if r == nil || r.self != r || ctx == nil || source == nil || epoch == nil || runtime == nil || guard == nil || revision == 0 {
		return zero, nil, ErrNFQWSScopedOwner
	}
	ref, err := source.ManagedReference(ctx, runtime, r.control)
	if err != nil {
		return zero, newManagedNFQWSProbeCompletion(runtime), fmt.Errorf("retain native probe source: %w", err)
	}
	record, err := epoch.Reference(ctx)
	if err != nil {
		return zero, newManagedNFQWSProbeCompletion(runtime), err
	}
	if record.CandidateID != ref.Material.CandidateID || record.Incarnation != ref.Material.Incarnation || record.ValidationGeneration != ref.ValidationGeneration || record.ServiceID != ref.Scope.Target.ServiceID || record.CriteriaDigest != ref.Scope.CriteriaDigest {
		return zero, newManagedNFQWSProbeCompletion(runtime), fmt.Errorf("probe epoch/source binding: %w", ErrNFQWSScopedOwner)
	}
	if err := epoch.ProbeOwnersCurrent(ctx, source, runtime, r.control); err != nil {
		return zero, newManagedNFQWSProbeCompletion(runtime), err
	}
	criteria, err := strategylab.ManagedProbeCriteriaDigest(service)
	if err != nil || criteria != ref.Scope.CriteriaDigest || service.ID != ref.Scope.Target.ServiceID || service.ProbeURL != ref.Scope.Target.ProbeURL {
		return zero, newManagedNFQWSProbeCompletion(runtime), fmt.Errorf("probe catalogue binding: %w", ErrNFQWSScopedOwner)
	}
	cleanup, err := r.control.ReviewExclusiveCleanup(ctx)
	if err != nil {
		return zero, newManagedNFQWSProbeCompletion(runtime), err
	}
	if deadline, ok := ctx.Deadline(); !ok || deadline.After(time.Now().Add(15*time.Second)) {
		return zero, newManagedNFQWSProbeCompletion(runtime), ErrNFQWSScopedOwner
	}
	e := &nfqwsProbeExecution{consumer: r, source: source, epoch: epoch, runtime: runtime, reference: ref, record: record, descriptor: runtime.Descriptor(), cleanup: cleanup, guard: guard, connect: make(chan struct{}), flow: make(chan nfqwsProbeDialResult, 1), service: service}
	e.self = e
	e.open.Store(true)
	e.executing.Store(true)
	defer e.executing.Store(false)
	r.mu.Lock()
	if r.active != nil {
		r.mu.Unlock()
		return zero, newManagedNFQWSProbeCompletion(runtime), ErrNFQWSScopedOwner
	}
	r.active = e
	r.mu.Unlock()
	consumption, err := epoch.RetainProbeConsumption(ctx, source, runtime, r.control)
	if err != nil {
		e.open.Store(false)
		r.mu.Lock()
		if r.active == e {
			r.active = nil
		}
		r.mu.Unlock()
		return zero, newManagedNFQWSProbeCompletion(runtime), err
	}
	e.consumption = consumption
	ctx = context.WithValue(ctx, nfqwsProbeExecutionKey{}, e)
	flowCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	ready := make(chan error, 1)
	dialer := &net.Dialer{ControlContext: func(c context.Context, network, address string, raw syscall.RawConn) error {
		owner, err := newNFQWSProbeSocketOwner(c, raw, source, r.provider)
		if err != nil {
			ready <- err
			return err
		}
		e.socket = owner
		ready <- nil
		select {
		case <-e.connect:
			return owner.current(c)
		case <-c.Done():
			return c.Err()
		}
	}}
	go func() {
		conn, err := dialer.DialContext(flowCtx, "tcp4", netip.AddrPortFrom(ref.Scope.Address, 443).String())
		e.flow <- nfqwsProbeDialResult{conn, err}
	}()
	select {
	case err = <-ready:
	case <-ctx.Done():
		err = ctx.Err()
	}
	if err == nil {
		err = e.prepare(ctx, revision)
		if err != nil {
			err = fmt.Errorf("prepare original NFQWS probe: %w", err)
		}
	} else {
		err = fmt.Errorf("reserve original probe socket: %w", err)
	}
	if err == nil {
		err = r.manager.ProbeCandidate(WithReviewGuard(ctx, e.operationGuard), e.plan, "nfqws2")
		if err != nil {
			err = fmt.Errorf("execute original NFQWS probe: %w", err)
		}
	}
	cancel()
	// Join the actual flow before releasing its retained duplicate. A blocked
	// ControlContext wakes on cancel; no detached HTTP goroutine remains.
	if e.connect != nil {
		result := <-e.flow
		if result.conn != nil {
			_ = result.conn.Close()
		}
	}
	if !e.entered.Load() || e.settled.Load() {
		if closeErr := e.finishKnown(); closeErr != nil {
			return e.evidence, nil, errors.Join(err, ErrNFQWSManagedProcessUnknown, closeErr)
		}
		if e.settled.Load() && nfqwsProbeOnlyPending(err, 0) {
			err = nil
		}
		return e.evidence, newManagedNFQWSProbeCompletion(runtime), err
	}
	// Unknown COMMON/process state retains the original socket and runtime.
	return e.evidence, nil, errors.Join(ErrNFQWSManagedProcessUnknown, err)
}

func (e *nfqwsProbeExecution) finishKnown() error {
	if e == nil || e.self != e || e.consumer == nil || e.consumer.self != e.consumer || e.entered.Load() && !e.settled.Load() {
		return ErrNFQWSManagedProcessUnknown
	}
	if e.socket != nil {
		if err := e.socket.retire(); err != nil {
			return err
		}
	}
	if e.resource != nil {
		s := e.resource.scope
		s.mu.Lock()
		s.execution.State = "temporary-complete"
		s.execution.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		publishErr := s.manager.writeExecutionOwned(s.root, *s.execution, s)
		s.mu.Unlock()
		if publishErr != nil {
			return publishErr
		}
	}
	if e.consumption == nil {
		return ErrNFQWSScopedOwner
	}
	if err := e.consumption.Close(); err != nil {
		return err
	}
	if e.resource != nil {
		e.finishing.Store(true)
		if err := e.resource.scope.close(); err != nil {
			return err
		}
		if e.records == nil {
			return ErrExecutionJournal
		}
		if err := e.records.close(); err != nil {
			return err
		}
		if e.processWait != nil && e.processWait.root != nil {
			if err := e.processWait.root.close(); err != nil {
				return err
			}
		}
	}
	e.open.Store(false)
	e.consumer.mu.Lock()
	defer e.consumer.mu.Unlock()
	if e.consumer.active != e {
		return ErrNFQWSScopedOwner
	}
	e.consumer.active = nil
	return nil
}

func nfqwsProbeOnlyPending(err error, depth int) bool {
	if err == nil || depth > 64 {
		return false
	}
	if many, ok := err.(interface{ Unwrap() []error }); ok {
		if len(many.Unwrap()) == 0 {
			return false
		}
		for _, child := range many.Unwrap() {
			if !nfqwsProbeOnlyPending(child, depth+1) {
				return false
			}
		}
		return true
	}
	if one, ok := err.(interface{ Unwrap() error }); ok {
		return nfqwsProbeOnlyPending(one.Unwrap(), depth+1)
	}
	return err == errNFQWSProbeScopeRetained
}

func (e *nfqwsProbeExecution) operationGuard(ctx context.Context) error {
	if ctx.Value(nfqwsProbeCleanupKey{}) == e {
		return e.cleanupCurrent(ctx)
	}
	return e.current(ctx)
}

func (e *nfqwsProbeExecution) prepare(ctx context.Context, revision uint64) error {
	c := e.consumer
	if err := e.current(ctx); err != nil {
		return err
	}
	parent, err := components.ReadNFQWSSupervisionIdentity()
	if err != nil {
		return err
	}
	owner, err := c.adapter.owner()
	if err != nil {
		return err
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return err
	}
	id := hex.EncodeToString(nonce[:])
	deadline, _ := ctx.Deadline()
	deadline = deadline.UTC() // Durable command equality excludes process-local monotonic time.
	control := c.control.Reference()
	d := e.descriptor
	if len(d.Lua) != 3 || len(d.Blobs) != 2 {
		return ErrNFQWSScopedOwner
	}
	command := nfqws2ManagedProcessCommand{ID: id, StateRoot: c.adapter.StateRoot, Owner: owner, ControlRoot: c.controlRoot, InstallationID: control.InstallationID, Sequence: control.Sequence, Program: nfqws2ManagedFile{Path: d.Executable.Path, SHA256: d.Executable.SHA256}, Parent: parent, Deadline: deadline, Args: []string{"--intercept=1", "--qnum=200"}}
	for _, asset := range d.Lua {
		command.Assets = append(command.Assets, nfqws2ManagedFile{Path: asset.Path, SHA256: asset.SHA256})
		command.Args = append(command.Args, "--lua-init=@"+asset.Path)
	}
	for _, blob := range d.Blobs {
		command.Assets = append(command.Assets, nfqws2ManagedFile{Path: blob.Path, SHA256: blob.SHA256})
		command.Args = append(command.Args, "--blob="+blob.Alias+":@"+blob.Path)
	}
	command.Args = append(command.Args, e.reference.Material.Arguments...)
	e.command = command
	probe, err := e.socket.probeSpec(e.record)
	if err != nil {
		return err
	}
	identity := e.socket.identity
	e.spec = NFQWSScopedSpec{Queue: 200, BootID: identity.BootID, SessionID: id, CommandSHA256: nfqws2ManagedCommandDigest(command), NetworkIdentity: &identity, Probe: &probe, Candidate: NFQWSScopedCandidate{ID: e.record.CandidateID, Incarnation: e.record.Incarnation, ServiceID: e.record.ServiceID, IPFamily: "ipv4", ArgumentsSHA256: components.NFQWSRuntimeArgumentsSHA256(command.Program.Path, command.Args), Traffic: []NFQWSScopedTraffic{{Protocol: "tcp", First: 443, Last: 443}}}}
	if identity.Kind == netidentity.ProcNetInode {
		e.spec.NetNamespace = nfqwsProbeNamespace(identity.Inode)
	}
	e.plan = Plan{SchemaVersion: SchemaVersion, PlanID: "dp-probe-" + id, Digest: stringsHashProbe(e.spec), Revision: revision, Ready: true, NetworkProfileID: e.record.NetworkID, Adapters: []string{"nfqws2"}, Routes: []Route{{ServiceID: e.record.ServiceID, Selected: "nfqws2", Resolved: "nfqws2", CIDRs: []string{e.reference.Scope.Address.String() + "/32"}}}}
	_, err = CompileNFQWSScopedPlan(e.plan, e.spec)
	return err
}

func nfqwsProbeNamespace(inode uint64) string { return "net:[" + strconv.FormatUint(inode, 10) + "]" }
func stringsHashProbe(spec NFQWSScopedSpec) string {
	data, _ := json.Marshal(spec)
	return routeidentity.Hash(append([]byte("managed-nfqws-probe-plan-v1\x00"), data...))
}
