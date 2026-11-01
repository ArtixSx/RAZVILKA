package dataplane

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

// This object belongs to the SAME finite Manager execution. It initially has
// no process/capture/publication capability. Only the actual emitted capture
// binds these fields; saved definitions and callback readiness cannot do so.
type DomainTCPOriginalScope struct {
	self              *DomainTCPOriginalScope
	binding           *SyntheticDNSExecutionBinding
	backend           *BackendInventory
	gate              *NetworkPolicyAdapter
	runtime           *LANPolicyRuntime
	runner            NFQWS2Runner
	tools             SyntheticDNSCommandTools
	source            any
	mu                sync.Mutex
	process           *XrayDomainTCPExecutionResource
	capture           *DomainPolicyTCPCapture
	baseline          *syntheticBaselineExecutionResource
	captureResource   *domainTCPCaptureExecutionResource
	prepared          *DomainPolicyTCPCaptureMapping
	kernel            *domainTCPBaselineKernelOwner
	closed            bool
	cancel            context.CancelFunc
	publicationOpen   bool // Only the completed original producer opens this phase.
	standbyReady      bool // Only the actual joined capture finalizer sets this.
	standbyHistory    *updatecheck.ExecutionHistoryAdmission
	standbyOwner      *domainTCPStandbyOwner
	standbyRetirement *domainTCPStandbyRetirement
}

func (m *Manager) NewDomainTCPOriginalScope(ctx context.Context, binding *SyntheticDNSExecutionBinding, backend *BackendInventory) (*DomainTCPOriginalScope, error) {
	if m == nil || binding == nil || binding.self != binding || binding.scope == nil || !binding.scope.domainTCPProof || binding.scope.manager != m || binding.scope.adapter != "xray" || backend == nil || len(binding.transport.Definition.ExactNames) != 1 {
		return nil, ErrDomainPolicyTCPConsumer
	}
	if err := binding.Current(ctx); err != nil {
		return nil, err
	}
	m.registryMu.RLock()
	registered := m.Adapters[NetworkPolicyAdapterID]
	m.registryMu.RUnlock()
	gate, ok := registered.(*NetworkPolicyAdapter)
	if !ok || gate == nil || gate.Binding == nil || gate.Binding.Runtime == nil || gate.identity != binding.scope.networkIdentity {
		return nil, ErrDomainPolicyTCPConsumer
	}
	runtime := gate.Binding.Runtime
	originalRunner, wrapped := runtime.Runner.(networkPolicyIdentityRunner)
	if !wrapped || originalRunner.identity != gate.identity || originalRunner.identity != binding.scope.networkIdentity || originalRunner.runner == nil {
		return nil, ErrDomainPolicyTCPConsumer
	}
	factory, ok := originalRunner.runner.(interface {
		DomainTCPCommandSource() (any, SyntheticDNSCommandTools, error)
	})
	if !ok {
		return nil, ErrDomainPolicyTCPConsumer
	}
	source, tools, err := factory.DomainTCPCommandSource()
	if err != nil || !tools.valid() || !sameNetworkPolicyDependency(source, backend.reader.Runner) || backend.reader.Provider != tools.Provider || tools.Provider != binding.scope.networkIdentity.provider || tools.Identity != binding.scope.networkIdentity.value || backend.review != tools.ReviewSHA256 || backend.reader.IPTables != tools.IPTables || runtime.IP != tools.IP || runtime.IPTables != tools.IPTables || runtime.IP6Tables != backend.reader.IP6Tables {
		return nil, errors.Join(ErrDomainPolicyTCPConsumer, err)
	}
	o := &DomainTCPOriginalScope{binding: binding, backend: backend, gate: gate, runtime: runtime, runner: runtime.Runner, tools: tools, source: source}
	o.self = o
	s := binding.scope
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.open || s.domainTCPOwner != nil || s.checkOriginalOwner(ctx, nil, true, false) != nil {
		return nil, ErrDomainPolicyTCPConsumer
	}
	s.domainTCPOwner = o
	return o, nil
}

func (o *DomainTCPOriginalScope) baseCurrent(ctx context.Context) error {
	if o == nil || o.self != o || o.binding == nil || o.binding.scope == nil || o.backend == nil || o.gate == nil || o.gate.Binding == nil || o.gate.Binding.Runtime != o.runtime || !sameNetworkPolicyDependency(o.runtime.Runner, o.runner) || !sameNetworkPolicyDependency(o.source, o.backend.reader.Runner) {
		return ErrDomainPolicyTCPConsumer
	}
	s := o.binding.scope
	s.mu.Lock()
	same := s.domainTCPOwner == o
	s.mu.Unlock()
	if !same {
		return ErrDomainPolicyTCPConsumer
	}
	s.manager.registryMu.RLock()
	same = s.manager.Adapters[NetworkPolicyAdapterID] == o.gate
	s.manager.registryMu.RUnlock()
	if !same {
		return ErrDomainPolicyTCPConsumer
	}
	return o.binding.Current(ctx)
}

// Run uses the original one-shot Xray process owner. No exported callback can
// substitute a process, capture, Current result or DNS send acknowledgement.
func (o *DomainTCPOriginalScope) Run(ctx context.Context, resource *XrayDomainTCPExecutionResource) error {
	if err := o.baseCurrent(ctx); err != nil {
		return err
	}
	if resource == nil || resource.self != resource || resource.scope != o.binding.scope || resource.material == nil || resource.material.binding != o.binding {
		return ErrDomainPolicyTCPConsumer
	}
	o.mu.Lock()
	if o.closed || o.process != nil {
		o.mu.Unlock()
		return ErrDomainPolicyTCPConsumer
	}
	o.process = resource
	o.mu.Unlock()
	return resource.material.adapter.RunDomainPolicyTCPResource(ctx, resource, o)
}

func (o *DomainTCPOriginalScope) CheckCapture(ctx context.Context, capture *DomainPolicyTCPCapture) error {
	if err := o.baseCurrent(ctx); err != nil {
		return err
	}
	o.mu.Lock()
	process, original, closed := o.process, o.capture, o.closed
	o.mu.Unlock()
	if closed || original != capture || capture == nil || capture.self != capture || capture.owner != o || process == nil || capture.xray == nil || capture.xray.resource != process || !reflect.DeepEqual(capture.spec, process.definition.Capture) {
		return ErrDomainPolicyTCPConsumer
	}
	return process.material.Current(ctx)
}

func (o *DomainTCPOriginalScope) WithCapture(ctx context.Context, spec DomainPolicyTCPCaptureSpec, capture *DomainPolicyTCPCapture, consume func(context.Context) error) error {
	if err := o.baseCurrent(ctx); err != nil {
		return err
	}
	o.mu.Lock()
	if o.closed || o.capture != nil || o.process == nil || capture == nil || capture.xray == nil || capture.xray.resource != o.process || capture.owner != o || spec != o.process.definition.Capture {
		o.mu.Unlock()
		return ErrDomainPolicyTCPConsumer
	}
	o.capture = capture
	process := o.process
	o.mu.Unlock()
	if _, err := o.binding.bindBaselineCoordinator(ctx, &o.tools, o.backend, capture); err != nil {
		return fmt.Errorf("domain TCP original baseline source: %w", err)
	}
	baseline, err := o.binding.issueBaseline(ctx, process.material.mapping, o.backend, capture)
	if err != nil {
		return fmt.Errorf("domain TCP original standby reservation: %w", err)
	}
	o.mu.Lock()
	o.baseline = baseline
	o.mu.Unlock()
	prepared, err := baseline.prepareCapture(ctx)
	if err != nil {
		return fmt.Errorf("domain TCP original capture preparation: %w", err)
	}
	o.mu.Lock()
	o.prepared = prepared
	resource := o.captureResource
	o.mu.Unlock()
	kernel, err := newDomainTCPBaselineKernelOwner(ctx, resource, baseline)
	if err != nil {
		return err
	}
	o.mu.Lock()
	o.kernel = kernel
	o.mu.Unlock()
	// Publication remains false until complete original process/capture/kernel
	// checks pass, including a genuine transparent baseline capability.
	if err := o.compareSyntheticMapping(ctx, process.material.mapping); err != nil {
		return err
	}
	if consume == nil {
		return ErrDomainPolicyTCPConsumer
	}
	life, cancel := context.WithCancel(ctx)
	o.mu.Lock()
	if ctx.Err() != nil || o.closed || o.prepared != prepared || o.kernel != kernel {
		o.mu.Unlock()
		cancel()
		return errors.Join(ErrDomainPolicyTCPConsumer, ctx.Err())
	}
	o.cancel = cancel
	o.publicationOpen = true
	o.mu.Unlock()
	defer func() { cancel(); o.mu.Lock(); o.publicationOpen = false; o.closed = true; o.mu.Unlock() }()
	return consume(life)
}

func (o *DomainTCPOriginalScope) PrepareSyntheticCapture(ctx context.Context, capture *DomainPolicyTCPCapture, mapping *dnscontrol.SyntheticDNSMapping) error {
	if err := o.CheckCapture(ctx, capture); err != nil {
		return err
	}
	o.mu.Lock()
	baseline, process, existing := o.baseline, o.process, o.captureResource
	o.mu.Unlock()
	if baseline == nil || baseline.mapping != mapping || existing != nil {
		return ErrDomainPolicyTCPConsumer
	}
	r, err := issueDomainTCPCaptureResource(ctx, process, capture, baseline)
	if r != nil {
		o.mu.Lock()
		o.captureResource = r
		o.mu.Unlock()
	}
	if err != nil {
		return err
	}
	return r.prepare(ctx, baseline)
}
func (o *DomainTCPOriginalScope) CurrentSyntheticCapture(ctx context.Context, capture *DomainPolicyTCPCapture, mapping *dnscontrol.SyntheticDNSMapping) error {
	return o.currentSyntheticCaptureWithFiles(ctx, capture, mapping, nil)
}
func (o *DomainTCPOriginalScope) currentSyntheticCaptureWithFiles(ctx context.Context, capture *DomainPolicyTCPCapture, mapping *dnscontrol.SyntheticDNSMapping, files *xrayDomainTCPFileObservation) error {
	if err := o.CheckCapture(ctx, capture); err != nil {
		return err
	}
	o.mu.Lock()
	r := o.captureResource
	o.mu.Unlock()
	if r == nil || r.capture != capture || r.mapping != mapping {
		return ErrDomainPolicyTCPConsumer
	}
	return r.checkPreparedWithFiles(ctx, files)
}
func (o *DomainTCPOriginalScope) CurrentSyntheticMapping(ctx context.Context, mapping *dnscontrol.SyntheticDNSMapping) error {
	if o == nil || o.self != o || ctx == nil || ctx.Err() != nil {
		return ErrDomainPolicyTCPConsumer
	}
	o.mu.Lock()
	open, closed := o.publicationOpen, o.closed
	o.mu.Unlock()
	if !open || closed {
		return ErrDomainPolicyTCPConsumer
	}
	return o.compareSyntheticMapping(ctx, mapping)
}

// The first producer comparison cannot be reentered as publication readiness.
// Opening the phase never replaces these full live comparisons on each send.
func (o *DomainTCPOriginalScope) compareSyntheticMapping(ctx context.Context, mapping *dnscontrol.SyntheticDNSMapping) (resultErr error) {
	finishMeasure := domainTCPMeasure("mapping-compare")
	defer func() {
		finishMeasure(0)
		if resultErr == nil {
			domainTCPMeasure("mapping-compare-success")(0)
		}
	}()
	if err := o.baseCurrent(ctx); err != nil {
		return err
	}
	o.mu.Lock()
	process := o.process
	o.mu.Unlock()
	if process == nil || process.self != process {
		return ErrDomainPolicyTCPConsumer
	}
	return process.withCurrentFileObservation(ctx, func(files *xrayDomainTCPFileObservation) error {
		return o.compareSyntheticMappingWithFiles(ctx, mapping, files)
	})
}
func (o *DomainTCPOriginalScope) compareSyntheticMappingWithFiles(ctx context.Context, mapping *dnscontrol.SyntheticDNSMapping, files *xrayDomainTCPFileObservation) error {
	if err := o.baseCurrent(ctx); err != nil {
		return err
	}
	o.mu.Lock()
	process, capture, prepared, kernel, closed := o.process, o.capture, o.prepared, o.kernel, o.closed
	o.mu.Unlock()
	if closed || process == nil || process.material.mapping != mapping || capture == nil || prepared == nil || kernel == nil {
		return ErrDomainPolicyTCPConsumer
	}
	if err := prepared.currentWithFiles(ctx, files); err != nil {
		return err
	}
	if err := kernel.currentWithFiles(ctx, files); err != nil {
		return err
	}
	return process.material.Current(ctx)
}
func (o *DomainTCPOriginalScope) WithSyntheticPublication(ctx context.Context, mapping *dnscontrol.SyntheticDNSMapping, send func(context.Context) error) (resultErr error) {
	finishMeasure := domainTCPMeasure("publication-gate")
	defer func() {
		finishMeasure(0)
		if resultErr == nil {
			domainTCPMeasure("publication-gate-success")(0)
		}
	}()
	if send == nil {
		return ErrDomainPolicyTCPConsumer
	}
	if err := o.CurrentSyntheticMapping(ctx, mapping); err != nil {
		return err
	}
	finishSend := domainTCPMeasure("dns-send")
	err := send(ctx)
	finishSend(0)
	if err == nil {
		domainTCPMeasure("dns-send-success")(0)
	}
	return errors.Join(err, o.CurrentSyntheticMapping(ctx, mapping))
}
func (o *DomainTCPOriginalScope) LookupPublished(ctx context.Context, client, synthetic netip.Addr) (*dnscontrol.SyntheticDNSMapping, error) {
	if err := o.baseCurrent(ctx); err != nil {
		return nil, err
	}
	o.mu.Lock()
	process := o.process
	o.mu.Unlock()
	if process == nil {
		return nil, ErrDomainPolicyTCPConsumer
	}
	mapping, err := process.material.dnsSource.LookupPublished(ctx, client, synthetic)
	if err != nil || mapping != process.material.mapping {
		return nil, errors.Join(ErrDomainPolicyTCPConsumer, err)
	}
	return mapping, o.CurrentSyntheticMapping(ctx, mapping)
}

type domainTCPOriginalFlowLease struct {
	self     *domainTCPOriginalFlowLease
	owner    *DomainTCPOriginalScope
	accepted *domainAcceptedTCP
	mapping  *dnscontrol.SyntheticDNSMapping
	socket   DomainPolicyTCPSocket
	flowID   string
	mu       sync.Mutex
	entered  bool
}

func (o *DomainTCPOriginalScope) AdmitTCP(ctx context.Context, socket DomainPolicyTCPSocket) (DomainPolicyTCPFlowLease, error) {
	o.mu.Lock()
	capture, process := o.capture, o.process
	o.mu.Unlock()
	accepted, err := originalDomainAcceptedTCP(ctx, capture, socket)
	if err != nil || process == nil {
		return nil, errors.Join(ErrDomainPolicyTCPConsumer, err)
	}
	if err := o.CurrentSyntheticMapping(ctx, process.material.mapping); err != nil {
		return nil, err
	}
	l := &domainTCPOriginalFlowLease{owner: o, accepted: accepted, mapping: process.material.mapping, socket: socket, flowID: process.id + "/" + socket.Source.String() + "/" + socket.OriginalDestination.String()}
	l.self = l
	return l, nil
}
func (l *domainTCPOriginalFlowLease) Binding() (*dnscontrol.SyntheticDNSMapping, string) {
	if l == nil || l.self != l {
		return nil, ""
	}
	return l.mapping, l.flowID
}
func (l *domainTCPOriginalFlowLease) Guard(ctx context.Context, socket DomainPolicyTCPSocket) (autonomy.ScopeObservation, error) {
	if l == nil || l.self != l || socket != l.socket || l.owner == nil {
		return autonomy.ScopeObservation{}, ErrDomainPolicyTCPConsumer
	}
	o := l.owner
	o.mu.Lock()
	capture := o.capture
	o.mu.Unlock()
	if err := l.accepted.current(ctx, capture, socket); err != nil {
		return autonomy.ScopeObservation{}, err
	}
	if err := o.CurrentSyntheticMapping(ctx, l.mapping); err != nil {
		return autonomy.ScopeObservation{}, err
	}
	// This is the immutable physical observation from the SAME reviewed plan;
	// it is never refreshed by changing timestamps or importing a snapshot.
	scope := cloneDomainPolicyScope(capture.policy.scope)
	if !time.Now().Before(scope.FreshUntil) {
		return autonomy.ScopeObservation{}, ErrDomainPolicyTCPConsumer
	}
	return scope, nil
}
func (l *domainTCPOriginalFlowLease) WithFlow(ctx context.Context, socket DomainPolicyTCPSocket, consume func(context.Context) error) error {
	if _, err := l.Guard(ctx, socket); err != nil {
		return err
	}
	if consume == nil {
		return ErrDomainPolicyTCPConsumer
	}
	l.mu.Lock()
	if l.entered {
		l.mu.Unlock()
		return ErrDomainPolicyTCPConsumer
	}
	l.entered = true
	l.mu.Unlock()
	return consume(ctx)
}

func (o *DomainTCPOriginalScope) originalBaselineForCapture(ctx context.Context, capture *DomainPolicyTCPCapture, mapping *dnscontrol.SyntheticDNSMapping) (*domainTCPBaselineKernelOwner, error) {
	if err := o.CurrentSyntheticMapping(ctx, mapping); err != nil {
		return nil, err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.capture != capture || o.kernel == nil {
		return nil, ErrDomainPolicyTCPConsumer
	}
	return o.kernel, nil
}

// No plain direct/default dial: this private method reaches only the actual
// accepted-FD baseline resource and native Connect producer above.
func (o *DomainTCPOriginalScope) dialBaseline(ctx context.Context, kernel *domainTCPBaselineKernelOwner, socket DomainPolicyTCPSocket, flow DomainPolicyTCPFlow, decision DomainPolicyDecision) (net.Conn, error) {
	return dialDomainTCPBaseline(ctx, kernel, socket, flow, decision)
}
