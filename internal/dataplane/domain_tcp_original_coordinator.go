package dataplane

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

// This object belongs to the SAME finite Manager execution. It initially has
// no process/capture/publication capability. Only the actual emitted capture
// binds these fields; saved definitions and callback readiness cannot do so.
type DomainTCPOriginalScope struct {
	self                   *DomainTCPOriginalScope
	binding                *SyntheticDNSExecutionBinding
	backend                *BackendInventory
	gate                   *NetworkPolicyAdapter
	runtime                *LANPolicyRuntime
	runner                 NFQWS2Runner
	tools                  SyntheticDNSCommandTools
	source                 any
	mu                     sync.Mutex
	process                *XrayDomainTCPExecutionResource
	run                    *domainTCPOriginalRun
	runStarted             chan struct{} // Lazily used by a waiter before Run or revocation.
	runRevoked             atomic.Bool
	capture                *DomainPolicyTCPCapture
	baseline               *syntheticBaselineExecutionResource
	captureResource        *domainTCPCaptureExecutionResource
	prepared               *DomainPolicyTCPCaptureMapping
	kernel                 *domainTCPBaselineKernelOwner
	unpublishedPreparation *domainTCPUnpublishedPreparation
	closed                 bool
	cancel                 context.CancelFunc
	publicationOpen        bool // Only the completed original producer opens this phase.
	standbyReady           bool // Only the actual joined capture finalizer sets this.
	standbyHistory         *updatecheck.ExecutionHistoryAdmission
	standbyOwner           *domainTCPStandbyOwner
	standbyRetirement      *domainTCPStandbyRetirement
	dnsDetachment          *DomainTCPDetachedStandby
	dnsDetachmentFault     func(string) error // Private CI-only lost-ACK seam; no grant.
	preparationFault       func() error       // CI-only refusal after actual preparation, never readiness.
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
	if err := o.baseAssociationCurrent(); err != nil {
		return err
	}
	if o.runRevoked.Load() {
		return ErrDomainTCPRunRevoked
	}
	if err := o.binding.Current(ctx); err != nil {
		return err
	}
	if o.runRevoked.Load() {
		return ErrDomainTCPRunRevoked
	}
	return nil
}

// Callback-free owner/registry comparison; no source or runtime grant.
func (o *DomainTCPOriginalScope) baseAssociationCurrent() error {
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
	return nil
}

// Run uses the original one-shot Xray process owner. No exported callback can
// substitute a process, capture, Current result or DNS send acknowledgement.
func (o *DomainTCPOriginalScope) Run(ctx context.Context, resource *XrayDomainTCPExecutionResource) error {
	run, err := o.reserveDomainTCPRun(ctx, resource)
	if err != nil {
		return err
	}
	return o.serveDomainTCPRun(run, resource)
}

// StartDomainTCPRun reserves this owner's single Run before returning. A
// preflight failure returns directly, so callers never wait for readiness or
// cleanup of a Run that did not start. The original finite context governs the
// worker. Success here means reservation only; WaitDomainTCPRunReady performs
// the separate current-resource checks. The channel delivers one terminal
// result even if its caller has gone away; Manager.JoinDomainTCPRun can reread it.
func (o *DomainTCPOriginalScope) StartDomainTCPRun(ctx context.Context, resource *XrayDomainTCPExecutionResource) (<-chan error, error) {
	run, err := o.reserveDomainTCPRun(ctx, resource)
	if err != nil {
		return nil, err
	}
	result := make(chan error, 1)
	go func() {
		result <- o.serveDomainTCPRun(run, resource)
		close(result)
	}()
	return result, nil
}

func (o *DomainTCPOriginalScope) reserveDomainTCPRun(ctx context.Context, resource *XrayDomainTCPExecutionResource) (*domainTCPOriginalRun, error) {
	if err := o.baseCurrent(ctx); err != nil {
		return nil, err
	}
	if resource == nil || resource.self != resource || resource.scope != o.binding.scope || resource.material == nil || resource.material.binding != o.binding {
		return nil, ErrDomainPolicyTCPConsumer
	}
	return o.beginDomainTCPRun(ctx, resource)
}

func (o *DomainTCPOriginalScope) serveDomainTCPRun(run *domainTCPOriginalRun, resource *XrayDomainTCPExecutionResource) (result error) {
	returned := false
	defer func() {
		terminal := result
		if !returned {
			terminal = ErrDomainPolicyTCPConsumer
		}
		o.finishDomainTCPRun(run, terminal)
	}()
	result = resource.material.adapter.RunDomainPolicyTCPResource(run.ctx, resource, o)
	returned = true
	return result
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
	if domainTCPHasPriorRead(ctx) {
		return ErrDomainPolicyTCPConsumer
	}
	// Native-only elapsed time to the real publication transition. A failed
	// preparation never records an open event; normal builds use a no-op.
	finishPublicationOpen := domainTCPMeasure("initial-capture-to-publication-open")
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
	fault := o.preparationFault
	o.mu.Unlock()
	if fault != nil {
		if err := fault(); err != nil {
			return err
		}
	}
	finishInitialKernel := domainTCPMeasure("initial-kernel")
	kernel, err := newDomainTCPBaselineKernelOwner(ctx, resource, baseline)
	finishInitialKernel(0)
	if err != nil {
		return err
	}
	o.mu.Lock()
	o.kernel = kernel
	o.mu.Unlock()
	// Publication remains false until complete original process/capture/kernel
	// checks pass, including a genuine transparent baseline capability.
	finishInitialCompare := domainTCPMeasure("initial-mapping-compare")
	compareErr := o.compareSyntheticMapping(ctx, process.material.mapping)
	finishInitialCompare(0)
	if compareErr != nil {
		return compareErr
	}
	if consume == nil {
		return ErrDomainPolicyTCPConsumer
	}
	life, cancel := context.WithCancel(ctx)
	o.mu.Lock()
	if ctx.Err() != nil || capture.ctx.Err() != nil || o.closed || o.runRevoked.Load() || o.run == nil || o.prepared != prepared || o.kernel != kernel {
		o.mu.Unlock()
		cancel()
		return errors.Join(ErrDomainPolicyTCPConsumer, ctx.Err())
	}
	o.cancel = cancel
	o.publicationOpen = true
	close(o.run.ready)
	o.mu.Unlock()
	finishPublicationOpen(0)
	defer func() { cancel(); o.mu.Lock(); o.publicationOpen = false; o.closed = true; o.mu.Unlock() }()
	return consume(life)
}

func (o *DomainTCPOriginalScope) PrepareSyntheticCapture(ctx context.Context, capture *DomainPolicyTCPCapture, mapping *dnscontrol.SyntheticDNSMapping) error {
	if domainTCPHasPriorRead(ctx) {
		return ErrDomainPolicyTCPConsumer
	}
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
	return o.currentSyntheticMappingWithFiles(ctx, mapping, nil)
}
func (o *DomainTCPOriginalScope) currentSyntheticMappingWithFiles(ctx context.Context, mapping *dnscontrol.SyntheticDNSMapping, files *xrayDomainTCPFileObservation) error {
	if o == nil || o.self != o || ctx == nil || ctx.Err() != nil {
		return ErrDomainPolicyTCPConsumer
	}
	o.mu.Lock()
	open, closed := o.publicationOpen, o.closed
	o.mu.Unlock()
	if !open || closed {
		return ErrDomainPolicyTCPConsumer
	}
	if files != nil {
		finish := domainTCPMeasure("mapping-compare")
		err := func() error {
			defer finish(0)
			return o.compareSyntheticMappingWithFiles(ctx, mapping, files)
		}()
		if err == nil {
			domainTCPMeasure("mapping-compare-success")(0)
		}
		return err
	}
	return o.compareSyntheticMapping(ctx, mapping)
}

// The first producer comparison cannot be reentered as publication readiness.
// Opening the phase never replaces these full live comparisons on each send.
func (o *DomainTCPOriginalScope) compareSyntheticMapping(ctx context.Context, mapping *dnscontrol.SyntheticDNSMapping) error {
	return o.compareSyntheticMappingFrom(ctx, mapping, nil)
}

func (o *DomainTCPOriginalScope) compareSyntheticMappingFrom(ctx context.Context, mapping *dnscontrol.SyntheticDNSMapping, parent *xrayDomainTCPFileObservation) (resultErr error) {
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
	return o.compareMappingInOriginalToolObservationFrom(ctx, process, mapping, parent)
}

// Local immutable associations only. This cannot mint a process, mapping or
// kernel observation; the unchanged full comparisons execute below.
type domainTCPMappingReadSources struct {
	baseline *domainTCPBaselineCurrentSources
	kernel   *domainTCPBaselineKernelOwner
	prepared *DomainPolicyTCPCaptureMapping
}

func (s *domainTCPMappingReadSources) current(ctx context.Context, owner *DomainTCPOriginalScope, process *XrayDomainTCPExecutionResource, mapping *dnscontrol.SyntheticDNSMapping) error {
	if s == nil || s.baseline == nil || owner == nil || s.baseline.owner != owner || s.baseline.process != process || s.baseline.mapping != mapping || s.prepared == nil || s.prepared.self != s.prepared || s.prepared.capture != s.baseline.capture || s.prepared.source != mapping {
		return ErrDomainPolicyTCPConsumer
	}
	if err := s.baseline.current(ctx, s.kernel); err != nil {
		return err
	}
	owner.mu.Lock()
	same := owner.prepared == s.prepared
	owner.mu.Unlock()
	if !same {
		return ErrDomainPolicyTCPConsumer
	}
	return nil
}

// The standalone mapping comparison used to open its tool byte observation
// only inside the process file callback. Enclose the SAME complete process
// opening/body/closing with the original tool source too. No effect, send or
// dial occurs here, and both byte scopes close before returning to the caller.
func (o *DomainTCPOriginalScope) compareMappingInOriginalToolObservation(ctx context.Context, process *XrayDomainTCPExecutionResource, mapping *dnscontrol.SyntheticDNSMapping) error {
	return o.compareMappingInOriginalToolObservationFrom(ctx, process, mapping, nil)
}

func (o *DomainTCPOriginalScope) compareMappingInOriginalToolObservationFrom(ctx context.Context, process *XrayDomainTCPExecutionResource, mapping *dnscontrol.SyntheticDNSMapping, parent *xrayDomainTCPFileObservation) error {
	read := func(c context.Context, prior *xrayDomainTCPFileObservation) error {
		return process.withCurrentFileObservationFrom(c, prior, func(files *xrayDomainTCPFileObservation) error {
			return o.compareSyntheticMappingWithFiles(c, mapping, files)
		})
	}
	if o == nil || o.self != o || process == nil || process.self != process {
		return ErrDomainPolicyTCPConsumer
	}
	o.mu.Lock()
	kernel, prepared := o.kernel, o.prepared
	o.mu.Unlock()
	if kernel == nil {
		return read(ctx, parent)
	}
	baseline, original, err := kernel.originalCurrentSources(ctx)
	if err != nil {
		return err
	}
	if !original {
		return read(ctx, parent)
	} // Exact custom/cleanup path, including nil view.
	s := &domainTCPMappingReadSources{baseline: baseline, kernel: kernel, prepared: prepared}
	if err := s.current(ctx, o, process, mapping); err != nil {
		return err
	}
	defer domainTCPMeasure("mapping-outer-tool-read")(0)
	err = baseline.resource.observeToolsWithFiles(ctx, parent, func(observed context.Context, child *xrayDomainTCPFileObservation) error {
		if err := domainTCPBaselineCurrentReadContext(ctx, observed); err != nil {
			return err
		}
		if err := s.current(observed, o, process, mapping); err != nil {
			return err
		}
		// Keep the exact accepted-prefix parent, when present. A standalone
		// mapping comparison instead lends this already-bounded file opening
		// to its nested predecessor reads. Both kernel passes, independent
		// old descriptor bytes and all process/receipt checks still execute.
		result := process.observeOriginalPriorFilesFrom(observed, true, child, func(readCtx context.Context, files *xrayDomainTCPFileObservation) error {
			return o.compareSyntheticMappingWithFiles(readCtx, mapping, files)
		})
		return errors.Join(result, s.current(observed, o, process, mapping), domainTCPBaselineCurrentReadContext(ctx, observed))
	})
	return errors.Join(err, s.current(ctx, o, process, mapping), ctx.Err())
}

func (o *DomainTCPOriginalScope) compareSyntheticMappingWithFiles(ctx context.Context, mapping *dnscontrol.SyntheticDNSMapping, files *xrayDomainTCPFileObservation) error {
	if err := o.baseCurrent(ctx); err != nil {
		return err
	}
	o.mu.Lock()
	process, capture, prepared, kernel, resource, baseline := o.process, o.capture, o.prepared, o.kernel, o.captureResource, o.baseline
	o.mu.Unlock()
	if process == nil || resource == nil {
		return ErrDomainPolicyTCPConsumer
	}
	material, tools, backend, binding := process.material, resource.tools, resource.backend, o.binding
	// Only this concrete original tuple may borrow the source's immutable
	// tool bytes. Every process, mapping, journal and actual kernel read below
	// still runs, in order, and publication/send stays outside this scope.
	association := func() error {
		o.mu.Lock()
		defer o.mu.Unlock()
		if o.closed || o.process != process || o.capture != capture || o.prepared != prepared ||
			o.kernel != kernel || o.captureResource != resource || o.baseline != baseline ||
			process.self != process || material == nil || process.material != material || material.mapping != mapping || material.binding != binding || o.binding != binding ||
			capture == nil || capture.owner != o || capture.xray == nil || capture.xray.resource != process ||
			prepared == nil || prepared.capture != capture || prepared.source != mapping ||
			resource.self != resource || resource.capture != capture || resource.process != process || resource.mapping != mapping || resource.tools != tools || resource.backend != backend ||
			baseline == nil || baseline.capture != capture || baseline.mapping != mapping || baseline.binding != binding || baseline.tools != tools || baseline.backend != backend ||
			kernel == nil || kernel.self != kernel || kernel.capture != resource || kernel.baseline != baseline {
			return ErrDomainPolicyTCPConsumer
		}
		return nil
	}
	if err := association(); err != nil {
		return err
	}
	defer domainTCPMeasure("mapping-original-tool-read")(0)
	err := resource.observeToolsWithFiles(ctx, files, func(observed context.Context, childFiles *xrayDomainTCPFileObservation) error {
		result := func() error {
			if err := prepared.currentWithFiles(observed, childFiles); err != nil {
				return err
			}
			if err := kernel.currentWithFiles(observed, childFiles); err != nil {
				return err
			}
			return material.Current(observed)
		}()
		return errors.Join(result, association(), observed.Err())
	})
	err = errors.Join(err, association(), ctx.Err())
	if err == nil {
		domainTCPMeasure("mapping-original-tool-closing")(0)
	}
	return err
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
	if err := captureRetirementContext(ctx); err != nil {
		return err
	}
	wire, err := o.prepareDomainTCPWireSend(mapping)
	if err != nil {
		return err
	}
	read, release := wire.run.readinessContext(ctx)
	defer release()
	finishOpening := domainTCPMeasure("dns-publication-opening")
	openingErr := o.CurrentSyntheticMapping(read, mapping)
	finishOpening(0)
	if openingErr != nil {
		return openingErr
	}
	finishSend := domainTCPMeasure("dns-send")
	err = func() error {
		defer wire.close()
		return send(context.WithValue(read, domainTCPWireSendKey{}, wire))
	}()
	finishSend(0)
	if err == nil {
		domainTCPMeasure("dns-send-success")(0)
	}
	finishClosing := domainTCPMeasure("dns-publication-closing")
	closingErr := o.CurrentSyntheticMapping(read, mapping)
	finishClosing(0)
	return errors.Join(err, closingErr)
}
func (o *DomainTCPOriginalScope) LookupPublished(ctx context.Context, client, synthetic netip.Addr) (*dnscontrol.SyntheticDNSMapping, error) {
	finish := domainTCPMeasure("accepted-flow-lookup")
	defer finish(0)
	if err := o.baseCurrent(ctx); err != nil {
		return nil, err
	}
	o.mu.Lock()
	process := o.process
	o.mu.Unlock()
	if process == nil {
		return nil, ErrDomainPolicyTCPConsumer
	}
	return o.lookupPublishedInOriginalToolObservation(ctx, process, client, synthetic)
}

type domainTCPLookupReadSources struct {
	mapping  *domainTCPMappingReadSources
	resolver *dnscontrol.NetworkPolicyDNSSyntheticResolver
}

func (s *domainTCPLookupReadSources) current(ctx context.Context, owner *DomainTCPOriginalScope, process *XrayDomainTCPExecutionResource, mapping *dnscontrol.SyntheticDNSMapping) error {
	if s == nil || s.mapping == nil || s.resolver == nil {
		return ErrDomainPolicyTCPConsumer
	}
	if err := s.mapping.current(ctx, owner, process, mapping); err != nil {
		return err
	}
	if process.material.dnsSource != s.resolver {
		return ErrDomainPolicyTCPConsumer
	}
	return nil
}

// Both original mapping comparisons remain independent: the resolver calls
// CurrentSyntheticMapping and this owner repeats it after mapping.Current.
// The fixed body is readonly; no flow registration, lease or dial is included.
func (o *DomainTCPOriginalScope) lookupPublishedRead(ctx context.Context, process *XrayDomainTCPExecutionResource, client, synthetic netip.Addr) (*dnscontrol.SyntheticDNSMapping, error) {
	mapping, err := process.material.dnsSource.LookupPublished(ctx, client, synthetic)
	if err != nil || mapping != process.material.mapping {
		return nil, errors.Join(ErrDomainPolicyTCPConsumer, err)
	}
	return mapping, o.CurrentSyntheticMapping(ctx, mapping)
}

func (o *DomainTCPOriginalScope) lookupPublishedInOriginalToolObservation(ctx context.Context, process *XrayDomainTCPExecutionResource, client, synthetic netip.Addr) (*dnscontrol.SyntheticDNSMapping, error) {
	if o == nil || o.self != o || process == nil || process.self != process || process.material == nil {
		return nil, ErrDomainPolicyTCPConsumer
	}
	o.mu.Lock()
	kernel, prepared := o.kernel, o.prepared
	o.mu.Unlock()
	if kernel == nil {
		return o.lookupPublishedRead(ctx, process, client, synthetic)
	}
	baseline, original, err := kernel.originalCurrentSources(ctx)
	if err != nil {
		return nil, err
	}
	if !original {
		return o.lookupPublishedRead(ctx, process, client, synthetic)
	}
	expected := baseline.mapping
	s := &domainTCPLookupReadSources{mapping: &domainTCPMappingReadSources{baseline: baseline, kernel: kernel, prepared: prepared}, resolver: process.material.dnsSource}
	if err := s.current(ctx, o, process, expected); err != nil {
		return nil, err
	}
	defer domainTCPMeasure("accepted-lookup-outer-tool-read")(0)
	mapping, err := domainTCPLookupObservedResult(ctx, baseline.resource.observeTools, func(observed context.Context) (*dnscontrol.SyntheticDNSMapping, error) {
		if err := domainTCPBaselineCurrentReadContext(ctx, observed); err != nil {
			return nil, err
		}
		if err := s.current(observed, o, process, expected); err != nil {
			return nil, err
		}
		mapping, readErr := o.lookupPublishedRead(observed, process, client, synthetic)
		return mapping, errors.Join(readErr, s.current(observed, o, process, expected), domainTCPBaselineCurrentReadContext(ctx, observed))
	})
	// A tentative mapping never escapes a failed actual tool closing or a
	// revoked original resolver/owner/context, even if both body reads passed.
	err = errors.Join(err, s.current(ctx, o, process, expected), ctx.Err())
	if err != nil {
		return nil, err
	}
	return mapping, nil
}

// This result bookend grants no source or mapping authority. It retains the
// fixed caller body's outcome independently of the tool observer's returned
// error, and accepts exactly one completed callback before outer closing.
func domainTCPLookupObservedResult(ctx context.Context, observe func(context.Context, func(context.Context) error) error, read func(context.Context) (*dnscontrol.SyntheticDNSMapping, error)) (*dnscontrol.SyntheticDNSMapping, error) {
	if ctx == nil || observe == nil || read == nil || ctx.Err() != nil {
		return nil, ErrDomainPolicyTCPConsumer
	}
	var mu sync.Mutex
	var calls int
	var complete, closed bool
	var mapping *dnscontrol.SyntheticDNSMapping
	var bodyErr error
	outerErr := observe(ctx, func(observed context.Context) error {
		mu.Lock()
		calls++
		if closed || calls != 1 {
			mu.Unlock()
			return ErrDomainPolicyTCPConsumer
		}
		mu.Unlock()
		result, err := read(observed)
		mu.Lock()
		defer mu.Unlock()
		if closed {
			return errors.Join(ErrDomainPolicyTCPConsumer, err)
		}
		mapping, bodyErr, complete = result, err, true
		return err
	})
	mu.Lock()
	defer mu.Unlock()
	closed = true
	err := errors.Join(outerErr, bodyErr, ctx.Err())
	if calls != 1 || !complete || mapping == nil || err != nil {
		return nil, errors.Join(ErrDomainPolicyTCPConsumer, err)
	}
	return mapping, nil
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
	return o.admitTCPFrom(ctx, socket, nil)
}

func (o *DomainTCPOriginalScope) admitTCPFrom(ctx context.Context, socket DomainPolicyTCPSocket, files *xrayDomainTCPFileObservation) (DomainPolicyTCPFlowLease, error) {
	o.mu.Lock()
	capture, process := o.capture, o.process
	o.mu.Unlock()
	accepted, err := originalDomainAcceptedTCP(ctx, capture, socket)
	if err != nil || process == nil {
		return nil, errors.Join(ErrDomainPolicyTCPConsumer, err)
	}
	if err := o.currentSyntheticMappingFrom(ctx, process.material.mapping, files); err != nil {
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
	return l.guardWithFiles(ctx, socket, nil)
}
func (l *domainTCPOriginalFlowLease) guardWithFiles(ctx context.Context, socket DomainPolicyTCPSocket, files *xrayDomainTCPFileObservation) (autonomy.ScopeObservation, error) {
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
	if err := o.currentSyntheticMappingWithFiles(ctx, l.mapping, files); err != nil {
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
	return l.consume(ctx, consume)
}

func (l *domainTCPOriginalFlowLease) consume(ctx context.Context, consume func(context.Context) error) error {
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
	return o.originalBaselineForCaptureFrom(ctx, capture, mapping, nil)
}

func (o *DomainTCPOriginalScope) originalBaselineForCaptureFrom(ctx context.Context, capture *DomainPolicyTCPCapture, mapping *dnscontrol.SyntheticDNSMapping, files *xrayDomainTCPFileObservation) (*domainTCPBaselineKernelOwner, error) {
	if err := o.currentSyntheticMappingFrom(ctx, mapping, files); err != nil {
		return nil, err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.capture != capture || o.kernel == nil {
		return nil, ErrDomainPolicyTCPConsumer
	}
	return o.kernel, nil
}

// No generic direct/default dial: only the exact accepted flow and original
// complete packet/route owner may issue the router-originated native socket.
func (o *DomainTCPOriginalScope) dialBaseline(ctx context.Context, kernel *domainTCPBaselineKernelOwner, socket DomainPolicyTCPSocket, flow DomainPolicyTCPFlow, decision DomainPolicyDecision) (net.Conn, error) {
	return dialDomainTCPDirect(ctx, o, kernel, socket, flow, decision)
}
