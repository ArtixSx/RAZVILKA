package dataplane

import (
	"context"
	"errors"
	"os"
	"reflect"
	"time"
)

type xrayDomainTCPRegistrarKey struct{}
type xrayDomainTCPRegistrar func(context.Context, *XrayDomainTCPOperationMaterial) (*XrayDomainTCPExecutionResource, error)

// Acquire registers only original DNS/node material in the existing Manager
// execution. A definition, copied context or pathname cannot supply material.
func AcquireXrayDomainTCPExecutionResource(ctx context.Context, material *XrayDomainTCPOperationMaterial) (*XrayDomainTCPExecutionResource, error) {
	if xraySelectedTCPFinite(ctx) != nil || material == nil || material.self != material {
		return nil, ErrXrayDomainTCPOriginal
	}
	issue, ok := ctx.Value(xrayDomainTCPRegistrarKey{}).(xrayDomainTCPRegistrar)
	if !ok || issue == nil {
		return nil, ErrXrayDomainTCPOriginal
	}
	return issue(ctx, material)
}

func (s *executionResourceScope) issueXrayDomainTCP(ctx context.Context, material *XrayDomainTCPOperationMaterial) (_ *XrayDomainTCPExecutionResource, result error) {
	if s == nil || xraySelectedTCPFinite(ctx) != nil || ctx.Value(syntheticExecutionRegistrarKey{}) != s {
		return nil, ErrXrayDomainTCPOriginal
	}
	r, err := s.prepareXrayDomainTCPResource(ctx, material)
	if err != nil {
		return nil, err
	}
	published := false
	defer func() {
		if !published {
			if r.records != nil {
				result = errors.Join(result, r.records.close())
			}
			result = errors.Join(result, r.closeUnpublishedFiles())
		}
	}()
	r.records, err = newXraySelectedTCPRecords(s)
	if err != nil {
		return nil, err
	}
	if err := material.Current(ctx); err != nil {
		return nil, err
	}
	s.startMu.RLock()
	defer s.startMu.RUnlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.xrayDomainTCP == nil || len(s.xrayDomainTCP) != 0 || len(s.xraySelectedTCP) != 0 || s.resourceCount() >= maxExecutionResources || s.checkOriginalOwner(ctx, nil, true, false) != nil {
		return nil, ErrXrayDomainTCPOriginal
	}
	s.xrayDomainTCP[r.id] = r
	d := r.definition.Clone()
	s.execution.Resources = append(s.execution.Resources, ExecutionResource{ID: r.id, Kind: "xray-domain-tcp", State: "prepared", Phase: "planned", Generation: d.Domain.Generation, EffectsDigest: d.ConfigSHA256, XrayDomainTCP: &d})
	published = true
	return r, s.persist()
}

func validateXrayDomainTCPExecutionResource(resource ExecutionResource, terminal bool) error {
	d := resource.XrayDomainTCP
	if d == nil || resource.Kind != "xray-domain-tcp" || resource.NodeTransit != nil || resource.NFQWS != nil || resource.SyntheticBaseline != nil || resource.XraySelectedTCP != nil || d.validate() != nil || resource.Generation != d.Domain.Generation || resource.EffectsDigest != d.ConfigSHA256 {
		return ErrExecutionJournal
	}
	switch resource.Phase {
	case "planned", "process-pending", "listener-ready", "closed":
		if resource.State != "prepared" || terminal {
			return ErrExecutionJournal
		}
	case "removed":
		if resource.State != "removed" {
			return ErrExecutionJournal
		}
	case "unused":
		if resource.State != "unused" {
			return ErrExecutionJournal
		}
	default:
		return ErrExecutionJournal
	}
	return nil
}

// Called with the scope mutex held; neither decoded records nor equal bytes
// replace the actual typed registration and its original descriptor owner.
func (r *XrayDomainTCPExecutionResource) matching() (int, error) {
	if r == nil || r.self != r || r.scope == nil || r.scope.xrayDomainTCP[r.id] != r || r.material == nil || r.material.self != r.material || r.material.resource != r {
		return -1, ErrXrayDomainTCPOriginal
	}
	for i, record := range r.scope.execution.Resources {
		if record.ID == r.id {
			if validateXrayDomainTCPExecutionResource(record, false) != nil || !reflect.DeepEqual(*record.XrayDomainTCP, r.definition) {
				return -1, ErrXrayDomainTCPOriginal
			}
			return i, nil
		}
	}
	return -1, ErrXrayDomainTCPOriginal
}

// The caller holds resource.mu and the scope start barrier. Cleanup uses the
// pre-issued exclusive cleanup lifetime, never the expired forward request.
func (r *XrayDomainTCPExecutionResource) originalContext(ctx context.Context, cleanup bool) (context.Context, error) {
	return r.originalContextWithFiles(ctx, cleanup, nil)
}
func (r *XrayDomainTCPExecutionResource) originalContextWithFiles(ctx context.Context, cleanup bool, files *xrayDomainTCPFileObservation) (context.Context, error) {
	if r == nil || r.material == nil {
		return nil, ErrXrayDomainTCPOriginal
	}
	if !cleanup {
		if err := r.material.Current(ctx); err != nil {
			return nil, err
		}
	}
	return r.originalContextAlreadyHeldWithFiles(ctx, cleanup, files)
}

// Local closing bookend after full external source reads. Native Start alone
// calls this while holding startMu; it must never recursively take that lock.
func (r *XrayDomainTCPExecutionResource) originalContextAlreadyHeld(ctx context.Context, cleanup bool) (context.Context, error) {
	return r.originalContextAlreadyHeldWithFiles(ctx, cleanup, nil)
}
func (r *XrayDomainTCPExecutionResource) originalContextAlreadyHeldWithFiles(ctx context.Context, cleanup bool, files *xrayDomainTCPFileObservation) (context.Context, error) {
	if r == nil || r.self != r || r.descriptorsClosed.Load() || r.scope == nil || r.records == nil || xraySelectedTCPFinite(ctx) != nil || ctx.Value(syntheticExecutionRegistrarKey{}) != r.scope {
		return nil, ErrXrayDomainTCPOriginal
	}
	if cleanup {
		if r.material.control.CurrentForCleanupOperation(ctx, r.material.cleanup) != nil {
			return nil, ErrXrayDomainTCPOriginal
		}
	} else if err := r.material.metadataCurrent(ctx); err != nil {
		return nil, err
	}
	r.scope.mu.Lock()
	_, err := r.matching()
	if err == nil {
		err = r.scope.checkOriginalOwner(ctx, nil, !cleanup, false)
	}
	r.scope.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if err := r.records.current(ctx, true); err != nil {
		return nil, err
	}
	if err := r.filesCurrentForObservation(ctx, files); err != nil {
		return nil, err
	}
	return ctx, nil
}

func (r *XrayDomainTCPExecutionResource) originalProcessReadContext(ctx context.Context, cleanup bool) (context.Context, func(), error) {
	c, err := r.originalContext(ctx, cleanup)
	if err != nil || r.child == nil {
		return nil, nil, errors.Join(ErrXrayDomainTCPOriginal, err)
	}
	return r.processReadContext(c)
}

func (r *XrayDomainTCPExecutionResource) originalProcessReadAlreadyHeld(ctx context.Context) (context.Context, func(), error) {
	c, err := r.originalContextAlreadyHeld(ctx, false)
	if err != nil || r.child == nil {
		return nil, nil, errors.Join(ErrXrayDomainTCPOriginal, err)
	}
	return r.processReadContext(c)
}

func (r *XrayDomainTCPExecutionResource) processReadContext(c context.Context) (context.Context, func(), error) {
	read := &xrayDomainTCPProcessRead{resource: r, process: r.child}
	read.self = read
	read.open.Store(true)
	return context.WithValue(c, xrayDomainTCPProcessReadKey{}, read), func() { read.open.Store(false) }, nil
}

// WithNative is a finite isolated process scenario. It does not publish DNS,
// capture rules, an active route, or permission to remove standby resources.
func (r *XrayDomainTCPExecutionResource) WithNative(ctx context.Context, consume func(context.Context) error) (result error) {
	if r == nil || r.self != r || r.scope == nil || r.material == nil || r.material.binding == nil || r.material.binding.phase == nil || consume == nil {
		return ErrXrayDomainTCPOriginal
	}
	return r.material.binding.phase.withDomainNativeActivity(ctx, func(held context.Context) error { return r.withNativeInPhase(held, consume) })
}

// Existing phase cancellation and join, without holding its DNS request lock
// while the native callback itself performs synchronous DNS requests.
func (p *syntheticBaselineExecutionPhase) withDomainNativeActivity(request context.Context, use func(context.Context) error) error {
	if p == nil || p.self != p || request == nil || use == nil || request.Err() != nil {
		return ErrDomainTransportRuntime
	}
	p.nativeMu.Lock()
	if p.closed.Load() || p.ctx.Err() != nil {
		p.nativeMu.Unlock()
		return ErrDomainTransportRuntime
	}
	p.nativeWG.Add(1)
	p.nativeMu.Unlock()
	defer p.nativeWG.Done()
	deadline, finite := p.ctx.Deadline()
	if !finite {
		return ErrDomainTransportRuntime
	}
	if sooner, bounded := request.Deadline(); bounded && sooner.Before(deadline) {
		deadline = sooner
	}
	held, cancel := context.WithDeadline(p.ctx, deadline)
	stop := context.AfterFunc(request, cancel)
	defer func() { stop(); cancel() }()
	if request.Err() != nil {
		cancel()
	}
	if err := p.binding.Current(held); err != nil {
		return err
	}
	err := use(held)
	if held.Err() != nil {
		// Forward Current refuses this canceled context before observing a
		// source. Preserve precise cancellation and all actual cleanup errors.
		return errors.Join(err, held.Err(), request.Err())
	}
	return errors.Join(err, held.Err(), request.Err(), p.binding.Current(held))
}

func (r *XrayDomainTCPExecutionResource) withNativeInPhase(ctx context.Context, consume func(context.Context) error) (result error) {
	r.mu.Lock()
	if _, err := r.originalContext(ctx, false); err != nil {
		r.mu.Unlock()
		return err
	}
	if r.startUsed {
		r.mu.Unlock()
		return ErrXrayDomainTCPOriginal
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 12*time.Second)
		defer cancel()
		r.mu.Lock()
		defer r.mu.Unlock()
		result = errors.Join(result, r.stopOriginalNative(cleanup))
	}()
	if err := r.startOriginalNative(ctx); err != nil {
		r.mu.Unlock()
		return err
	}
	r.mu.Unlock()
	if err := consume(ctx); err != nil {
		return err
	}
	return r.Current(ctx)
}

// Current observes the actual original child/listener inside the same finite
// execution. It is not an active-route, capture or DNS-publication receipt.
func (r *XrayDomainTCPExecutionResource) Current(ctx context.Context) error {
	return r.currentWithFiles(ctx, nil)
}
func (r *XrayDomainTCPExecutionResource) currentWithFiles(ctx context.Context, files *xrayDomainTCPFileObservation) error {
	defer domainTCPMeasure("process-current")(0)
	if r == nil || r.self != r {
		return ErrXrayDomainTCPOriginal
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.listenerCurrentWithFiles(ctx, files)
}

func (r *XrayDomainTCPExecutionResource) listenerCurrent(ctx context.Context) error {
	return r.listenerCurrentWithFiles(ctx, nil)
}
func (r *XrayDomainTCPExecutionResource) listenerCurrentWithFiles(ctx context.Context, files *xrayDomainTCPFileObservation) error {
	if files != nil {
		return r.listenerCurrentInFileObservation(ctx, files)
	}
	read, closeRead, err := r.originalProcessReadContext(ctx, false)
	if err != nil {
		return err
	}
	defer closeRead()
	// No callback or native effect occurs between the full originalContext
	// opening above and this one-use, same-process readonly observation.
	opening := r.fileOpeningAfterOriginalRead(read)
	actual, err := r.observeDomainListenerWithOpening(read, opening)
	if err != nil || r.birth == nil || !r.birth.same(actual.process) {
		return errors.Join(ErrXrayDomainTCPOriginal, err)
	}
	return nil
}

func (r *XrayDomainTCPExecutionResource) phase(phase, state string) error {
	r.scope.mu.Lock()
	defer r.scope.mu.Unlock()
	i, err := r.matching()
	if err != nil {
		return err
	}
	r.scope.execution.Resources[i].Phase, r.scope.execution.Resources[i].State = phase, state
	return r.scope.persist()
}

func (r *XrayDomainTCPExecutionResource) closeOriginalDescriptors() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.descriptorsClosed.Load() {
		return r.descriptorsErr
	}
	if r.scope == nil {
		return ErrXrayDomainTCPOriginal
	}
	r.scope.mu.Lock()
	i, matchErr := r.matching()
	if matchErr == nil {
		matchErr = validateXrayDomainTCPExecutionResource(r.scope.execution.Resources[i], true)
	}
	r.scope.mu.Unlock()
	if matchErr != nil {
		return errors.Join(ErrPolicyAdditionUnknown, matchErr)
	}
	if r.child != nil {
		select {
		case <-r.child.done:
		default:
			return ErrXrayDomainTCPOriginal
		}
	}
	r.descriptorsClosed.Store(true)
	var err error
	if r.log != nil {
		err = errors.Join(err, r.log.Close())
	}
	if r.records != nil {
		err = errors.Join(err, r.records.close())
	}
	if r.config != nil {
		err = errors.Join(err, r.config.Close())
	}
	if r.executable != nil {
		err = errors.Join(err, r.executable.file.Close())
	}
	if r.root != nil {
		err = errors.Join(err, r.root.Close())
	}
	r.descriptorsErr = err
	return err
}

// Needed by native Start callers to keep file identity at both bookends.
func (r *XrayDomainTCPExecutionResource) originalFilesSame() bool {
	return r.birth != nil && os.SameFile(r.birth.executable, r.executable.info) && os.SameFile(r.birth.config, r.configInfo)
}

func (r *XrayDomainTCPExecutionResource) listenerCurrentInFileObservation(ctx context.Context, files *xrayDomainTCPFileObservation) error {
	if err := files.current(ctx, r); err != nil {
		return err
	}
	original, err := r.originalContextWithFiles(ctx, false, files)
	if err != nil || r.child == nil {
		return errors.Join(ErrXrayDomainTCPOriginal, err)
	}
	read, closeRead, err := r.processReadContext(original)
	if err != nil {
		return err
	}
	defer closeRead()
	nested, closeFiles, err := files.forOriginalProcessRead(ctx, read, r)
	if err != nil {
		return err
	}
	defer closeFiles()
	actual, err := r.observeDomainListenerUsingFiles(read, nested)
	if err != nil || r.birth == nil || !r.birth.same(actual.process) {
		return errors.Join(ErrXrayDomainTCPOriginal, err)
	}
	return nil
}
