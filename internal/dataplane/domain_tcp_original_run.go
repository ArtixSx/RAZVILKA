package dataplane

import (
	"context"
	"errors"
	"time"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

var ErrDomainTCPRunRevoked = errors.New("original domain TCP run revoked")
var ErrDomainTCPRunNotStarted = errors.New("original domain TCP run did not start")
var ErrDomainTCPRunNotReady = errors.New("original domain TCP run ended before confirming publication readiness")

// DomainTCPRunReadiness is an observation of the installed publication path.
// The mapping's expiry is an upper bound for scheduling revalidation. Neither
// the observation nor its expiry authorizes DNS publication, flow or Apply.
type DomainTCPRunReadiness struct {
	Generation       string
	ServiceID        string
	NodeID           string
	MappingExpiresAt time.Time
}

type domainTCPOriginalRun struct {
	ctx    context.Context
	cancel context.CancelFunc
	ready  chan struct{}
	done   chan struct{}
	result error // Published by the sole original Run before closing done.
}

type domainTCPWireSendKey struct{}

// All mutable fields are guarded by the original scope's mutex. Each answer
// retains the admission from its own completed opening check.
type domainTCPWireSend struct {
	owner   *DomainTCPOriginalScope
	run     *domainTCPOriginalRun
	mapping *dnscontrol.SyntheticDNSMapping
	closed  bool
	used    bool
}

func (o *DomainTCPOriginalScope) prepareDomainTCPWireSend(mapping *dnscontrol.SyntheticDNSMapping) (*domainTCPWireSend, error) {
	if o == nil || o.self != o || mapping == nil {
		return nil, ErrDomainPolicyTCPConsumer
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.runPublicationLocked(o.run) != mapping {
		return nil, ErrDomainPolicyTCPConsumer
	}
	return &domainTCPWireSend{owner: o, run: o.run, mapping: mapping}, nil
}

func (a *domainTCPWireSend) close() {
	a.owner.mu.Lock()
	defer a.owner.mu.Unlock()
	a.closed = true
}

// WithSyntheticWireSend linearizes the actual write with capture closure and
// explicit Run revocation. All source, Store, kernel and durable Stop reads
// belong to the surrounding publication, outside this short owner lock.
func (o *DomainTCPOriginalScope) WithSyntheticWireSend(ctx context.Context, mapping *dnscontrol.SyntheticDNSMapping, write func() error) error {
	if o == nil || o.self != o || mapping == nil || write == nil || captureRetirementContext(ctx) != nil {
		return ErrDomainPolicyTCPConsumer
	}
	a, _ := ctx.Value(domainTCPWireSendKey{}).(*domainTCPWireSend)
	if a == nil || a.owner != o || a.mapping != mapping {
		return ErrDomainPolicyTCPConsumer
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if a.closed || a.used || o.runPublicationLocked(a.run) != mapping {
		return ErrDomainPolicyTCPConsumer
	}
	capture := o.capture
	if capture == nil || capture.self != capture || capture.owner != o || capture.listener == nil || capture.ctx == nil || capture.ctx.Err() != nil {
		return ErrDomainPolicyTCPConsumer
	}
	listener, err := capture.listener.SyscallConn()
	if err != nil {
		return errors.Join(ErrDomainPolicyTCPConsumer, err)
	}
	if err := listener.Control(func(uintptr) {}); err != nil {
		return errors.Join(ErrDomainPolicyTCPConsumer, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	a.used = true
	return write()
}

// The execution resource, Manager and forward scope were already compared by
// Run. This local reservation serializes the one Run with explicit revocation.
func (o *DomainTCPOriginalScope) beginDomainTCPRun(ctx context.Context, resource *XrayDomainTCPExecutionResource) (*domainTCPOriginalRun, error) {
	if ctx == nil || domainTCPHasPriorRead(ctx) {
		return nil, ErrDomainPolicyTCPConsumer
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.runRevoked.Load() {
		return nil, ErrDomainTCPRunRevoked
	}
	if o.closed || o.process != nil || o.run != nil || ctx.Err() != nil {
		return nil, errors.Join(ErrDomainPolicyTCPConsumer, ctx.Err())
	}
	life, cancel := context.WithCancel(ctx)
	run := &domainTCPOriginalRun{ctx: life, cancel: cancel, ready: make(chan struct{}), done: make(chan struct{})}
	o.process, o.run = resource, run
	o.wakeDomainTCPStartLocked()
	return run, nil
}

func (o *DomainTCPOriginalScope) wakeDomainTCPStartLocked() {
	if o.runStarted != nil {
		close(o.runStarted)
		o.runStarted = nil
	}
}

func (o *DomainTCPOriginalScope) finishDomainTCPRun(run *domainTCPOriginalRun, result error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.publicationOpen = false
	// Only the original capture or DNS finalizer may report its close.
	// Run can return before the native listener or DNS cleanup is entered.
	run.result = result
	run.cancel()
	close(run.done)
}

// This identity check retains the original Manager/owner association after
// forward authority expires. Revoking or joining it grants no packet or
// cleanup authority and cannot take over another Manager's execution.
func (m *Manager) ownsDomainTCPRun(owner *DomainTCPOriginalScope) bool {
	if m == nil || owner == nil || owner.self != owner || owner.binding == nil || owner.binding.self != owner.binding || owner.binding.scope == nil || owner.binding.scope.manager != m {
		return false
	}
	scope := owner.binding.scope
	scope.mu.Lock()
	same := scope.domainTCPOwner == owner
	scope.mu.Unlock()
	return same
}

// RevokeDomainTCPRun stops new publication and cancels the original Run even
// if native preparation is still in progress. It may also prevent a prepared
// owner from starting later. Stop must separately settle all other original
// resources, including DNS/retirement when Run has never started.
func (m *Manager) RevokeDomainTCPRun(ctx context.Context, owner *DomainTCPOriginalScope) error {
	if captureRetirementContext(ctx) != nil || !m.ownsDomainTCPRun(owner) {
		return ErrDomainPolicyTCPConsumer
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	owner.runRevoked.Store(true)
	owner.publicationOpen = false
	owner.wakeDomainTCPStartLocked()
	if owner.run != nil {
		owner.run.cancel()
	}
	if owner.cancel != nil {
		owner.cancel()
	}
	return nil
}

// JoinDomainTCPRun returns the original Run result after its process/capture
// callbacks and cleanup returned. A joined Run can still report errors or an
// unresolved restorative baseline for an issued alias. A bounded wait failure
// and an unstarted Run both return joined=false.
func (m *Manager) JoinDomainTCPRun(ctx context.Context, owner *DomainTCPOriginalScope) (joined bool, err error) {
	if captureRetirementContext(ctx) != nil || !m.ownsDomainTCPRun(owner) {
		return false, ErrDomainPolicyTCPConsumer
	}
	owner.mu.Lock()
	run := owner.run
	owner.mu.Unlock()
	if run == nil {
		return false, ErrDomainTCPRunNotStarted
	}
	select {
	case <-run.done:
		return true, run.result
	case <-ctx.Done():
		// Cancellation bounds waiting; it does not erase a Run result that
		// was already published. Both channels can be ready in this select.
		select {
		case <-run.done:
			return true, run.result
		default:
			return false, ctx.Err()
		}
	}
}

// CheckDomainTCPRunReady reads the original published phase and revalidates
// the actual mapping, listener, process, receipts and kernel. The original
// context/current sources must still admit the read. It reports publication
// readiness, while service and applied client probes remain separate checks.
func (o *DomainTCPOriginalScope) CheckDomainTCPRunReady(ctx context.Context) error {
	if o == nil || o.self != o || captureRetirementContext(ctx) != nil {
		return ErrDomainPolicyTCPConsumer
	}
	o.mu.Lock()
	run := o.run
	o.mu.Unlock()
	_, err := o.observeDomainTCPRunReady(ctx, run)
	return err
}

// WaitDomainTCPRunReady observes the same owner from reservation through the
// publication-opening signal. The signal only schedules a fresh read of all
// original resources. A stopped Run cannot use a prior signal as readiness.
func (o *DomainTCPOriginalScope) WaitDomainTCPRunReady(ctx context.Context) (DomainTCPRunReadiness, error) {
	if o == nil || o.self != o || captureRetirementContext(ctx) != nil || o.binding == nil || o.binding.scope == nil || !o.binding.scope.manager.ownsDomainTCPRun(o) {
		return DomainTCPRunReadiness{}, ErrDomainPolicyTCPConsumer
	}
	o.mu.Lock()
	run, revoked := o.run, o.runRevoked.Load()
	if run == nil && !revoked {
		if o.runStarted == nil {
			o.runStarted = make(chan struct{})
		}
		started := o.runStarted
		o.mu.Unlock()
		select {
		case <-started:
		case <-ctx.Done():
			return DomainTCPRunReadiness{}, ctx.Err()
		}
		o.mu.Lock()
		run, revoked = o.run, o.runRevoked.Load()
	}
	o.mu.Unlock()
	if revoked {
		return DomainTCPRunReadiness{}, ErrDomainTCPRunRevoked
	}
	if run == nil {
		return DomainTCPRunReadiness{}, ErrDomainTCPRunNotStarted
	}
	select {
	case <-run.done:
		return DomainTCPRunReadiness{}, errors.Join(ErrDomainTCPRunNotReady, run.result)
	case <-run.ctx.Done():
		// A terminal Run cancels and publishes done under the same lock.
		// An independent revocation can cancel while cleanup is still live.
		o.mu.Lock()
		defer o.mu.Unlock()
		select {
		case <-run.done:
			return DomainTCPRunReadiness{}, errors.Join(ErrDomainTCPRunNotReady, run.result)
		default:
		}
		return DomainTCPRunReadiness{}, errors.Join(ErrDomainTCPRunNotReady, run.ctx.Err())
	case <-ctx.Done():
		return DomainTCPRunReadiness{}, ctx.Err()
	case <-run.ready:
		ready, err := o.observeDomainTCPRunReady(ctx, run)
		if err != nil {
			select {
			case <-run.done:
				err = errors.Join(ErrDomainTCPRunNotReady, run.result, err)
			default:
			}
		}
		return ready, err
	}
}

func (o *DomainTCPOriginalScope) observeDomainTCPRunReady(ctx context.Context, run *domainTCPOriginalRun) (DomainTCPRunReadiness, error) {
	o.mu.Lock()
	mapping := o.runPublicationLocked(run)
	o.mu.Unlock()
	if mapping == nil {
		return DomainTCPRunReadiness{}, ErrDomainPolicyTCPConsumer
	}
	read, cancel := run.readinessContext(ctx)
	defer cancel()
	if err := errors.Join(o.CurrentSyntheticMapping(read, mapping), read.Err()); err != nil {
		return DomainTCPRunReadiness{}, err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.runPublicationLocked(run) != mapping || read.Err() != nil {
		return DomainTCPRunReadiness{}, errors.Join(ErrDomainPolicyTCPConsumer, read.Err())
	}
	spec := o.process.definition.Capture.Xray
	return DomainTCPRunReadiness{Generation: spec.Generation, ServiceID: spec.ServiceID, NodeID: spec.NodeID, MappingExpiresAt: o.prepared.observation.ExpiresAt}, nil
}

func (r *domainTCPOriginalRun) readinessContext(ctx context.Context) (context.Context, func()) {
	deadline, _ := ctx.Deadline() // CheckDomainTCPRunReady requires a bounded caller.
	if original, finite := r.ctx.Deadline(); finite && original.Before(deadline) {
		deadline = original
	}
	read, cancel := context.WithDeadline(ctx, deadline)
	stop := context.AfterFunc(r.ctx, cancel)
	if r.ctx.Err() != nil {
		cancel()
	}
	return read, func() {
		stop()
		cancel()
	}
}

func (o *DomainTCPOriginalScope) runPublicationLocked(run *domainTCPOriginalRun) *dnscontrol.SyntheticDNSMapping {
	if run == nil || o.run != run || run.ctx.Err() != nil || o.runRevoked.Load() || o.closed || !o.publicationOpen ||
		o.process == nil || o.process.material == nil || o.prepared == nil || o.kernel == nil {
		return nil
	}
	mapping := o.process.material.mapping
	if o.prepared.source != mapping {
		return nil
	}
	return mapping
}
