package dataplane

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

type NFQWSActiveGuard func(context.Context, *NFQWSActiveHandle, NFQWSActiveObservation) error

// No public constructor or decoded image can mint either handle. Identity of
// the original handle pointer is checked against its actual live owner.
type NFQWSPreparedHandle struct{ owner *nfqws2ActiveOwner }
type NFQWSActiveHandle struct{ owner *nfqws2ActiveOwner }

type nfqws2ActivePreparedKey struct{}

func nfqws2ActivePreparedFromContext(ctx context.Context) *NFQWSPreparedHandle {
	if ctx == nil {
		return nil
	}
	p, _ := ctx.Value(nfqws2ActivePreparedKey{}).(*NFQWSPreparedHandle)
	return p
}

// Supplied only by DEFAULT's actual ordinary retained Manager execution.
// Provider is the SAME concrete production provider, never a DTO issuer.
type nfqws2ActiveProcessAdmission struct {
	Binding            NFQWSExecutionBinding
	Spec               NFQWSScopedSpec
	Provider           *netidentity.Provider
	BeforeStart        func(context.Context, NFQWSExecutionBinding) error
	WithStart          func(context.Context, NFQWSExecutionBinding, func() error) error
	Current            func(context.Context, NFQWSExecutionBinding) error
	Prepared           func(context.Context, NFQWSExecutionBinding, NFQWSActiveObservation) error
	WithTransfer       func(context.Context, NFQWSExecutionBinding, func() error) error
	PublishTransferACK func(context.Context, NFQWSActiveObservation) error
}

func (a nfqws2ActiveProcessAdmission) valid(c nfqws2ActiveProcessCommand) bool {
	return nfqws2ActiveBindingValid(a.Binding, c) && nfqws2ActiveCommandMatchesSpec(c, a.Spec) == nil && a.Provider != nil && a.BeforeStart != nil && a.WithStart != nil && a.Current != nil && a.Prepared != nil && a.WithTransfer != nil && a.PublishTransferACK != nil
}

type nfqws2ActiveOwner struct {
	mu                                sync.Mutex
	adapter                           *NFQWS2Adapter
	command                           nfqws2ActiveProcessCommand
	admission                         nfqws2ActiveProcessAdmission
	base                              nfqws2ActiveFrame
	child                             components.NFQWSRuntimeProcessIdentity
	transport                         nfqws2ActiveTransport
	activation, panel                 context.Context
	activationCancel                  context.CancelFunc
	prepared                          *NFQWSPreparedHandle
	active                            *NFQWSActiveHandle
	state                             string
	finalACK, detached, stopRequested bool
	committed, cleanup                NFQWSActiveGuard
	// Actual platform producer installs these closures; none is caller-facing.
	read   func(context.Context, bool) (nfqws2ActiveProcessLease, error)
	signal func()
	done   <-chan struct{}
	result func() (nfqws2ActiveProcessLease, error)
	// Retirement is installed only by the actual platform producer. It holds
	// the existing file writer, proves empty typed queues around COMMON cleanup,
	// and CAS-removes only this terminal ownership.json.
	retire            func(context.Context, nfqws2ActiveProcessLease, func() error) error
	startDone         <-chan struct{}
	commitDone        <-chan struct{}
	retirementStarted bool
	requestWatchStop  chan struct{}
	requestWatchDone  chan struct{}
	requestWatchOnce  sync.Once
}

var nfqws2ActiveAdapterMu sync.Mutex // Protects only private participant pointer association.

func (a *NFQWS2Adapter) retainNFQWSActiveProcess(o *nfqws2ActiveOwner) error {
	if a == nil || o == nil || o.adapter != a {
		return ErrNFQWSManagedProcessUnknown
	}
	nfqws2ActiveAdapterMu.Lock()
	defer nfqws2ActiveAdapterMu.Unlock()
	if a.activeProcess != nil {
		return ErrNFQWSManagedProcessUnknown
	}
	a.activeProcess = o
	return nil
}

// Private markers let DEFAULT retain the original concrete participant across
// its SAME Manager execution. Cold metadata/another adapter cannot return it.
func (a *NFQWS2Adapter) activePreparedNFQWSProcess(binding NFQWSExecutionBinding) (*NFQWSPreparedHandle, error) {
	if a == nil {
		return nil, ErrNFQWSManagedProcessUnknown
	}
	nfqws2ActiveAdapterMu.Lock()
	o := a.activeProcess
	nfqws2ActiveAdapterMu.Unlock()
	if o == nil || o.adapter != a {
		return nil, ErrNFQWSManagedProcessUnknown
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.admission.Binding != binding || o.prepared == nil || o.detached || o.stopRequested || (o.state != "prepared" && o.state != "committing") {
		return nil, ErrNFQWSManagedProcessUnknown
	}
	return o.prepared, nil
}
func (a *NFQWS2Adapter) activeCommittedNFQWSProcess(binding NFQWSExecutionBinding) (*NFQWSActiveHandle, error) {
	if a == nil {
		return nil, ErrNFQWSManagedProcessUnknown
	}
	nfqws2ActiveAdapterMu.Lock()
	o := a.activeProcess
	nfqws2ActiveAdapterMu.Unlock()
	if o == nil || o.adapter != a {
		return nil, ErrNFQWSManagedProcessUnknown
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.admission.Binding != binding || o.active == nil || !o.detached || !o.finalACK || o.state != "active" {
		return nil, ErrNFQWSManagedProcessUnknown
	}
	return o.active, nil
}

type nfqws2ActiveOnce struct {
	mu                     sync.Mutex
	open, called, violated bool
	begin                  func() error
	outcome                error
}

func (s *nfqws2ActiveOnce) run() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.open || s.begin == nil {
		return ErrNFQWSManagedProcessUnknown
	}
	if s.called {
		s.violated = true
		return ErrNFQWSManagedProcessUnknown
	}
	s.called = true
	s.outcome = ErrNFQWSManagedProcessUnknown
	s.outcome = s.begin()
	return s.outcome
}
func (s *nfqws2ActiveOnce) seal() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.open = false
	if !s.called || s.violated {
		return ErrNFQWSManagedProcessUnknown
	}
	return s.outcome
}
func (s *nfqws2ActiveOnce) invoke(action func(func() error) error) (err error) {
	defer func() { err = errors.Join(err, s.seal()) }()
	if action == nil {
		return ErrNFQWSManagedProcessUnknown
	}
	return action(s.run)
}

func nfqws2ActiveOperation(ctx context.Context) error {
	if ctx == nil {
		return ErrNFQWSManagedProcessUnknown
	}
	deadline, ok := ctx.Deadline()
	if !ok || !time.Now().Before(deadline) || ctx.Err() != nil {
		return errors.Join(ErrNFQWSManagedProcessUnknown, ctx.Err())
	}
	return nil
}
func (o *nfqws2ActiveOwner) known(l nfqws2ActiveProcessLease) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return nfqws2ValidateActiveLease(l) == nil && reflect.DeepEqual(l.Command, o.command) && l.Binding == o.admission.Binding &&
		l.Receipt.PID == o.base.Helper.PID && l.Receipt.Group == o.base.Helper.Group && l.Receipt.Start == o.base.Helper.Start && l.Receipt.BootID == o.base.Helper.BootID && l.Child == o.child
}
func (o *nfqws2ActiveOwner) observe(ctx context.Context, running bool) (nfqws2ActiveProcessLease, error) {
	if o == nil || o.read == nil || nfqws2ActiveOperation(ctx) != nil {
		return nfqws2ActiveProcessLease{}, ErrNFQWSManagedProcessUnknown
	}
	l, err := o.read(ctx, running)
	if err != nil || !o.known(l) || ctx.Err() != nil {
		return nfqws2ActiveProcessLease{}, errors.Join(ErrNFQWSManagedProcessUnknown, err, ctx.Err())
	}
	return l, nil
}
func (o *nfqws2ActiveOwner) abort() {
	o.mu.Lock()
	o.stopRequested = true
	signal := o.signal
	t := o.transport
	o.mu.Unlock()
	if t != nil {
		_ = t.close()
	}
	if signal != nil {
		signal()
	} // Exact launched exec.Cmd, never PID discovery.
}
func (o *nfqws2ActiveOwner) join(ctx context.Context) (NFQWSScopedProcessProof, error) {
	if o == nil || o.done == nil || o.result == nil {
		return NFQWSScopedProcessProof{}, ErrNFQWSManagedProcessUnknown
	}
	// Join/terminal ACK is compensating known ownership. A cancelled forward
	// request cannot prevent the sole wait owner from producing its real result.
	cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	select {
	case <-o.done:
		l, err := o.result()
		if err != nil || !o.known(l) || !nfqws2ActiveProcessSettled(l) {
			return NFQWSScopedProcessProof{}, errors.Join(ErrNFQWSManagedProcessUnknown, err)
		}
		var caller error
		if ctx != nil {
			caller = ctx.Err()
		}
		return l.proof(), caller
	case <-cleanup.Done():
		return NFQWSScopedProcessProof{}, ErrNFQWSManagedProcessUnknown
	}
}
func (o *nfqws2ActiveOwner) watches() {
	o.requestWatchStop = make(chan struct{})
	o.requestWatchDone = make(chan struct{})
	go func() {
		defer close(o.requestWatchDone)
		select {
		case <-o.activation.Done():
			o.mu.Lock()
			abort := !o.detached
			if abort {
				o.stopRequested = true
			}
			signal, t := o.signal, o.transport
			o.mu.Unlock()
			if abort {
				if t != nil {
					_ = t.close()
				}
				if signal != nil {
					signal()
				}
			}
		case <-o.requestWatchStop:
		case <-o.done:
		}
	}()
	go func() {
		select {
		case <-o.panel.Done():
			o.abort()
		case <-o.done:
		}
	}()
}
func (o *nfqws2ActiveOwner) endRequestWatch() {
	o.requestWatchOnce.Do(func() { close(o.requestWatchStop) })
	<-o.requestWatchDone
}

func nfqws2ActivePublicError(stage string, err *error) {
	if *err != nil {
		*err = nfqws2ActiveFailure(stage, *err)
	}
}

func (p *NFQWSPreparedHandle) Observe(ctx context.Context) (observation NFQWSActiveObservation, err error) {
	defer nfqws2ActivePublicError("prepared Observe", &err)
	if p == nil || p.owner == nil {
		return NFQWSActiveObservation{}, ErrNFQWSManagedProcessUnknown
	}
	o := p.owner
	o.mu.Lock()
	valid := o.prepared == p && o.state == "prepared" && !o.stopRequested
	activation, current, binding := o.activation, o.admission.Current, o.admission.Binding
	o.mu.Unlock()
	if !valid || activation == nil || current == nil || activation.Err() != nil {
		return NFQWSActiveObservation{}, ErrNFQWSManagedProcessUnknown
	}
	if err := current(ctx, binding); err != nil {
		return NFQWSActiveObservation{}, err
	}
	l, err := o.observe(ctx, true)
	if err != nil {
		return NFQWSActiveObservation{}, err
	}
	o.mu.Lock()
	valid = o.prepared == p && o.state == "prepared" && !o.detached && !o.stopRequested
	o.mu.Unlock()
	if !valid || activation.Err() != nil {
		return NFQWSActiveObservation{}, ErrNFQWSManagedProcessUnknown
	}
	return l.observation(), nil
}

func (p *NFQWSPreparedHandle) VerifyOwnerObservation(ctx context.Context, supplied NFQWSActiveObservation) (err error) {
	defer nfqws2ActivePublicError("prepared owner proof", &err)
	if p == nil || p.owner == nil {
		return ErrNFQWSManagedProcessUnknown
	}
	o := p.owner
	o.mu.Lock()
	valid := o.prepared == p && !o.detached && !o.stopRequested && (o.state == "starting" || o.state == "prepared" || o.state == "committing")
	activation := o.activation
	o.mu.Unlock()
	if !valid || activation == nil || activation.Err() != nil {
		return ErrNFQWSManagedProcessUnknown
	}
	l, err := o.observe(ctx, true)
	if err != nil || l.observation() != supplied || (l.Transfer != "none" && l.Transfer != "provisional") {
		return errors.Join(ErrNFQWSManagedProcessUnknown, err)
	}
	o.mu.Lock()
	valid = o.prepared == p && !o.detached && !o.stopRequested && (o.state == "starting" || o.state == "prepared" || o.state == "committing")
	o.mu.Unlock()
	if !valid || activation.Err() != nil {
		return ErrNFQWSManagedProcessUnknown
	}
	return nil
}
func (p *NFQWSPreparedHandle) Stop(ctx context.Context) (proof NFQWSScopedProcessProof, err error) {
	defer nfqws2ActivePublicError("prepared Stop", &err)
	if p == nil || p.owner == nil {
		return NFQWSScopedProcessProof{}, ErrNFQWSManagedProcessUnknown
	}
	o := p.owner
	o.mu.Lock()
	valid := o.prepared == p && !o.detached
	if valid {
		o.stopRequested = true
	} // Linearize against D before releasing the lock.
	o.mu.Unlock()
	if !valid {
		return NFQWSScopedProcessProof{}, ErrNFQWSManagedProcessUnknown
	}
	inputErr := nfqws2ActiveOperation(ctx)
	o.abort()
	proof, joinErr := o.join(ctx)
	return proof, errors.Join(inputErr, joinErr)
}

func (p *NFQWSPreparedHandle) CommitPrepared(ctx context.Context, committed, cleanup NFQWSActiveGuard) (handle *NFQWSActiveHandle, err error) {
	defer nfqws2ActivePublicError("CommitPrepared", &err)
	if p == nil || p.owner == nil {
		return nil, ErrNFQWSManagedProcessUnknown
	}
	o := p.owner
	o.mu.Lock()
	if o.prepared != p || o.state != "prepared" || o.stopRequested || o.activation.Err() != nil {
		o.mu.Unlock()
		return nil, ErrNFQWSManagedProcessUnknown
	}
	o.state = "committing"
	commitDone := make(chan struct{})
	o.commitDone = commitDone
	o.committed, o.cleanup = committed, cleanup
	o.mu.Unlock()
	defer close(commitDone) // Retirement cannot race unfinished transfer compensation.
	if committed == nil || cleanup == nil || nfqws2ActiveOperation(ctx) != nil {
		o.abort()
		_, joinErr := o.join(ctx)
		return nil, errors.Join(ErrNFQWSManagedProcessUnknown, nfqws2ActiveOperation(ctx), joinErr)
	}
	// Preserve original values/token and cancellation; a later Commit context
	// may shorten this operation but cannot replace or extend the launch grant.
	commitCtx, cancel := context.WithCancel(o.activation)
	defer cancel()
	stopCaller := context.AfterFunc(ctx, cancel)
	defer stopCaller()
	if deadline, _ := ctx.Deadline(); deadline.Before(o.command.ActivationDeadline) {
		var deadlineCancel context.CancelFunc
		commitCtx, deadlineCancel = context.WithDeadline(commitCtx, deadline)
		defer deadlineCancel()
	}
	defer func() {
		if handle == nil {
			o.mu.Lock()
			candidate := o.active
			final := o.finalACK
			o.mu.Unlock()
			if final && candidate != nil {
				known, finish := context.WithTimeout(context.Background(), 15*time.Second)
				_, cleanupErr := candidate.Stop(known)
				finish()
				err = errors.Join(err, cleanupErr)
			}
			o.abort()
			proof, stopErr := o.join(ctx)
			_ = proof
			err = errors.Join(ErrNFQWSManagedProcessUnknown, err, stopErr)
		}
	}()
	once := &nfqws2ActiveOnce{open: true, begin: func() error {
		current := func() error {
			l, e := o.observe(commitCtx, true)
			if e != nil {
				return e
			}
			if l.Transfer != "none" && l.Transfer != "provisional" {
				return ErrNFQWSManagedProcessUnknown
			}
			return o.admission.Current(commitCtx, o.admission.Binding)
		}
		publish := func() error {
			l, e := o.observe(commitCtx, true)
			if e != nil || l.Transfer != "provisional" {
				return errors.Join(ErrNFQWSManagedProcessUnknown, e)
			}
			return o.admission.PublishTransferACK(commitCtx, l.observation())
		}
		if e := nfqws2ActiveTransferParent(commitCtx, o.transport, o.command, o.base, o.child, current, publish); e != nil {
			return e
		}
		o.mu.Lock()
		o.finalACK = true
		o.active = &NFQWSActiveHandle{owner: o}
		candidate := o.active
		o.mu.Unlock()
		// CORE checks current Store/control through a fresh bounded panel operation.
		fresh, finish := context.WithTimeout(o.panel, 15*time.Second)
		defer finish()
		l, e := o.observe(fresh, true)
		if e != nil || l.Transfer != "final" {
			return errors.Join(ErrNFQWSManagedProcessUnknown, e)
		}
		if e = committed(fresh, candidate, l.observation()); e != nil {
			return e
		}
		if e = candidate.VerifyOwnerObservation(fresh, l.observation()); e != nil {
			return e
		}
		o.mu.Lock()
		if o.stopRequested || commitCtx.Err() != nil || o.panel.Err() != nil {
			o.mu.Unlock()
			return ErrNFQWSManagedProcessUnknown
		}
		o.detached = true
		o.state = "active"
		o.mu.Unlock()
		o.endRequestWatch() // Joined before returning any active capability.
		handle = candidate
		return nil
	}}
	err = once.invoke(func(finish func() error) error {
		return o.admission.WithTransfer(commitCtx, o.admission.Binding, finish)
	})
	if err != nil {
		handle = nil
	}
	if handle != nil {
		o.activationCancel()
		o.mu.Lock()
		// The only retained authority now is the confirmed live owner and fresh
		// committed/cleanup guards. Drop every old request callback/context.
		o.activation, o.activationCancel, o.prepared = nil, nil, nil
		o.admission.BeforeStart, o.admission.WithStart, o.admission.Current, o.admission.Prepared = nil, nil, nil, nil
		o.admission.WithTransfer, o.admission.PublishTransferACK = nil, nil
		o.mu.Unlock()
	}
	return handle, err
}

// Read-only independent authentication for CORE; never calls either guard.
func (a *NFQWSActiveHandle) VerifyOwnerObservation(ctx context.Context, supplied NFQWSActiveObservation) (err error) {
	defer nfqws2ActivePublicError("active owner proof", &err)
	if a == nil || a.owner == nil {
		return ErrNFQWSManagedProcessUnknown
	}
	o := a.owner
	o.mu.Lock()
	valid := o.active == a && o.finalACK && !o.stopRequested
	o.mu.Unlock()
	if !valid {
		return ErrNFQWSManagedProcessUnknown
	}
	l, err := o.observe(ctx, true)
	if err != nil || l.Transfer != "final" || l.observation() != supplied {
		return errors.Join(ErrNFQWSManagedProcessUnknown, err)
	}
	o.mu.Lock()
	valid = o.active == a && o.finalACK && !o.stopRequested
	o.mu.Unlock()
	if !valid {
		return ErrNFQWSManagedProcessUnknown
	}
	return nil
}
func (a *NFQWSActiveHandle) VerifyCleanupObservation(ctx context.Context, supplied NFQWSActiveObservation) (err error) {
	defer nfqws2ActivePublicError("active cleanup proof", &err)
	if a == nil || a.owner == nil {
		return ErrNFQWSManagedProcessUnknown
	}
	o := a.owner
	o.mu.Lock()
	valid := o.active == a && o.finalACK
	o.mu.Unlock()
	if !valid {
		return ErrNFQWSManagedProcessUnknown
	}
	l, err := o.observe(ctx, false)
	if err != nil || l.Transfer != "final" || l.observation() != supplied {
		return errors.Join(ErrNFQWSManagedProcessUnknown, err)
	}
	if l.Receipt.State != "running" {
		select {
		case <-o.done:
		default:
			return ErrNFQWSManagedProcessUnknown
		}
	}
	return nil
}
func (a *NFQWSActiveHandle) Current(ctx context.Context) (observation NFQWSActiveObservation, err error) {
	defer nfqws2ActivePublicError("Current", &err)
	if a == nil || a.owner == nil || nfqws2ActiveOperation(ctx) != nil {
		return NFQWSActiveObservation{}, ErrNFQWSManagedProcessUnknown
	}
	o := a.owner
	o.mu.Lock()
	valid := o.active == a && o.detached && o.state == "active" && !o.stopRequested
	guard := o.committed
	o.mu.Unlock()
	if !valid || guard == nil {
		return NFQWSActiveObservation{}, ErrNFQWSManagedProcessUnknown
	}
	l, err := o.observe(ctx, true)
	if err != nil {
		return NFQWSActiveObservation{}, err
	}
	obs := l.observation()
	if err = guard(ctx, a, obs); err != nil {
		return NFQWSActiveObservation{}, err
	}
	if err = a.VerifyOwnerObservation(ctx, obs); err != nil {
		return NFQWSActiveObservation{}, err
	}
	o.mu.Lock()
	valid = o.active == a && o.detached && o.state == "active" && !o.stopRequested
	o.mu.Unlock()
	if !valid || o.panel.Err() != nil {
		return NFQWSActiveObservation{}, ErrNFQWSManagedProcessUnknown
	}
	return obs, nil
}
func (a *NFQWSActiveHandle) Stop(ctx context.Context) (proof NFQWSScopedProcessProof, err error) {
	defer nfqws2ActivePublicError("active Stop", &err)
	if a == nil || a.owner == nil {
		return NFQWSScopedProcessProof{}, ErrNFQWSManagedProcessUnknown
	}
	o := a.owner
	o.mu.Lock()
	valid := o.active == a && o.finalACK
	guard := o.cleanup
	o.mu.Unlock()
	if !valid || guard == nil {
		return NFQWSScopedProcessProof{}, ErrNFQWSManagedProcessUnknown
	}
	inputErr := nfqws2ActiveOperation(ctx)
	// Signal/reap the already owned process before authenticating a cleanup
	// observation. Panel cancellation may otherwise race a running->terminal
	// lease write. This grants no common rule/receipt deletion on guard failure.
	o.abort()
	proof, joinErr := o.join(ctx)
	if inputErr != nil || joinErr != nil {
		return proof, errors.Join(inputErr, joinErr)
	}
	var l nfqws2ActiveProcessLease
	l, readErr := o.observe(ctx, false)
	var guardErr error
	if readErr == nil {
		guardErr = guard(ctx, a, l.observation())
	}
	return proof, errors.Join(readErr, guardErr, joinErr)
}
