package dataplane

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
)

type nfqws2ActiveModelTransport struct {
	frames    []nfqws2ActiveFrame
	sent      []nfqws2ActiveFrame
	onReceive func(int)
	index     int
	mu        sync.Mutex
	closed    bool
}

func (s *nfqws2ActiveModelTransport) send(f nfqws2ActiveFrame) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrNFQWSManagedProcessUnknown
	}
	s.sent = append(s.sent, f)
	return nil
}
func (s *nfqws2ActiveModelTransport) receive() (nfqws2ActiveFrame, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.index >= len(s.frames) {
		return nfqws2ActiveFrame{}, ErrNFQWSManagedProcessUnknown
	}
	i := s.index
	s.index++
	if s.onReceive != nil {
		s.onReceive(i)
	}
	return s.frames[i], nil
}
func (s *nfqws2ActiveModelTransport) close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

func nfqws2ActiveRunningFixture(t *testing.T) (nfqws2ActiveProcessLease, NFQWSScopedSpec, nfqws2ActiveFrame) {
	c, s, b := nfqws2ActiveCommandFixture(t)
	helper := components.NFQWSSupervisionIdentity{BootID: c.NetworkIdentity.BootID, Start: "123", PID: 233, Group: 233}
	base, err := nfqws2ActiveFrameBase(c, b, helper)
	if err != nil {
		t.Fatal(err)
	}
	child := components.NFQWSRuntimeProcessIdentity{BootID: helper.BootID, Start: "124", PID: 234, ParentPID: 233, Group: 234, Executable: c.Program.Path, ArgumentsSHA256: components.NFQWSRuntimeArgumentsSHA256(c.Program.Path, c.Args)}
	l := nfqws2ActiveProcessLease{Version: 3, StateRoot: c.StateRoot, Owner: c.Owner, Command: c, CommandSHA256: nfqws2ActiveCommandDigest(c), Binding: b, Transfer: "none", Child: child,
		Receipt: components.NFQWSSupervisionReceipt{State: "running", BootID: helper.BootID, Start: helper.Start, PID: helper.PID, Group: helper.Group, ChildPID: child.PID, Started: true, CommandSHA256: b.CommandSHA256}}
	if nfqws2ValidateActiveLease(l) != nil {
		t.Fatal("invalid running fixture")
	}
	return l, s, base
}

type nfqws2ActiveModel struct {
	mu                                     sync.Mutex
	lease                                  nfqws2ActiveProcessLease
	owner                                  *nfqws2ActiveOwner
	prepared                               *NFQWSPreparedHandle
	transport                              *nfqws2ActiveModelTransport
	cancelRequest, cancelPanel             context.CancelFunc
	request                                context.Context
	signals, published, committed, cleanup int
	stopOnce                               sync.Once
	done                                   chan struct{}
}
type nfqws2ActiveModelKey struct{}

func nfqws2ActiveOwnerFixture(t *testing.T) *nfqws2ActiveModel {
	t.Helper()
	l, s, base := nfqws2ActiveRunningFixture(t)
	request, cancelRequest := context.WithCancel(context.WithValue(context.Background(), nfqws2ActiveModelKey{}, "request"))
	activation, cancel, _ := nfqws2ActiveActivationContext(request, l.Command)
	panel, cancelPanel := context.WithCancel(context.WithValue(context.Background(), nfqws2ActiveModelKey{}, "panel"))
	m := &nfqws2ActiveModel{lease: l, cancelRequest: cancelRequest, cancelPanel: cancelPanel, request: activation, done: make(chan struct{})}
	tr := &nfqws2ActiveModelTransport{}
	for _, kind := range []string{"transfer-ack", "active"} {
		f := base
		f.Kind, f.Child = kind, l.Child
		tr.frames = append(tr.frames, f)
	}
	tr.onReceive = func(i int) {
		m.mu.Lock()
		defer m.mu.Unlock()
		if i == 0 {
			m.lease.Transfer = "provisional"
		} else {
			m.lease.Transfer = "final"
		}
	}
	o := &nfqws2ActiveOwner{command: l.Command, base: base, child: l.Child, activation: activation, activationCancel: cancel, panel: panel, state: "prepared", transport: tr, done: m.done}
	o.admission = nfqws2ActiveProcessAdmission{Binding: l.Binding, Spec: s, Current: func(ctx context.Context, b NFQWSExecutionBinding) error {
		if b != l.Binding || ctx.Value(nfqws2ActiveModelKey{}) != "request" {
			return ErrNFQWSManagedProcessUnknown
		}
		return ctx.Err()
	}, WithTransfer: func(ctx context.Context, b NFQWSExecutionBinding, finish func() error) error {
		if b != l.Binding || ctx.Err() != nil {
			return ErrNFQWSManagedProcessUnknown
		}
		return finish()
	},
		PublishTransferACK: func(ctx context.Context, obs NFQWSActiveObservation) error {
			m.mu.Lock()
			defer m.mu.Unlock()
			if m.lease.Transfer != "provisional" || obs != m.lease.observation() {
				return ErrNFQWSManagedProcessUnknown
			}
			m.published++
			return ctx.Err()
		}}
	o.read = func(ctx context.Context, live bool) (nfqws2ActiveProcessLease, error) {
		m.mu.Lock()
		defer m.mu.Unlock()
		if live && m.lease.Receipt.State != "running" {
			return nfqws2ActiveProcessLease{}, ErrNFQWSManagedProcessUnknown
		}
		return m.lease, ctx.Err()
	}
	o.result = func() (nfqws2ActiveProcessLease, error) { m.mu.Lock(); defer m.mu.Unlock(); return m.lease, nil }
	o.signal = func() {
		m.stopOnce.Do(func() {
			m.mu.Lock()
			m.signals++
			m.lease.Receipt.State = "reaped"
			m.lease.Receipt.Reaped = 1
			m.lease.Receipt.DirectReaped = true
			m.lease.Receipt.WaitECHILD = true
			m.lease.Receipt.Cancelled = true
			m.lease.Receipt.ExitCode = 125
			m.lease.Acknowledged = true
			m.mu.Unlock()
			close(m.done)
		})
	}
	p := &NFQWSPreparedHandle{owner: o}
	o.prepared = p
	m.owner, m.prepared, m.transport = o, p, tr
	o.watches()
	t.Cleanup(func() { cancelRequest(); cancelPanel(); o.abort(); o.endRequestWatch(); cancel() })
	return m
}
func (m *nfqws2ActiveModel) guards() (NFQWSActiveGuard, NFQWSActiveGuard) {
	return func(ctx context.Context, a *NFQWSActiveHandle, obs NFQWSActiveObservation) error {
			if ctx.Value(nfqws2ActiveModelKey{}) != "panel" {
				return errors.New("old request context retained")
			}
			m.mu.Lock()
			m.committed++
			m.mu.Unlock()
			return a.VerifyOwnerObservation(ctx, obs)
		}, func(ctx context.Context, a *NFQWSActiveHandle, obs NFQWSActiveObservation) error {
			m.mu.Lock()
			m.cleanup++
			m.mu.Unlock()
			return a.VerifyCleanupObservation(ctx, obs)
		}
}

func TestNFQWSActiveCommitDetachesOnlyAfterFinalACKAndFreshGuard(t *testing.T) {
	m := nfqws2ActiveOwnerFixture(t)
	current, cleanup := m.guards()
	a, err := m.prepared.CommitPrepared(m.request, current, cleanup)
	if err != nil || a == nil {
		t.Fatal("confirmed transfer failed", err)
	}
	if m.owner.activation != nil || m.owner.prepared != nil || m.owner.admission.Current != nil || m.owner.admission.WithTransfer != nil {
		t.Fatal("old request authority retained after D")
	}
	m.cancelRequest()
	ctx, finish := context.WithTimeout(context.Background(), time.Second)
	defer finish()
	// Current itself receives a new operation; CORE guard here verifies that
	// context, so replace the fixture-only panel-value assertion after D.
	m.owner.committed = func(c context.Context, h *NFQWSActiveHandle, obs NFQWSActiveObservation) error {
		return h.VerifyOwnerObservation(c, obs)
	}
	obs, err := a.Current(ctx)
	if err != nil || obs.Binding != m.lease.Binding || m.published != 1 || m.committed != 1 {
		t.Fatal("original request cancellation killed transferred owner", err)
	}
	if _, err = m.prepared.Stop(ctx); err == nil {
		t.Fatal("old prepared handle retained stop authority after D")
	}
	if _, err = m.prepared.CommitPrepared(ctx, current, cleanup); err == nil {
		t.Fatal("replayed CommitPrepared")
	}
	copy := *a
	if copy.VerifyOwnerObservation(ctx, obs) == nil || copy.VerifyCleanupObservation(ctx, obs) == nil {
		t.Fatal("copied active pointer became owner")
	}
	if _, err = copy.Stop(ctx); err == nil {
		t.Fatal("copied active handle signalled owner")
	}
	proof, err := a.Stop(ctx)
	if err != nil || !proof.Acknowledged || !proof.Receipt.WaitECHILD || !proof.Receipt.DirectReaped || m.signals != 1 || m.cleanup != 1 {
		t.Fatal("actual owner settlement lost", err)
	}
}

func TestNFQWSActivePanelCancellationJoinsKnownOwner(t *testing.T) {
	m := nfqws2ActiveOwnerFixture(t)
	c, k := m.guards()
	a, err := m.prepared.CommitPrepared(m.request, c, k)
	if err != nil {
		t.Fatal(err)
	}
	m.cancelPanel()
	select {
	case <-m.done:
	case <-time.After(time.Second):
		t.Fatal("panel cancellation did not stop actual owner")
	}
	ctx, finish := context.WithTimeout(context.Background(), time.Second)
	defer finish()
	proof, err := a.Stop(ctx)
	if err != nil || !proof.Acknowledged || !proof.Receipt.WaitECHILD || m.signals != 1 {
		t.Fatal("panel stop did not return sole join proof", err)
	}
}

func TestNFQWSActiveTransferFailuresNeverMintHandleAndJoin(t *testing.T) {
	for _, which := range []string{"provisional-is-final", "foreign-binding", "foreign-child", "publish-failed", "cancel-provisional", "cancel-final", "fresh-guard-failed", "late-barrier-failed", "callback-not-called", "callback-twice"} {
		t.Run(which, func(t *testing.T) {
			m := nfqws2ActiveOwnerFixture(t)
			c, k := m.guards()
			switch which {
			case "provisional-is-final":
				m.transport.frames[1].Kind = "transfer-ack"
			case "foreign-binding":
				m.transport.frames[1].Binding.EffectsDigest = strings.Repeat("1", 64)
			case "foreign-child":
				m.transport.frames[1].Child.Start = "999"
			case "publish-failed":
				m.owner.admission.PublishTransferACK = func(context.Context, NFQWSActiveObservation) error { return ErrReviewChanged }
			case "cancel-provisional":
				m.owner.admission.PublishTransferACK = func(context.Context, NFQWSActiveObservation) error { m.cancelRequest(); return nil }
			case "cancel-final":
				c = func(context.Context, *NFQWSActiveHandle, NFQWSActiveObservation) error { m.cancelRequest(); return nil }
			case "fresh-guard-failed":
				c = func(context.Context, *NFQWSActiveHandle, NFQWSActiveObservation) error { return ErrReviewChanged }
			case "late-barrier-failed":
				m.owner.admission.WithTransfer = func(_ context.Context, _ NFQWSExecutionBinding, f func() error) error {
					if err := f(); err != nil {
						return err
					}
					return ErrReviewChanged
				}
			case "callback-not-called":
				m.owner.admission.WithTransfer = func(context.Context, NFQWSExecutionBinding, func() error) error { return nil }
			case "callback-twice":
				m.owner.admission.WithTransfer = func(_ context.Context, _ NFQWSExecutionBinding, f func() error) error {
					if err := f(); err != nil {
						return err
					}
					_ = f()
					return nil
				}
			}
			a, err := m.prepared.CommitPrepared(m.request, c, k)
			// The existing once wrapper remembers a second rejected callback only
			// if its caller propagates it; swallowing it must not mint a handle.
			if a != nil || !errors.Is(err, ErrNFQWSManagedProcessUnknown) {
				t.Fatal("failed/ambiguous transfer became active", err)
			}
			select {
			case <-m.done:
			case <-time.After(time.Second):
				t.Fatal("failed transfer did not join")
			}
			if m.signals != 1 {
				t.Fatal("failure failed to stop known owner")
			}
			if _, err = m.prepared.CommitPrepared(m.request, c, k); err == nil {
				t.Fatal("failed transfer replayed")
			}
		})
	}
}

func TestNFQWSActiveCopiedPreparedAndZeroHandlesRefuse(t *testing.T) {
	m := nfqws2ActiveOwnerFixture(t)
	ctx, finish := context.WithTimeout(context.Background(), time.Second)
	defer finish()
	copy := *m.prepared
	if _, err := copy.Observe(ctx); err == nil {
		t.Fatal("copied prepared owner accepted")
	}
	if _, err := copy.Stop(ctx); err == nil {
		t.Fatal("copied prepared stopped actual owner")
	}
	var p NFQWSPreparedHandle
	var a NFQWSActiveHandle
	if _, err := p.Stop(ctx); err == nil {
		t.Fatal("zero prepared handle accepted")
	}
	if a.VerifyOwnerObservation(ctx, NFQWSActiveObservation{}) == nil {
		t.Fatal("zero active handle accepted")
	}
	if m.prepared.VerifyOwnerObservation(ctx, m.lease.observation()) != nil {
		t.Fatal("actual prepared observer refused")
	}
}

func TestNFQWSActiveCancelledStopStillJoinsWithoutCleanupGrant(t *testing.T) {
	m := nfqws2ActiveOwnerFixture(t)
	c, k := m.guards()
	a, err := m.prepared.CommitPrepared(m.request, c, k)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	cancel()
	proof, err := a.Stop(ctx)
	if !errors.Is(err, context.Canceled) || !proof.Acknowledged || !proof.Receipt.WaitECHILD || m.signals != 1 || m.cleanup != 0 {
		t.Fatal("cancelled Stop lost actual join or issued cleanup", err)
	}
}

func TestNFQWSActiveInvalidCommitInputConsumesPrepared(t *testing.T) {
	m := nfqws2ActiveOwnerFixture(t)
	c, k := m.guards()
	if a, err := m.prepared.CommitPrepared(m.request, nil, k); a != nil || err == nil {
		t.Fatal("nil fresh guard became active")
	}
	if a, err := m.prepared.CommitPrepared(m.request, c, k); a != nil || err == nil {
		t.Fatal("invalid commit replayed")
	}
	select {
	case <-m.done:
	default:
		t.Fatal("invalid commit did not stop known helper")
	}
}

func TestNFQWSActiveParticipantMarkersRequireOriginalInstance(t *testing.T) {
	m := nfqws2ActiveOwnerFixture(t)
	a := &NFQWS2Adapter{}
	m.owner.adapter = a
	if a.retainNFQWSActiveProcess(m.owner) != nil {
		t.Fatal("original owner association failed")
	}
	binding := m.lease.Binding
	if p, err := a.activePreparedNFQWSProcess(binding); err != nil || p != m.prepared {
		t.Fatal("actual prepared pointer lost")
	}
	copy := *a
	if _, err := copy.activePreparedNFQWSProcess(binding); err == nil {
		t.Fatal("copied adapter returned owner")
	}
	wrong := binding
	wrong.CommandSHA256 = strings.Repeat("0", 64)
	if _, err := a.activePreparedNFQWSProcess(wrong); err == nil {
		t.Fatal("different execution returned owner")
	}
	c, k := m.guards()
	active, err := m.prepared.CommitPrepared(m.request, c, k)
	if err != nil {
		t.Fatal(err)
	}
	if h, err := a.activeCommittedNFQWSProcess(binding); err != nil || h != active {
		t.Fatal("final original live pointer lost")
	}
	if _, err := copy.activeCommittedNFQWSProcess(binding); err == nil {
		t.Fatal("copied adapter returned final owner")
	}
	if a.retainNFQWSActiveProcess(m.owner) == nil {
		t.Fatal("participant owner was replayed/replaced")
	}
}

func TestNFQWSActivePublicErrorsHideGuardAndFilesystemPayload(t *testing.T) {
	m := nfqws2ActiveOwnerFixture(t)
	_, cleanup := m.guards()
	private := errors.New("private-control-root/frame/argv/net-identity")
	_, err := m.prepared.CommitPrepared(m.request, func(context.Context, *NFQWSActiveHandle, NFQWSActiveObservation) error { return private }, cleanup)
	if err == nil || strings.Contains(err.Error(), private.Error()) || !errors.Is(err, private) || !errors.Is(err, ErrNFQWSManagedProcessUnknown) {
		t.Fatal("public diagnostics leaked payload or lost cause")
	}
}
