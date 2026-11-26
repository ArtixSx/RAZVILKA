package dataplane

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

func domainTCPRunCustodyModel(t *testing.T) (*Manager, *DomainTCPOriginalScope, *XrayDomainTCPExecutionResource, context.Context) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	manager := &Manager{}
	scope := &executionResourceScope{manager: manager}
	binding := &SyntheticDNSExecutionBinding{scope: scope}
	binding.self = binding
	owner := &DomainTCPOriginalScope{binding: binding}
	owner.self, scope.domainTCPOwner = owner, owner
	process := &XrayDomainTCPExecutionResource{scope: scope}
	process.self = process
	return manager, owner, process, ctx
}

func TestDomainTCPRunStartReportsPreflightFailureWithoutWait(t *testing.T) {
	manager, owner, process, ctx := domainTCPRunCustodyModel(t)
	// This registered owner has no native backend. The caller must receive
	// the refusal directly and can immediately take its unstarted cleanup path.
	done, err := owner.StartDomainTCPRun(ctx, process)
	if done != nil || !errors.Is(err, ErrDomainPolicyTCPConsumer) || ctx.Err() != nil {
		t.Fatalf("failed start returned a worker or exhausted the original budget: %v %v %v", done, err, ctx.Err())
	}
	if joined, err := manager.JoinDomainTCPRun(ctx, owner); joined || !errors.Is(err, ErrDomainTCPRunNotStarted) {
		t.Fatalf("unstarted resource unexpectedly owned a worker: %t %v", joined, err)
	}
	if owner.process != nil || owner.run != nil || owner.runStarted != nil || owner.closed || owner.runRevoked.Load() {
		t.Fatal("failed preflight changed original ownership or retirement")
	}
}

func TestDomainTCPRunRevocationCannotCrossOwnership(t *testing.T) {
	manager, owner, process, ctx := domainTCPRunCustodyModel(t)
	foreign := &Manager{}
	if err := foreign.RevokeDomainTCPRun(ctx, owner); !errors.Is(err, ErrDomainPolicyTCPConsumer) {
		t.Fatalf("foreign manager revoked run: %v", err)
	}
	madeUp := &DomainTCPOriginalScope{binding: owner.binding}
	madeUp.self = madeUp
	if err := manager.RevokeDomainTCPRun(ctx, madeUp); !errors.Is(err, ErrDomainPolicyTCPConsumer) {
		t.Fatalf("unregistered owner revoked run: %v", err)
	}
	if joined, err := manager.JoinDomainTCPRun(ctx, owner); joined || !errors.Is(err, ErrDomainTCPRunNotStarted) {
		t.Fatalf("unstarted owner had a Run result: %t %v", joined, err)
	}
	if err := manager.RevokeDomainTCPRun(ctx, owner); err != nil {
		t.Fatal(err)
	}
	if err := manager.RevokeDomainTCPRun(ctx, owner); err != nil {
		t.Fatal("repeated revocation failed", err)
	}
	if _, err := owner.beginDomainTCPRun(ctx, process); !errors.Is(err, ErrDomainTCPRunRevoked) {
		t.Fatalf("late Run passed revocation: %v", err)
	}
}

func TestDomainTCPRunRevocationWaitsForOriginalJoin(t *testing.T) {
	manager, owner, process, ctx := domainTCPRunCustodyModel(t)
	run, err := owner.beginDomainTCPRun(ctx, process)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.beginDomainTCPRun(ctx, process); err == nil {
		t.Fatal("second Run reserved the original owner")
	}
	capture, cancelCapture := context.WithCancel(ctx)
	defer cancelCapture()
	owner.mu.Lock()
	owner.cancel, owner.publicationOpen = cancelCapture, true
	owner.mu.Unlock()
	if err := manager.RevokeDomainTCPRun(ctx, owner); err != nil {
		t.Fatal(err)
	}
	if run.ctx.Err() != context.Canceled || capture.Err() != context.Canceled || owner.publicationOpen {
		t.Fatal("revocation did not close publication and both original lifetimes")
	}

	wait, cancelWait := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancelWait()
	if joined, err := manager.JoinDomainTCPRun(wait, owner); joined || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("revocation claimed an unjoined Run: %t %v", joined, err)
	}
	terminal := dnscontrol.ErrSyntheticDNSTransitionPending
	owner.finishDomainTCPRun(run, terminal)
	for range 2 {
		if joined, err := manager.JoinDomainTCPRun(ctx, owner); !joined || !errors.Is(err, terminal) {
			t.Fatalf("joined Run lost the original unsettled baseline result: %t %v", joined, err)
		}
	}
	if _, err := owner.beginDomainTCPRun(ctx, process); !errors.Is(err, ErrDomainTCPRunRevoked) {
		t.Fatalf("joining a revoked run permitted its revival: %v", err)
	}
}

func TestDomainTCPRunEarlyReturnDoesNotClaimCaptureRetirement(t *testing.T) {
	manager, owner, process, ctx := domainTCPRunCustodyModel(t)
	run, err := owner.beginDomainTCPRun(ctx, process)
	if err != nil {
		t.Fatal(err)
	}
	failure := ErrXrayDomainTCPOriginal
	owner.finishDomainTCPRun(run, failure)
	if joined, err := manager.JoinDomainTCPRun(ctx, owner); !joined || !errors.Is(err, failure) {
		t.Fatalf("early Run loss was not retained: %t %v", joined, err)
	}
	if owner.closed || owner.standbyReady {
		t.Fatal("early start refusal fabricated completed capture or standby")
	}
}

func TestDomainTCPRunReadinessWaitPreservesOriginalFailure(t *testing.T) {
	_, owner, process, ctx := domainTCPRunCustodyModel(t)
	type result struct {
		ready DomainTCPRunReadiness
		err   error
	}
	done := make(chan result, 1)
	go func() {
		ready, err := owner.WaitDomainTCPRunReady(ctx)
		done <- result{ready: ready, err: err}
	}()
	// Observe registration before starting, so this covers the wakeup before
	// a Run exists as well as the post-start terminal handoff.
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		owner.mu.Lock()
		waiting := owner.runStarted != nil
		owner.mu.Unlock()
		if waiting {
			break
		}
		select {
		case result := <-done:
			t.Fatalf("readiness returned before Run started: %+v", result)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-ticker.C:
		}
	}
	run, err := owner.beginDomainTCPRun(ctx, process)
	if err != nil {
		t.Fatal(err)
	}
	owner.finishDomainTCPRun(run, ErrXrayDomainTCPOriginal)
	select {
	case result := <-done:
		if result.ready != (DomainTCPRunReadiness{}) || !errors.Is(result.err, ErrDomainTCPRunNotReady) || !errors.Is(result.err, ErrXrayDomainTCPOriginal) {
			t.Fatalf("unready observation lost original failure: %+v", result)
		}
	case <-ctx.Done():
		t.Fatal("wait missed terminal Run result")
	}
}

func TestDomainTCPRunReadinessWaitCannotGrantStaleOrForgedPublication(t *testing.T) {
	manager, owner, process, ctx := domainTCPRunCustodyModel(t)
	run, err := owner.beginDomainTCPRun(ctx, process)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.finishDomainTCPRun(run, context.Canceled)
	// An expired observer does not revoke the actual Run it is watching.
	short, cancel := context.WithTimeout(ctx, 10*time.Millisecond)
	defer cancel()
	if ready, err := owner.WaitDomainTCPRunReady(short); ready != (DomainTCPRunReadiness{}) || !errors.Is(err, context.DeadlineExceeded) || run.ctx.Err() != nil {
		t.Fatalf("readiness wait changed original ownership: %+v %v", ready, err)
	}
	owner.mu.Lock()
	owner.publicationOpen = true
	close(run.ready) // Even a signal cannot replace a real capture and owner.
	owner.mu.Unlock()
	if ready, err := owner.WaitDomainTCPRunReady(ctx); ready != (DomainTCPRunReadiness{}) || !errors.Is(err, ErrDomainPolicyTCPConsumer) {
		t.Fatalf("forged signal passed original resource checks: %+v %v", ready, err)
	}
	if err := manager.RevokeDomainTCPRun(ctx, owner); err != nil {
		t.Fatal(err)
	}
	if ready, err := owner.WaitDomainTCPRunReady(ctx); ready != (DomainTCPRunReadiness{}) || !errors.Is(err, ErrDomainTCPRunRevoked) {
		t.Fatalf("revoked Run retained publication readiness: %+v %v", ready, err)
	}
}

// Cancel between the caller's fresh admission and its wait. This preserves
// the refusal of a context that was already canceled on entry, while making
// the competing completed-run/caller-cancellation channels deterministic.
type domainTCPJoinCancellationContext struct {
	context.Context
	cancel context.CancelFunc
}

func (c *domainTCPJoinCancellationContext) Deadline() (time.Time, bool) {
	deadline, finite := c.Context.Deadline()
	c.cancel()
	return deadline, finite
}

func TestDomainTCPRunJoinKeepsPublishedResultWhenWaitIsCanceled(t *testing.T) {
	manager, owner, process, ctx := domainTCPRunCustodyModel(t)
	run, err := owner.beginDomainTCPRun(ctx, process)
	if err != nil {
		t.Fatal(err)
	}
	newWait := func() context.Context {
		wait, cancel := context.WithCancel(ctx)
		t.Cleanup(cancel)
		return &domainTCPJoinCancellationContext{Context: wait, cancel: cancel}
	}
	if joined, err := manager.JoinDomainTCPRun(newWait(), owner); joined || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled wait claimed an unfinished Run: %t %v", joined, err)
	}
	terminal := dnscontrol.ErrSyntheticDNSTransitionPending
	owner.finishDomainTCPRun(run, terminal)
	for range 64 {
		if joined, err := manager.JoinDomainTCPRun(newWait(), owner); !joined || !errors.Is(err, terminal) {
			t.Fatalf("canceled wait hid the published original Run result: %t %v", joined, err)
		}
	}
}

func TestDomainTCPRunReadinessKeepsCallerAndOriginalBudgets(t *testing.T) {
	_, owner, process, ctx := domainTCPRunCustodyModel(t)
	original, cancelOriginal := context.WithTimeout(ctx, time.Second)
	defer cancelOriginal()
	run, err := owner.beginDomainTCPRun(original, process)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.finishDomainTCPRun(run, context.Canceled)

	read, release := run.readinessContext(ctx)
	defer release()
	originalDeadline, _ := original.Deadline()
	if deadline, finite := read.Deadline(); !finite || !deadline.Equal(originalDeadline) {
		t.Fatalf("read deadline exceeded original Run: %v", deadline)
	}
	caller, cancelCaller := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancelCaller()
	shortRead, releaseShort := run.readinessContext(caller)
	defer releaseShort()
	callerDeadline, _ := caller.Deadline()
	if deadline, finite := shortRead.Deadline(); !finite || !deadline.Equal(callerDeadline) {
		t.Fatalf("read deadline exceeded caller: %v", deadline)
	}
	cancelCaller()
	if !errors.Is(shortRead.Err(), context.Canceled) || read.Err() != nil {
		t.Fatal("cancellation crossed independent reads")
	}
	run.cancel()
	select {
	case <-read.Done():
		if !errors.Is(read.Err(), context.Canceled) {
			t.Fatalf("original revocation arrived as %v", read.Err())
		}
	case <-ctx.Done():
		t.Fatal("original revocation did not cancel readiness")
	}
}

func TestDomainTCPRunStartAndStopRaceKeepsRevocation(t *testing.T) {
	for range 32 {
		manager, owner, process, ctx := domainTCPRunCustodyModel(t)
		type reservation struct {
			run *domainTCPOriginalRun
			err error
		}
		ready, attempted := make(chan struct{}), make(chan reservation, 1)
		go func() {
			<-ready
			run, err := owner.beginDomainTCPRun(ctx, process)
			attempted <- reservation{run, err}
		}()
		close(ready)
		if err := manager.RevokeDomainTCPRun(ctx, owner); err != nil {
			t.Fatal(err)
		}
		result := <-attempted
		if result.run != nil {
			if result.err != nil || !errors.Is(result.run.ctx.Err(), context.Canceled) {
				t.Fatalf("a racing Run escaped revocation: %v", result.err)
			}
			owner.finishDomainTCPRun(result.run, result.run.ctx.Err())
		} else if !errors.Is(result.err, ErrDomainTCPRunRevoked) {
			t.Fatalf("racing Run refused for the wrong reason: %v", result.err)
		}
		if _, err := owner.beginDomainTCPRun(ctx, process); !errors.Is(err, ErrDomainTCPRunRevoked) {
			t.Fatalf("a late request reopened a revoked Run after the race: %v", err)
		}
	}
}

func TestDomainTCPRunReadyRequiresOriginalKernelAndSource(t *testing.T) {
	manager, owner, process, ctx := domainTCPRunCustodyModel(t)
	run, err := owner.beginDomainTCPRun(ctx, process)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.finishDomainTCPRun(run, context.Canceled)
	mapping := &dnscontrol.SyntheticDNSMapping{}
	process.material = &XrayDomainTCPOperationMaterial{mapping: mapping}
	owner.mu.Lock()
	owner.prepared = &DomainPolicyTCPCaptureMapping{source: mapping}
	owner.kernel = &domainTCPBaselineKernelOwner{}
	owner.publicationOpen = true
	owner.mu.Unlock()
	if err := owner.CheckDomainTCPRunReady(ctx); !errors.Is(err, ErrDomainPolicyTCPConsumer) {
		t.Fatalf("phase and reconstructed native fields fabricated readiness: %v", err)
	}
	if err := manager.RevokeDomainTCPRun(ctx, owner); err != nil {
		t.Fatal(err)
	}
	if err := owner.CheckDomainTCPRunReady(ctx); !errors.Is(err, ErrDomainPolicyTCPConsumer) {
		t.Fatalf("revoked run became ready: %v", err)
	}
}

func TestDomainTCPWireSendRejectsStaleAndForeignAdmission(t *testing.T) {
	manager, owner, process, ctx := domainTCPRunCustodyModel(t)
	run, err := owner.beginDomainTCPRun(ctx, process)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.finishDomainTCPRun(run, context.Canceled)
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	live, cancel := context.WithCancel(ctx)
	defer cancel()
	capture := &DomainPolicyTCPCapture{owner: owner, listener: listener, ctx: live, cancel: cancel}
	capture.self, owner.capture = capture, capture
	mapping := &dnscontrol.SyntheticDNSMapping{}
	process.material = &XrayDomainTCPOperationMaterial{mapping: mapping}
	owner.prepared = &DomainPolicyTCPCaptureMapping{source: mapping}
	owner.kernel, owner.publicationOpen = &domainTCPBaselineKernelOwner{}, true
	permit, err := owner.prepareDomainTCPWireSend(mapping)
	if err != nil {
		t.Fatal(err)
	}
	held := context.WithValue(ctx, domainTCPWireSendKey{}, permit)
	rejectWrite := func() error { t.Fatal("unadmitted socket write"); return nil }
	if err := owner.WithSyntheticWireSend(ctx, mapping, rejectWrite); !errors.Is(err, ErrDomainPolicyTCPConsumer) {
		t.Fatal("write lacked its publication owner", err)
	}
	if err := owner.WithSyntheticWireSend(held, &dnscontrol.SyntheticDNSMapping{}, rejectWrite); !errors.Is(err, ErrDomainPolicyTCPConsumer) {
		t.Fatal("write borrowed another mapping", err)
	}
	if err := owner.WithSyntheticWireSend(held, mapping, func() error {
		if owner.mu.TryLock() {
			owner.mu.Unlock()
			t.Fatal("socket write was not serialized with revocation")
		}
		return nil
	}); err != nil {
		t.Fatal("original write refused", err)
	}
	if err := owner.WithSyntheticWireSend(held, mapping, rejectWrite); !errors.Is(err, ErrDomainPolicyTCPConsumer) {
		t.Fatal("same publication wrote twice", err)
	}
	closed, err := owner.prepareDomainTCPWireSend(mapping)
	if err != nil {
		t.Fatal(err)
	}
	closed.close()
	if err := owner.WithSyntheticWireSend(context.WithValue(ctx, domainTCPWireSendKey{}, closed), mapping, rejectWrite); !errors.Is(err, ErrDomainPolicyTCPConsumer) {
		t.Fatal("closed callback retained socket authority", err)
	}
	late, err := owner.prepareDomainTCPWireSend(mapping)
	if err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	lateContext := context.WithValue(ctx, domainTCPWireSendKey{}, late)
	if err := owner.WithSyntheticWireSend(lateContext, mapping, rejectWrite); !errors.Is(err, ErrDomainPolicyTCPConsumer) {
		t.Fatal("reply escaped after the listener closed while its Run still existed", err)
	}
	capture.stopAccepting()
	if owner.publicationOpen || live.Err() == nil || run.ctx.Err() != nil {
		t.Fatal("stopping accepts did not revoke publication separately from joining Run")
	}
	if err := manager.RevokeDomainTCPRun(ctx, owner); err != nil {
		t.Fatal(err)
	}
	if err := owner.WithSyntheticWireSend(lateContext, mapping, rejectWrite); !errors.Is(err, ErrDomainPolicyTCPConsumer) {
		t.Fatal("previously admitted reply escaped revocation", err)
	}
}
