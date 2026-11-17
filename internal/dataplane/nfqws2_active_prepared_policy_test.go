package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Original COMMON files/lock/control and resource journal, with explicitly
// modeled native process/queue observations. Native tests remain independent.
func nfqPreparedPolicyFixture(t *testing.T) (*policyEffectFixture, *nfqwsPolicyRecovery, *nfqwsActivePreparedPolicy, context.Context) {
	t.Helper()
	f, c, borrowed := nfqPreLedgerOriginalFixture(t)
	e := c.execution
	parent := context.WithValue(borrowed, policyEffectReceiptBorrowKey{}, nil)
	parent = context.WithValue(parent, nfqws2ActivePreparedKey{}, e.prepared)
	proof := (&nfqwsScopedModel{p: e.resource.Plan(), running: true}).proof(false)
	observation := NFQWSActiveObservation{Binding: e.resource.Binding(), NetworkIdentity: e.material.command.NetworkIdentity, Receipt: proof.Receipt, Child: proof.Child}
	s, err := newNFQWSActivePreparedPolicy(parent, e, e.prepared, e.resource.Binding(), observation)
	if err != nil {
		t.Fatal("preparation fixture", err)
	}
	c.preparedPolicy = s
	e.resource.preparedUsed = false
	e.resource.scope.execution.Resources[0].Phase = "process-pending"
	return f, c, s, context.WithValue(parent, policyEffectReceiptBorrowKey{}, c.session.borrow)
}

func TestNFQWSPreparedPolicyHeldWriterLifetimeAndOriginalTransition(t *testing.T) {
	f, c, s, ctx := nfqPreparedPolicyFixture(t)
	var escaped context.Context
	reads := 0
	s.resource.activeReadback = func(read context.Context, p *NFQWSScopedPlan, root string, mode nfqwsExecutionActiveReadbackMode, observed NFQWSActiveObservation) error {
		if mode != nfqwsExecutionActiveBeforeCapture || observed != s.observation || read.Value(networkPolicyConsumerPlanKey{}) != s.parent.Value(networkPolicyConsumerPlanKey{}) {
			t.Fatal("prepared transition changed its original inputs")
		}
		escaped = read
		for range 2 {
			present, err := nfqwsPreparedHeldAbsence(read, s.binding, p, root)
			if !present || err != nil {
				t.Fatal("same original held writer refused", present, err)
			}
			reads++
		}
		return nil
	}
	if err := s.prepare(ctx, c); err != nil {
		t.Fatal("original PreparedActive failed", err)
	}
	if reads != 2 || !s.used || s.open || !s.resource.preparedUsed || s.resource.scope.execution.Resources[0].Phase != "capture-ready" || c.publication != 0 || c.entered || len(f.calls) != 0 || !c.preLedgerArmed() {
		t.Fatal("preparation fabricated COMMON publication/effect or lost transition")
	}
	if present, err := nfqwsPreparedHeldAbsence(escaped, s.binding, s.plan, s.root); !present || err == nil {
		t.Fatal("escaped preparation borrowed the writer")
	}
	if err := s.prepare(ctx, c); err == nil {
		t.Fatal("preparation replayed")
	}
}

func TestNFQWSPreparedPolicyFailureRetainsSamePreLedgerCustody(t *testing.T) {
	for _, kind := range []string{"before-read", "read-refusal", "panic"} {
		t.Run(kind, func(t *testing.T) {
			f, c, s, ctx := nfqPreparedPolicyFixture(t)
			cut := errors.New("prepared read refusal")
			if kind == "before-read" {
				s.resource.preparedUsed = true
			}
			s.resource.activeReadback = func(read context.Context, p *NFQWSScopedPlan, root string, _ nfqwsExecutionActiveReadbackMode, _ NFQWSActiveObservation) error {
				if present, err := nfqwsPreparedHeldAbsence(read, s.binding, p, root); !present || err != nil {
					t.Fatal("original absence before injected refusal", err)
				}
				if kind == "panic" {
					panic(cut)
				}
				return cut
			}
			var result error
			var caught any
			func() {
				defer func() { caught = recover() }()
				result = s.prepare(ctx, c)
			}()
			c.finishApply()
			if (kind == "panic" && caught != cut) || (kind != "panic" && result == nil) || s.open || !c.retained || !c.preLedgerArmed() || c.publication != 0 || len(f.calls) != 0 {
				t.Fatal("failed preparation lost original custody", result, caught)
			}
			if err := c.settlePreLedger(ctx, func() error { return nfqPreLedgerModelAbsence(f, ctx) }); err != nil {
				t.Fatal("original modeled absence could not settle", err)
			}
			if !c.settled || c.publication != 1 || len(f.calls) != 0 {
				t.Fatal("recovery issued kernel command or failed planned publication")
			}
		})
	}
}

func TestNFQWSPreparedPolicyHeldAbsenceRefusesForeignAndClosed(t *testing.T) {
	for _, kind := range []string{"nil-marker", "copied", "closed", "nil-parent", "other-root", "other-plan", "control", "prepared-owner", "owner-pointer", "foreign-borrow", "published", "foreign-receipt", "canceled", "extended", "tool-source", "network"} {
		t.Run(kind, func(t *testing.T) {
			_, c, s, _ := nfqPreparedPolicyFixture(t)
			s.open, s.used, s.custody = true, true, c // Explicit comparator model, no PreparedActive authority.
			read := context.WithValue(s.parent, policyEffectReceiptBorrowKey{}, c.session.borrow)
			read = context.WithValue(read, nfqwsActivePreparedPolicyKey{}, s)
			path, plan := s.root, s.plan
			switch kind {
			case "nil-marker":
				read = context.WithValue(read, nfqwsActivePreparedPolicyKey{}, (*nfqwsActivePreparedPolicy)(nil))
			case "copied":
				read = context.WithValue(read, nfqwsActivePreparedPolicyKey{}, &nfqwsActivePreparedPolicy{self: s})
			case "closed":
				s.open = false
			case "nil-parent":
				s.parent = nil
			case "other-root":
				path = t.TempDir()
			case "other-plan":
				plan = &NFQWSScopedPlan{}
			case "control":
				s.material.control = nil
			case "prepared-owner":
				s.resource.preparedOwner = &NFQWSPreparedHandle{}
			case "owner-pointer":
				s.prepared.owner = &nfqws2ActiveOwner{admission: nfqws2ActiveProcessAdmission{Binding: s.resource.Binding()}}
			case "tool-source":
				s.execution.inventory.reader.Runner = &activePredicateObservationModel{}
				s.binding.network.inventory.reader.Runner = s.execution.inventory.reader.Runner
			case "network":
				other := *s.binding.network
				s.binding.network = &other
			case "foreign-borrow":
				read = context.WithValue(read, policyEffectReceiptBorrowKey{}, &policyEffectReceiptBorrow{})
			case "published":
				c.publication = 1
			case "foreign-receipt":
				if err := os.WriteFile(filepath.Join(path, policyAdditionFile), []byte("foreign"), 0600); err != nil {
					t.Fatal(err)
				}
			case "canceled":
				var cancel context.CancelFunc
				read, cancel = context.WithCancel(read)
				cancel()
			case "extended":
				read = context.WithoutCancel(read)
				var cancel context.CancelFunc
				read, cancel = context.WithTimeout(read, time.Hour)
				defer cancel()
			}
			if present, err := nfqwsPreparedHeldAbsence(read, s.binding, plan, path); !present || err == nil {
				t.Fatal("foreign preparation accepted/fell back", present, err)
			}
		})
	}
}

type nfqPreparedPolicyPausedDeadline struct {
	context.Context
	entered func()
	release <-chan struct{}
}

func (c nfqPreparedPolicyPausedDeadline) Deadline() (time.Time, bool) {
	c.entered()
	<-c.release
	return c.Context.Deadline()
}

func TestNFQWSPreparedPolicyJoinsBorrowedAbsenceBeforeReturn(t *testing.T) {
	_, c, s, ctx := nfqPreparedPolicyFixture(t)
	readerEntered := make(chan struct{})
	enterReader := sync.OnceFunc(func() { close(readerEntered) })
	releaseReader := make(chan struct{})
	release := sync.OnceFunc(func() { close(releaseReader) })
	defer release()
	readerDone := make(chan error, 1)
	readerStarted := make(chan struct{})
	readerJoined := make(chan struct{})
	bodyReturned := make(chan struct{})
	var preparedRead context.Context
	cut := errors.New("prepared body failed with entered reader")
	s.resource.activeReadback = func(read context.Context, p *NFQWSScopedPlan, root string, _ nfqwsExecutionActiveReadbackMode, _ NFQWSActiveObservation) error {
		preparedRead = read
		close(readerStarted)
		go func() {
			defer close(readerJoined)
			// Deadline is read after the original RLock. Pause there, not at
			// borrow.mu: cancellation may legitimately refuse before that lock.
			paused := nfqPreparedPolicyPausedDeadline{Context: read, entered: enterReader, release: releaseReader}
			present, err := nfqwsPreparedHeldAbsence(paused, s.binding, p, root)
			if !present {
				err = errors.New("reader silently fell back")
			}
			readerDone <- err
		}()
		select {
		case <-readerEntered:
		case <-time.After(time.Second):
			return errors.New("reader did not enter bounded absence comparison")
		}
		close(bodyReturned)
		return cut
	}
	preparedDone := make(chan error, 1)
	preparedJoined := make(chan struct{})
	go func() {
		defer close(preparedJoined)
		preparedDone <- s.prepare(ctx, c)
	}()
	defer func() {
		release()
		select {
		case <-preparedJoined:
		case <-time.After(2 * time.Second):
			t.Error("preparation did not join after releasing paused reader")
		}
		select {
		case <-readerStarted:
			select {
			case <-readerJoined:
			case <-time.After(2 * time.Second):
				t.Error("paused reader did not join")
			}
		default:
		}
	}()
	select {
	case <-bodyReturned:
	case err := <-preparedDone:
		t.Fatal("preparation returned without joined reader", err)
	case <-time.After(2 * time.Second):
		t.Fatal("prepared body did not reach entered reader")
	}
	// Observe the real closing cancellation before checking its reader join.
	select {
	case <-preparedRead.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("preparation did not reach closing cancellation")
	}
	select {
	case err := <-preparedDone:
		t.Fatal("preparation escaped reader ownership", err)
	default:
	}
	release()
	select {
	case <-readerDone: // Closing may cancel this comparison; never publish it.
	case <-time.After(2 * time.Second):
		t.Fatal("reader did not return after release")
	}
	select {
	case err := <-preparedDone:
		if !errors.Is(err, cut) || s.open {
			t.Fatal("joined preparation did not preserve failure/revocation", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("preparation did not return after joined reader")
	}
}

func TestNFQWSPreparedPolicyOriginalEntryBeforeFirstGuard(t *testing.T) {
	for _, kind := range []string{"prepared-refusal", "post-prepared-guard"} {
		t.Run(kind, func(t *testing.T) {
			e, ctx, f := nfqwsActiveCommandPolicyFixture(t)
			e.material.execution, e.material.executionBound = e, true
			e.inventory.reader.Runner = &activePredicateObservationModel{}
			e.binding.activeReadback = e
			e.binding.network = &nfqwsScopedNetworkBinding{provider: e.material.provider, inventory: e.inventory}
			ctx = context.WithValue(ctx, nfqws2ActivePreparedKey{}, e.prepared)
			proof := (&nfqwsScopedModel{p: e.resource.Plan(), running: true}).proof(false)
			observation := NFQWSActiveObservation{Binding: e.resource.Binding(), NetworkIdentity: e.material.command.NetworkIdentity, Receipt: proof.Receipt, Child: proof.Child}
			s, err := newNFQWSActivePreparedPolicy(ctx, e, e.prepared, e.resource.Binding(), observation)
			if err != nil {
				t.Fatal(err)
			}
			e.resource.preparedUsed = false
			e.resource.scope.execution.Resources[0].Phase = "process-pending"
			c := &nfqwsPolicyRecovery{execution: e, index: -1, preparedPolicy: s}
			c.self, e.partialRecovery = c, c
			t.Cleanup(c.close)
			cut := errors.New(kind)
			readCalls, guards := 0, 0
			e.resource.activeReadback = func(read context.Context, p *NFQWSScopedPlan, root string, _ nfqwsExecutionActiveReadbackMode, _ NFQWSActiveObservation) error {
				readCalls++
				if !c.preLedgerArmed() || c.publication != 0 || c.entered {
					t.Fatal("prepared read began without original pre-ledger custody")
				}
				for range 2 {
					if present, err := nfqwsPreparedHeldAbsence(read, s.binding, p, root); !present || err != nil {
						t.Fatal("owned lock was not proven", err)
					}
				}
				if kind == "prepared-refusal" {
					return cut
				}
				return nil
			}
			f.runtime.Guard = func(context.Context, int) error {
				guards++
				if s.open || e.resource.scope.execution.Resources[0].Phase != "capture-ready" {
					t.Fatal("policy guard overlapped preparation or skipped transition")
				}
				return cut
			}
			f.runtime.Runner = nfqwsScopedApplyRunner{base: f, binding: e.binding, scoped: e.resource.Plan(), plan: f.plan, tools: f.runtime.Tools, guard: f.runtime.Guard}
			f.runtime, err = newNFQWSActivePreAddRead(e, e.binding, e.resource.Plan(), f.runtime, f.plan, f.root, c)
			if err != nil {
				t.Fatal(err)
			}
			err = applyPolicyEffectsWithOriginalRecovery(ctx, f.runtime, f.plan, f.root, f.options, nil, c)
			wantedGuards := 0
			if kind == "post-prepared-guard" {
				wantedGuards = 1
			}
			if !errors.Is(err, cut) || readCalls != 1 || guards != wantedGuards || s.open || !c.retained || !c.preLedgerArmed() || c.publication != 0 || len(f.calls) != 0 {
				t.Fatal("original entry/custody/order changed", err, readCalls, guards, c.retained)
			}
		})
	}
}

func TestNFQWSPreparedPolicyNoMarkerDoesNotAdmitHeldLock(t *testing.T) {
	_, c, s, ctx := nfqPreparedPolicyFixture(t)
	if present, err := nfqwsPreparedHeldAbsence(ctx, s.binding, s.plan, s.root); present || err != nil {
		t.Fatal("generic borrow changed absent-lock contract", present, err)
	}
	if _, err := c.session.root.Stat(policyAdditionLock); err != nil {
		t.Fatal("fixture lacks foreign-to-generic held lock", err)
	}
}

func TestNFQWSPreparedPolicyCustomRuntimeCannotAdoptPreparation(t *testing.T) {
	f := newPolicyEffectFixture(t)
	b := &NFQWSScopedBinding{options: f.options}
	if err := b.applyOriginalPolicyEffectsPrepared(context.Background(), nil, f.runtime, f.plan, f.root, &nfqwsActivePreparedPolicy{}); err == nil || len(f.calls) != 0 {
		t.Fatal("custom runtime adopted preparation", err)
	}
	if err := b.applyOriginalPolicyEffects(context.Background(), nil, f.runtime, f.plan, f.root); err != nil || len(f.calls) != len(f.plan.Effects) {
		t.Fatal("ordinary custom nil path changed", err, len(f.calls))
	}
}

func TestNFQWSPreparedPolicyHonorsActualCallerCancellation(t *testing.T) {
	for _, when := range []string{"opening", "during-read"} {
		t.Run(when, func(t *testing.T) {
			f, c, s, parent := nfqPreparedPolicyFixture(t)
			ctx, cancel := context.WithCancel(parent)
			defer cancel()
			calls := 0
			s.resource.activeReadback = func(read context.Context, _ *NFQWSScopedPlan, _ string, _ nfqwsExecutionActiveReadbackMode, _ NFQWSActiveObservation) error {
				calls++
				cancel()
				if !errors.Is(read.Err(), context.Canceled) {
					t.Fatal("prepared body lost actual caller cancellation")
				}
				return nil // Closing must refuse despite nominal callback success.
			}
			if when == "opening" {
				cancel()
			}
			if err := s.prepare(ctx, c); err == nil || s.open || s.resource.scope.execution.Resources[0].Phase != "process-pending" || c.publication != 0 || len(f.calls) != 0 {
				t.Fatal("canceled prepared body persisted capture-ready", err)
			}
			wanted := 0
			if when == "during-read" {
				wanted = 1
			}
			if calls != wanted || s.parent.Err() != nil {
				t.Fatal("wrong cancellation boundary", calls, s.parent.Err())
			}
		})
	}
}

func TestNFQWSPreparedPolicyAlsoHonorsOriginalParentCancellation(t *testing.T) {
	_, c, s, ctx := nfqPreparedPolicyFixture(t)
	parent, cancel := context.WithCancel(s.parent)
	defer cancel()
	s.parent = parent // Model a caller ctx that did not inherit this cancellation.
	s.resource.activeReadback = func(read context.Context, _ *NFQWSScopedPlan, _ string, _ nfqwsExecutionActiveReadbackMode, _ NFQWSActiveObservation) error {
		cancel()
		select {
		case <-read.Done():
		case <-time.After(time.Second):
			t.Fatal("prepared read dropped original parent cancellation")
		}
		return nil
	}
	if err := s.prepare(ctx, c); !errors.Is(err, context.Canceled) || ctx.Err() != nil || s.open || s.resource.scope.execution.Resources[0].Phase != "process-pending" {
		t.Fatal("detached actual caller outlived original preparation", err, ctx.Err())
	}
}

func TestNFQWSPreparedPolicyFaultRunsAfterBothComparisonLocks(t *testing.T) {
	f, c, s, _ := nfqPreparedPolicyFixture(t)
	s.open, s.used, s.custody = true, true, c // Explicit open-comparator model.
	ctx := context.WithValue(s.parent, policyEffectReceiptBorrowKey{}, c.session.borrow)
	ctx = context.WithValue(ctx, nfqwsActivePreparedPolicyKey{}, s)
	cut := errors.New("prepared absence fault")
	calls := 0
	c.session.options.fault = func(point string, index int) error {
		calls++
		if point != "nfq-original-prepared-absence" || index != -1 || !s.mu.TryLock() {
			t.Fatal("fault under preparation lock or wrong boundary", point, index)
		}
		s.mu.Unlock()
		if !c.session.borrow.mu.TryLock() {
			t.Fatal("fault under original borrow lock")
		}
		c.session.borrow.mu.Unlock()
		return cut
	}
	if present, err := nfqwsPreparedHeldAbsence(ctx, s.binding, s.plan, s.root); !present || err != nil {
		t.Fatal("fresh comparison before fault", err)
	}
	if err := nfqwsPreparedAbsenceFault(ctx); !errors.Is(err, cut) || calls != 1 || c.publication != 0 || len(f.calls) != 0 {
		t.Fatal("fault did not preserve original no-effect state", err, calls)
	}
	s.open = false
	if err := nfqwsPreparedAbsenceFault(ctx); err == nil || calls != 1 {
		t.Fatal("closed scope invoked fault", err, calls)
	}
}
