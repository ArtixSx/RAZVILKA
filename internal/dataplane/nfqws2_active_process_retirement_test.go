package dataplane

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func nfqws2ActiveRetirementFixture(t *testing.T) (*nfqws2ActiveModel, *NFQWS2Adapter, *int) {
	t.Helper()
	m := nfqws2ActiveOwnerFixture(t)
	a := &NFQWS2Adapter{StateRoot: m.owner.command.StateRoot}
	m.owner.adapter = a
	startDone := make(chan struct{})
	close(startDone)
	m.owner.startDone = startDone
	removed := new(int)
	m.owner.retire = func(ctx context.Context, l nfqws2ActiveProcessLease, common func() error) error {
		if !nfqws2ActiveProcessSettled(l) || ctx.Err() != nil {
			return ErrNFQWSManagedProcessUnknown
		}
		if err := common(); err != nil {
			return err
		}
		*removed++
		return ctx.Err()
	}
	if err := a.retainNFQWSActiveProcess(m.owner); err != nil {
		t.Fatal(err)
	}
	return m, a, removed
}

func TestNFQWSActiveRetirementRequiresStopAndCommonAndOriginalPointers(t *testing.T) {
	for _, active := range []bool{false, true} {
		t.Run(map[bool]string{false: "prepared", true: "active"}[active], func(t *testing.T) {
			m, a, removed := nfqws2ActiveRetirementFixture(t)
			ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), nfqws2ActiveModelKey{}, "cleanup"), time.Second)
			defer cancel()
			var h *NFQWSActiveHandle
			if active {
				var err error
				committed, cleanup := m.guards()
				h, err = m.prepared.CommitPrepared(m.request, committed, cleanup)
				if err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			common := func(c context.Context, b NFQWSExecutionBinding, proof NFQWSScopedProcessProof) error {
				calls++
				m.mu.Lock()
				actual := m.lease
				m.mu.Unlock()
				if c != ctx || b != actual.Binding || proof != actual.proof() || !proof.Acknowledged || !proof.Receipt.WaitECHILD {
					t.Fatal("COMMON received replaced context/binding or unjoined proof")
				}
				if h != nil {
					return h.VerifyCleanupObservation(c, actual.observation()) // Must not deadlock on owner.mu.
				}
				_, err := m.owner.observe(c, false)
				return err
			}
			retire := func(adapter *NFQWS2Adapter) error {
				if h != nil {
					return adapter.retireActiveNFQWSProcess(ctx, h, common)
				}
				return adapter.retirePreparedNFQWSProcess(ctx, m.prepared, common)
			}
			if retire(a) == nil || calls != 0 || m.owner.retirementStarted {
				t.Fatal("running owner retired")
			}
			if h != nil {
				if _, err := h.Stop(ctx); err != nil {
					t.Fatal(err)
				}
			} else if _, err := m.prepared.Stop(ctx); err != nil {
				t.Fatal(err)
			}
			if a.activeProcess != m.owner || a.retainNFQWSActiveProcess(&nfqws2ActiveOwner{adapter: a}) == nil {
				t.Fatal("Stop alone cleared original participant")
			}
			copyAdapter := *a
			if retire(&copyAdapter) == nil || retire(&NFQWS2Adapter{StateRoot: a.StateRoot}) == nil {
				t.Fatal("copied/new adapter retired original owner")
			}
			if h != nil {
				copyHandle := *h
				if a.retireActiveNFQWSProcess(ctx, &copyHandle, common) == nil {
					t.Fatal("copied active handle accepted")
				}
			} else {
				copyHandle := *m.prepared
				if a.retirePreparedNFQWSProcess(ctx, &copyHandle, common) == nil {
					t.Fatal("copied prepared handle accepted")
				}
			}
			if calls != 0 || m.owner.retirementStarted || *removed != 0 {
				t.Fatal("foreign input consumed retirement")
			}
			if err := retire(a); err != nil {
				t.Fatal(err)
			}
			if calls != 1 || *removed != 1 || a.activeProcess != nil || m.owner.state != "retired" {
				t.Fatal("finished retirement did not revoke original association")
			}
			if retire(a) == nil || calls != 1 {
				t.Fatal("retirement replay accepted")
			}
			if h != nil {
				if _, err := h.Stop(ctx); err == nil {
					t.Fatal("retired active handle retained cleanup authority")
				}
			} else if _, err := m.prepared.Stop(ctx); err == nil {
				t.Fatal("retired prepared handle retained ownership")
			}
			next := &nfqws2ActiveOwner{adapter: a}
			if err := a.retainNFQWSActiveProcess(next); err != nil {
				t.Fatal("next participant still fenced after exact retirement", err)
			}
		})
	}
}

func TestNFQWSActiveRetirementFailureRetainsFence(t *testing.T) {
	for _, failure := range []string{"common", "readback", "terminal-metadata", "missing-wait", "post-unlink", "cancel-during-common", "omit-common", "duplicate-common"} {
		t.Run(failure, func(t *testing.T) {
			m, a, removed := nfqws2ActiveRetirementFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err := m.prepared.Stop(ctx); err != nil {
				t.Fatal(err)
			}
			calls := 0
			common := func(context.Context, NFQWSExecutionBinding, NFQWSScopedProcessProof) error {
				calls++
				if failure == "common" {
					return errors.New("known COMMON cleanup failed")
				}
				if failure == "cancel-during-common" {
					cancel()
				}
				return nil
			}
			switch failure {
			case "readback":
				read := m.owner.read
				m.owner.read = func(c context.Context, live bool) (nfqws2ActiveProcessLease, error) {
					l, err := read(c, live)
					l.Receipt.ExitCode++ // Valid terminal shape, different actual Wait result.
					return l, err
				}
			case "terminal-metadata":
				m.lease.Acknowledged = false
			case "missing-wait":
				m.owner.done = make(chan struct{}) // Terminal file alone cannot substitute sole Wait.
			case "post-unlink":
				retire := m.owner.retire
				m.owner.retire = func(c context.Context, l nfqws2ActiveProcessLease, f func() error) error {
					if err := retire(c, l, f); err != nil {
						return err
					}
					return ErrNFQWSManagedProcessUnknown
				}
			case "omit-common":
				m.owner.retire = func(context.Context, nfqws2ActiveProcessLease, func() error) error { return nil }
			case "duplicate-common":
				m.owner.retire = func(_ context.Context, _ nfqws2ActiveProcessLease, f func() error) error {
					_ = f()
					_ = f()
					return nil // Swallowing the second error cannot hide reuse.
				}
			}
			if err := a.retirePreparedNFQWSProcess(ctx, m.prepared, common); !errors.Is(err, ErrNFQWSManagedProcessUnknown) || strings.Contains(err.Error(), "known COMMON") {
				t.Fatal("failure did not produce static unknown diagnostic", err)
			}
			if a.activeProcess != m.owner || a.retainNFQWSActiveProcess(&nfqws2ActiveOwner{adapter: a}) == nil {
				t.Fatal("failed retirement cleared the fence")
			}
			if failure == "common" && *removed != 0 || failure == "readback" && calls != 0 || failure == "missing-wait" && calls != 0 {
				t.Fatal("unproven terminal or COMMON failure reached removal")
			}
		})
	}
}

func TestNFQWSActiveRetirementJoinsFailedTransferBeforeCommon(t *testing.T) {
	m, a, removed := nfqws2ActiveRetirementFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	_, cleanup := m.guards()
	commitResult := make(chan error, 1)
	go func() {
		_, err := m.prepared.CommitPrepared(m.request, func(c context.Context, h *NFQWSActiveHandle, obs NFQWSActiveObservation) error {
			close(entered)
			<-release
			return h.VerifyOwnerObservation(c, obs)
		}, cleanup)
		commitResult <- err
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("transfer never reached final guard")
	}
	if _, err := m.prepared.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	calls := 0
	common := func(context.Context, NFQWSExecutionBinding, NFQWSScopedProcessProof) error { calls++; return nil }
	if a.retirePreparedNFQWSProcess(ctx, m.prepared, common) == nil || calls != 0 || m.owner.retirementStarted {
		t.Fatal("unfinished transfer compensation admitted COMMON retirement")
	}
	close(release)
	select {
	case err := <-commitResult:
		if err == nil {
			t.Fatal("stopped transfer succeeded")
		}
	case <-ctx.Done():
		t.Fatal("transfer did not join")
	}
	if err := a.retirePreparedNFQWSProcess(ctx, m.prepared, common); err != nil || calls != 1 || *removed != 1 {
		t.Fatal("joined failed transfer remained unavailable", err)
	}
}

func TestNFQWSActiveRetirementInvalidInputDoesNotConsumeCommon(t *testing.T) {
	for _, input := range []string{"nil-context", "unbounded", "cancelled", "nil-common", "wrong-spec", "wrong-binding"} {
		t.Run(input, func(t *testing.T) {
			m, a, removed := nfqws2ActiveRetirementFixture(t)
			bounded, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err := m.prepared.Stop(bounded); err != nil {
				t.Fatal(err)
			}
			ctx := bounded
			calls := 0
			common := func(context.Context, NFQWSExecutionBinding, NFQWSScopedProcessProof) error { calls++; return nil }
			switch input {
			case "nil-context":
				ctx = nil
			case "unbounded":
				ctx = context.Background()
			case "cancelled":
				cancel()
			case "nil-common":
				common = nil
			case "wrong-spec":
				m.owner.admission.Spec.Queue++
			case "wrong-binding":
				m.owner.admission.Binding.ExecutionID = "dp-other"
			}
			if a.retirePreparedNFQWSProcess(ctx, m.prepared, common) == nil || calls != 0 || *removed != 0 || m.owner.retirementStarted || a.activeProcess != m.owner {
				t.Fatal("invalid input consumed COMMON or retired the participant")
			}
		})
	}
}
