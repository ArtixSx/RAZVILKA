package dataplane

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Actual original private Commit/Stop/retire protocol and one-use COMMON
// callback, with existing explicitly modeled native transport/Wait/file/queue
// leaves. These prove handle identity and retirement completion, not Native.
func nfqws2RetiredHandleFixture(t *testing.T, closeFailure bool) (*NFQWSActiveHandle, *nfqws2ActiveModel, context.Context, error) {
	t.Helper()
	m, a, _ := nfqws2ActiveRetirementFixture(t)
	committed, cleanup := m.guards()
	h, err := m.prepared.CommitPrepared(m.request, committed, cleanup)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), nfqws2ActiveModelKey{}, "cleanup"), 5*time.Second)
	t.Cleanup(cancel)
	if _, err := h.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if closeFailure {
		retire := m.owner.retire
		m.owner.retire = func(c context.Context, l nfqws2ActiveProcessLease, common func() error) error {
			if err := retire(c, l, common); err != nil {
				return err
			}
			return errors.New("modeled post-unlink uncertainty")
		}
	}
	err = a.retireActiveNFQWSProcess(ctx, h, func(context.Context, NFQWSExecutionBinding, NFQWSScopedProcessProof) error { return nil })
	return h, m, ctx, err
}

func TestNFQWSRetiredObservationRequiresSuccessfulOriginalCloseAndNeverReadsDeletedLease(t *testing.T) {
	h, m, ctx, err := nfqws2RetiredHandleFixture(t, false)
	if err != nil || m.owner.retiredActive != h || m.owner.active != nil || m.owner.prepared != nil || m.owner.adapter.activeProcess != nil {
		t.Fatal("original final retirement did not retain only its completion identity", err)
	}
	settled, err := m.owner.result()
	if err != nil {
		t.Fatal(err)
	}
	m.owner.read = func(context.Context, bool) (nfqws2ActiveProcessLease, error) {
		t.Fatal("retired proof read deleted ownership.json")
		return nfqws2ActiveProcessLease{}, nil
	}
	if err := h.VerifyRetiredObservation(ctx, settled.observation()); err != nil {
		t.Fatal("original successful retired proof refused", err)
	}
	if err := h.VerifyRetiredObservation(ctx, settled.observation()); err != nil {
		t.Fatal("read-only terminal authentication consumed an effect grant", err)
	}
	if _, err := h.Stop(ctx); err == nil {
		t.Fatal("terminal proof revived Stop authority")
	}
	copy := *h
	if err := copy.VerifyRetiredObservation(ctx, settled.observation()); err == nil {
		t.Fatal("copied active handle authenticated terminal completion")
	}
	changed := settled.observation()
	changed.Receipt.CommandSHA256 = "foreign"
	if err := h.VerifyRetiredObservation(ctx, changed); err == nil {
		t.Fatal("foreign terminal observation authenticated")
	}
}

func TestNFQWSRetiredObservationRefusesUnknownCloseAndChangedCompletion(t *testing.T) {
	for _, failure := range []string{"close-unknown", "cancelled", "unbounded", "wait-error", "changed-result", "replacement-process"} {
		t.Run(failure, func(t *testing.T) {
			h, m, ctx, closeErr := nfqws2RetiredHandleFixture(t, failure == "close-unknown")
			settled, err := m.owner.result()
			if err != nil {
				t.Fatal(err)
			}
			switch failure {
			case "close-unknown":
				if closeErr == nil || m.owner.retiredActive != nil {
					t.Fatal("fixture unexpectedly completed unknown retirement", closeErr)
				}
			case "cancelled":
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			case "unbounded":
				ctx = context.Background()
			case "wait-error":
				m.owner.result = func() (nfqws2ActiveProcessLease, error) {
					return nfqws2ActiveProcessLease{}, errors.New("lost original Wait outcome")
				}
			case "changed-result":
				calls := 0
				m.owner.result = func() (nfqws2ActiveProcessLease, error) {
					calls++
					changed := settled
					if calls == 2 {
						changed.Receipt.ExitCode++
					}
					return changed, nil
				}
			case "replacement-process":
				m.owner.adapter.activeProcess = &nfqws2ActiveOwner{adapter: m.owner.adapter}
			}
			if err := h.VerifyRetiredObservation(ctx, settled.observation()); err == nil {
				t.Fatal("unknown or changed completion became terminal proof", failure)
			}
		})
	}
}
