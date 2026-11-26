package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/evidence"
)

func TestNodeCheckResourceBookendCancellationClassification(t *testing.T) {
	for _, guarded := range []bool{false, true} {
		scope := "standalone"
		if guarded {
			scope = "guarded"
		}
		for _, phase := range []string{"resolve", "service-ip", "cleanup"} {
			t.Run(scope+"/"+phase, func(t *testing.T) {
				checker := fakeExactNodeChecker(t)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				guardCalls := 0
				if guarded {
					ctx = WithNodeResourceGuard(ctx, func(context.Context, string, netip.Addr) error { guardCalls++; return nil })
				}
				if phase == "resolve" {
					original := checker.resolve
					checker.resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
						addresses, err := original(ctx, host)
						cancel()
						return addresses, err
					}
				}
				if phase == "service-ip" {
					original := checker.serviceIPProbe
					checker.serviceIPProbe = func(ctx context.Context, address, route, egress string, service catalog.Service, pin netip.Addr) (evidence.ProbeEvidence, error) {
						proof, err := original(ctx, address, route, egress, service, pin)
						cancel()
						return proof, err
					}
				}
				cleaned := 0
				checker.cleanup = func(cleanupCtx context.Context, _ exactNodeSession) error {
					cleaned++
					if cleanupCtx.Err() != nil {
						t.Fatal("cancellation reached cleanup", cleanupCtx.Err())
					}
					if _, bounded := cleanupCtx.Deadline(); !bounded {
						t.Fatal("cleanup lost its deadline")
					}
					if _, err := checker.Check(cleanupCtx, checkedNodeRequest()); !errors.Is(err, ErrExactNodeBusy) {
						t.Fatal("checker released its runtime slot before cleanup", err)
					}
					if phase == "cleanup" {
						cancel()
					}
					return nil
				}
				result, err := checker.Check(ctx, checkedNodeRequest())
				wantCleanup := 1
				if phase == "resolve" {
					wantCleanup = 0
				}
				if !errors.Is(err, context.Canceled) || errors.Is(err, ErrNodeResourceDenied) || result.Stage != "canceled" || result.ErrorCode != "node-check-canceled" || result.Evidence.ErrorCode != result.ErrorCode ||
					result.Available || result.Verdict != evidence.VerdictInconclusive || result.EgressIP != "" || result.Evidence.AssuranceLevel().AtLeast(evidence.Service) || cleaned != wantCleanup || checker.poisoned.Load() || len(checker.gate) != checker.Capacity() || guarded && guardCalls == 0 {
					t.Fatal("resource bookend changed cancellation or cleanup ownership", result, err, cleaned, guardCalls)
				}
			})
		}
	}
}

func TestNodeScreenResourceBookendPreservesCancellation(t *testing.T) {
	checker := fakeExactNodeChecker(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	checker.resolve = func(context.Context, string) ([]netip.Addr, error) {
		cancel()
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}
	result, decided, err := checker.ScreenTransport(ctx, checkedNodeRequest())
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrNodeResourceDenied) || decided || result.Stage != "canceled" || result.ErrorCode != "node-check-canceled" || result.Available || result.Verdict != evidence.VerdictInconclusive || len(checker.gate) != checker.Capacity() {
		t.Fatal("transport screen fabricated a resource refusal", result, decided, err)
	}
}

func TestNodeResourceObservationGuardDeadlineRemainsActualDenial(t *testing.T) {
	for _, screen := range []bool{false, true} {
		checker := fakeExactNodeChecker(t)
		ctx := WithNodeResourceGuard(context.Background(), func(context.Context, string, netip.Addr) error { return context.DeadlineExceeded })
		calls := 0
		checker.resolve = func(context.Context, string) ([]netip.Addr, error) { calls++; return nil, nil }
		var result NodeCheckResult
		var err error
		if screen {
			var decided bool
			result, decided, err = checker.ScreenTransport(ctx, checkedNodeRequest())
			if decided {
				t.Fatal("guard timeout acquired transport decision authority")
			}
		} else {
			result, err = checker.Check(ctx, checkedNodeRequest())
		}
		if !errors.Is(err, ErrNodeResourceDenied) || !errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil || calls != 0 || result.Stage != "resource_scope" || result.ErrorCode != "node-resource-refused" || result.Available || result.Verdict != evidence.VerdictInconclusive {
			t.Fatal("guard's own timeout bypassed its actual resource refusal", result, err, calls)
		}
	}
}

func TestNodeCheckCanceledCleanupFailureRetainsFenceAndPriority(t *testing.T) {
	checker := fakeExactNodeChecker(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	checker.proxyEgress = func(context.Context, string) (string, error) { cancel(); return "", context.Canceled }
	cleaned := 0
	checker.cleanup = func(cleanupCtx context.Context, _ exactNodeSession) error {
		cleaned++
		if cleanupCtx.Err() != nil {
			t.Fatal("cleanup inherited probe cancellation")
		}
		return errors.New("owned process remained")
	}
	result, err := checker.Check(ctx, checkedNodeRequest())
	if !errors.Is(err, context.Canceled) || cleaned != 1 || result.Stage != "cleanup" || result.ErrorCode != "node-cleanup-failed" || result.Available || result.Evidence.AssuranceLevel().AtLeast(evidence.Service) || !checker.poisoned.Load() || len(checker.gate) != checker.Capacity() {
		t.Fatal("cancellation hid cleanup failure or lost its fence", result, err, cleaned)
	}
	if _, err := checker.Check(context.Background(), checkedNodeRequest()); !errors.Is(err, ErrExactNodeUnavailable) {
		t.Fatal("cleanup failure allowed the next checker", err)
	}
}
