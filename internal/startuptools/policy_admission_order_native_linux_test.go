//go:build linux && (amd64 || arm64)

package startuptools

import (
	"context"
	"errors"
	"os"
	"testing"
)

// Use the original production lease so the admission-order regression passes
// through the real tool gate, Provider and held-fd review. The owner deliberately
// refuses without calling begin; this test never launches a policy mutation.
func TestProductionPolicyAdmissionHoldsToolGateNative(t *testing.T) {
	mode := os.Getenv("RAZVILKA_STARTUP_TOOLS_NATIVE")
	if mode == "" {
		t.Skip("Root production startup tools native fixture opt-in disabled")
	}
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	setup, setupCancel := context.WithTimeout(lifetime, operationTimeout)
	provider := nativeProvider(t, setup, mode)
	setupCancel()
	var lease *Lease
	var err error
	if mode == "stock-nc1812" {
		lease, err = AcquireReviewedStockNC1812Policy(lifetime, provider)
	} else {
		lease, err = AcquireUbuntuLegacyPolicy(lifetime, provider)
	}
	if err != nil {
		t.Fatal("production policy acquisition refused: stages=", nativeStages(err))
	}
	defer lease.Close()
	tools, runner, err := lease.PolicyRuntimeTools()
	if err != nil {
		t.Fatal(err)
	}

	refusal := errors.New("admission-order fixture refuses actual Start")
	calls := 0
	var original context.Context
	owner := admissionFunc(func(ctx context.Context, _ string, _ []string, _ string, _ func() error) error {
		calls++
		if ctx != original {
			return errors.New("admission replaced the original context")
		}
		// Inspect only the private gate token. Do not reenter tool/provider
		// readers from the admission owner: the gate is already held here.
		select {
		case token := <-lease.gate:
			lease.gate <- token
			return errors.New("admission preceded the production tool lock")
		default:
		}
		return refusal
	})
	request, requestCancel := context.WithTimeout(lifetime, operationTimeout)
	defer requestCancel()
	original = WithCommandAdmission(request, owner)
	data, err := runner.Run(original, tools.IPTables, "-t", "mangle", "-N", "RZG_admission_order_native")
	if calls != 1 || !errors.Is(err, refusal) || !errors.Is(err, ErrUnknown) || len(data) != 0 {
		t.Fatalf("actual admission must hold the gate and preserve refusal: calls=%d stages=%s bytes=%d", calls, nativeStages(err), len(data))
	}
}
