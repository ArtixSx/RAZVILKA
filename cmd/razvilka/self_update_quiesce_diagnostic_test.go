package main

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

type quiesceDiagnosticPrivateError struct{}

func (quiesceDiagnosticPrivateError) Error() string { panic("raw private error was inspected") }

func TestRuntimeQuiesceInactiveDiagnosticUsesOnlyActualClosedCauses(t *testing.T) {
	private := quiesceDiagnosticPrivateError{}
	for _, tc := range []struct {
		cause error
		want  string
	}{{nil, "runtime-inactivity"}, {private, "runtime-inactivity"}, {dataplane.ErrRuntimeInactivity, "runtime-inactivity"},
		{errors.Join(private, context.DeadlineExceeded), "runtime-inactivity-deadline"},
		{errors.Join(private, context.Canceled), "runtime-inactivity-canceled"},
		{errors.Join(private, dataplane.ErrScopedDNSRuntimeInactive), "runtime-inactivity-scoped-dns"},
		{errors.Join(private, dataplane.ErrProxyRuntimeInactive), "runtime-inactivity-proxy"},
		{errors.Join(private, dataplane.ErrNFQWSManagedProcessUnknown), "runtime-inactivity-nfq-process"},
		{errors.Join(private, dataplane.ErrNFQWSManagedKernelOwner), "runtime-inactivity-nfq-kernel"},
		{errors.Join(private, dataplane.ErrRuntimeInactivity, fmt.Errorf("fixed owner: %w", dataplane.ErrNFQWSManagedKernelOwner), dataplane.ErrScopedDNSRuntimeInactive, context.DeadlineExceeded), "runtime-inactivity-deadline-scoped-dns-nfq-kernel"}} {
		if got := selfUpdateRuntimeInactiveFailureStage(tc.cause); got != tc.want {
			t.Fatal("actual closed cause was lost", got, tc.want)
		}
		if output := updatecheck.RuntimeQuiesceFailureOutput(tc.want); output != "runtime quiesce refused; category="+tc.want {
			t.Fatal("fixed diagnostic was not admitted", output)
		}
	}
	misleading := errors.New("runtime-inactivity-scoped-dns nfq-kernel context deadline exceeded secret/PID/token")
	if selfUpdateRuntimeInactiveFailureStage(misleading) != "runtime-inactivity" {
		t.Fatal("private error text forged a causal owner")
	}
}

func TestRuntimeQuiesceInactiveDiagnosticUsesOriginalDNSObservation(t *testing.T) {
	var owner *dataplane.ScopedDNSAdapter
	// The actual public negative source branch supplies the private stage;
	// neither arbitrary Error text nor this diagnostic grants an observer.
	cause := errors.Join(quiesceDiagnosticPrivateError{}, owner.VerifyRuntimeInactive(context.Background()), context.DeadlineExceeded, dataplane.ErrNFQWSManagedKernelOwner)
	want := "runtime-inactivity-deadline-scoped-dns-nfq-kernel-dns-observation-source"
	if got := selfUpdateRuntimeInactiveFailureStage(cause); got != want {
		t.Fatal("actual DNS observation or other joined causal bit was lost", got)
	}
	if updatecheck.RuntimeQuiesceFailureOutput(want) != "runtime quiesce refused; category="+want {
		t.Fatal("original closed observation was refused by the sole output formatter")
	}
}
