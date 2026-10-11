package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

func refuseSelfUpdateRuntimeQuiesce(stage string) int {
	fmt.Fprintln(os.Stderr, updatecheck.RuntimeQuiesceFailureOutput(stage))
	return 3
}

// Read only the actual causal chain returned by the sole Manager observation.
// No Error text, adapter ID, PID, path or new observation enters the diagnostic.
func selfUpdateRuntimeInactiveFailureStage(err error) string {
	var reasons updatecheck.RuntimeQuiesceInactiveReasons
	for _, reason := range []struct {
		cause error
		bit   updatecheck.RuntimeQuiesceInactiveReasons
	}{{context.DeadlineExceeded, updatecheck.QuiesceInactiveDeadline}, {context.Canceled, updatecheck.QuiesceInactiveCanceled},
		{dataplane.ErrScopedDNSRuntimeInactive, updatecheck.QuiesceInactiveScopedDNS}, {dataplane.ErrProxyRuntimeInactive, updatecheck.QuiesceInactiveProxy},
		{dataplane.ErrNFQWSManagedProcessUnknown, updatecheck.QuiesceInactiveNFQProcess}, {dataplane.ErrNFQWSManagedKernelOwner, updatecheck.QuiesceInactiveNFQKernel}} {
		if errors.Is(err, reason.cause) {
			reasons |= reason.bit
		}
	}
	return updatecheck.RuntimeQuiesceInactiveObservationFailureStage(reasons, dataplane.ScopedDNSRuntimeInactiveStage(err), updatecheck.OrdinaryInstallerControllerFailureStage(err))
}
