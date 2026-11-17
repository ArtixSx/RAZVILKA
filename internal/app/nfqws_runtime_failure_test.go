package app

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func TestManagedNFQRuntimeDiagnosticPreservesCauseAndSanitizesPresentation(t *testing.T) {
	secret := errors.New("private native path and argv with secret")
	for _, test := range []struct {
		cause  error
		reason string
	}{
		{errors.Join(secret, context.DeadlineExceeded), "DEADLINE_EXCEEDED"},
		{errors.Join(secret, ErrListScopeChanged), "ORIGINAL_SCOPE_CHANGED"},
		{errors.Join(secret, fs.ErrPermission), "SOURCE_PERMISSION"},
		{errors.Join(secret, ErrDefaultRouteCapability), "COMPILED_CAPABILITY_REFUSED"},
		{errors.Join(secret, dataplane.ErrNFQWSScopedOwner), "NATIVE_OWNER_REFUSED"},
		{errors.Join(secret, dataplane.ErrLANPolicyRuntime), "LAN_GATE_REFUSED"},
	} {
		err := managedNFQFailureAt("physical-observe", test.cause)
		stage, reason := managedNFQFailureDiagnostic(err)
		if stage != "physical-observe" || reason != test.reason || !errors.Is(err, secret) || strings.Contains(err.Error()+stage+reason, "secret") {
			t.Fatal("cause lost or diagnostic leaked", stage, reason)
		}
		wrapped := managedNFQFailureAt("outer-apply", err)
		if got, _ := managedNFQFailureDiagnostic(wrapped); got != stage {
			t.Fatal("original failed stage replaced", got)
		}
	}
}

func TestManagedNFQRuntimeDiagnosticReportsActualClosedLANPreflightStage(t *testing.T) {
	cause := (&dataplane.LANPolicyRuntime{}).Preflight(context.Background(), nil)
	err := managedNFQFailureAt("native-apply", cause)
	stage, reason := managedNFQFailureDiagnostic(err)
	if stage != "lan-preflight-runtime-plan" || reason != "LAN_GATE_REFUSED" || !errors.Is(err, dataplane.ErrLANPolicyRuntime) {
		t.Fatal("actual LAN branch hidden by outer operation", stage, reason, err)
	}
}

// Models timer delivery lag while preserving an actual original cleanup owner.
type nfqDiagnosticUndeliveredDeadline struct {
	context.Context
	deadline time.Time
}

func (c nfqDiagnosticUndeliveredDeadline) Deadline() (time.Time, bool) { return c.deadline, true }
func (nfqDiagnosticUndeliveredDeadline) Err() error                    { return nil }

func TestManagedNFQRuntimeDiagnosticExpiredCleanupBeforeContextDelivery(t *testing.T) {
	var gate operationgate.Gate
	owner, release, err := gate.ExclusiveContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	cleanup, err := gate.ReviewExclusiveCleanup(owner)
	if err != nil {
		t.Fatal(err)
	}
	expired := nfqDiagnosticUndeliveredDeadline{context.Background(), time.Now().Add(-time.Second)}
	cause := cleanup.WithCurrent(expired, func() error { t.Fatal("expired callback ran"); return nil })
	wrapped := managedNFQFailureAt("native-apply", errors.Join(dataplane.ErrNFQWSScopedOwner, cause))
	stage, reason := managedNFQFailureDiagnostic(wrapped)
	if stage != "native-apply" || reason != "DEADLINE_EXCEEDED" || !errors.Is(wrapped, operationgate.ErrBusy) || !errors.Is(wrapped, dataplane.ErrNFQWSScopedOwner) {
		t.Fatalf("deadline hidden: %s %s %v", stage, reason, wrapped)
	}
	release()
	live, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cause = cleanup.WithCurrent(live, func() error { t.Fatal("released callback ran"); return nil })
	_, reason = managedNFQFailureDiagnostic(managedNFQFailureAt("native-apply", cause))
	if cause != operationgate.ErrBusy || reason != "OPERATION_BUSY" || errors.Is(cause, context.DeadlineExceeded) {
		t.Fatalf("actual busy hidden: %s %v", reason, cause)
	}
}
