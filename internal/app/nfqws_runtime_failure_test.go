package app

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/dataplane"
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
	if stage != "lan-preflight-scope-open" || reason != "LAN_GATE_REFUSED" || !errors.Is(err, dataplane.ErrLANPolicyRuntime) {
		t.Fatal("actual LAN branch hidden by outer operation", stage, reason, err)
	}
}
