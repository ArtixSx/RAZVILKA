package app

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestListScopeOriginalPhysicalFailureKeepsExactSafeSubstage(t *testing.T) {
	a, binding, physical := listScopeFixture(t, "mac", false)
	// Physical verification is the explicit existing model. Original actual
	// Store/control/admission are used and no native/source PASS is fabricated.
	cause := errors.New("private modeled physical cause with secret")
	physical.verifyErr = cause
	listScopeOperation(t, a, func(ctx context.Context) {
		_, err := binding.Observe(ctx)
		stage, reason := managedNFQFailureDiagnostic(err)
		if stage != "scope-physical-verify" || reason != "ORIGINAL_SCOPE_CHANGED" || !errors.Is(err, cause) || !errors.Is(err, ErrListScopeChanged) || strings.Contains(err.Error(), "secret") {
			t.Fatal("original scope cause lost or diagnostic leaked", stage, reason)
		}
	})
}
