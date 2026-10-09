package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/dataplane"
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

func TestListScopeBindRefusalIdentifiesOriginalInfrastructureMembership(t *testing.T) {
	a, binding, _ := listScopeFixture(t, "all", true)
	listScopeOperation(t, a, func(ctx context.Context) {
		compiled := listScopeCompilation(t, ctx, a, binding)
		gate := compiled.LAN().Ingress
		gate[0].ExcludedMACs = nil
		var err error
		compiled.lan, err = dataplane.CompileLANPolicyRuntime(compiled.Digest(), gate)
		if err != nil {
			t.Fatal(err)
		}
		err = binding.BindCompilation(ctx, compiled)
		stage, reason := managedNFQFailureDiagnostic(err)
		if stage != "bind-router-membership" || reason != "ORIGINAL_SCOPE_CHANGED" || !errors.Is(err, ErrListScopeChanged) || binding.boundOnce {
			t.Fatal("infrastructure refusal lost or bound", stage, reason)
		}
	})
}

func TestListScopeRouterIdentityMatchesCanonicalIncludedAndExcludedMACs(t *testing.T) {
	for _, test := range []struct {
		name, included, excluded string
		allow                    bool
	}{
		{"excluded lower", "", "02:00:00:00:00:ff", true},
		{"excluded upper", "", "02:00:00:00:00:FF", true},
		{"included lower", "02:00:00:00:00:ff", "", false},
		{"included upper", "02:00:00:00:00:FF", "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			a, binding, _ := listScopeFixture(t, "all", true)
			listScopeOperation(t, a, func(ctx context.Context) {
				compiled := listScopeCompilation(t, ctx, a, binding)
				// A normalized gate definition is a comparison model only;
				// this unit exercises the real binding's negative check and
				// never issues a kernel/native execution permission or proof.
				gate := compiled.LAN().Ingress
				gate[0].ExcludedMACs = nil
				if test.excluded != "" {
					gate[0].ExcludedMACs = defaultRouteLANMACs([]string{test.excluded})
				}
				if test.included != "" {
					gate[0].Membership = "mac"
					gate[0].IncludedMACs = defaultRouteLANMACs([]string{test.included})
				}
				var err error
				compiled.lan, err = dataplane.CompileLANPolicyRuntime(compiled.Digest(), gate)
				if err != nil {
					t.Fatal(err)
				}
				err = binding.BindCompilation(ctx, compiled)
				if (err == nil) != test.allow {
					t.Fatal("canonical router identity changed admission", err)
				}
			})
		})
	}
}
