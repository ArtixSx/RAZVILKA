package dataplane

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestNFQDirectRetirementProofReportsExactRefusalWithoutReleasingOwners(t *testing.T) {
	for _, stage := range []string{"nfq-absence", "consumer-retire-check", "backend-inventory", "rpdb-absence"} {
		t.Run(stage, func(t *testing.T) {
			f := newPreEffectLANFixture(t)
			w := f.activateLANThenRefuseNFQ(t)
			private := errors.New("private-command-path-and-owner")
			refusal := errors.Join(private, context.DeadlineExceeded)
			switch stage {
			case "nfq-absence":
				w.observe = func(context.Context) error { return refusal }
			case "consumer-retire-check":
				f.e.lanFrozen.RetireCheck = func(context.Context, *LANPolicyRuntimePlan) error { return refusal }
			case "backend-inventory":
				f.e.gateInventoryCheck = func(context.Context) error { return refusal }
			case "rpdb-absence":
				f.model.rpdb = "private-unrecognized-rpdb-image"
			}
			err := f.e.gate.Rollback(f.nextCycle(), f.e.plan, f.root)
			var diagnostic *nfqwsDirectRetirementDiagnostic
			if !errors.As(err, &diagnostic) || diagnostic.stage != stage {
				t.Fatalf("proof cause or stage lost: %v", err)
			}
			if stage != "rpdb-absence" && (!errors.Is(err, private) || !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), stage+" deadline")) {
				t.Fatal("wrapped proof cause or deadline classification lost")
			}
			if strings.Contains(err.Error(), private.Error()) || strings.Contains(err.Error(), f.model.rpdb) {
				t.Fatal("diagnostic lost stage or exposed private error")
			}
			if owner, status := directPreparationState(t, f); !owner || !status.Complete || status.Removed || f.e.directPreparation != w {
				t.Fatal("diagnostic refusal released original metadata owner")
			}
		})
	}
}
