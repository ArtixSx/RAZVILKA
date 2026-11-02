//go:build linux

package dataplane

import (
	"context"
	"encoding/json"
	"github.com/ArtixSx/razvilka/internal/privaterestore"
	"os"
	"testing"
)

// Actual held input files and absent-name bookends. Historical candidate is a
// comparison model, not a native admission or process/kernel absence proof.
func TestMihomoSameBootCandidateRetainsBothPlanAbsences(t *testing.T) {
	sameBootInputsFixture(t, func(ctx context.Context, set *privaterestore.OfflineServiceControlSet, state string, e Execution) {
		i, err := holdMihomoSameBootInputs(ctx, set, state, e.PlanID, e.Digest)
		if err != nil {
			t.Fatal(err)
		}
		defer i.close()
		i.candidate = true // Exact typed candidate input is independently tested.
		c := &mihomoSameBootRetirementCursor{owner: &mihomoSameBootCleanup{inputs: i}}
		if err := c.capturePlans(); err != nil {
			t.Fatal("genuine initial absence refused", err)
		}
		if len(c.intent.Plans) != 0 || len(c.plans) != 0 {
			t.Fatal("missing plans synthesized")
		}
		if validateMihomoSameBootPlans(i.definition.Plan, c.intent.Plans, false) == nil {
			t.Fatal("committed lane weakened")
		}
		for _, name := range mihomoStoppedPlanNames {
			if err := i.roots[0].WriteFile(name, []byte("appeared"), 0600); err != nil {
				t.Fatal(err)
			}
			if c.plansCurrent() == nil {
				t.Fatal("late plan appearance ignored", name)
			}
			if err := i.roots[0].Remove(name); err != nil {
				t.Fatal(err)
			}
		}
		if err := c.plansCurrent(); err != nil {
			t.Fatal(err)
		}
		for _, name := range mihomoStoppedPlanNames {
			if _, err := i.roots[0].Lstat(name); !os.IsNotExist(err) {
				t.Fatal("recovery wrote missing plan", name, err)
			}
		}
	})
}

func TestMihomoSameBootCommittedPlanCaptureStillPinsPresentAndAbsentNames(t *testing.T) {
	sameBootInputsFixture(t, func(ctx context.Context, set *privaterestore.OfflineServiceControlSet, state string, e Execution) {
		i, err := holdMihomoSameBootInputs(ctx, set, state, e.PlanID, e.Digest)
		if err != nil {
			t.Fatal(err)
		}
		defer i.close()
		plan, err := json.Marshal(i.definition.Plan)
		if err != nil {
			t.Fatal(err)
		}
		if err := i.roots[0].WriteFile("latest-plan.json", plan, 0600); err != nil {
			t.Fatal(err)
		}
		c := &mihomoSameBootRetirementCursor{owner: &mihomoSameBootCleanup{inputs: i}}
		defer func() {
			for _, r := range c.plans {
				if err := r.file.Close(); err != nil {
					t.Error(err)
				}
			}
		}()
		if err := c.plansCurrent(); err != nil {
			t.Fatal("opening source check incorrectly assumed missing before capture", err)
		}
		if err := c.capturePlans(); err != nil {
			t.Fatal("original committed plan refused", err)
		}
		if !c.plansCaptured || len(c.plans) != 1 {
			t.Fatal("original comparison not retained")
		}
		if err := i.roots[0].WriteFile("latest-committed-plan.json", plan, 0600); err != nil {
			t.Fatal(err)
		}
		if c.plansCurrent() == nil {
			t.Fatal("optional committed name appeared without refusal")
		}
		if err := i.roots[0].Remove("latest-committed-plan.json"); err != nil {
			t.Fatal(err)
		}
		if err := i.roots[0].WriteFile("foreign-plan", plan, 0600); err != nil {
			t.Fatal(err)
		}
		if err := i.roots[0].Rename("foreign-plan", "latest-plan.json"); err != nil {
			t.Fatal(err)
		}
		if c.plansCurrent() == nil {
			t.Fatal("same bytes foreign plan inode adopted")
		}
	})
}
