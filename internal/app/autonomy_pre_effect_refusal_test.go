package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func TestAutonomyActualNFQSnapshotRefusalReturnsOnlyCurrentReservation(t *testing.T) {
	m := dataplane.New(filepath.Join(t.TempDir(), "dataplane"))
	a := dataplane.NewNFQWS2Adapter()
	if err := m.Register(a); err != nil {
		t.Fatal(err)
	}
	// Real NFQ snapshot reads a foreign/malformed ownership manifest. It must
	// refuse before any command or live mutation, not compensate that owner.
	if err := os.MkdirAll(a.StateRoot, 0700); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(a.StateRoot, "ownership.json")
	before := []byte(`{"foreign":true}`)
	if err := os.WriteFile(manifest, before, 0600); err != nil {
		t.Fatal(err)
	}
	plan := dataplane.Plan{SchemaVersion: dataplane.SchemaVersion, PlanID: "dp-autonomy-preflight", Digest: strings.Repeat("a", 64), Ready: true, Adapters: []string{"nfqws2"}}
	x, err := m.Apply(context.Background(), plan, nil)
	if err == nil || x.State != "canary-failed" || len(x.Steps) != 1 || x.Steps[0].Phase != "snapshot" {
		t.Fatalf("fixture did not reach the actual read-only NFQ snapshot refusal: %+v %v", x, err)
	}
	previous := time.Now().Add(-time.Minute)
	r := autonomy.Runtime{Switches: []time.Time{previous}}
	if !r.ReserveSwitch(time.Now(), 6) {
		t.Fatal("reserve")
	}
	state, message := autonomyLegacyApplyRefused(&autonomyApplyFailure{Plan: plan, Execution: x, Cause: err}, &r, "attempted rollback")
	after, readErr := os.ReadFile(manifest)
	if state != "apply-refused" || len(r.Switches) != 1 || !r.Switches[0].Equal(previous) || strings.Contains(message, "откат") || readErr != nil || string(after) != string(before) {
		t.Fatal("preflight consumed a switch, claimed rollback or changed foreign ownership", r.Switches, message, readErr)
	}
}

func TestAutonomyActualPostWriteFailureKeepsReservation(t *testing.T) {
	for _, phase := range []string{"activate", "health", "stage"} {
		t.Run(phase, func(t *testing.T) {
			m := dataplane.New(filepath.Join(t.TempDir(), "dataplane"))
			written := filepath.Join(t.TempDir(), "attempted-effect")
			failure := errors.New("post-write result is unknown")
			adapter := &serviceRuntimeAdapter{nodeApplyAdapter: &nodeApplyAdapter{after: func(current string) error {
				if current == phase {
					if err := os.WriteFile(written, []byte("effect attempted"), 0600); err != nil {
						return err
					}
					return failure
				}
				return nil
			}}, name: "nfqws2"}
			if err := m.Register(adapter); err != nil {
				t.Fatal(err)
			}
			plan := dataplane.Plan{SchemaVersion: dataplane.SchemaVersion, PlanID: "dp-autonomy-postwrite", Digest: strings.Repeat("b", 64), Ready: true, Adapters: []string{"nfqws2"}}
			x, err := m.Apply(context.Background(), plan, nil)
			if !errors.Is(err, failure) {
				t.Fatal("fixture did not reach the post-write error", x, err)
			}
			if _, err := os.Stat(written); err != nil {
				t.Fatal("fixture did not attempt its effect", err)
			}
			r := autonomy.Runtime{}
			if !r.ReserveSwitch(time.Now(), 6) {
				t.Fatal("reserve")
			}
			state, message := autonomyLegacyApplyRefused(&autonomyApplyFailure{Plan: plan, Execution: x, Cause: err}, &r, "attempted rollback")
			if state != "apply-refused" || len(r.Switches) != 1 || message != "attempted rollback" {
				t.Fatal("post-write/unknown phase failure lost its reservation", x, r, message)
			}
		})
	}
}
