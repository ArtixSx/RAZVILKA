package strategylab

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Negative lifecycle model only: these values cannot pass real material or
// runtime verification and issue no process, queue or positive native proof.
func TestManagedProbeReferenceRejectsChangedOriginalOwnersBeforeObservation(t *testing.T) {
	for _, change := range []string{"source-copy", "epoch-copy", "foreign-runtime", "foreign-control", "closed-source", "completed", "unknown", "cancelled"} {
		t.Run(change, func(t *testing.T) {
			m, epoch := managedProbeSlotFixture(t)
			source := epoch.source
			source.self = source
			lease, control := &components.ManagedNFQWSRuntimeLease{}, &operationgate.ControlEpochReview{}
			source.material.runtime = lease
			source.material.binding.manager = m
			source.material.provider = &SupervisedCompatibilityProvider{managedControl: control}
			epoch.environment = managedProbeEnvironmentFunc(func(context.Context) error {
				t.Fatal("changed owner reached environment/material observation")
				return nil
			})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			switch change {
			case "source-copy":
				source = &CandidateProbeReview{self: source, material: source.material}
			case "epoch-copy":
				epoch = &ManagedProbeEpoch{self: epoch, manager: m, source: source, environment: epoch.environment, running: true}
			case "foreign-runtime":
				lease = &components.ManagedNFQWSRuntimeLease{}
			case "foreign-control":
				control = &operationgate.ControlEpochReview{}
			case "closed-source":
				source.closed = true
			case "completed":
				epoch.complete = true
			case "unknown":
				m.compatibilityUnknown = true
			case "cancelled":
				cancel()
			}
			err := epoch.WithProbeReferenceCurrent(ctx, source, lease, control, func(CandidateProbeReference) error {
				t.Fatal("changed owner reached kernel/effect observer")
				return nil
			})
			if !errors.Is(err, ErrSelectedCandidateChanged) {
				t.Fatal(err)
			}
		})
	}
}
