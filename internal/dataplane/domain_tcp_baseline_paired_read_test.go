package dataplane

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

func TestDomainOriginalKernelPairRejectsChangedAssociations(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, change := range []string{"backend", "network", "mapping", "different-capture", "different-successor", "expired"} {
		t.Run(change, func(t *testing.T) {
			backend := new(BackendInventory)
			identity := new(networkPolicyIdentity)
			mapping := new(dnscontrol.SyntheticDNSMapping)
			capture := &domainTCPCaptureExecutionResource{backend: backend, mapping: mapping, process: &XrayDomainTCPExecutionResource{scope: &executionResourceScope{networkIdentity: identity}}}
			capture.self = capture
			inspector := &syntheticBaselineKernelInspector{backend: backend, identity: identity, mapping: mapping}
			inspector.self = inspector
			inspector.capture.Store(capture)
			operation := ctx
			switch change {
			case "backend":
				capture.backend = new(BackendInventory)
			case "network":
				capture.process.scope.networkIdentity = new(networkPolicyIdentity)
			case "mapping":
				capture.mapping = new(dnscontrol.SyntheticDNSMapping)
			case "different-capture":
				inspector.capture.Store(&domainTCPCaptureExecutionResource{})
			case "different-successor":
				capture.process.scope.domainSuccessor = new(domainTCPGlobalSuccessor)
			case "expired":
				var stop context.CancelFunc
				operation, stop = context.WithCancel(ctx)
				stop()
			}
			compared := false
			err := inspector.comparePreparedWithCaptureInventory(operation, capture, &xrayDomainTCPFileObservation{}, func([]backendInventoryRow) error {
				compared = true
				return nil
			})
			if compared || !errors.Is(err, ErrSyntheticBaselineTransition) {
				t.Fatalf("foreign source reached the combined predicate: compared=%t err=%v", compared, err)
			}
		})
	}
}
