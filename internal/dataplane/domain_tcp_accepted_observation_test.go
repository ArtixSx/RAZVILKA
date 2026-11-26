package dataplane

import (
	"context"
	"errors"
	"testing"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

// Comparison-only objects cannot become an original accepted-flow/file scope.
// This covers refusal before touching a nil model socket/source, not success.
func TestDomainAcceptedGuardCannotMintOrRebindOriginalFlow(t *testing.T) {
	for _, kind := range []string{"no-resource", "copied-lease", "other-owner", "other-mapping", "other-prepared", "nil-context", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			o := &DomainTCPOriginalScope{}
			o.self = o
			c := &DomainPolicyTCPCapture{owner: o}
			c.self = c
			mapping := &dnscontrol.SyntheticDNSMapping{}
			p := &DomainPolicyTCPCaptureMapping{capture: c, source: mapping}
			p.self = p
			l := &domainTCPOriginalFlowLease{owner: o, mapping: mapping}
			l.self = l
			ctx := context.Background()
			switch kind {
			case "copied-lease":
				l.self = &domainTCPOriginalFlowLease{}
			case "other-owner":
				l.owner = &DomainTCPOriginalScope{}
			case "other-mapping":
				l.mapping = &dnscontrol.SyntheticDNSMapping{}
			case "other-prepared":
				p.capture = &DomainPolicyTCPCapture{}
			case "nil-context":
				ctx = nil
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			scope, err := c.guardPreparedFlow(ctx, mapping, p, l, DomainPolicyTCPSocket{})
			if !errors.Is(err, ErrDomainPolicyTCPConsumer) || !scope.FreshUntil.IsZero() {
				t.Fatal("comparison objects minted an accepted guard", kind, err)
			}
		})
	}
}

func TestDomainAcceptedGuardDecisionRefusesUnclosedOriginal(t *testing.T) {
	for _, variant := range []string{"modeled", "copied", "unprepared"} {
		t.Run(variant, func(t *testing.T) {
			o := &DomainTCPOriginalScope{}
			o.self = o
			c := &DomainPolicyTCPCapture{owner: o}
			c.self = c
			mapping := &dnscontrol.SyntheticDNSMapping{}
			prepared := &DomainPolicyTCPCaptureMapping{capture: c, source: mapping}
			prepared.self = prepared
			original := &domainTCPOriginalFlowLease{owner: o, mapping: mapping}
			original.self = original
			var lease DomainPolicyTCPFlowLease = original
			switch variant {
			case "modeled":
				lease = &acceptedPrefixTestLease{}
			case "copied":
				original.self = &domainTCPOriginalFlowLease{}
			}
			scope, err := c.guardPreparedFlowThen(context.Background(), mapping, prepared, lease, DomainPolicyTCPSocket{}, func(context.Context, autonomy.ScopeObservation, *xrayDomainTCPFileObservation) error {
				t.Fatal("unclosed guard supplied scope to decision")
				return nil
			})
			if !errors.Is(err, ErrDomainPolicyTCPConsumer) || !scope.FreshUntil.IsZero() {
				t.Fatalf("unclosed guard returned scope %+v or wrong error %v", scope, err)
			}
		})
	}
}
