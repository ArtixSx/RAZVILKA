package app

import (
	"context"
	"errors"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"net"
	"os"
	"testing"
)

func domainOriginalNativeService() catalog.Service {
	return catalog.Service{ID: "service", Name: "Original native domain service", Category: "fixture", Domains: []string{"service.example.com"}, Strategy: []string{"xray"}, ProbeURL: "https://service.example.com/", Probes: []catalog.Probe{{ID: "primary", Label: "Native TLS service", URL: "https://service.example.com/", Required: true, Expect: catalog.ProbeExpectation{StatusCodes: []int{200}, BodyContains: []string{"native-domain-service"}}}}}
}

// Whole-join errors.Is would hide unrelated native cleanup errors. Consume
// only cancellation, the actual listener close, and explicit standby pending.
func domainOriginalExpectedStopError(err error) bool {
	if !errors.Is(err, context.Canceled) || !errors.Is(err, dnscontrol.ErrSyntheticDNSTransitionPending) {
		return false
	}
	var allowed func(error) bool
	allowed = func(current error) bool {
		if current == nil {
			return true
		}
		if joined, ok := current.(interface{ Unwrap() []error }); ok {
			for _, child := range joined.Unwrap() {
				if !allowed(child) {
					return false
				}
			}
			return true
		}
		if wrapped, ok := current.(interface{ Unwrap() error }); ok {
			return allowed(wrapped.Unwrap())
		}
		return current == context.Canceled || current == net.ErrClosed || current == dnscontrol.ErrSyntheticDNSTransitionPending
	}
	return allowed(err)
}

func TestDomainOriginalNativeStopNeverSwallowsUnexpectedFailure(t *testing.T) {
	expected := errors.Join(context.Canceled, &net.OpError{Op: "accept", Net: "tcp", Err: net.ErrClosed}, dnscontrol.ErrSyntheticDNSTransitionPending)
	if !domainOriginalExpectedStopError(expected) {
		t.Fatal("expected original close/pending refusal rejected")
	}
	if domainOriginalExpectedStopError(errors.Join(expected, errors.New("unrelated original cleanup failed"))) || domainOriginalExpectedStopError(context.Canceled) {
		t.Fatal("unexpected failure or missing original standby sentinel hidden")
	}
}

func domainOriginalDNSRefusalTimeout(mode string, err error) bool {
	if mode != "dns-unready" && mode != "dns-wait" && mode != "dns-other-client" {
		return false
	}
	return errors.Is(err, os.ErrDeadlineExceeded) && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
}

func TestDomainOriginalDNSRefusalDoesNotBecomePublication(t *testing.T) {
	timeout := &net.OpError{Op: "read", Net: "udp4", Err: os.ErrDeadlineExceeded}
	for _, mode := range []string{"dns-unready", "dns-wait", "dns-other-client"} {
		if !domainOriginalDNSRefusalTimeout(mode, timeout) {
			t.Fatal("bounded negative DNS refusal rejected", mode)
		}
	}
	for _, mode := range []string{"dns", "selected", "mismatch", "opaque"} {
		if domainOriginalDNSRefusalTimeout(mode, timeout) {
			t.Fatal("positive transport timeout was accepted", mode)
		}
	}
	for _, err := range []error{context.Canceled, context.DeadlineExceeded, errors.New("unexpected UDP transport failure")} {
		if domainOriginalDNSRefusalTimeout("dns-wait", err) {
			t.Fatal("unexpected/canceled caller hidden", err)
		}
	}
}

// The native check and the sealed route predicate have different entry points;
// validate their actual shared catalog contract before expensive native setup.
func TestDomainOriginalNativeCatalogContract(t *testing.T) {
	service := domainOriginalNativeService()
	if err := catalog.Validate(catalog.Catalog{Services: []catalog.Service{service}}); err != nil {
		t.Fatal(err)
	}
	frozen, err := dataplane.FrozenProbeService(dataplane.Route{LogicalServiceID: service.ID, ProbeURL: service.ProbeURL, ProbeService: &service})
	if err != nil || frozen.Probes[0].Expect.BodyContains[0] != "native-domain-service" {
		t.Fatal("native fixture lost exact sealed service predicate", err)
	}
}
