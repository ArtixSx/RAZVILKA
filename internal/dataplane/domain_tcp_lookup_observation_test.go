package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

func TestDomainLookupObservationResultBookends(t *testing.T) {
	for _, mode := range []string{"success", "zero", "double", "swallowed", "closing", "nil-result", "canceled", "late"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			bodyFailure, closingFailure := errors.New("body refused"), errors.New("closing refused")
			want := &dnscontrol.SyntheticDNSMapping{}
			calls := 0
			var late func(context.Context) error
			observe := func(observed context.Context, fn func(context.Context) error) error {
				if mode == "zero" || mode == "late" {
					late = fn
					return nil
				}
				err := fn(observed)
				if mode == "double" {
					_ = fn(observed) // even a swallowed duplicate invalidates the result
				}
				if mode == "swallowed" {
					return nil
				}
				if mode == "closing" {
					return closingFailure
				}
				if mode == "canceled" {
					cancel()
				}
				return err
			}
			got, err := domainTCPLookupObservedResult(ctx, observe, func(context.Context) (*dnscontrol.SyntheticDNSMapping, error) {
				calls++
				if mode == "swallowed" {
					return want, bodyFailure
				}
				if mode == "nil-result" {
					return nil, nil
				}
				return want, nil
			})
			if mode == "success" {
				if err != nil || got != want || calls != 1 {
					t.Fatal("successful result changed", err, calls)
				}
				return
			}
			if err == nil || got != nil || calls > 1 {
				t.Fatal("invalid observer published mapping", err, calls)
			}
			if mode == "swallowed" && !errors.Is(err, bodyFailure) {
				t.Fatal("body error lost", err)
			}
			if mode == "closing" && !errors.Is(err, closingFailure) {
				t.Fatal("closing error lost", err)
			}
			if late != nil && (late(ctx) == nil || calls != 0) {
				t.Fatal("late callback entered body", calls)
			}
		})
	}
}

func TestDomainLookupObservationConcurrentCallbackCannotRepeatBody(t *testing.T) {
	ctx := context.Background()
	entered, release, joined := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	calls := 0
	got, err := domainTCPLookupObservedResult(ctx, func(ctx context.Context, fn func(context.Context) error) error {
		go func() { joined <- fn(ctx) }()
		<-entered
		duplicate := fn(ctx)
		close(release)
		first := <-joined // original callback joined before observer returns
		if duplicate == nil || first != nil {
			t.Error("callback admission changed", duplicate, first)
		}
		return nil // swallowing duplicate failure cannot grant success
	}, func(context.Context) (*dnscontrol.SyntheticDNSMapping, error) {
		calls++
		close(entered)
		<-release
		return &dnscontrol.SyntheticDNSMapping{}, nil
	})
	if got != nil || err == nil || calls != 1 {
		t.Fatal("duplicate callback changed result", err, calls)
	}
}

func TestDomainLookupObservationRejectsChangedClosingSources(t *testing.T) {
	for _, mode := range []string{"resolver", "material", "mapping", "prepared", "source", "scope", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			f, kernel, runner, mapping := mappingReadSourcesFixture(t)
			resolver := &dnscontrol.NetworkPolicyDNSSyntheticResolver{}
			f.material.dnsSource = resolver
			s := &domainTCPLookupReadSources{mapping: mapping, resolver: resolver}
			if err := s.current(f.ctx, f.owner, f.process, kernel.capture.mapping); err != nil {
				t.Fatal("opening local identity", err)
			}
			switch mode {
			case "resolver":
				f.material.dnsSource = &dnscontrol.NetworkPolicyDNSSyntheticResolver{}
			case "material":
				f.process.material = &XrayDomainTCPOperationMaterial{}
			case "mapping":
				f.material.mapping = &dnscontrol.SyntheticDNSMapping{}
			case "prepared":
				f.owner.prepared = &DomainPolicyTCPCaptureMapping{}
			case "source":
				f.owner.source = &baselineCurrentComparisonRunner{}
			case "scope":
				f.process.scope = &executionResourceScope{}
			case "cancel":
				f.cancel()
			}
			if s.current(f.ctx, f.owner, f.process, kernel.capture.mapping) == nil {
				t.Fatal("changed closing source admitted", mode)
			}
			if runner.calls != 0 {
				t.Fatal("local comparison reached external source")
			}
		})
	}
}

func TestDomainLookupObservationInvalidOrCanceledCannotPublishMapping(t *testing.T) {
	f, _, runner, _ := mappingReadSourcesFixture(t)
	f.material.dnsSource = &dnscontrol.NetworkPolicyDNSSyntheticResolver{}
	for _, canceled := range []bool{false, true} {
		if canceled {
			f.cancel()
		}
		mapping, err := f.owner.lookupPublishedInOriginalToolObservation(f.ctx, f.process, netip.Addr{}, netip.Addr{})
		if err == nil || mapping != nil {
			t.Fatal("unowned/canceled lookup published mapping", canceled)
		}
		if runner.calls != 0 {
			t.Fatal("unowned lookup reached external observer")
		}
	}
}

func TestDomainLookupObservationPreservesCleanupAndCustomRefusal(t *testing.T) {
	for _, mode := range []string{"baseline-cleanup", "capture-cleanup", "failure-cleanup", "custom-source", "missing-kernel"} {
		t.Run(mode, func(t *testing.T) {
			f, kernel, runner, _ := mappingReadSourcesFixture(t)
			f.material.dnsSource = &dnscontrol.NetworkPolicyDNSSyntheticResolver{}
			ctx := f.ctx
			switch mode {
			case "baseline-cleanup":
				ctx = context.WithValue(ctx, domainTCPBaselineCleanupKey{}, "foreign")
			case "capture-cleanup":
				ctx = context.WithValue(ctx, domainTCPCaptureCleanupKey{}, "foreign")
			case "failure-cleanup":
				ctx = context.WithValue(ctx, domainTCPFailureCleanupKey{}, "foreign")
			case "custom-source":
				kernel.capture.backend.reader.Runner = &baselineCurrentUnobservedRunner{}
			case "missing-kernel":
				f.owner.kernel = nil
			}
			before, beforeErr := f.owner.lookupPublishedRead(ctx, f.process, netip.Addr{}, netip.Addr{})
			after, afterErr := f.owner.lookupPublishedInOriginalToolObservation(ctx, f.process, netip.Addr{}, netip.Addr{})
			if beforeErr == nil || afterErr == nil || beforeErr.Error() != afterErr.Error() || before != after || runner.calls != 0 {
				t.Fatal("original fallback changed", beforeErr, afterErr)
			}
		})
	}
}
