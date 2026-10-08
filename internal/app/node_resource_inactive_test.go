package app

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/evidence"
)

func TestNodeResourceInactiveManualActualCASStopsCandidateWithoutScopeGrant(t *testing.T) {
	for _, match := range []config.ResourceMatch{{Kind: "service", Value: "telegram"}, {Kind: "exact", Value: "telegram.org"}} {
		t.Run(match.Kind, func(t *testing.T) {
			a, id, adapter := nodeApplyFixture(t)
			before := a.Store.Get()
			manual := []config.ResourceMatch{match}
			cfg, err := a.Store.UpdateResourceExclusions(context.Background(), before, &manual, nil)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.NetworkPolicy != nil || cfg.DefaultRouteConsent != nil || cfg.InactiveResourceExclusions == nil || !reflect.DeepEqual(cfg.Services, before.Services) || !reflect.DeepEqual(cfg.AppliedServices, before.AppliedServices) {
				t.Fatal("inactive edit fabricated scope/positive permission")
			}
			calls := 0
			a.NodeChecker = jobNodeChecker(func(_ context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				calls++
				return autofallbackResult(r, true), nil
			})
			nodes, _ := a.Nodes.Snapshot(context.Background(), time.Now())
			_, _, err = a.checkAndRecordNode(context.Background(), id, a.Catalog.Services[0], "", 0)
			after, _ := a.Nodes.Snapshot(context.Background(), time.Now())
			if !errors.Is(err, dataplane.ErrNodeResourceDenied) || calls != 0 || len(adapter.calls) != 0 || nodes.Generation != after.Generation {
				t.Fatal("nil-policy manual negative ignored", err, calls, adapter.calls)
			}
		})
	}
}

func TestNodeResourceAuxiliaryServiceClassificationUsesCoreCanonicalDomains(t *testing.T) {
	a, _, _ := nodeApplyFixture(t)
	a.Catalog.Services = append(a.Catalog.Services,
		catalog.Service{ID: "cloudflare", Domains: []string{"www.cloudflare.com."}},
		catalog.Service{ID: "international", Domains: []string{"пример.рф"}},
	)
	manual := []config.ResourceMatch{{Kind: "service", Value: "cloudflare"}, {Kind: "service", Value: "international"}}
	if _, err := a.Store.UpdateResourceExclusions(context.Background(), a.Store.Get(), &manual, nil); err != nil {
		t.Fatal(err)
	}
	cfg := a.Store.Get()
	for _, host := range []string{"www.cloudflare.com", "WWW.CLOUDFLARE.COM.", "sub.www.cloudflare.com.", "пример.рф", "ПРИМЕР.РФ.", "xn--e1afmkfd.xn--p1ai", "sub.xn--e1afmkfd.xn--p1ai."} {
		if err := a.nodeResourceAdmission(context.Background(), cfg, a.Catalog.Services[0], host, netip.Addr{}); !errors.Is(err, dataplane.ErrNodeResourceDenied) {
			t.Fatal("canonical auxiliary service negative bypass", host, err)
		}
	}
	for _, host := range []string{"notwww.cloudflare.com", "www.cloudflare.com.attacker.example", "notxn--e1afmkfd.xn--p1ai", "xn--e1afmkfd.xn--p1ai.attacker.example"} {
		if err := a.nodeResourceAdmission(context.Background(), cfg, a.Catalog.Services[0], host, netip.Addr{}); err != nil {
			t.Fatal("service classification crossed a label boundary", host, err)
		}
	}
	if !reflect.DeepEqual(cfg, a.Store.Get()) {
		t.Fatal("negative classification created positive intent")
	}
}

func TestNodeResourceInactiveManualCASDuringCandidateClosesBeforeRecord(t *testing.T) {
	a, id, _ := nodeApplyFixture(t)
	before, _ := a.Nodes.Snapshot(context.Background(), time.Now())
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		manual := []config.ResourceMatch{{Kind: "service", Value: "telegram"}}
		if _, err := a.Store.UpdateResourceExclusions(ctx, a.Store.Get(), &manual, nil); err != nil {
			t.Fatal(err)
		}
		return autofallbackResult(r, true), nil
	})
	result, _, err := a.checkAndRecordNode(context.Background(), id, a.Catalog.Services[0], "", 0)
	after, _ := a.Nodes.Snapshot(context.Background(), time.Now())
	if !errors.Is(err, dataplane.ErrNodeResourceDenied) || result.Available || result.Verdict != evidence.VerdictInconclusive || result.EgressIP != "" || before.Generation != after.Generation {
		t.Fatal("inactive negative did not revoke original candidate", result, err)
	}
}

func TestNodeResourceInactiveNegativePreservesOwnedDNSCleanupBeforeRefusingRestore(t *testing.T) {
	a := dnsRuntimeFixture(t)
	previous, _, err := a.Dataplane.Committed()
	if err != nil {
		t.Fatal(err)
	}
	adapter := a.Dataplane.Adapters["dns-scoped"].(*dnsReviewAdapter)
	if adapter.active == nil {
		t.Fatal("fixture has no owned DNS runtime")
	}
	manual := []config.ResourceMatch{{Kind: "service", Value: "telegram"}}
	if _, err := a.Store.UpdateResourceExclusions(context.Background(), a.Store.Get(), &manual, nil); err != nil {
		t.Fatal(err)
	}
	before := a.Store.Get()
	adapter.calls = nil
	calls := 0
	a.NodeChecker = jobNodeChecker(func(_ context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		calls++
		return autofallbackResult(r, true), nil
	})
	ctx := context.Background()
	release, err := a.Operations.Exclusive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	execution, err := a.recoverAppliedNodes(ctx, previous, recoveryProfile)
	if err == nil || execution.State == "committed" || adapter.active != nil || adapter.inactive == nil || calls != 0 || len(adapter.calls) != 0 {
		t.Fatal("negative either revoked cleanup or granted restoration", execution, err, calls, adapter.calls)
	}
	if !reflect.DeepEqual(before, a.Store.Get()) || a.DNS.VerifyServiceSelection("telegram", "private") != nil {
		t.Fatal("cleanup replayed saved config/DNS choice")
	}
}
