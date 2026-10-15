package app

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/probecheck"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
	"github.com/ArtixSx/razvilka/internal/testlab"
)

func rateLimitedRoute(ctx context.Context, s catalog.Service, route string) testlab.Result {
	r := confirmedRouteProber{}.Probe(ctx, s, route)
	r.HTTPStatus = 429
	r.EvaluateHTTP(s, probecheck.Observation{RequestedURL: s.ProbeURL, FinalURL: s.ProbeURL, HTTPStatus: 429, RetryAfter: "120", ExpectedRoutePathID: "isolated:" + route, ObservedRoutePathID: "isolated:" + route})
	return r
}

// Real coordinator, stores and compilation; only the prober and OS adapter
// are modeled. An explicit return used to enter Apply despite a partial probe.
func TestAutonomyHTTP429DefersReturnWithoutApplyBudgetOrRetry(t *testing.T) {
	a, node, adapter := nfqws2StandardFixture(t, starterService(t, "speedtest"))
	a.TestLab = testlab.NewRunner()
	if _, err := a.Nodes.SetDisabled(context.Background(), node, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	calls := 0
	a.RouteProber = autonomyResourceRouteProber(func(ctx context.Context, s catalog.Service, route string) testlab.Result {
		calls++
		return rateLimitedRoute(ctx, s, route)
	})
	before := a.Store.Get()
	switches := append([]time.Time(nil), standardRuntime(a, "speedtest").Switches...)
	standardDue(a, "speedtest")
	start := time.Now()
	a.autonomyRound(context.Background(), start)
	r := standardRuntime(a, "speedtest")
	if r.State != "unconfirmed" || !strings.Contains(r.Message, "429") || r.NextCheck.Sub(start) < 119*time.Second || r.NextCheck.Sub(start) > 125*time.Second {
		t.Fatalf("no service cooldown: %+v", r)
	}
	if calls != 1 || len(adapter.calls) != 0 || !reflect.DeepEqual(before, a.Store.Get()) || !reflect.DeepEqual(switches, r.Switches) {
		t.Fatalf("429 retried or consumed Apply: probes=%d adapters=%v switches=%v", calls, adapter.calls, r.Switches)
	}
	a.autonomyRound(context.Background(), time.Now())
	if calls != 1 || len(adapter.calls) != 0 {
		t.Fatal("cooldown ran another check or Apply")
	}
}

func TestAutonomyHTTP429PauseLeavesOtherServiceDue(t *testing.T) {
	a, _, adapter := autonomousIntegrationFixture(t)
	a.RouteProber = autonomyResourceRouteProber(rateLimitedRoute)
	a.TestLab = testlab.NewRunner()
	service, _ := a.autonomyService("my-independent-site")
	profile, _ := a.freshNetworkProfile(context.Background())
	ctx, release, err := a.privateExclusiveOperation(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	o := a.autonomyProbeRouteObservation(ctx, service, "direct", profile)
	release()
	r := autonomy.Runtime{Failures: 2, Switches: []time.Time{time.Now().Add(-time.Minute)}}
	if o.Verdict == "PASS" || !o.pause(&r) || r.Failures != 0 || len(r.Switches) != 1 {
		t.Fatal("rate limit became success/failure quorum", o, r)
	}
	a.autonomyRuntime(service.ID, r)
	// An independently enrolled service still gets the next coordinator round.
	other := catalog.Service{ID: "other-site", Name: "Other", Domains: []string{"other.example"}, ProbeURL: "https://other.example/"}
	a.Catalog.Services = append(a.Catalog.Services, other)
	if err := a.Store.UpdateService(other.ID, a.Store.Get().Services[service.ID]); err != nil {
		t.Fatal(err)
	}
	if err := a.inheritAutonomyService(context.Background(), other.ID); err != nil {
		t.Fatal(err)
	}
	checked := []string{}
	a.RouteProber = autonomyResourceRouteProber(func(ctx context.Context, s catalog.Service, route string) testlab.Result {
		checked = append(checked, s.ID)
		return rateLimitedRoute(ctx, s, route)
	})
	a.autonomy.mu.Lock()
	p := a.autonomy.doc.Policy
	p.PreferredRoutes = []string{"nfqws2"}
	a.autonomy.doc.Policy = p
	if err := a.persistAutonomyLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	a.autonomy.mu.Unlock()
	options := a.nodeReviews.options
	a.nodeReviews.options = func() []routecatalog.Option {
		return append(options(), routecatalog.Option{ID: "nfqws2", Ready: true, Installed: true, Configured: true, Selectable: true, Running: true})
	}
	a.autonomyRound(context.Background(), time.Now())
	if !reflect.DeepEqual(checked, []string{other.ID}) || len(adapter.calls) != 0 {
		t.Fatal("cooldown blocked another service or mutated runtime", checked, adapter.calls)
	}
}

func TestAutonomyHTTP429CannotHideTLSOrMisroute(t *testing.T) {
	for _, outcome := range []string{"tls", "misroute", "stale", "unproved", "foreign-network"} {
		t.Run(outcome, func(t *testing.T) {
			a, _, _ := autonomousIntegrationFixture(t)
			a.TestLab = testlab.NewRunner()
			service, _ := a.autonomyService("my-independent-site")
			profile, _ := a.freshNetworkProfile(context.Background())
			a.RouteProber = autonomyResourceRouteProber(func(ctx context.Context, s catalog.Service, route string) testlab.Result {
				r := rateLimitedRoute(ctx, s, route)
				switch outcome {
				case "tls":
					r.Status, r.Verdict, r.ErrorCode = "fail", evidence.VerdictError, "tls-certificate-mismatch"
				case "misroute":
					r.ObservedRoutePathID = "isolated:foreign"
				case "stale":
					r.CheckedAt = time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339)
				case "unproved":
					r.RouteProofError = "missing-proof"
				case "foreign-network":
					r.NetworkProfileID = "wan-ffffffffffff"
				}
				return r
			})
			ctx, release, err := a.privateExclusiveOperation(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			o := a.autonomyProbeRouteObservation(ctx, service, "direct", profile)
			if o.RetryAfterSeconds != 0 || o.Verdict == "PASS" {
				t.Fatal("invalid observation received cooldown/pass", o)
			}
			if outcome == "tls" && o.Verdict != "FAIL" {
				t.Fatal("TLS refusal changed", o)
			}
		})
	}
}
