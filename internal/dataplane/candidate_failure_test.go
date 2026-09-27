package dataplane

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestCandidateFailureOnlyAttributesDefiniteServiceRejection(t *testing.T) {
	for _, scenario := range []string{"403", "451", "429", "503", "transport", "stream", "redirect", "process", "forwarding", "network", "cancel", "review"} {
		t.Run(scenario, func(t *testing.T) {
			a, runner, policy := proxyForwardingFixture(t)
			a.Processes = runner.processes
			a.SOCKSProbe = func(context.Context, string) error { return nil }
			network := executionNetwork
			a.FreshProfile = func(context.Context) (string, error) { return network, nil }
			a.Resolver = func(context.Context, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
			}
			runner.processes.running["sing-box-engine"], runner.processes.running["sing-box-tun"] = true, true
			if err := a.installForwarding(context.Background(), policy); err != nil {
				t.Fatal(err)
			}
			plan := networkExecutionPlan()
			plan.Routes[0].Sources = []string{"192.168.1.25/32"}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var reviewChanged bool
			ctx = WithReviewGuard(ctx, func(context.Context) error {
				if reviewChanged {
					return ErrReviewChanged
				}
				return nil
			})
			a.ServiceIPProbe = func(_ context.Context, rawURL, _ string, _ netip.Addr) error {
				code := 403
				switch scenario {
				case "451":
					code = 451
				case "429":
					code = 429
				case "503":
					code = 503
				case "transport":
					return errors.New("transport failed")
				case "process":
					runner.processes.running["sing-box-engine"] = false
				case "forwarding":
					if err := a.removeForwarding(context.Background()); err != nil {
						t.Fatal(err)
					}
				case "network":
					network = "wan-abcdef123456"
				case "cancel":
					cancel()
				case "review":
					reviewChanged = true
				}
				response := &http.Response{StatusCode: code, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("blocked"))}
				if scenario == "stream" {
					response.Body = io.NopCloser(candidateBrokenStream{})
				}
				if scenario == "redirect" {
					response.Request, _ = http.NewRequest("GET", "https://unrelated.example/", nil)
				}
				_, err := strictServiceResponse(rawURL, response)
				return err
			}
			err := a.healthState(ctx, plan, policy)
			var failure *CandidateServiceFailure
			got := errors.As(err, &failure)
			want := scenario == "403" || scenario == "451"
			if err == nil || got != want {
				t.Fatalf("attribution=%t want=%t err=%v", got, want, err)
			}
			if got && !failure.Matches(plan, plan.Routes[0], time.Now()) {
				t.Fatal("receipt is not bound to route")
			}
		})
	}
}

type candidateBrokenStream struct{}

func (candidateBrokenStream) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestCandidateFailureReceiptCannotCrossScopeOrEpoch(t *testing.T) {
	p := networkExecutionPlan()
	r := p.Routes[0]
	now := time.Now()
	f := &CandidateServiceFailure{PlanID: p.PlanID, Digest: p.Digest, Network: p.NetworkProfileID,
		ServiceID: r.ServiceID, Route: r.Resolved, RouteDigest: candidateRouteDigest(r), Code: "http-403", ObservedAt: now}
	if !f.Matches(p, r, now) {
		t.Fatal("valid receipt rejected")
	}
	for _, scenario := range []string{"plan", "digest", "network", "service", "node", "scope", "probe", "domains", "expired", "future", "partial"} {
		t.Run(scenario, func(t *testing.T) {
			plan, route, receipt := p, r, *f
			switch scenario {
			case "plan":
				plan.PlanID += "x"
			case "digest":
				plan.Digest += "x"
			case "network":
				plan.NetworkProfileID += "x"
			case "service":
				route.ServiceID += "x"
			case "node":
				route.Resolved += "x"
			case "scope":
				route.Sources = []string{"192.168.1.2/32"}
			case "probe":
				route.ProbeURL += "other"
			case "domains":
				route.Domains = []string{"other.example"}
			case "expired":
				receipt.ObservedAt = now.Add(-2 * time.Minute)
			case "future":
				receipt.ObservedAt = now.Add(time.Second)
			case "partial":
				receipt.Code = "http-429"
			}
			if receipt.Matches(plan, route, now) {
				t.Fatal("changed receipt accepted")
			}
		})
	}
}
