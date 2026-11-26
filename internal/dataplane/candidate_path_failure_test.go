package dataplane

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestCandidatePathFailureRequiresClosedIOAndHealthyRuntime(t *testing.T) {
	for _, scenario := range []string{"io", "generic-io", "unknown", "tls", "dns", "timeout", "process", "forwarding", "network", "cancel", "review", "resource"} {
		t.Run(scenario, func(t *testing.T) {
			a, runner, policy := proxyForwardingFixture(t)
			a.Processes = runner.processes
			a.SOCKSProbe = func(context.Context, string) error { return nil }
			network := executionNetwork
			a.FreshProfile = func(context.Context) (string, error) { return network, nil }
			a.Resolver = func(context.Context, string) ([]netip.Addr, error) {
				if scenario == "dns" {
					return nil, errors.New("private resolver failure")
				}
				return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
			}
			runner.processes.running["sing-box-engine"], runner.processes.running["sing-box-tun"] = true, true
			if err := a.installForwarding(context.Background(), policy); err != nil {
				t.Fatal(err)
			}
			plan := networkExecutionPlan()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			revoked := false
			ctx = WithReviewGuard(ctx, func(context.Context) error {
				if revoked && scenario == "review" {
					return ErrReviewChanged
				}
				return nil
			})
			ctx = WithNodeResourceGuard(ctx, func(context.Context, string, netip.Addr) error {
				if revoked && scenario == "resource" {
					return ErrNodeResourceDenied
				}
				return nil
			})
			a.ServiceIPProbe = func(context.Context, string, string, netip.Addr) error {
				switch scenario {
				case "generic-io":
					return errors.New("node service IP path unsupported or unavailable; reason=io")
				case "unknown":
					return errors.New("private unclassified transport failure")
				case "tls":
					return tls.RecordHeaderError{Msg: "private TLS failure"}
				case "timeout":
					return context.DeadlineExceeded
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
				case "review", "resource":
					revoked = true
				}
				return io.ErrUnexpectedEOF
			}
			err := a.healthState(ctx, plan, policy)
			var path *CandidatePathFailure
			var service *CandidateServiceFailure
			got := errors.As(err, &path)
			if err == nil || got != (scenario == "io") || errors.As(err, &service) {
				t.Fatalf("path-only attribution=%t scenario=%s err=%v", got, scenario, err)
			}
			if got && (!path.Matches(plan, plan.Routes[0], time.Now()) || strings.Contains(path.Error(), "private") || errors.Unwrap(path) != nil) {
				t.Fatal("path receipt lost exact binding or retained private cause")
			}
		})
	}
}

func TestCandidatePathFailureCannotCrossScopeOrEpoch(t *testing.T) {
	plan := networkExecutionPlan()
	route := plan.Routes[0]
	now := time.Now()
	receipt := CandidatePathFailure{PlanID: plan.PlanID, Digest: plan.Digest, Network: plan.NetworkProfileID,
		ServiceID: route.ServiceID, Route: route.Resolved, RouteDigest: candidateRouteDigest(route), Code: "node-path-io", ObservedAt: now}
	if !receipt.Matches(plan, route, now) {
		t.Fatal("valid path receipt rejected")
	}
	for _, scenario := range []string{"plan", "digest", "network", "service", "node", "scope", "probe", "domains", "expired", "future", "code", "engine"} {
		t.Run(scenario, func(t *testing.T) {
			p, r, f := plan, route, receipt
			switch scenario {
			case "plan":
				p.PlanID += "x"
			case "digest":
				p.Digest += "x"
			case "network":
				p.NetworkProfileID += "x"
			case "service":
				r.ServiceID += "x"
			case "node":
				r.Resolved += "x"
			case "scope":
				r.Sources = []string{"192.168.1.2/32"}
			case "probe":
				r.ProbeURL += "other"
			case "domains":
				r.Domains = []string{"other.example"}
			case "expired":
				f.ObservedAt = now.Add(-2 * time.Minute)
			case "future":
				f.ObservedAt = now.Add(time.Second)
			case "code":
				f.Code = "timeout"
			case "engine":
				r.Resolved = strings.Replace(r.Resolved, "sing-box:", "xray:", 1)
			}
			if f.Matches(p, r, now) {
				t.Fatal("changed path receipt accepted")
			}
		})
	}
}
