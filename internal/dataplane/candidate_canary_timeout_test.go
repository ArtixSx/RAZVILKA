package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
)

type mismatchedCanaryOriginal struct {
	token             *OriginalProcess
	legacyStart, stop bool
	finiteStart       bool
}

func TestCandidateCanaryTimeoutFreezesCanonicalEmptyRouteFields(t *testing.T) {
	for _, present := range []bool{false, true} {
		p, _, x := canaryTimeoutFixture(t)
		p.Routes[0].ProbeService = &catalog.Service{ID: p.Routes[0].ServiceID}
		if present {
			p.Routes[0].Domains, p.Routes[0].Sources, p.Routes[0].SourceRefs, p.Routes[0].Ingress = []string{}, []string{}, []string{}, []string{}
			p.Routes[0].ProbeService.Domains, p.Routes[0].ProbeService.SourceRefs = []string{}, []string{}
			p.Routes[0].ProbeService.Probes = []catalog.Probe{}
		}
		routes := p.RoutePlanFor("xray")
		f := candidateCanaryTimeout(routes, routes.Routes[0], nodeIPProbeFailure{nodeIPTimeout}).(*CandidateCanaryTimeout)
		if !canaryImageEqual(f.routes, routes) || !canaryImageEqual(f.route, routes.Routes[0]) {
			t.Fatal("freezing changed an actual Manager route image", present)
		}
		f.cleaned = true
		f.seal(New(t.TempDir()), p, x, Plan{}, false)
		if f.manager == nil {
			t.Fatal("present-empty route could not close", present)
		}
		routes.Routes[0].CIDRs[0] = "8.8.8.8/32"
		if canaryImageEqual(f.routes, routes) || canaryImageEqual(f.route, routes.Routes[0]) {
			t.Fatal("frozen scope retained a caller-owned slice")
		}
	}
}

func TestCandidateCanaryTimeoutMatchesFullDurableExecutionImage(t *testing.T) {
	p, f, x := canaryTimeoutFixture(t)
	x.Resources = []ExecutionResource{} // omitempty round-trip becomes nil.
	m := New(t.TempDir())
	data, err := json.Marshal(x)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m.StateRoot, "latest-execution.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	f.cleaned = true
	f.seal(m, p, x, Plan{}, false)
	if !f.Matches(context.Background(), m, p, x, p.Routes[0], time.Now()) {
		t.Fatal("unchanged durable execution image refused present-empty resources")
	}
	x.Error = "different failed execution"
	if f.Matches(context.Background(), m, p, x, p.Routes[0], time.Now()) {
		t.Fatal("different returned execution matched certificate")
	}
	data, _ = json.Marshal(x)
	if err := os.WriteFile(filepath.Join(m.StateRoot, "latest-execution.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if f.Matches(context.Background(), m, p, x, p.Routes[0], time.Now()) {
		t.Fatal("different durable execution matched certificate")
	}
}

func (c *mismatchedCanaryOriginal) Start(context.Context, ProcessSpec) error {
	c.legacyStart = true
	return nil
}
func (c *mismatchedCanaryOriginal) Stop(context.Context, ProcessSpec) error {
	c.stop = true
	return nil
}
func (*mismatchedCanaryOriginal) Running(ProcessSpec) bool { return false }
func (c *mismatchedCanaryOriginal) StartOriginal(ctx context.Context, _ ProcessSpec, _ string) (*OriginalProcess, error) {
	deadline, ok := ctx.Deadline()
	c.finiteStart = ok && deadline.After(time.Now())
	return c.token, nil
}

func TestCandidateCanaryTimeoutRefusesUnboundOriginalWithoutPIDFallback(t *testing.T) {
	for _, token := range []*OriginalProcess{nil, {}} {
		p, _, _ := canaryTimeoutFixture(t)
		controller := &mismatchedCanaryOriginal{token: token}
		a := &ProxyTunnelAdapter{EngineID: "xray", Processes: controller, Resolver: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		}}
		_, err := a.runCanaryAttempt(context.Background(), p.RoutePlanFor("xray"), ProcessSpec{ID: "expected-canary"}, "127.0.0.1:19081")
		if !errors.Is(err, errProxyCanaryCleanup) || controller.legacyStart || controller.stop || !controller.finiteStart || ExactCandidateCanaryTimeout(err) != nil {
			t.Fatal("unbound original acquired cleanup or retry authority", err, controller)
		}
	}
}

type canaryTimeoutGateAdapter struct {
	*fakeAdapter
	reject func(context.Context, RoutePlan) error
}

func (a *canaryTimeoutGateAdapter) Canary(ctx context.Context, p RoutePlan, _ string) error {
	if err := a.call("canary"); err != nil {
		return err
	}
	return a.reject(ctx, p)
}

func canaryTimeoutFixture(t *testing.T) (Plan, *CandidateCanaryTimeout, Execution) {
	t.Helper()
	p := networkExecutionPlan()
	p.Adapters = []string{"xray"}
	p.Routes[0].Resolved, p.Routes[0].Selected = "xray:"+checkedNodeID, "xray:"+checkedNodeID
	p.Routes[0].Domains, p.Routes[0].CIDRs = nil, []string{"93.184.216.0/24"}
	f, ok := candidateCanaryTimeout(p.RoutePlanFor("xray"), p.Routes[0], nodeIPProbeFailure{nodeIPTimeout}).(*CandidateCanaryTimeout)
	if !ok {
		t.Fatal("exact typed timeout not selected")
	}
	x := Execution{PlanID: p.PlanID, Digest: p.Digest, State: "canary-failed", Steps: []ExecutionStep{{Adapter: "xray", Phase: "canary", State: "failed"}}}
	return p, f, x
}

func TestCandidateCanaryTimeoutIsLiveExactAndNotMixedErrorAuthority(t *testing.T) {
	p, f, x := canaryTimeoutFixture(t)
	for _, other := range []error{errors.New("cleanup"), context.Canceled, context.DeadlineExceeded, ErrReviewChanged, ErrNetworkChanged, ErrNodeResourceDenied} {
		if ExactCandidateCanaryTimeout(errors.Join(f, other)) != nil {
			t.Fatal("mixed cause accepted", other)
		}
	}
	if ExactCandidateCanaryTimeout(errors.Join(f, nil)) != f {
		t.Fatal("sole cause lost")
	}
	copy := *f
	if ExactCandidateCanaryTimeout(&copy) != nil || ExactCandidateCanaryTimeout(&CandidateCanaryTimeout{}) != nil {
		t.Fatal("copied or reconstructed error acquired identity")
	}
	for _, cause := range []error{nodeIPProbeFailure{nodeIPIO}, nodeIPProbeFailure{nodeIPUnknown}, errors.New("node service IP path unsupported or unavailable; reason=timeout"), context.DeadlineExceeded} {
		if _, ok := candidateCanaryTimeout(p.RoutePlanFor("xray"), p.Routes[0], cause).(*CandidateCanaryTimeout); ok {
			t.Fatal("untyped/non-timeout cause admitted", cause)
		}
	}
	if f.Matches(context.Background(), New(t.TempDir()), p, x, p.Routes[0], time.Now()) {
		t.Fatal("unclosed timeout granted continuation")
	}
}

func TestCandidateCanaryTimeoutSealRequiresNoEffectsAndJoinedCleanup(t *testing.T) {
	for _, mode := range []string{"not-joined", "activated", "mixed-step", "running-step", "two-failures", "rollback", "wrong-plan", "wrong-scope", "resource"} {
		t.Run(mode, func(t *testing.T) {
			p, f, x := canaryTimeoutFixture(t)
			f.cleaned = true // Gate unit model only; actual producer/join is native-tested.
			switch mode {
			case "not-joined":
				f.cleaned = false
			case "activated":
				x.Steps = append(x.Steps, ExecutionStep{Adapter: "xray", Phase: "activate", State: "passed"})
			case "mixed-step":
				x.Steps[0].Adapter = "dns"
			case "running-step":
				x.Steps = append(x.Steps, ExecutionStep{Adapter: "dns", Phase: "snapshot", State: "running"})
			case "two-failures":
				x.Steps = append(x.Steps, x.Steps[0])
			case "rollback":
				x.State = "rolled-back"
			case "wrong-plan":
				p.Digest += "changed"
			case "wrong-scope":
				p.Routes[0].Sources = []string{"192.168.1.99/32"}
			case "resource":
				x.Resources = []ExecutionResource{{}}
			}
			f.seal(New(t.TempDir()), p, x, Plan{}, false)
			if f.manager != nil {
				t.Fatal("unverified result sealed", mode)
			}
		})
	}
}

// Model only the cleanup leaf here; the real producer and original child
// join are exercised by the native App test. Manager/journals are real.
func TestCandidateCanaryTimeoutManagerPublishesOnlySoleUnchangedRejection(t *testing.T) {
	for _, mode := range []string{"closed", "not-joined", "mixed-cleanup", "network", "review", "cancel", "journal", "committed-changed"} {
		t.Run(mode, func(t *testing.T) {
			p, _, _ := canaryTimeoutFixture(t)
			m := New(t.TempDir())
			profile := p.NetworkProfileID
			m.FreshProfile = func(context.Context) (string, error) { return profile, nil }
			prior := p
			prior.PlanID, prior.State = "dp-existing-runtime", "committed"
			if err := m.Record(prior); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			revoked := false
			ctx = WithReviewGuard(ctx, func(context.Context) error {
				if revoked {
					return ErrReviewChanged
				}
				return nil
			})
			var produced *CandidateCanaryTimeout
			a := &canaryTimeoutGateAdapter{fakeAdapter: &fakeAdapter{id: "xray"}}
			a.reject = func(_ context.Context, routes RoutePlan) error {
				produced = candidateCanaryTimeout(routes, routes.Routes[0], nodeIPProbeFailure{nodeIPTimeout}).(*CandidateCanaryTimeout)
				produced.cleaned = mode != "not-joined"
				switch mode {
				case "mixed-cleanup":
					return errors.Join(produced, errProxyCanaryCleanup)
				case "network":
					profile = "wan-ffffffffffff"
				case "review":
					revoked = true
				case "cancel":
					cancel()
				case "journal":
					path := filepath.Join(m.StateRoot, "latest-execution.json")
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(path, 0700); err != nil {
						t.Fatal(err)
					}
				case "committed-changed":
					changed := prior
					changed.PlanID = "dp-other-runtime"
					data, _ := json.Marshal(changed)
					if err := os.WriteFile(filepath.Join(m.StateRoot, "latest-committed-plan.json"), data, 0600); err != nil {
						t.Fatal(err)
					}
				}
				return produced
			}
			if err := m.Register(a); err != nil {
				t.Fatal(err)
			}
			x, err := m.Apply(ctx, p, func() (func() error, error) { t.Fatal("canary rejection reached commit"); return nil, nil })
			if err == nil || produced == nil {
				t.Fatal("missing rejection", err)
			}
			got := ExactCandidateCanaryTimeout(err)
			accepted := got != nil && got.Matches(ctx, m, p, x, p.Routes[0], time.Now())
			if accepted != (mode == "closed") {
				t.Fatal("wrong continuation eligibility", mode, x.State, err)
			}
			if produced.manager != nil && mode != "closed" {
				t.Fatal("failed cycle issued a live certificate", mode)
			}
			if accepted && got.Matches(ctx, New(m.StateRoot), p, x, p.Routes[0], time.Now()) {
				t.Fatal("reopened Manager reconstructed continuation")
			}
			for _, phase := range a.calls {
				if phase == "activate" || phase == "health" || phase == "rollback" || phase == "commit-adapter" {
					t.Fatal("canary rejection touched live lifecycle", phase)
				}
			}
		})
	}
}
