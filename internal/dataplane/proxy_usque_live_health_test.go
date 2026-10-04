package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/routeidentity"
	"github.com/ArtixSx/razvilka/internal/usquediag"
)

type usqueLiveProcesses struct {
	running   bool
	specs     []ProcessSpec
	onRunning func()
}

func (*usqueLiveProcesses) Start(context.Context, ProcessSpec) error {
	panic("live health started a process")
}
func (*usqueLiveProcesses) Stop(context.Context, ProcessSpec) error {
	panic("live health stopped a process")
}
func (p *usqueLiveProcesses) Running(spec ProcessSpec) bool {
	p.specs = append(p.specs, spec)
	if p.onRunning != nil {
		p.onRunning()
	}
	return p.running
}

type usqueLiveFixture struct {
	a         *ProxyTunnelAdapter
	plan      RoutePlan
	transport usqueTransport
	ctx       context.Context
	inspect   usqueLiveHealthIO
	processes *usqueLiveProcesses
	identity  usquediag.OwnedRuntimeIdentity
	produced  usquediag.OwnedRuntimeEvidence
	profile   string
	revoked   bool
	observed  int
	probes    int
}

func usqueLiveBind(i *usquediag.OwnedRuntimeIdentity) {
	raw, _ := json.Marshal([]string{"owned-usque-path-v1", i.RuntimeID, i.BinarySHA256, i.SessionSHA256, i.ArgsSHA256,
		i.EnvironmentID, i.Transport, i.Endpoint, i.PeerObservation, i.SocketBinding, i.SourceCommit})
	i.BindingID = routeidentity.Hash(raw)
}

func TestUSQUELiveIdentityLeafUsesOnlyFrozenEnvironmentAndOriginalProof(t *testing.T) {
	for _, transport := range []usqueTransport{{}, {HTTP2: true, SNI: "cloudflareclient.com"}} {
		t.Run(usqueTransportName(transport), func(t *testing.T) {
			f := newUSQUELiveFixture(t, transport)
			if _, err := f.run(); err != nil {
				t.Fatal(err)
			}
			proof, before := f.produced, nodeRouterTransitReadbackTree(t, f.a.StateRoot)
			f.a.FreshProfile = func(context.Context) (string, error) { panic("identity leaf called WAN") }
			f.processes.onRunning = func() { panic("identity leaf called process controller") }
			ctx := WithReviewGuard(context.Background(), func(context.Context) error { panic("identity leaf acquired action authority") })
			calls := 0
			inspect := usqueLiveHealthIO{
				observe: func(context.Context, usquediag.OwnedRuntimeRequest) (usquediag.OwnedRuntimeIdentity, error) {
					panic("identity leaf reused action observer")
				},
				produce: func(context.Context, usquediag.OwnedProbeOptions) (usquediag.OwnedRuntimeEvidence, error) {
					panic("identity leaf replayed producer")
				},
				identity: func(c context.Context, r usquediag.OwnedRuntimeRequest) (usquediag.OwnedRuntimeIdentity, error) {
					calls++
					if r.Root != f.a.runtimeRoot() || r.Binary != f.a.EngineBin || r.SOCKSAddress != "127.0.0.1:18081" || r.Transport != proof.Identity.Transport || r.Endpoint.String() != proof.Identity.Endpoint {
						t.Fatal("identity leaf lost exact original runtime request")
					}
					deadline, bounded := c.Deadline()
					if !bounded || time.Until(deadline) > 5*time.Second {
						t.Fatal("identity leaf is unbounded")
					}
					for range 2 {
						value, err := r.Environment(c)
						if err != nil || value != proof.Identity.EnvironmentID {
							t.Fatal("identity leaf did not retain original environment", err)
						}
					}
					return proof.Identity, nil
				},
			}
			if err := verifyOwnedUSQUELiveIdentityWith(ctx, f.a.engineProcessWithTransport(transport), "127.0.0.1:18081", proof, inspect.identity); err != nil || calls != 1 {
				t.Fatal("identity leaf refused unchanged original runtime", err, calls)
			}
			if !reflect.DeepEqual(proof, f.produced) || !reflect.DeepEqual(before, nodeRouterTransitReadbackTree(t, f.a.StateRoot)) {
				t.Fatal("identity leaf changed receipt, TTL or files")
			}
		})
	}
}

func TestUSQUELiveIdentityLeafRefusesDeathAndEveryOriginalIdentityReplacement(t *testing.T) {
	for _, mode := range []string{"death", "birth", "exe", "config", "argv", "environment", "transport", "endpoint", "listener", "source", "binding", "peer", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			f := newUSQUELiveFixture(t, usqueTransport{HTTP2: true})
			if _, err := f.run(); err != nil {
				t.Fatal(err)
			}
			proof := f.produced
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cause := errors.New("owned process disappeared")
			observe := func(c context.Context, r usquediag.OwnedRuntimeRequest) (usquediag.OwnedRuntimeIdentity, error) {
				if mode == "death" {
					return usquediag.OwnedRuntimeIdentity{}, cause
				}
				current := proof.Identity
				switch mode {
				case "birth":
					current.RuntimeID = "managed:usque:" + strings.Repeat("b", 64)
				case "exe":
					current.BinarySHA256 = strings.Repeat("b", 64)
				case "config":
					current.SessionSHA256 = strings.Repeat("b", 64)
				case "argv":
					current.ArgsSHA256 = strings.Repeat("b", 64)
				case "environment":
					current.EnvironmentID = strings.Repeat("b", 64)
				case "transport":
					current.Transport = "QUIC"
				case "endpoint":
					current.Endpoint = "1.1.1.1:443"
				case "listener":
					current.SocketBinding = strings.Repeat("b", 64)
				case "source":
					current.SourceCommit = strings.Repeat("b", 40)
				case "binding":
					current.BindingID = strings.Repeat("b", 64)
				case "peer":
					current.PeerObservation = "udp-connected-default-peer"
				case "canceled":
					cancel()
				}
				if mode != "binding" {
					usqueLiveBind(&current)
				}
				return current, nil
			}
			err := verifyOwnedUSQUELiveIdentityWith(ctx, f.a.engineProcessWithTransport(f.transport), "127.0.0.1:18081", proof, observe)
			if err == nil || mode == "death" && !errors.Is(err, cause) || mode == "canceled" && !errors.Is(err, context.Canceled) || !reflect.DeepEqual(proof, f.produced) {
				t.Fatal("identity leaf adopted replacement/dead runtime or changed proof", err)
			}
		})
	}
}

func TestUSQUELiveIdentityLeafRejectsInvalidInputsBeforeObservation(t *testing.T) {
	for _, mode := range []string{"nil-context", "canceled", "empty", "expired", "future", "extended", "binding", "spec", "argv", "address"} {
		t.Run(mode, func(t *testing.T) {
			f := newUSQUELiveFixture(t, usqueTransport{})
			if _, err := f.run(); err != nil {
				t.Fatal(err)
			}
			proof, spec, address, ctx := f.produced, f.a.engineProcessWithTransport(f.transport), "127.0.0.1:18081", context.Background()
			switch mode {
			case "nil-context":
				ctx = nil
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "empty":
				proof = usquediag.OwnedRuntimeEvidence{}
			case "expired":
				proof.ValidUntil = time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)
			case "future":
				proof.CheckedAt = time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)
			case "extended":
				proof.ValidUntil = time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
			case "binding":
				proof.Identity.BindingID = strings.Repeat("b", 64)
			case "spec":
				spec.ID = "usque-canary"
			case "argv":
				spec.Args = append(spec.Args, "--http2")
			case "address":
				address = "127.0.0.1:18082"
			}
			calls := 0
			err := verifyOwnedUSQUELiveIdentityWith(ctx, spec, address, proof, func(context.Context, usquediag.OwnedRuntimeRequest) (usquediag.OwnedRuntimeIdentity, error) {
				calls++
				return proof.Identity, nil
			})
			if err == nil || calls != 0 {
				t.Fatal("invalid input reached observer", err, calls)
			}
		})
	}
}

func TestUSQUELiveIdentityLeafNilUsesActualObserverAndCannotAdoptFixture(t *testing.T) {
	f := newUSQUELiveFixture(t, usqueTransport{})
	if _, err := f.run(); err != nil {
		t.Fatal(err)
	}
	// The fixture has no PID or launcher passport. Actual observation must refuse
	// before any procfs process inspection; no executable/process is created.
	if _, err := os.Lstat(f.a.engineProcess().PIDPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if err := verifyOwnedUSQUELiveIdentity(context.Background(), f.a.engineProcessWithTransport(f.transport), "127.0.0.1:18081", f.produced); err == nil {
		t.Fatal("nil identity seam adopted fixture or used its action observer")
	}
}

// Local files plus private observer/producer doubles; no procfs, executable,
// DNS, sockets, registration, Start/Stop, policy commands or native proof.
func newUSQUELiveFixture(t *testing.T, transport usqueTransport) *usqueLiveFixture {
	t.Helper()
	f := &usqueLiveFixture{transport: transport, profile: "wan-123456789abc", processes: &usqueLiveProcesses{running: true}}
	root := filepath.Join(t.TempDir(), "usque")
	f.a = &ProxyTunnelAdapter{EngineID: "usque", StateRoot: root, EngineBin: filepath.Join(root, "usque-bin"), SOCKSPort: 18081,
		Processes: f.processes, FreshProfile: func(context.Context) (string, error) { return f.profile, nil }}
	if err := os.MkdirAll(f.a.runtimeRoot(), 0700); err != nil {
		t.Fatal(err)
	}
	config := []byte(`{"private_key":"fixture-key","endpoint_pub_key":"fixture-pub","id":"fixture-device","access_token":"fixture-token","endpoint_v4":"1.1.1.1","endpoint_h2_v4":"162.159.193.10"}`)
	if err := os.WriteFile(f.a.engineConfigPath(), config, 0600); err != nil {
		t.Fatal(err)
	}
	service := proxyPredicateFixtureService()
	service.Strategy = []string{"usque"}
	f.plan = RoutePlan{Adapter: "usque", NetworkProfileID: f.profile, Routes: []Route{{ServiceID: service.ID, Resolved: "usque", ProbeURL: service.ProbeURL, ProbeService: &service}}}
	f.ctx = WithReviewGuard(context.Background(), func(context.Context) error {
		if f.revoked {
			return ErrReviewChanged
		}
		return nil
	})
	spec := f.a.engineProcessWithTransport(transport)
	protocol := usqueTransportName(transport)
	endpoint, err := usquediag.SelectedOwnedUSQUEEndpoint(config, protocol)
	if err != nil {
		t.Fatal(err)
	}
	options := usquediag.OwnedProbeOptions{Runtime: usquediag.OwnedRuntimeRequest{Transport: protocol, Endpoint: endpoint}}
	f.identity = usqueOwnedBridgeProof(options).Identity
	f.identity.SessionSHA256 = routeidentity.Hash(config)
	f.identity.ArgsSHA256 = routeidentity.Hash([]byte(strings.Join(append([]string{spec.Binary}, spec.Args...), "\x00") + "\x00"))
	f.identity.EnvironmentID, err = usquediag.OwnedUSQUEEnvironment(f.a.FreshProfile)(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	usqueLiveBind(&f.identity)
	f.inspect.observe = func(ctx context.Context, request usquediag.OwnedRuntimeRequest) (usquediag.OwnedRuntimeIdentity, error) {
		f.observed++
		if request.Root != f.a.runtimeRoot() || request.Binary != spec.Binary || request.SOCKSAddress != "127.0.0.1:18081" ||
			request.Endpoint != endpoint || request.Transport != protocol || request.Environment == nil || ctx.Err() != nil {
			t.Fatal("live observer lost exact current ProcessSpec/config/listener", request)
		}
		return f.identity, nil
	}
	f.inspect.produce = func(ctx context.Context, options usquediag.OwnedProbeOptions) (usquediag.OwnedRuntimeEvidence, error) {
		f.probes++
		if !options.Enabled || options.Authority == nil || options.Network.Timeout != 20*time.Second || options.Network.UDP != nil ||
			options.Runtime.Root != spec.Dir || options.Network.SOCKSAddress != options.Runtime.SOCKSAddress {
			t.Fatal("live producer options changed authority, runtime or bounded proof scope")
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 30*time.Second {
			t.Fatal("live producer is not bounded")
		}
		if err := options.Authority(ctx); err != nil {
			return usquediag.OwnedRuntimeEvidence{}, err
		}
		for _, service := range options.Network.Services {
			if service.Validator == nil || service.Challenge {
				t.Fatal("live service predicate or proof grade was replaced")
			}
			if err := service.Validator(usqueOwnedBridgeAcceptedResponse(service.URL)); err != nil {
				return usquediag.OwnedRuntimeEvidence{}, err
			}
		}
		f.produced = usqueOwnedBridgeProof(options)
		f.produced.Identity = f.identity
		f.produced.CheckedAt = time.Now().UTC().Format(time.RFC3339Nano)
		checked, _ := time.Parse(time.RFC3339Nano, f.produced.CheckedAt)
		f.produced.ValidUntil = checked.Add(usquediag.MaxCanaryAge).Format(time.RFC3339Nano)
		return f.produced, nil
	}
	f.a.CanaryProbe = func(context.Context, string, string) error { panic("live health ran a second generic probe") }
	f.a.CanaryTraceProbe = func(context.Context, string) (usqueCanaryEvidence, error) { panic("live health used a legacy trace") }
	return f
}

func (f *usqueLiveFixture) run() (usquediag.CanaryEvidence, error) {
	return f.a.probeOwnedUSQUELiveWith(f.ctx, f.plan, f.transport, f.inspect)
}

func TestUSQUELiveHealthUsesActualProcessAndPreservesFreshTypedReceipt(t *testing.T) {
	for _, transport := range []usqueTransport{{}, {HTTP2: true, SNI: "cloudflareclient.com"}} {
		t.Run(usqueTransportName(transport), func(t *testing.T) {
			f := newUSQUELiveFixture(t, transport)
			// A stale on-disk Canary must neither supply proof nor be refreshed.
			if err := os.WriteFile(f.a.evidencePath(), []byte(`{"historical_canary":"leave unchanged"}`), 0600); err != nil {
				t.Fatal(err)
			}
			before := nodeRouterTransitReadbackTree(t, f.a.StateRoot)
			got, err := f.run()
			if err != nil || f.probes != 1 || f.observed != 2 || got.Owned == nil || !reflect.DeepEqual(got, f.produced.CanaryEvidence()) {
				t.Fatal("fresh live receipt was replaced, refreshed or downgraded", err)
			}
			for _, spec := range f.processes.specs {
				if spec.ID != "usque-engine" || spec.Dir != f.a.runtimeRoot() || !reflect.DeepEqual(spec, f.a.engineProcessWithTransport(transport)) {
					t.Fatal("actual active ProcessSpec was aliased to Canary")
				}
			}
			if !reflect.DeepEqual(before, nodeRouterTransitReadbackTree(t, f.a.StateRoot)) || got.BindingID != "" || got.Owned.Negotiated || got.Owned.UDPForwarding || len(got.Owned.ChallengeRoutes) != 0 {
				t.Fatal("live health wrote state or invented broad capability")
			}
			f.produced.ReachableRoutes[0], f.produced.ConfirmedRoutes[0] = "tampered", "tampered"
			if got.Owned.ConfirmedRoutes[0] != f.plan.Routes[0].ServiceID || got.Owned.ReachableRoutes[0] != f.plan.Routes[0].ServiceID {
				t.Fatal("receipt retains mutable producer slices")
			}
		})
	}
}

func TestUSQUELiveHealthRejectsMissingAuthorityScopeAndPinBeforeProducer(t *testing.T) {
	for _, kind := range []string{"nil-context", "missing-authority", "revoked", "canceled", "missing-profile", "WAN", "missing-process", "missing-predicate", "foreign-route", "empty-plan", "missing-pin", "relative-binary", "unsafe-SNI", "default-without-seal"} {
		t.Run(kind, func(t *testing.T) {
			f := newUSQUELiveFixture(t, usqueTransport{})
			switch kind {
			case "nil-context":
				f.ctx = nil
			case "missing-authority":
				f.ctx = context.Background()
			case "revoked":
				f.revoked = true
			case "canceled":
				ctx, cancel := context.WithCancel(f.ctx)
				cancel()
				f.ctx = ctx
			case "missing-profile":
				f.plan.NetworkProfileID = ""
			case "WAN":
				f.profile = "wan-abcdef123456"
			case "missing-process":
				f.processes.running = false
			case "missing-predicate":
				f.plan.Routes[0].ProbeService = nil
			case "foreign-route":
				f.plan.Routes[0].Resolved = "sing-box"
			case "empty-plan":
				f.plan.Routes = nil
			case "missing-pin":
				if err := os.WriteFile(f.a.engineConfigPath(), []byte(`{"endpoint_h2_v4":"162.159.193.10"}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "relative-binary":
				f.a.EngineBin = "usque"
			case "unsafe-SNI":
				f.transport.SNI = "invalid;value"
			case "default-without-seal":
				f.plan.Routes[0].NetworkPolicyRole = "default"
			}
			got, err := f.run()
			if err == nil || f.probes != 0 || f.observed != 0 || !reflect.DeepEqual(got, usquediag.CanaryEvidence{}) {
				t.Fatal("refused preflight reached live producer/observer", err)
			}
		})
	}
}

func TestUSQUELiveHealthRejectsStopWANRevocationAndCanceledProducer(t *testing.T) {
	for _, kind := range []string{"Stop", "WAN", "review", "cancel", "producer-failure"} {
		t.Run(kind, func(t *testing.T) {
			f := newUSQUELiveFixture(t, usqueTransport{})
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			f.ctx = ctx
			produce := f.inspect.produce
			f.inspect.produce = func(ctx context.Context, options usquediag.OwnedProbeOptions) (usquediag.OwnedRuntimeEvidence, error) {
				proof, err := produce(ctx, options)
				switch kind {
				case "Stop":
					f.processes.running = false
				case "WAN":
					f.profile = "wan-abcdef123456"
				case "review":
					f.revoked = true
				case "cancel":
					cancel()
				case "producer-failure":
					return usquediag.OwnedRuntimeEvidence{}, errors.New("owned producer refused")
				}
				return proof, err
			}
			got, err := f.run()
			if err == nil || f.probes != 1 || f.observed != 1 || !reflect.DeepEqual(got, usquediag.CanaryEvidence{}) {
				t.Fatal("invalidated health escaped or retried producer", err)
			}
		})
	}
}

func TestUSQUELiveHealthFencesCallbackDriftBeforeNextObservation(t *testing.T) {
	for _, callback := range []string{"FreshProfile", "Running"} {
		t.Run(callback, func(t *testing.T) {
			f := newUSQUELiveFixture(t, usqueTransport{})
			if callback == "FreshProfile" {
				fresh := f.a.FreshProfile
				f.a.FreshProfile = func(ctx context.Context) (string, error) {
					profile, err := fresh(ctx)
					f.revoked = true
					return profile, err
				}
			} else {
				f.processes.onRunning = func() { f.revoked = true }
			}
			got, err := f.run()
			if !errors.Is(err, ErrReviewChanged) || f.observed != 0 || f.probes != 0 || !reflect.DeepEqual(got, usquediag.CanaryEvidence{}) ||
				(callback == "FreshProfile" && len(f.processes.specs) != 0) {
				t.Fatal("revoked callback reached another process/runtime observation", err)
			}
		})
	}
}

func TestUSQUELiveHealthRejectsAuthorityDriftDuringClosingCallbacks(t *testing.T) {
	for _, callback := range []string{"FreshProfile", "Running"} {
		for _, effect := range []string{"revoke", "cancel-nil"} {
			t.Run(callback+"/"+effect, func(t *testing.T) {
				f := newUSQUELiveFixture(t, usqueTransport{})
				ctx, cancel := context.WithCancel(f.ctx)
				defer cancel()
				f.ctx = ctx
				late := false
				drift := func() {
					if f.observed != 2 {
						return
					}
					late = true
					if effect == "revoke" {
						f.revoked = true
					} else {
						cancel()
					}
				}
				if callback == "FreshProfile" {
					fresh := f.a.FreshProfile
					f.a.FreshProfile = func(ctx context.Context) (string, error) {
						profile, err := fresh(ctx)
						drift()
						return profile, err // matching profile and nil despite drift
					}
				} else {
					f.processes.onRunning = drift // returns true despite drift
				}
				got, err := f.run()
				want := ErrReviewChanged
				if effect == "cancel-nil" {
					want = context.Canceled
				}
				if !late || f.probes != 1 || f.observed != 2 || !errors.Is(err, want) || !reflect.DeepEqual(got, usquediag.CanaryEvidence{}) {
					t.Fatal("closing callback invalidated authority but retained receipt", err)
				}
			})
		}
	}
}

func TestUSQUELiveHealthRejectsProcessConfigBinaryAndListenerReplacement(t *testing.T) {
	for _, kind := range []string{"birth", "binary", "config", "argv", "listener", "profile"} {
		t.Run(kind, func(t *testing.T) {
			f := newUSQUELiveFixture(t, usqueTransport{})
			observe := f.inspect.observe
			f.inspect.observe = func(ctx context.Context, request usquediag.OwnedRuntimeRequest) (usquediag.OwnedRuntimeIdentity, error) {
				identity, err := observe(ctx, request)
				if f.observed == 2 {
					switch kind {
					case "birth":
						identity.RuntimeID = "managed:usque:" + strings.Repeat("b", 64)
					case "binary":
						identity.BinarySHA256 = strings.Repeat("b", 64)
					case "config":
						identity.SessionSHA256 = strings.Repeat("b", 64)
					case "argv":
						identity.ArgsSHA256 = strings.Repeat("b", 64)
					case "listener":
						identity.SocketBinding = strings.Repeat("b", 64)
					case "profile":
						identity.EnvironmentID = strings.Repeat("b", 64)
					}
					usqueLiveBind(&identity)
				}
				return identity, err
			}
			got, err := f.run()
			if err == nil || f.probes != 1 || !reflect.DeepEqual(got, usquediag.CanaryEvidence{}) {
				t.Fatal("replacement retained fresh health", err)
			}
		})
	}
}

func TestUSQUELiveHealthRejectsHistoricalTTLAndInventedGrades(t *testing.T) {
	for _, kind := range []string{"historical-within-TTL", "expired", "future", "extended-TTL", "foreign-runtime", "UDP", "challenge", "missing-service", "foreign-service"} {
		t.Run(kind, func(t *testing.T) {
			f := newUSQUELiveFixture(t, usqueTransport{})
			produce := f.inspect.produce
			f.inspect.produce = func(ctx context.Context, options usquediag.OwnedProbeOptions) (usquediag.OwnedRuntimeEvidence, error) {
				proof, err := produce(ctx, options)
				now := time.Now().UTC()
				switch kind {
				case "historical-within-TTL":
					proof.CheckedAt = now.Add(-time.Second).Format(time.RFC3339Nano)
				case "expired":
					proof.ValidUntil = now.Add(-time.Second).Format(time.RFC3339Nano)
				case "future":
					proof.CheckedAt = now.Add(time.Second).Format(time.RFC3339Nano)
				case "extended-TTL":
					proof.ValidUntil = now.Add(usquediag.MaxCanaryAge + time.Minute).Format(time.RFC3339Nano)
				case "foreign-runtime":
					proof.Identity.RuntimeID = "managed:usque:" + strings.Repeat("b", 64)
					usqueLiveBind(&proof.Identity)
				case "UDP":
					proof.UDPForwarding = true
				case "challenge":
					proof.ChallengeRoutes = []string{f.plan.Routes[0].ServiceID}
				case "missing-service":
					proof.ConfirmedRoutes = nil
				case "foreign-service":
					proof.ConfirmedRoutes = []string{"foreign"}
				}
				return proof, err
			}
			got, err := f.run()
			if err == nil || f.probes != 1 || !reflect.DeepEqual(got, usquediag.CanaryEvidence{}) {
				t.Fatal("historical/invalid proof became current health", err)
			}
		})
	}
}

func TestUSQUELiveHealthDefaultIsOnlyExplicitWARPTransportReadiness(t *testing.T) {
	f := newUSQUELiveFixture(t, usqueTransport{HTTP2: true})
	input := networkPolicyLANFixture(t)
	input.Routes[0].Resolved = "usque"
	plan, err := BuildAt(input, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	f.plan = plan.RoutePlanFor("usque")
	f.plan.NetworkProfileID = f.profile
	produce := f.inspect.produce
	f.inspect.produce = func(ctx context.Context, options usquediag.OwnedProbeOptions) (usquediag.OwnedRuntimeEvidence, error) {
		if len(options.Network.Services) != 0 || options.Network.UDP != nil {
			t.Fatal("DEFAULT borrowed catalog or UDP authority")
		}
		return produce(ctx, options)
	}
	got, err := f.run()
	if err != nil || f.probes != 1 || got.Owned == nil || len(got.Owned.ConfirmedRoutes) != 0 || len(got.Owned.ReachableRoutes) != 0 || got.Warp != "plus" {
		t.Fatal("sealed DEFAULT did not retain only explicit WARP readiness", err)
	}
}

func TestUSQUELiveHealthUsesFullFrozenPredicateAndDetachedCriteria(t *testing.T) {
	for _, kind := range []string{"status", "content-type", "body", "truncated", "caller-mutates"} {
		t.Run(kind, func(t *testing.T) {
			f := newUSQUELiveFixture(t, usqueTransport{})
			produce := f.inspect.produce
			f.inspect.produce = func(ctx context.Context, options usquediag.OwnedProbeOptions) (usquediag.OwnedRuntimeEvidence, error) {
				response := usqueOwnedBridgeAcceptedResponse(options.Network.Services[0].URL)
				switch kind {
				case "status":
					response.HTTPStatus = 403
				case "content-type":
					response.ContentType = "text/plain"
				case "body":
					response.Body = `{"result":{"accepted":false}}`
				case "truncated":
					response.BodyTruncated = true
				case "caller-mutates":
					f.plan.Routes[0].ProbeService.Probes[0].Expect.BodyContains[0] = `"accepted":false`
				}
				if err := options.Network.Services[0].Validator(response); err != nil {
					f.probes++
					return usquediag.OwnedRuntimeEvidence{}, err
				}
				return produce(ctx, options)
			}
			got, err := f.run()
			if f.probes != 1 || (kind == "caller-mutates") != (err == nil) || (err != nil && !reflect.DeepEqual(got, usquediag.CanaryEvidence{})) {
				t.Fatal("full frozen predicate was replaced or downgraded", err)
			}
		})
	}
}
