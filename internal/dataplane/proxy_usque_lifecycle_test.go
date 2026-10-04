package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
	"github.com/ArtixSx/razvilka/internal/usquediag"
)

// Running must bind the full spec, including the selected transport argv.
// The shared proxyFakeProcesses checks only ID, which would hide a QUIC/H2 bug.
type usqueLifecycleProcesses struct {
	base         *proxyFakeProcesses
	active       map[string]ProcessSpec
	starts       int
	stops        int
	runningCalls int
	afterRunning func(ProcessSpec, bool)
}

func (p *usqueLifecycleProcesses) Start(ctx context.Context, spec ProcessSpec) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.starts++
	spec.Args = append([]string(nil), spec.Args...)
	p.active[spec.ID] = spec
	return p.base.Start(ctx, spec)
}

func (p *usqueLifecycleProcesses) Stop(ctx context.Context, spec ProcessSpec) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.stops++
	if current, present := p.active[spec.ID]; present && !reflect.DeepEqual(current, spec) {
		return errors.New("fixture refused Stop of a different exact process spec")
	}
	delete(p.active, spec.ID)
	return p.base.Stop(ctx, spec)
}

func (p *usqueLifecycleProcesses) Running(spec ProcessSpec) bool {
	p.runningCalls++
	current, present := p.active[spec.ID]
	running := present && p.base.Running(spec) && reflect.DeepEqual(current, spec)
	if p.afterRunning != nil {
		p.afterRunning(spec, running)
	}
	return running
}

type usqueLifecycleRunner struct {
	base  *proxyFakeRunner
	a     *ProxyTunnelAdapter
	seen  []string
	after func(string, []string)
}

func (r *usqueLifecycleRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	r.seen = append(r.seen, name+" "+strings.Join(args, " "))
	var output []byte
	var err error
	if name == "ip" && strings.Join(args, " ") == "link show dev "+r.a.Interface {
		if r.base.processes.running["usque-tun"] {
			output = []byte(r.a.Interface + ": UP")
		} else {
			err = errors.New("fixture interface absent")
		}
	} else {
		// Version/validation remain entirely in memory, including an absolute
		// startup binary coordinate; no executable file is created or invoked.
		if name == r.a.SidecarBin {
			name = "sing-box"
		}
		output, err = r.base.Run(ctx, name, args...)
	}
	if r.after != nil {
		r.after(name, args)
	}
	return output, err
}

type usqueLifecycleFixture struct {
	t            *testing.T
	base, root   string
	a            *ProxyTunnelAdapter
	plan         Plan
	ctx          context.Context
	processes    *usqueLifecycleProcesses
	runner       *usqueLifecycleRunner
	profile      string
	revoked      bool
	canaryCalls  int
	liveCalls    int
	observations int
	canary       usquediag.CanaryEvidence
	produced     usquediag.OwnedRuntimeEvidence
}

func newUSQUELifecycleFixture(t *testing.T) *usqueLifecycleFixture {
	t.Helper()
	base := privateScopedXrayFixtureDir(t)
	configs := engineconfig.New(filepath.Join(base, "drafts"), filepath.Join(base, "backups"))
	configs.LiveRoot = filepath.Join(base, "private-live-catalog")
	session := `{"private_key":"fixture-key","endpoint_pub_key":"fixture-pub","id":"fixture-device","access_token":"fixture-token","endpoint_v4":"1.1.1.1","endpoint_h2_v4":"162.159.193.10"}`
	if _, err := configs.Stage("usque", "main", session); err != nil {
		t.Fatal(err)
	}
	a, err := NewProxyTunnelAdapter("usque", configs, filepath.Join(base, "state"))
	if err != nil {
		t.Fatal(err)
	}
	f := &usqueLifecycleFixture{t: t, base: base, root: filepath.Join(base, "transaction"), a: a, profile: "wan-123456789abc"}
	f.processes = &usqueLifecycleProcesses{base: &proxyFakeProcesses{running: map[string]bool{}}, active: map[string]ProcessSpec{}}
	f.runner = &usqueLifecycleRunner{a: a, base: &proxyFakeRunner{processes: f.processes.base, iface: a.Interface}}
	a.Processes, a.Runner = f.processes, f.runner
	a.EngineBin, a.SidecarBin = filepath.Join(base, "bin", "usque"), filepath.Join(base, "bin", "sing-box")
	a.IP, a.IPTables, a.IP6Tables = "ip", "iptables", "ip6tables"
	a.UsqueConfig = filepath.Join(base, "package-usque.conf")
	if err := os.WriteFile(a.UsqueConfig, []byte("SNI=cloudflareclient.com\nHTTP2_ENABLE=0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	a.bootIdentity = func() (string, error) { return "usque-lifecycle-boot", nil }
	a.FreshProfile = func(context.Context) (string, error) { return f.profile, nil }
	a.Resolver = func(_ context.Context, host string) ([]netip.Addr, error) {
		t.Fatal("literal lifecycle scope unexpectedly requested DNS", host)
		return nil, errors.New("fixture forbids DNS")
	}
	a.SOCKSProbe = func(ctx context.Context, address string) error {
		if ctx.Err() != nil || address != "127.0.0.1:18080" && address != "127.0.0.1:19080" {
			return errors.New("unexpected fixture SOCKS address")
		}
		return nil
	}
	a.CanaryProbe = func(context.Context, string, string) error { panic("owned lifecycle used generic service probe") }
	a.CanaryTraceProbe = func(context.Context, string) (usqueCanaryEvidence, error) { panic("owned lifecycle used legacy trace") }
	a.Probe = func(context.Context, string) error { panic("owned lifecycle used generic live probe") }
	service := proxyPredicateFixtureService()
	service.Strategy = []string{"usque"}
	f.plan = Plan{NetworkProfileID: f.profile, EngineDrafts: []string{"usque/main"},
		Routes: []Route{{ServiceID: service.ID, ServiceName: service.Name, Resolved: "usque", CIDRs: []string{"8.8.8.8/32"}, Sources: []string{"192.168.1.25/32"}, ProbeURL: service.ProbeURL, ProbeService: &service}}}
	if f.plan.RequiresNetworkProof() {
		t.Fatal("ordinary USQUE fixture unexpectedly acquired scoped-node authority")
	}
	f.ctx = WithReviewGuard(context.Background(), func(context.Context) error {
		if f.revoked {
			return ErrReviewChanged
		}
		return nil
	})
	a.ownedUSQUEProbe = func(ctx context.Context, options usquediag.OwnedProbeOptions) (usquediag.OwnedRuntimeEvidence, error) {
		f.canaryCalls++
		if options.Runtime.SOCKSAddress != "127.0.0.1:19080" || options.Authority == nil {
			t.Fatal("Canary lost isolated owned runtime")
		}
		if err := options.Authority(ctx); err != nil {
			return usquediag.OwnedRuntimeEvidence{}, err
		}
		if f.canaryCalls == 1 {
			if options.Runtime.Transport != "QUIC" {
				t.Fatal("preferred QUIC was not attempted first")
			}
			return usquediag.OwnedRuntimeEvidence{}, errors.New("fixture QUIC unavailable")
		}
		if f.canaryCalls != 2 || options.Runtime.Transport != "HTTP/2" {
			t.Fatal("Canary transport fallback changed or repeated")
		}
		f.validateServices(options)
		proof := usqueOwnedBridgeProof(options)
		f.canary = proof.CanaryEvidence()
		return proof, nil
	}
	a.ownedUSQUELiveIO = usqueLiveHealthIO{
		observe: func(ctx context.Context, request usquediag.OwnedRuntimeRequest) (usquediag.OwnedRuntimeIdentity, error) {
			f.observations++
			return f.identity(ctx, request)
		},
		produce: func(ctx context.Context, options usquediag.OwnedProbeOptions) (usquediag.OwnedRuntimeEvidence, error) {
			f.liveCalls++
			if !options.Enabled || options.Authority == nil || options.Runtime.Root != a.runtimeRoot() || options.Runtime.Transport != "HTTP/2" ||
				options.Network.SOCKSAddress != "127.0.0.1:18080" || options.Network.UDP != nil || options.Network.Timeout > 20*time.Second {
				t.Fatal("live producer lost active selected transport/bounded scope")
			}
			deadline, bounded := ctx.Deadline()
			if !bounded || time.Until(deadline) > 30*time.Second {
				t.Fatal("public live producer has no bounded deadline")
			}
			if err := options.Authority(ctx); err != nil {
				return usquediag.OwnedRuntimeEvidence{}, err
			}
			f.validateServices(options)
			identity, err := f.identity(ctx, options.Runtime)
			if err != nil {
				return usquediag.OwnedRuntimeEvidence{}, err
			}
			proof := usqueOwnedBridgeProof(options)
			proof.Identity = identity
			checked := time.Now().UTC()
			proof.CheckedAt, proof.ValidUntil = checked.Format(time.RFC3339Nano), checked.Add(usquediag.MaxCanaryAge).Format(time.RFC3339Nano)
			proof.Colo = []string{"AMS", "FRA", "LHR"}[(f.liveCalls-1)%3]
			f.produced = proof
			return proof, nil
		},
	}
	return f
}

func TestUSQUEPublicLifecycleReconcileRestartsCommittedHTTP2WithoutCanary(t *testing.T) {
	f := newUSQUELifecycleFixture(t)
	f.activate()
	if err := f.a.Commit(f.ctx, f.plan, f.root); err != nil {
		t.Fatal(err)
	}
	previous := f.evidence(f.a.evidencePath())
	previousIdentity := f.produced.Identity
	selected, err := os.ReadFile(f.a.transportPath())
	if err != nil {
		t.Fatal(err)
	}
	// Only this in-memory fixture loses the two exact processes; files and the
	// durable policy/selection remain the real public Commit output.
	for _, id := range []string{"usque-engine", "usque-tun"} {
		delete(f.processes.active, id)
		f.processes.base.running[id] = false
	}
	starts, canaries, producers := f.processes.starts, f.canaryCalls, f.liveCalls
	started := time.Now()
	if err := f.a.Reconcile(f.ctx, f.plan); err != nil {
		t.Fatal("stopped committed H2 runtime did not recover", err)
	}
	f.proofWindow(started)
	current := f.evidence(f.a.evidencePath())
	closingSelection, err := os.ReadFile(f.a.transportPath())
	engine := f.processes.active["usque-engine"]
	protocol, protocolErr := ownedUSQUELiveTransport(engine, "127.0.0.1:18080")
	if err != nil || string(closingSelection) != string(selected) || f.processes.starts != starts+2 || f.canaryCalls != canaries || f.liveCalls != producers+1 ||
		protocolErr != nil || protocol != "HTTP/2" || !f.processes.Running(engine) || !f.processes.Running(f.a.sidecarProcess()) ||
		string(current) == string(previous) || f.produced.Identity.RuntimeID == previousIdentity.RuntimeID {
		t.Fatal("Reconcile changed committed selection, fell back, reused proof or did not restart the exact H2 process", err, protocolErr)
	}
}

func TestUSQUEPublicLifecycleRunningCallbackRevocationFencesNextObservationAndRestart(t *testing.T) {
	for _, operation := range []string{"Health", "Reconcile", "RefreshPolicy"} {
		t.Run(operation, func(t *testing.T) {
			f := newUSQUELifecycleFixture(t)
			f.activate()
			if operation != "Health" {
				if err := f.a.Commit(f.ctx, f.plan, f.root); err != nil {
					t.Fatal(err)
				}
			}
			before := nodeRouterTransitReadbackTree(t, f.base)
			calls, observations, starts, stops, queries := f.liveCalls, f.observations, f.processes.starts, f.processes.stops, f.processes.runningCalls
			mutations := len(receiptMutationCalls(f.runner.seen))
			commandsAtRevocation := -1
			f.processes.afterRunning = func(spec ProcessSpec, running bool) {
				if spec.ID != "usque-engine" || !running || f.revoked {
					t.Fatal("unexpected query before the closing runtime guard")
				}
				f.revoked = true
				commandsAtRevocation = len(f.runner.seen)
			}
			var err error
			if operation == "Health" {
				err = f.a.Health(f.ctx, f.plan, f.root)
			} else if operation == "Reconcile" {
				err = f.a.Reconcile(f.ctx, f.plan)
			} else {
				_, err = f.a.RefreshPolicy(f.ctx, f.plan)
			}
			if !errors.Is(err, ErrReviewChanged) || !f.revoked || f.processes.runningCalls != queries+1 || len(f.runner.seen) != commandsAtRevocation ||
				f.liveCalls != calls || f.observations != observations || f.processes.starts != starts || f.processes.stops != stops ||
				len(receiptMutationCalls(f.runner.seen)) != mutations || !reflect.DeepEqual(before, nodeRouterTransitReadbackTree(t, f.base)) {
				t.Fatal("matching Running callback revocation reached another observation/producer, restart or mutation", err)
			}
		})
	}
}

func TestUSQUEPublicLifecycleRefreshSamePolicyClosesFinalSuccessfulReadback(t *testing.T) {
	for _, mode := range []string{"revoked", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			f := newUSQUELifecycleFixture(t)
			f.activate()
			if err := f.a.Commit(f.ctx, f.plan, f.root); err != nil {
				t.Fatal(err)
			}
			before := nodeRouterTransitReadbackTree(t, f.base)
			// Same-policy Refresh intentionally writes its one fresh evidence;
			// every policy, config, generation, lock and directory must survive.
			evidenceName, err := filepath.Rel(f.base, f.a.evidencePath())
			if err != nil {
				t.Fatal(err)
			}
			oldEvidence := before[evidenceName]
			delete(before, evidenceName)
			producers, starts, stops, canaries := f.liveCalls, f.processes.starts, f.processes.stops, f.canaryCalls
			mutations := len(receiptMutationCalls(f.runner.seen))
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			cut := false
			commandsAtCut := -1
			f.runner.after = func(name string, args []string) {
				if cut || f.liveCalls != producers+1 || name != "iptables" || strings.Join(args, " ") != "-t nat -S" {
					return
				}
				// The IPv4-only fixture's final successful forwarding snapshot
				// comes after Health has written the original current proof.
				f.evidence(f.a.evidencePath())
				cut, commandsAtCut = true, len(f.runner.seen)
				if mode == "revoked" {
					f.revoked = true
				} else {
					cancel()
				}
			}
			started := time.Now()
			changed, err := f.a.RefreshPolicy(ctx, f.plan)
			f.proofWindow(started)
			f.evidence(f.a.evidencePath())
			after := nodeRouterTransitReadbackTree(t, f.base)
			newEvidence := after[evidenceName]
			delete(after, evidenceName)
			want := ErrReviewChanged
			if mode == "canceled" {
				want = context.Canceled
			}
			if !cut || !errors.Is(err, want) || changed || f.liveCalls != producers+1 || f.processes.starts != starts || f.processes.stops != stops ||
				f.canaryCalls != canaries || len(receiptMutationCalls(f.runner.seen)) != mutations || len(f.runner.seen) != commandsAtCut ||
				oldEvidence == newEvidence || !reflect.DeepEqual(before, after) {
				t.Fatal("final successful readback callback was accepted or caused policy/process mutation", err, cut, changed)
			}
		})
	}
}

func (f *usqueLifecycleFixture) validateServices(options usquediag.OwnedProbeOptions) {
	f.t.Helper()
	if len(options.Network.Services) != 1 {
		f.t.Fatal("full frozen catalog service disappeared")
	}
	service := options.Network.Services[0]
	if service.ID != f.plan.Routes[0].ServiceID || service.URL != f.plan.Routes[0].ProbeURL || service.Validator == nil || service.Challenge {
		f.t.Fatal("semantic service binding or grade changed")
	}
	if err := service.Validator(usqueOwnedBridgeAcceptedResponse(service.URL)); err != nil {
		f.t.Fatal("full frozen predicate refused accepted fixture body", err)
	}
}

func (f *usqueLifecycleFixture) identity(ctx context.Context, request usquediag.OwnedRuntimeRequest) (usquediag.OwnedRuntimeIdentity, error) {
	f.t.Helper()
	spec, active := f.processes.active["usque-engine"]
	if !active || !f.processes.Running(spec) || request.Root != spec.Dir || request.Binary != spec.Binary || request.SOCKSAddress != "127.0.0.1:18080" || request.Transport != "HTTP/2" {
		return usquediag.OwnedRuntimeIdentity{}, errors.New("fixture current exact HTTP/2 process absent")
	}
	protocol, err := ownedUSQUELiveTransport(spec, request.SOCKSAddress)
	if err != nil || protocol != request.Transport {
		return usquediag.OwnedRuntimeIdentity{}, errors.New("fixture active argv has a different transport")
	}
	config, err := os.ReadFile(spec.MatchArg)
	if err != nil {
		return usquediag.OwnedRuntimeIdentity{}, err
	}
	endpoint, err := usquediag.SelectedOwnedUSQUEEndpoint(config, request.Transport)
	if err != nil || request.Endpoint != endpoint || request.Environment == nil {
		return usquediag.OwnedRuntimeIdentity{}, errors.New("fixture active config endpoint differs")
	}
	environment, err := request.Environment(ctx)
	if err != nil {
		return usquediag.OwnedRuntimeIdentity{}, err
	}
	identity := usqueOwnedBridgeProof(usquediag.OwnedProbeOptions{Runtime: request}).Identity
	identity.RuntimeID = "managed:usque:" + routeidentity.Hash([]byte(fmt.Sprintf("public-lifecycle-start-%d", f.processes.starts)))
	identity.SessionSHA256, identity.EnvironmentID = routeidentity.Hash(config), environment
	identity.ArgsSHA256 = routeidentity.Hash([]byte(strings.Join(append([]string{spec.Binary}, spec.Args...), "\x00") + "\x00"))
	identity.SocketBinding = routeidentity.Hash([]byte(request.SOCKSAddress + identity.RuntimeID))
	usqueLiveBind(&identity)
	return identity, nil
}

func (f *usqueLifecycleFixture) stageCandidate() {
	f.t.Helper()
	for _, step := range []struct {
		name string
		run  func(context.Context, Plan, string) error
	}{{"Snapshot", f.a.Snapshot}, {"Stage", f.a.Stage}, {"Validate", f.a.Validate}} {
		if err := step.run(f.ctx, f.plan, f.root); err != nil {
			f.t.Fatal(step.name, err)
		}
	}
	if err := f.a.Canary(f.ctx, f.plan.RoutePlanFor("usque"), f.root); err != nil {
		f.t.Fatal("Canary", err)
	}
	if len(f.processes.active) != 0 || f.canaryCalls != 2 {
		f.t.Fatal("isolated Canary leaked or changed fallback attempts")
	}
}

func (f *usqueLifecycleFixture) activate() {
	f.t.Helper()
	f.stageCandidate()
	if err := f.a.Activate(f.ctx, f.plan, f.root); err != nil {
		f.t.Fatal("Activate", err)
	}
	if f.processes.starts != 4 || !f.processes.Running(f.a.engineProcessWithTransport(usqueTransport{HTTP2: true, SNI: "cloudflareclient.com"})) || f.processes.Running(f.a.engineProcess()) {
		f.t.Fatal("fixture failed to distinguish actual selected H2 argv from preferred QUIC")
	}
}

func TestUSQUEPublicLifecycleActivateRefusesMalformedOrMissingSelectionBeforeMutation(t *testing.T) {
	for _, mode := range []struct {
		name, selection string
	}{
		{"empty-object", `{}`},
		{"null", `null`},
		{"duplicate-http2", `{"http2":true,"http2":false}`},
		{"unknown-field", `{"http2":true,"unknown":false}`},
		{"wrong-type", `{"http2":"true"}`},
		{"invalid-SNI", `{"http2":true,"sni":"bad value"}`},
		{"missing-file", ""},
	} {
		t.Run(mode.name, func(t *testing.T) {
			f := newUSQUELifecycleFixture(t)
			f.stageCandidate()
			selectionPath := filepath.Join(f.root, "transport.staged.json")
			var err error
			if mode.name == "missing-file" {
				err = os.Remove(selectionPath)
			} else {
				err = os.WriteFile(selectionPath, []byte(mode.selection), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			before := nodeRouterTransitReadbackTree(t, f.base)
			starts, stops, queries, commands := f.processes.starts, f.processes.stops, f.processes.runningCalls, len(f.runner.seen)
			canaries, producers, observations := f.canaryCalls, f.liveCalls, f.observations
			err = f.a.Activate(f.ctx, f.plan, f.root)
			var refusal preflightRefusalError
			if !errors.As(err, &refusal) || f.processes.starts != starts || f.processes.stops != stops || f.processes.runningCalls != queries || len(f.runner.seen) != commands ||
				f.canaryCalls != canaries || f.liveCalls != producers || f.observations != observations || len(f.processes.active) != 0 ||
				!reflect.DeepEqual(before, nodeRouterTransitReadbackTree(t, f.base)) {
				t.Fatal("invalid staged selection was not refused before any runtime/file mutation or external observation", err)
			}
		})
	}
}

func (f *usqueLifecycleFixture) evidence(path string) []byte {
	f.t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		f.t.Fatal(err)
	}
	var receipt usquediag.CanaryEvidence
	if json.Unmarshal(data, &receipt) != nil {
		f.t.Fatal("public action did not write a valid typed receipt")
	}
	canonical, _ := json.Marshal(f.produced.CanaryEvidence())
	decodedCanonical, _ := json.Marshal(receipt)
	if string(data) != string(canonical) || string(decodedCanonical) != string(canonical) {
		f.t.Fatal("public action changed whole original producer receipt, identity, grades or TTL")
	}
	return data
}

func (f *usqueLifecycleFixture) proofWindow(started time.Time) {
	f.t.Helper()
	checked, checkedErr := time.Parse(time.RFC3339Nano, f.produced.CheckedAt)
	expires, expiresErr := time.Parse(time.RFC3339Nano, f.produced.ValidUntil)
	if checkedErr != nil || expiresErr != nil || checked.Before(started) || checked.After(time.Now()) || !expires.Equal(checked.Add(usquediag.MaxCanaryAge)) {
		f.t.Fatal("public action did not retain this-call proof time and the original TTL")
	}
}

func TestUSQUEPublicLifecycleSelectedTransportFreshHealthCommitAndReconcile(t *testing.T) {
	f := newUSQUELifecycleFixture(t)
	f.activate()
	started := time.Now()
	if err := f.a.Health(f.ctx, f.plan, f.root); err != nil || f.liveCalls != 1 {
		t.Fatal("Health did not probe actual selected H2 process exactly once", err, f.liveCalls)
	}
	f.proofWindow(started)
	f.evidence(filepath.Join(f.root, "evidence.staged.json"))
	canaryBytes, _ := json.Marshal(f.canary)
	injected := false
	f.runner.after = func(name string, args []string) {
		if !injected && f.liveCalls == 2 && name == "ip" && strings.Join(args, " ") == "route get 192.168.1.25" {
			// Actual Commit's forwarding readback follows its private Health capture.
			// A substituted staged Canary must not become the active receipt.
			f.evidence(filepath.Join(f.root, "evidence.staged.json"))
			if err := os.WriteFile(filepath.Join(f.root, "evidence.staged.json"), canaryBytes, 0600); err != nil {
				t.Fatal(err)
			}
			injected = true
		}
	}
	started = time.Now()
	if err := f.a.Commit(f.ctx, f.plan, f.root); err != nil || f.liveCalls != 2 || !injected {
		t.Fatal("Commit failed to produce/capture one fresh health before policy promotion", err, f.liveCalls, injected)
	}
	f.proofWindow(started)
	committed := f.evidence(f.a.evidencePath())
	staged, err := os.ReadFile(filepath.Join(f.root, "evidence.staged.json"))
	if err != nil || string(staged) != string(canaryBytes) || string(committed) == string(canaryBytes) {
		t.Fatal("Commit trusted mutable staged Canary bytes instead of private Health capture", err)
	}
	f.runner.after = nil
	starts, stops, canaries := f.processes.starts, f.processes.stops, f.canaryCalls
	mutations := len(receiptMutationCalls(f.runner.seen))
	started = time.Now()
	if err := f.a.Reconcile(f.ctx, f.plan); err != nil || f.liveCalls != 3 {
		t.Fatal("Reconcile did not refresh current selected runtime proof", err, f.liveCalls)
	}
	f.proofWindow(started)
	refreshed := f.evidence(f.a.evidencePath())
	if string(refreshed) == string(committed) || f.processes.starts != starts || f.processes.stops != stops || f.canaryCalls != canaries || len(receiptMutationCalls(f.runner.seen)) != mutations {
		t.Fatal("healthy Reconcile started/stopped/repaired/fell back or reused historical proof")
	}
}

func TestUSQUEPublicLifecycleAuthorityFailurePrecedesPolicyAndLiveProducer(t *testing.T) {
	for _, operation := range []string{"Health", "Commit", "Reconcile", "RefreshPolicy"} {
		for _, mode := range []string{"missing-review", "revoked", "missing-WAN", "changed-WAN", "matching-profile-revokes"} {
			t.Run(operation+"/"+mode, func(t *testing.T) {
				f := newUSQUELifecycleFixture(t)
				f.activate()
				if operation == "Reconcile" || operation == "RefreshPolicy" {
					if err := f.a.Commit(f.ctx, f.plan, f.root); err != nil {
						t.Fatal(err)
					}
				}
				before := nodeRouterTransitReadbackTree(t, f.base)
				calls, observations, starts, stops, commands := f.liveCalls, f.observations, f.processes.starts, f.processes.stops, len(f.runner.seen)
				switch mode {
				case "missing-review":
					f.ctx = context.Background()
				case "revoked":
					f.revoked = true
				case "missing-WAN":
					f.plan.NetworkProfileID = ""
				case "changed-WAN":
					f.profile = "wan-abcdef123456"
				case "matching-profile-revokes":
					f.a.FreshProfile = func(context.Context) (string, error) { f.revoked = true; return f.profile, nil }
				}
				var err error
				switch operation {
				case "Health":
					err = f.a.Health(f.ctx, f.plan, f.root)
				case "Commit":
					err = f.a.Commit(f.ctx, f.plan, f.root)
				case "Reconcile":
					err = f.a.Reconcile(f.ctx, f.plan)
				case "RefreshPolicy":
					_, err = f.a.RefreshPolicy(f.ctx, f.plan)
				}
				if err == nil || f.liveCalls != calls || f.observations != observations || f.processes.starts != starts || f.processes.stops != stops || len(f.runner.seen) != commands ||
					!reflect.DeepEqual(before, nodeRouterTransitReadbackTree(t, f.base)) {
					t.Fatal("authority failure reached receipt/kernel observation, producer or mutation", err)
				}
			})
		}
	}
}
