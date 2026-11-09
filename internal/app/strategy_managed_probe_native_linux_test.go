//go:build linux && razvilka_native_fixture

package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	goruntime "runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/startuptools"
	"github.com/ArtixSx/razvilka/internal/strategylab"
)

func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == "-dataplane-execution-read-version" {
		fmt.Println(dataplane.ExecutionReadVersion)
		os.Exit(0)
	}
	// Actual supervisor ABI dispatch, before Go's flag parser. The production
	// helper still validates protected original intent and fixed environment.
	if len(os.Args) == 3 {
		switch os.Args[1] {
		case "nfqws-compatibility-supervisor":
			os.Exit(strategylab.RunCompatibilitySupervisor(os.Args[2], os.Getenv("RAZVILKA_STRATEGY_LAB_STATE"), os.Getenv("RAZVILKA_SELF_UPDATE_CONTROL_STATE")))
		case "nfqws-managed-process-supervisor":
			root := filepath.Join(os.Getenv("RAZVILKA_DATAPLANE_STATE"), "runtime", "nfqws2")
			result := dataplane.RunNFQWSManagedProcessSupervisor(os.Args[2], root, os.Getenv("RAZVILKA_SELF_UPDATE_CONTROL_STATE"))
			if marker, err := os.ReadFile(filepath.Join(root, ".native-fixture-delayed-exit")); result == 0 && err == nil && string(marker) == "after-real-wait\n" {
				// CI-only fault AFTER actual child/subreaper WaitECHILD publication:
				// delay THIS original helper's exit beyond the controller join grace.
				// It owns no remaining child and cannot start another one here.
				signal.Ignore(syscall.SIGTERM)
				time.Sleep(3 * time.Second)
			}
			os.Exit(result)
		}
	}
	os.Exit(m.Run())
}

type managedProbeNativeAdmission struct {
	consumer *dataplane.ManagedNFQWSProbeConsumer
}

func (a *managedProbeNativeAdmission) WithStart(ctx context.Context, name string, args []string, digest string, begin func() error) error {
	if a.consumer == nil || !a.consumer.OwnsContext(ctx) {
		return dataplane.ErrNFQWSScopedOwner
	}
	if a.consumer.ProbeCounterCommandCurrent(ctx, name, args, digest) == nil {
		return a.consumer.WithProbeCounterCommandStart(ctx, name, args, digest, begin)
	}
	return dataplane.WithNFQWSScopedCommandStart(ctx, name, args, digest, begin)
}

// Opt-in isolated ROOT experiment. Only platform/architecture classification
// and WAN ID are modeled. Artifact bytes, installer/receipt, source validation,
// held descriptor/tool graph, serial lease, socket, queue, TLS/HTTP criteria,
// actual positive+negative packets and cleanup are the production consumers.
func TestManagedStrategyProbeNativeConsumer(t *testing.T) {
	runManagedStrategyProbeNativeConsumer(t, false, false)
}

func TestManagedStrategyProbeNativeConsumerLateWaitCleanup(t *testing.T) {
	runManagedStrategyProbeNativeConsumer(t, true, false)
}

func TestManagedStrategyProbeNativeAppHTTP(t *testing.T) {
	runManagedStrategyProbeNativeConsumer(t, false, true)
}

func TestManagedStrategyProbeNativeClosingSource(t *testing.T) {
	runManagedStrategyProbeNativeConsumer(t, false, false, "source")
}
func TestManagedStrategyProbeNativeClosingRuntime(t *testing.T) {
	runManagedStrategyProbeNativeConsumer(t, false, false, "runtime")
}
func TestManagedStrategyProbeNativeClosingControl(t *testing.T) {
	runManagedStrategyProbeNativeConsumer(t, false, false, "control")
}
func TestManagedStrategyProbeNativeClosingEnvironment(t *testing.T) {
	runManagedStrategyProbeNativeConsumer(t, false, false, "environment")
}

func runManagedStrategyProbeNativeConsumer(t *testing.T, lateWait, appHTTP bool, revoke ...string) {
	lan := appHTTP && len(revoke) == 1 && (revoke[0] == "lan" || revoke[0] == "lan-manual")
	manualOnly := lan && revoke[0] == "lan-manual"
	if os.Getenv("RAZVILKA_MANAGED_PROBE_NATIVE") != "1" {
		t.Skip("explicit isolated native fixture only")
	}
	ns, err := os.Readlink("/proc/self/ns/net")
	initial, e := os.Readlink("/proc/1/ns/net")
	if os.Geteuid() != 0 || err != nil || e != nil || ns == initial {
		t.Fatal("ROOT non-init network namespace required")
	}
	fixtureBudget := 90 * time.Second
	if lan {
		fixtureBudget = 3 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), fixtureBudget)
	defer cancel()
	command := func(args ...string) {
		t.Helper()
		out, err := exec.CommandContext(ctx, "/usr/sbin/ip", args...).CombinedOutput()
		if err != nil {
			t.Fatal(args, string(out), err)
		}
	}
	out, err := exec.CommandContext(ctx, "/usr/sbin/ip", "-o", "link", "show").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if !strings.Contains(line, ": lo:") {
			t.Fatal("refusing namespace with preexisting interface", line)
		}
	}
	if lan {
		setupManagedProbeNativeLAN(t, ctx)
		traceManagedProbeNativeLinks(t, ctx)
	} else {
		command("link", "set", "lo", "up")
		command("addr", "add", "8.8.8.8/32", "dev", "lo")
	}
	// The real installer publishes immutable public-traversable generations.
	// Keep them below a new protected /var/lib leaf, since production source
	// guards deliberately refuse public payload directories below sticky /tmp.
	root, err := os.MkdirTemp("/var/lib", "razvilka-probe-native-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	if lan {
		serveManagedProbeNativeTLS(t, root, managedProbeNativeWANListener)
	} else {
		serveManagedProbeNativeTLS(t, root)
	}
	provider := netidentity.NewProcProvider()
	var tools *startuptools.Lease
	if lan {
		tools, err = startuptools.AcquireNativeFixtureManagedListPolicy(ctx, provider, os.Getenv("RAZVILKA_MANAGED_PROBE_TOOLS_REVIEW"))
	} else {
		tools, err = startuptools.AcquireNativeFixturePolicy(ctx, provider, os.Getenv("RAZVILKA_MANAGED_PROBE_TOOLS_REVIEW"))
	}
	if err != nil {
		managedProbeNativeErrorChain(t, err, 0)
		t.Fatal("actual protected tool closure", err)
	}
	defer tools.Close()
	descriptor, err := tools.InventoryTools()
	if err != nil {
		t.Fatal(err)
	}
	var toolMeasurements managedProbeNativeToolMeasurements
	descriptor.Check = toolMeasurements.wrap(descriptor.Check)
	inventory, err := dataplane.NewBackendInventory(provider, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := provider.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	readEmpty := func(c context.Context) error {
		view, err := inventory.Read(c, identity)
		if err != nil {
			return err
		}
		if err := view.RequireComplete(); err != nil {
			return err
		}
		for _, row := range view.Rows {
			for _, token := range row.Tokens {
				if token == "NFQUEUE" || token == "QUEUE" || strings.HasPrefix(token, "RZP_") {
					return dataplane.ErrNFQWSScopedOwner
				}
			}
		}
		return nil
	}
	if err := readEmpty(ctx); err != nil {
		managedProbeNativeErrorChain(t, err, 0)
		t.Fatal("native empty packet namespace", err)
	}
	store, err := config.Load(filepath.Join(root, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetSafeMode(false); err != nil {
		t.Fatal(err)
	}
	// A real persisted draft revision, never an invented transaction number.
	// The kernel plan protocol deliberately rejects unversioned revision zero.
	initialService := config.ServiceState{Route: "direct"}
	if lan {
		initialService = config.ServiceState{Enabled: true, Route: "nfqws2"}
	}
	if err := store.UpdateService("native", initialService); err != nil {
		t.Fatal(err)
	}
	lab, err := strategylab.New(filepath.Join(root, "strategy-lab.json"))
	if err != nil {
		t.Fatal(err)
	}
	lab.Validator, lab.Executor = strategylab.CompatibleValidator{}, nil
	controlRoot := filepath.Join(root, "control")
	if _, err := operationgate.InitializeSelfUpdateControl(ctx, controlRoot); err != nil {
		t.Fatal(err)
	}
	a := &App{Store: store, StrategyLab: lab, SelfUpdateFiles: &SelfUpdateFiles{ControlRoot: controlRoot}, FreshProfile: func(c context.Context) (string, error) { return "wan-0123456789ab", c.Err() }}
	original, release, err := a.Operations.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	control, err := a.Operations.ReviewControlEpoch(original, controlRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	if lan {
		approveManagedProbeNativeLAN(t, original, a, control)
	}
	if err := lab.InitializeManagedCompatibilitySource(original, control); err != nil {
		t.Fatal(err)
	}
	inactive, err := lab.ReviewManagedCompatibilityInactive(original, control)
	if err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(root, "bundle")
	if err := os.Mkdir(bundle, 0700); err != nil {
		t.Fatal(err)
	}
	ref := control.Reference()
	revision := store.Get().Revision
	check := func(c context.Context, id string, seq, rev uint64, reader int) error {
		if id != ref.InstallationID || seq != ref.Sequence || rev != revision || reader != 3 {
			return components.ErrRecoveryAuthority
		}
		return control.Current(c)
	}
	owner, err := components.InstallNativeFixtureManagedNFQWS(original, bundle, os.Getenv("RAZVILKA_NFQWS_MANAGED_GENUINE_REVIEW"), revision, components.ManagedNFQWSBundleAuthority{InstallationID: ref.InstallationID, Sequence: ref.Sequence, ReaderVersion: 3, Check: check,
		Admit: func(c context.Context, tx, id string, seq, rev uint64, effect string, begin func() error) error {
			if err := check(c, id, seq, rev, 3); err != nil {
				return err
			}
			return control.WithStart(c, begin)
		},
		Inactive: func(c context.Context) error { return errors.Join(inactive.Current(c), readEmpty(c)) }})
	if err != nil {
		t.Fatal("actual artifact installation", err)
	}
	a.Components = owner
	bootstrap, err := owner.AcquireCurrentManagedNFQWSRuntime(original)
	if err != nil {
		t.Fatal(err)
	}
	p, v, err := strategylab.NewManagedSupervisedCompatibilityProvider(original, lab, bootstrap, control, controlRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err := lab.InstallManagedCompatibilityValidator(original, control, p, v, inactive); err != nil {
		t.Fatal(err)
	}
	a.retainManagedNFQControl(control)
	_ = inactive.Close()
	if err := bootstrap.Close(); err != nil {
		t.Fatal(err)
	}
	candidate, err := lab.AddCandidate("tcp-tls", "native isolated original candidate", "--filter-tcp=443 --lua-desync=multisplit:pos=1", "expert")
	if err != nil {
		t.Fatal(err)
	}
	validationRuntime, err := owner.AcquireCurrentManagedNFQWSRuntime(original)
	if err != nil {
		t.Fatal(err)
	}
	validated, completion, err := lab.ValidateManagedCandidate(original, candidate.ID, validationRuntime)
	if err != nil || completion == nil || !validated.Validation.OK || !validated.Validation.Native {
		t.Fatal("actual managed validation", validated.Validation, err)
	}
	if err := completion.RetireKnown(original); err != nil {
		t.Fatal(err)
	}
	dataplaneRoot := filepath.Join(root, "dataplane")
	if appHTTP {
		dataplaneRoot = "/opt/razvilka/state/dataplane"
	}
	if err := os.MkdirAll(dataplaneRoot, 0700); err != nil {
		t.Fatal(err)
	}
	manager := dataplane.New(dataplaneRoot)
	manager.FreshProfile = a.FreshProfile
	a.Dataplane = manager
	adapter := dataplane.NewNFQWS2Adapter()
	if err := manager.Register(adapter); err != nil {
		t.Fatal(err)
	}
	if lan {
		configs := engineconfig.New(filepath.Join(root, "engine-stage"), filepath.Join(root, "engine-backup"))
		for _, other := range []dataplane.Adapter{dataplane.NewWireGuardAdapter(configs, manager.StateRoot), dataplane.NewAmneziaWGAdapter(configs, manager.StateRoot)} {
			if err := manager.Register(other); err != nil {
				t.Fatal(err)
			}
		}
	}
	policyTools, runner, err := tools.PolicyRuntimeTools()
	if err != nil {
		t.Fatal(err)
	}
	admission := &managedProbeNativeAdmission{}
	var appPolicy *managedListPolicyOwner
	current := func(c context.Context, p *dataplane.LANPolicyRuntimePlan) error {
		if appHTTP {
			if appPolicy == nil {
				return dataplane.ErrNFQWSScopedOwner
			}
			return appPolicy.scopeCheck(c, p)
		}
		if admission.consumer == nil || p != nil {
			return dataplane.ErrNFQWSScopedOwner
		}
		return admission.consumer.ScopeCurrent(c, "")
	}
	denyEffect := func(context.Context, *dataplane.LANPolicyRuntimePlan, dataplane.LANPolicyEffect) error {
		return dataplane.ErrNFQWSScopedOwner
	}
	lanRuntime := &dataplane.LANPolicyRuntime{Runner: runner, IP: policyTools.IP, IPTables: policyTools.IPTables, IP6Tables: policyTools.IP6Tables, ScopeCheck: current}
	binding := &dataplane.LANPolicyReceiptBinding{Runtime: lanRuntime, ApplyGuard: denyEffect, CleanupGuard: denyEffect, RetireCheck: current}
	if lan {
		configureManagedProbeNativeLANBinding(lanRuntime, binding, func() *managedListPolicyOwner { return appPolicy })
	}
	gate, err := dataplane.NewNetworkPolicyAdapter(original, dataplane.NetworkPolicyAssemblyOptions{Mode: dataplane.LANPolicyManagedListMode, Provider: provider, Binding: binding, InventoryCheck: func(c context.Context, id netidentity.Identity, p *dataplane.LANPolicyRuntimePlan) error {
		if lan {
			if appPolicy == nil || appPolicy.checks == nil {
				return dataplane.ErrNetworkPolicyConsumers
			}
			return appPolicy.checks.InventoryCheck(c, id, p)
		}
		if id != identity {
			return dataplane.ErrNetworkPolicyIdentity
		}
		view, err := inventory.Read(c, id)
		if err != nil {
			return err
		}
		return view.RequireComplete()
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Register(gate); err != nil {
		t.Fatal(err)
	}
	consumer, err := dataplane.NewManagedNFQWSProbeConsumer(manager, gate, inventory, control, controlRoot, provider, ctx)
	if err != nil {
		t.Fatal(err)
	}
	admission.consumer = consumer
	if lateWait {
		if err := os.MkdirAll(adapter.StateRoot, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(adapter.StateRoot, ".native-fixture-delayed-exit"), []byte("after-real-wait\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	service := catalog.Service{ID: "native", Name: "Native isolated TLS", Category: "native-fixture", Strategy: []string{"nfqws2", "direct"}, Domains: []string{"managed-probe.example"}, ProbeURL: "https://managed-probe.example/", Probes: []catalog.Probe{{ID: "primary", Label: "Owned native HTTPS", URL: "https://managed-probe.example/", Required: true, Expect: catalog.ProbeExpectation{StatusCodes: []int{200}, BodyContains: []string{"owned-native-service"}}}}}
	if lan {
		service.Domains = nil
		service.CIDRs = []string{"8.8.8.8/32"}
	}
	a.Catalog = catalog.Catalog{Services: []catalog.Service{service}}
	if err := catalog.Validate(a.Catalog); err != nil {
		t.Fatal("fixture must satisfy the SAME complete catalog predicate before validation/probe/Apply", err)
	}
	if appHTTP {
		checks, err := manager.BindNetworkPolicyChecks(gate, inventory)
		if err != nil {
			t.Fatal("bind actual registered policy checks", err)
		}
		defer checks.Close()
		var wgSources map[string]*dataplane.WGInactivityRead
		if lan {
			wgSources = map[string]*dataplane.WGInactivityRead{}
			for _, engine := range []string{"wireguard", "amneziawg"} {
				source, err := tools.ReviewWGInactivity(original, manager, control, engine)
				if err != nil {
					t.Fatal("actual managed-list WG inactivity source", engine, err)
				}
				defer source.Close()
				wgSources[engine] = source
			}
			if err := checks.BindManagedWGInactivitySources(original, wgSources); err != nil {
				t.Fatal("actual both WG inactivity binding", err)
			}
		}
		// CI-only platform classification factory. Every retained owner below
		// is the SAME actual protected tool/provider/control/registered consumer.
		appPolicy = &managedListPolicyOwner{app: a, manager: manager, panel: ctx, provider: provider, tools: tools, inventory: inventory, gate: gate, checks: checks, control: control, wgInactivity: wgSources}
		appPolicy.self = appPolicy
		a.managedListPolicy = appPolicy
		r := &ManagedNFQWSListRuntime{policy: appPolicy, app: a, manager: manager, panel: ctx, provider: provider, tools: tools, inventory: inventory, gate: gate, checks: checks, control: control, probe: consumer}
		r.self = r
		appPolicy.nfq, a.managedNFQList = r, r
		if lan {
			if err := installNativeFixtureNFQListPhysicalSource(r); err != nil {
				t.Fatal(err)
			}
		}
		release() // Each actual HTTP request must obtain its own new admission.
		metadataStarted := startuptools.NativeFixtureVersionMetadataCount(tools)
		versionChildrenStarted := startuptools.NativeFixtureVersionChildCount(tools)
		stopOriginalToolStarts := startuptools.StartDomainNativeToolMeasurement()
		defer func() { t.Log("native actual HTTP original started tool children by kind", stopOriginalToolStarts()) }()
		payloadAttempts, payloadBytes := components.NativeFixtureManagedNFQWSPayloadReads(owner)
		stopHTTPProfile := managedProbeNativeCPUProfile(t, root)
		defer stopHTTPProfile()
		var memoryBefore goruntime.MemStats
		goruntime.ReadMemStats(&memoryBefore)
		defer func() {
			var memoryAfter goruntime.MemStats
			goruntime.ReadMemStats(&memoryAfter)
			t.Log("native actual HTTP in-process allocated-bytes/objects", memoryAfter.TotalAlloc-memoryBefore.TotalAlloc, memoryAfter.Mallocs-memoryBefore.Mallocs)
			attempts, returnedBytes := components.NativeFixtureManagedNFQWSPayloadReads(owner)
			t.Log("native actual HTTP member-read attempts/returned-bytes", attempts-payloadAttempts, returnedBytes-payloadBytes)
			t.Log("native actual HTTP inclusive phase [started completed wall]", dataplane.NativeFixtureNFQWSProbePhases(consumer))
			t.Log("native actual HTTP aggregate inventory ToolCheck calls", toolMeasurements.calls.Load(), "wall", time.Duration(toolMeasurements.nanos.Load()))
			t.Log("native actual HTTP aggregate original metadata traversal attempts", startuptools.NativeFixtureVersionMetadataCount(tools)-metadataStarted)
			children := startuptools.NativeFixtureVersionChildCount(tools)
			for i := range children {
				children[i] -= versionChildrenStarted[i]
			}
			t.Log("native actual HTTP aggregate actual version child Starts [iptables ip6tables IP]", children)
		}()
		runManagedStrategyProbeNativeHTTP(t, a, candidate.ID, readEmpty, lan, manualOnly)
		return
	}
	criteria, err := strategylab.ManagedProbeCriteriaDigest(service)
	if err != nil {
		t.Fatal(err)
	}
	scope := strategylab.CandidateProbeScope{Target: strategylab.ProbeTarget{ServiceID: service.ID, ProbeURL: service.ProbeURL, Protocol: "tcp", IPFamily: "ipv4"}, Address: netip.MustParseAddr("8.8.8.8"), CriteriaDigest: criteria}
	runtime, err := owner.AcquireCurrentManagedNFQWSRuntime(original)
	if err != nil {
		t.Fatal(err)
	}
	source, err := lab.RetainCandidateProbeReview(original, candidate.ID, scope, runtime)
	if err != nil {
		t.Fatal(err)
	}
	env, err := newManagedStrategyProbeEnvironment(original, a, control, runtime, service, scope)
	if err != nil {
		t.Fatal(err)
	}
	epoch, err := lab.BeginManagedProbe(original, source, env, env.networkID, env.policyHash)
	if err != nil {
		t.Fatal(err)
	}
	probeCtx, probeCancel := context.WithTimeout(original, 14*time.Second)
	defer probeCancel()
	probeCtx = startuptools.WithCommandAdmission(probeCtx, admission)
	if _, parentErr := os.Stat(adapter.StateRoot); parentErr != nil {
		t.Log("actual producer private parent before first consumer:", parentErr)
	}
	stopStackDiagnostic := managedProbeNativeStackDeadline(t)
	defer stopStackDiagnostic()
	stopCPUProfile := managedProbeNativeCPUProfile(t, root)
	defer stopCPUProfile()
	toolCalls, toolNanos := toolMeasurements.calls.Load(), toolMeasurements.nanos.Load()
	var memoryBefore goruntime.MemStats
	goruntime.ReadMemStats(&memoryBefore)
	probeStarted := time.Now()
	metadataStarted := startuptools.NativeFixtureVersionMetadataCount(tools)
	versionChildrenStarted := startuptools.NativeFixtureVersionChildCount(tools)
	payloadAttempts, payloadBytes := components.NativeFixtureManagedNFQWSPayloadReads(owner)
	evidence, cleaned, err := consumer.Execute(probeCtx, source, epoch, runtime, service, revision, env.Current)
	probeElapsed := time.Since(probeStarted)
	var memoryAfter goruntime.MemStats
	goruntime.ReadMemStats(&memoryAfter)
	t.Log("native measured Execute in-process allocated-bytes/objects", memoryAfter.TotalAlloc-memoryBefore.TotalAlloc, memoryAfter.Mallocs-memoryBefore.Mallocs)
	attempts, returnedBytes := components.NativeFixtureManagedNFQWSPayloadReads(owner)
	t.Log("native measured Execute member-read attempts/returned-bytes", attempts-payloadAttempts, returnedBytes-payloadBytes)
	t.Log("native measured Execute inclusive phase [started completed wall]", dataplane.NativeFixtureNFQWSProbePhases(consumer))
	versionChildren := startuptools.NativeFixtureVersionChildCount(tools)
	for i := range versionChildren {
		versionChildren[i] -= versionChildrenStarted[i]
	}
	t.Log("native measured Execute actual version child Starts [iptables ip6tables IP]", versionChildren)
	t.Log("native measured Execute original metadata traversal attempts", startuptools.NativeFixtureVersionMetadataCount(tools)-metadataStarted)
	stopStackDiagnostic()
	t.Log("native measured Execute", probeElapsed, "actual inventory ToolCheck calls", toolMeasurements.calls.Load()-toolCalls, "ToolCheck wall", time.Duration(toolMeasurements.nanos.Load()-toolNanos))
	stopCPUProfile()
	if lateWait {
		if err == nil || cleaned != nil || !consumer.Pending() {
			t.Fatal("late original helper exit did not retain its lifetime", evidence, err)
		}
		if !evidence.Success || !evidence.RouteConfirmed {
			t.Fatal("fault did not follow actual owned service flow", evidence, err)
		}
		if failure := epoch.Finish(original, nil, err); failure == nil {
			t.Fatal("unknown original helper Wait published eligibility")
		}
		retryCtx := startuptools.WithCommandAdmission(original, admission)
		completion, cleanupErr := consumer.RetryKnownCleanup(retryCtx)
		if cleanupErr != nil || completion == nil || consumer.Pending() {
			t.Fatal("actual original late Wait cleanup failed", cleanupErr)
		}
		if err := completion.CloseRuntime(); err != nil {
			t.Fatal(err)
		}
		if err := env.runtimeRetired(); err != nil {
			t.Fatal(err)
		}
		if err := readEmpty(original); err != nil {
			t.Fatal("late cleanup retained packets/rules", err)
		}
		snapshot := lab.SnapshotWithContext(original)
		if !snapshot.QuiescenceUnknown || len(snapshot.Evidence) != 0 {
			t.Fatal("physical cleanup cleared source fence or published delayed PASS", snapshot)
		}
		t.Log("actual late original helper exit: sole Wait custody + exact ACK CAS + same COMMON removal confirmed; runtime released; source unknown/finalizing preserved; no delayed PASS")
		return
	}
	if err != nil || cleaned == nil {
		managedProbeNativeProcessDiagnostic(t, manager.StateRoot, adapter.StateRoot)
		t.Fatal("actual managed kernel/flow consumer", evidence, err)
	}
	if !evidence.Success || !evidence.RouteConfirmed || evidence.HTTPStatus != 200 {
		t.Fatal("native flow not confirmed", evidence)
	}
	if len(revoke) > 0 {
		beforeImage, err := os.ReadFile(lab.Path)
		if err != nil {
			t.Fatal(err)
		}
		callbackFailure := errors.New("original native observation callback failed")
		called := false
		readErr := epoch.WithProbeReferenceCurrent(original, source, runtime, control, func(strategylab.CandidateProbeReference) error {
			called = true
			var closeErr error
			switch revoke[0] {
			case "source":
				closeErr = source.Close()
			case "runtime":
				closeErr = runtime.Close()
			case "control":
				closeErr = control.Close()
			case "environment":
				closeErr = a.Store.SetSafeMode(true)
			default:
				t.Fatal("unknown native revocation")
			}
			return errors.Join(callbackFailure, closeErr)
		})
		// Store revision refusal is intentionally preserved by the real
		// exclusion observer; source/runtime/control revoke their own owner.
		revoked := errors.Is(readErr, strategylab.ErrSelectedCandidateChanged) || errors.Is(readErr, dataplane.ErrReviewChanged)
		if revoke[0] == "environment" {
			revoked = errors.Is(readErr, config.ErrRevisionChanged)
		}
		if !called || !errors.Is(readErr, callbackFailure) || !revoked {
			t.Fatal("actual closing revocation or original callback failure lost", readErr)
		}
		// Cleanup was independently confirmed before the revocation. Refusing
		// stale publication must not fabricate a cleanup failure or new fence.
		if err := epoch.Finish(original, &evidence, nil); err == nil {
			t.Fatal("revoked original owner published stale PASS")
		}
		if err := cleaned.CloseRuntime(); err != nil {
			t.Fatal(err)
		}
		if consumer.Pending() {
			t.Fatal("known cleanup acquired a pending owner")
		}
		if err := readEmpty(original); err != nil {
			t.Fatal("original physical cleanup lost", err)
		}
		afterImage, err := os.ReadFile(lab.Path)
		if err != nil || !bytes.Equal(beforeImage, afterImage) || len(lab.Snapshot().Evidence) != 0 {
			t.Fatal("revocation mutated StrategyLab or published evidence", err)
		}
		t.Log("actual closing", revoke[0], "revocation refused stale evidence; callback error retained; same physical cleanup confirmed")
		return
	}
	// Genuine owner regression: a read receives detached data and its error
	// survives fresh closing material checks after the physical cleanup.
	beforeReference, err := source.ManagedReference(original, runtime, control)
	if err != nil {
		t.Fatal(err)
	}
	observationFailure := errors.New("native detached observation failed")
	observeErr := epoch.WithProbeReferenceCurrent(original, source, runtime, control, func(reference strategylab.CandidateProbeReference) error {
		if len(reference.Material.Arguments) == 0 {
			t.Fatal("native candidate has no actual arguments")
		}
		reference.Material.Arguments[0] = "changed-local-comparison"
		return observationFailure
	})
	afterReference, referenceErr := source.ManagedReference(original, runtime, control)
	if !errors.Is(observeErr, observationFailure) || errors.Is(observeErr, strategylab.ErrSelectedCandidateChanged) || referenceErr != nil || !reflect.DeepEqual(beforeReference, afterReference) {
		t.Fatal("reference observation lost errors, freshness or detachment", observeErr, referenceErr)
	}
	if err := epoch.Finish(original, &evidence, nil); err != nil {
		t.Fatal(err)
	}
	if err := epoch.WithProbeReferenceCurrent(original, source, runtime, control, func(strategylab.CandidateProbeReference) error {
		t.Fatal("completed original epoch reached an observation")
		return nil
	}); !errors.Is(err, strategylab.ErrSelectedCandidateChanged) {
		t.Fatal("completed original epoch remained active", err)
	}
	if err := cleaned.CloseRuntime(); err != nil {
		t.Fatal(err)
	}
	if err := env.runtimeRetired(); err != nil {
		t.Fatal(err)
	}
	if err := readEmpty(original); err != nil {
		t.Fatal("actual cleanup retained queue/rules", err)
	}
	snapshot := lab.SnapshotWithContext(original)
	if len(snapshot.Evidence) != 1 || snapshot.QuiescenceUnknown {
		t.Fatal("native publication missing or fenced", snapshot)
	}
	t.Log("actual isolated consumer: managed native validation + held source socket + queue200 + wrong-source negative + exact counters + TLS/catalogue predicates + soleWait/ACK + COMMON cleanup; platform/WAN classification modeled; no router/LAN acceptance")
}

func managedProbeNativeStackDeadline(t *testing.T) func() {
	done := make(chan struct{})
	timer := time.AfterFunc(12*time.Second, func() {
		defer close(done)
		data := make([]byte, 64<<10)
		used := goruntime.Stack(data, true)
		t.Log("native parent goroutine stacks before bounded probe deadline:\n" + string(data[:used]))
	})
	var once sync.Once
	return func() {
		once.Do(func() {
			if !timer.Stop() {
				<-done
			}
		})
	}
}

// Read-only diagnostics for this explicitly isolated CI tree. Emit only
// closed protocol phase/receipt fields, never keys, PEM or arbitrary files.
func managedProbeNativeProcessDiagnostic(t *testing.T, stateRoot, processRoot string) {
	t.Helper()
	for _, path := range []string{filepath.Join(stateRoot, "latest-execution.json"), filepath.Join(processRoot, "ownership.json")} {
		f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
		if err != nil {
			t.Log("native retained diagnostic", filepath.Base(path), err)
			continue
		}
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() > 2<<20 {
			_ = f.Close()
			t.Log("native retained diagnostic is not a bounded regular file", filepath.Base(path), err)
			continue
		}
		var record struct {
			State        string
			Resources    []struct{ Kind, State, Phase string }
			Receipt      components.NFQWSSupervisionReceipt `json:"process_receipt"`
			Acknowledged bool                               `json:"process_acknowledged"`
		}
		decodeErr := json.NewDecoder(io.LimitReader(f, 2<<20)).Decode(&record)
		_ = f.Close()
		t.Log("native retained diagnostic", filepath.Base(path), "decode", decodeErr, "state", record.State, "resources", record.Resources, "receipt", record.Receipt.State, "started", record.Receipt.Started, "WaitECHILD", record.Receipt.WaitECHILD, "ACK", record.Acknowledged, "PID", record.Receipt.PID, "exit", record.Receipt.ExitCode)
	}
}

func managedProbeNativeErrorChain(t *testing.T, err error, depth int) {
	if err == nil || depth > 12 {
		return
	}
	t.Logf("native diagnostic[%d] %T: %v", depth, err, err)
	if many, ok := err.(interface{ Unwrap() []error }); ok {
		for _, child := range many.Unwrap() {
			managedProbeNativeErrorChain(t, child, depth+1)
		}
	} else if one, ok := err.(interface{ Unwrap() error }); ok {
		managedProbeNativeErrorChain(t, one.Unwrap(), depth+1)
	}
}

func serveManagedProbeNativeTLS(t *testing.T, root string, listen ...func() (net.Listener, error)) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "managed-probe.example"}, DNSNames: []string{"managed-probe.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "native-ca.pem")
	if err := os.WriteFile(path, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", path)
	var listener net.Listener
	if len(listen) == 0 {
		listener, err = net.Listen("tcp4", "8.8.8.8:443")
	} else {
		listener, err = listen[0]()
	}
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("owned-native-service"))
	}), ReadHeaderTimeout: 2 * time.Second}
	go func() {
		_ = server.Serve(tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}))
	}()
	t.Cleanup(func() { _ = server.Close() })
}
