package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// The SAME test binary is a private CLI model only for the existing fixture's
// child process. This avoids requiring a compiler on a native test router.
// No WG command is implemented: the exact kernel observations remain models.
func init() {
	if os.Getenv("RAZVILKA_WG_COMMAND_CLI_MODEL") != "1" {
		return
	}
	f, err := os.OpenFile(os.Getenv("RAZVILKA_WG_COMMAND_TEST_MARKER"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		os.Exit(2)
	}
	_, err = f.WriteString(strings.Join(os.Args[1:], " ") + "\n")
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		os.Exit(3)
	}
	os.Exit(0)
}

// Reuse the existing WG fixture's plan/profile. Gate/control/Manager/owned
// files and the child Start/Wait are genuine; LAN/kernel/probe facts remain
// that fixture's explicit models. This does not claim a native WG/App path.
func wgNetworkCommandOwnerFixture(t *testing.T) (*WARPWireGuardAdapter, *wgOperationOwner, context.Context, context.CancelFunc, func(), string) {
	t.Helper()
	a, _, plan, _, _ := wgNetworkLifecycleFixture(t, true)
	program, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	a.IP, a.WG = program, program
	return wgNetworkCommandOwnerForPlan(t, a, plan)
}

func wgNetworkCommandOwnerForPlan(t *testing.T, a *WARPWireGuardAdapter, plan Plan) (*WARPWireGuardAdapter, *wgOperationOwner, context.Context, context.CancelFunc, func(), string) {
	t.Helper()
	// These fixtures inherit this test binary as their actual child. Keep all
	// race checks and the genuine Wait, but omit the race runtime's artificial
	// exit sleep: it alone exhausts a one-second cleanup budget and compounds
	// across COMMON's many commands. The current parent runtime is unchanged.
	t.Setenv("GORACE", strings.TrimSpace(os.Getenv("GORACE")+" atexit_sleep_ms=0"))
	a.Runner = wgExecRunner{adapter: a}
	manager := New(t.TempDir())
	if err := manager.Register(a); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	gate := &operationgate.Gate{}
	ctx, release, err := gate.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	controlRoot := filepath.Join(t.TempDir(), "control")
	if _, err := operationgate.InitializeSelfUpdateControl(ctx, controlRoot); err != nil {
		t.Fatal(err)
	}
	control, err := gate.ReviewControlEpoch(ctx, controlRoot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	var material *WGOperationMaterial
	ctx = WithReviewGuard(ctx, func(c context.Context) error {
		if material != nil && material.IsCleanupContext(c) {
			return control.CurrentForCleanup(c)
		}
		return control.Current(c)
	})
	material, err = ReviewWGOperationMaterial(ctx, manager, control, plan.LAN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = material.Close() })
	ctx, err = material.Context(ctx)
	if err != nil {
		t.Fatal(err)
	}
	plan.PlanID, plan.Digest, plan.Adapters = "dp-0123456789abcdef", strings.Repeat("b", 64), []string{a.ID()}
	if err := manager.beginOperation(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.endOperation)
	execution := Execution{PlanID: plan.PlanID, Digest: plan.Digest, State: "applying"}
	root := filepath.Join(manager.StateRoot, "transactions", plan.PlanID)
	if err := manager.prepareExecutionRoot(root); err != nil {
		t.Fatal(err)
	}
	scope, err := manager.newExecutionResourceScope(ctx, plan, a.ID(), &execution, root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = scope.close() })
	owner, err := newWGOperationOwner(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err = owner.context(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return a, owner, ctx, cancel, release, controlRoot
}

func TestWGOperationCommandProcess(t *testing.T) {
	mode := os.Getenv("RAZVILKA_WG_COMMAND_TEST_PROCESS")
	if mode == "" {
		return
	}
	if err := os.WriteFile(os.Getenv("RAZVILKA_WG_COMMAND_TEST_MARKER"), []byte("started"), 0600); err != nil {
		t.Fatal(err)
	}
	if mode == "wait" {
		time.Sleep(time.Minute)
	}
}

func TestWGNetworkCommandOwnerActualStartStopAndOriginalCleanup(t *testing.T) {
	a, owner, ctx, _, release, controlRoot := wgNetworkCommandOwnerFixture(t)
	marker := filepath.Join(t.TempDir(), "started")
	t.Setenv("RAZVILKA_WG_COMMAND_TEST_PROCESS", "echo")
	t.Setenv("RAZVILKA_WG_COMMAND_TEST_MARKER", marker)
	args := []string{"-test.run=^TestWGOperationCommandProcess$"}
	if _, err := a.Runner.Run(ctx, a.IP, args...); !errors.Is(err, ErrWGOperationOwner) {
		t.Fatal("direct runner created native issuer", err)
	}
	if _, err := a.run(ctx, a.IP, args...); err != nil {
		t.Fatal("actual original Start/Wait", err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if _, err := operationgate.RequestSelfUpdateStop(ctx, controlRoot, strings.Repeat("c", 32), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := a.run(ctx, a.IP, args...); err == nil {
		t.Fatal("Start after durable Stop")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("rejected Start ran child", err)
	}
	cleanup, cancel := context.WithTimeout(wgNamedCleanupContext(context.WithoutCancel(ctx)), time.Second)
	defer cancel()
	if _, err := a.run(cleanup, a.IP, args...); err != nil {
		t.Fatal("original preissued cleanup Start/Wait after Stop", err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	release()
	if _, err := a.run(cleanup, a.IP, args...); err == nil {
		t.Fatal("cleanup after original release")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("released cleanup ran child", err)
	}
	if err := owner.material.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWGNetworkCommandOwnerCancellationJoinsWaitAndClose(t *testing.T) {
	a, owner, ctx, cancelOriginal, _, controlRoot := wgNetworkCommandOwnerFixture(t)
	marker := filepath.Join(t.TempDir(), "started")
	t.Setenv("RAZVILKA_WG_COMMAND_TEST_PROCESS", "wait")
	t.Setenv("RAZVILKA_WG_COMMAND_TEST_MARKER", marker)
	result := make(chan error, 1)
	go func() { _, err := a.run(ctx, a.IP, "-test.run=^TestWGOperationCommandProcess$"); result <- err }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("actual child did not start")
		}
		time.Sleep(time.Millisecond)
	}
	closed := make(chan error, 1)
	stopCtx, cancelStop := context.WithTimeout(context.Background(), time.Second)
	defer cancelStop()
	if _, err := operationgate.RequestSelfUpdateStop(stopCtx, controlRoot, strings.Repeat("d", 32), 0); err != nil {
		t.Fatal("Wait retained the durable Stop lock", err)
	}
	go func() { closed <- owner.material.Close() }()
	select {
	case err := <-closed:
		t.Fatal("material closed before child Wait joined", err)
	case <-time.After(15 * time.Millisecond):
	}
	cancelOriginal()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("canceled command acknowledged success")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("canceled child Wait did not join")
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("material close did not join")
	}
}

func TestWGNetworkCommandOwnerCanceledForwardRetainsCleanupOnly(t *testing.T) {
	a, _, ctx, cancelOriginal, _, _ := wgNetworkCommandOwnerFixture(t)
	marker := filepath.Join(t.TempDir(), "started")
	t.Setenv("RAZVILKA_WG_COMMAND_TEST_PROCESS", "echo")
	t.Setenv("RAZVILKA_WG_COMMAND_TEST_MARKER", marker)
	cancelOriginal()
	args := []string{"-test.run=^TestWGOperationCommandProcess$"}
	detached, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer cancel()
	if _, err := a.run(detached, a.IP, args...); err == nil {
		t.Fatal("detachment revived forward Start")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("detached forward ran child", err)
	}
	if _, err := a.run(wgNamedCleanupContext(detached), a.IP, args...); err != nil {
		t.Fatal("preissued cleanup lost original owner", err)
	}
}

func TestWGNetworkCommandOwnerRejectsCopiedForeignAndMissingScope(t *testing.T) {
	a, owner, ctx, _, _, _ := wgNetworkCommandOwnerFixture(t)
	args := []string{"-test.run=^TestWGOperationCommandProcess$"}
	for _, wrong := range []context.Context{
		context.WithValue(ctx, wgOperationOwnerKey{}, "wrong owner type"),
		context.WithValue(ctx, wgOperationMaterialKey{}, "wrong material type"),
		context.WithValue(context.WithValue(ctx, wgOperationOwnerKey{}, "wrong owner type"), wgOperationMaterialKey{}, "wrong material type"),
		context.WithValue(ctx, wgOperationOwnerKey{}, (*wgOperationOwner)(nil)),
		context.WithValue(ctx, wgOperationMaterialKey{}, (*WGOperationMaterial)(nil)),
		context.WithValue(ctx, wgOperationMaterialKey{}, &WGOperationMaterial{}),
	} {
		if _, err := a.run(wrong, a.IP, args...); !errors.Is(err, ErrWGOperationOwner) {
			t.Fatal("present invalid issuer downgraded to legacy", err)
		}
	}
	materialOnly := context.WithValue(ctx, wgOperationOwnerKey{}, nil)
	if _, err := a.run(materialOnly, a.IP, args...); !errors.Is(err, ErrWGOperationOwner) {
		t.Fatal("material alone issued command owner", err)
	}
	copy := &wgOperationOwner{self: owner.self, material: owner.material, scope: owner.scope, adapter: owner.adapter, shape: owner.shape}
	copied := context.WithValue(ctx, wgOperationOwnerKey{}, copy)
	if _, err := a.run(copied, a.IP, args...); !errors.Is(err, ErrWGOperationOwner) {
		t.Fatal("copied private owner", err)
	}
	other := NewWireGuardAdapter(a.Configs, t.TempDir())
	if _, err := other.Runner.Run(ctx, a.IP, args...); !errors.Is(err, ErrWGOperationOwner) {
		t.Fatal("foreign registered adapter", err)
	}
	foreignGate := &operationgate.Gate{}
	foreign, cancelForeign := context.WithTimeout(context.Background(), time.Second)
	defer cancelForeign()
	foreign, releaseForeign, err := foreignGate.ExclusiveContext(foreign)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseForeign()
	foreign = context.WithValue(context.WithValue(foreign, wgOperationMaterialKey{}, owner.material), wgOperationOwnerKey{}, owner)
	if _, err := a.run(foreign, a.IP, args...); err == nil {
		t.Fatal("foreign Gate operation adopted original owner")
	}
	owner.scope.manager.StateRoot += "-foreign"
	if _, err := a.run(ctx, a.IP, args...); !errors.Is(err, ErrWGOperationOwner) {
		t.Fatal("changed Manager root", err)
	}
}

func TestWGNetworkCommandOwnerCommonReceiptActualRunner(t *testing.T) {
	// The existing lifecycle fixture supplies explicit kernel/health models
	// and a genuine immutable WG binding/COMMON receipt. A private CLI model
	// accepts the compiler's argv; its actual process Start/Wait runs unchanged.
	a, _, plan, transaction, fixtureCtx := wgNetworkLifecycleFixture(t, true)
	for _, step := range []func(context.Context, Plan, string) error{a.Snapshot, a.Stage, a.Activate, a.Commit} {
		if err := step(fixtureCtx, plan, transaction); err != nil {
			t.Fatal(err)
		}
	}
	state, exists, err := a.loadPolicyState()
	if err != nil || !exists {
		t.Fatal(err)
	}
	ref, err := a.committedWGPolicyReference(state)
	if err != nil {
		t.Fatal(err)
	}
	ref.ID = strings.Repeat("e", 32) // new private test generation, never an App proof
	ref.Checksum = wgPolicyReferenceChecksum(ref)
	compiled, err := a.compileWGNetworkEffects(ref)
	if err != nil {
		t.Fatal(err)
	}
	program, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	a.IP, a.WG, a.IPTables, a.IP6Tables = program, program, program, program
	a, owner, ctx, _, _, controlRoot := wgNetworkCommandOwnerForPlan(t, a, plan)
	marker := filepath.Join(t.TempDir(), "commands")
	t.Setenv("RAZVILKA_WG_COMMAND_CLI_MODEL", "1")
	t.Setenv("RAZVILKA_WG_COMMAND_TEST_MARKER", marker)
	presence := make([]int, len(compiled.plan.Effects)) // explicit exact-kernel model
	var escaped context.Context
	trusted := wgPolicyCommandRunner{base: a.Runner, command: wgPolicyCommand{adapter: a, ref: ref, compiled: compiled}}
	rt := PolicyEffectRuntime{Tools: PolicyEffectTools{IP: program, IPTables: program, IP6Tables: program}, Preflight: func(c context.Context) error { return c.Err() }, BeforeDelete: func(c context.Context, _ int) error { return c.Err() }, Guard: func(c context.Context, _ int) error { return c.Err() }, ExactPresence: func(_ context.Context, i int) (int, error) { return presence[i], nil }}
	rt.Runner = policyEffectInvocationTestRunner(func(c context.Context, name string, args ...string) ([]byte, error) {
		escaped = context.WithValue(c, wgPolicyCommandKey{}, trusted.command)
		out, err := trusted.Run(c, name, args...)
		if err == nil {
			i := c.Value(policyEffectCommandInvocationKey{}).(*policyEffectCommandInvocation)
			if i.cleanup {
				presence[i.index] = 0
			} else {
				presence[i.index] = 1
			}
		}
		return out, err
	})
	receiptRoot := a.wgPolicyGenerationRoot(ref, "")
	if err := os.MkdirAll(receiptRoot, 0700); err != nil {
		t.Fatal(err)
	}
	if err := applyPolicyEffects(ctx, rt, compiled.plan, receiptRoot, a.policyReceiptOptions); err != nil {
		t.Fatal("actual COMMON add Start/Wait", err)
	}
	before, err := os.ReadFile(marker)
	if err != nil || len(before) == 0 {
		t.Fatal("COMMON add did not start CLI model", err)
	}
	last := len(compiled.plan.Effects) - 1
	if _, err := a.Runner.Run(escaped, program, compiled.plan.Effects[last].Add...); err == nil {
		t.Fatal("escaped COMMON issuer restarted command")
	}
	if after, err := os.ReadFile(marker); err != nil || string(after) != string(before) {
		t.Fatal("escaped COMMON context launched CLI", err)
	}
	if _, err := operationgate.RequestSelfUpdateStop(ctx, controlRoot, strings.Repeat("f", 32), 0); err != nil {
		t.Fatal(err)
	}
	cleanup, cancelCleanup := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancelCleanup()
	cleanup, err = owner.cleanupContext(cleanup)
	if err != nil {
		t.Fatal(err)
	}
	if err := removePolicyEffects(cleanup, rt, compiled.plan, receiptRoot, a.policyReceiptOptions); err != nil {
		t.Fatal("actual COMMON original cleanup Start/Wait", err)
	}
	for _, count := range presence {
		if count != 0 {
			t.Fatal("COMMON cleanup did not settle")
		}
	}
	status, err := inspectPolicyEffects(cleanup, compiled.plan, receiptRoot, a.policyReceiptOptions)
	if err != nil || !status.Removed || status.Unknown {
		t.Fatal("original COMMON removal receipt", status, err)
	}
}

type wgNetworkLANReadbackRunner struct {
	base     NFQWS2Runner
	kernel   *warpFakeRunner
	firewall *proxyFirewallFake
}

func (r wgNetworkLANReadbackRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	plain := strings.Join(args, " ")
	if name == "iptables" || name == "ip6tables" {
		if r.firewall == nil {
			return nil, errors.New("network firewall inventory model is unavailable")
		}
		return r.firewall.Run(ctx, name, args...)
	}
	if name == "ip" {
		prefix, router, connected := netip.MustParsePrefix("192.168.1.0/24"), "192.168.1.1", "192.168.1.0/24 dev br0 proto kernel scope link src 192.168.1.1\n"
		address := "2: br0: <BROADCAST,MULTICAST,UP> mtu 1500\n    inet 192.168.1.1/24 scope global br0\n"
		wan := "default via 93.184.216.1 dev wan0\n"
		if strings.HasPrefix(plain, "-N ") {
			plain = strings.TrimPrefix(plain, "-N ")
		}
		modelArgs := args
		if len(args) > 1 && args[0] == "-N" && args[1] == "-details" {
			plain = strings.TrimPrefix(plain, "-details ")
			modelArgs = append([]string{"-N"}, args[2:]...)
		}
		if strings.HasPrefix(plain, "-6 ") {
			prefix, router = netip.MustParsePrefix("fd01::/64"), "fd01::1"
			connected = "fd01::/64 dev br0 proto kernel scope link\n"
			address = "2: br0: <BROADCAST,MULTICAST,UP> mtu 1500\n    inet6 fd01::1/64 scope global\n"
			wan = "default via 2001:db8::1 dev wan0\n"
			plain = strings.TrimPrefix(plain, "-6 ")
		}
		if plain == "-j route show table 206" {
			data, err := r.base.Run(ctx, name, modelArgs...)
			if err != nil {
				return data, err
			}
			var rows []json.RawMessage
			if json.Unmarshal(data, &rows) != nil {
				return nil, errors.New("complete table model unavailable")
			}
			family, metric, scope := "4", 0, 253
			if prefix.Addr().Is6() {
				family, metric, scope = "6", 1024, 0
			}
			if line := r.kernel.policy.defaults[family+"/206"]; line != "" {
				fields := strings.Fields(line)
				if len(fields) != 7 || fields[0] != "default" || fields[1] != "dev" || fields[3] != "proto" || fields[4] != "boot" || fields[5] != "metric" || fields[6] != strconv.Itoa(metric) {
					return nil, errors.New("noncanonical default table model")
				}
				row, _ := json.Marshal(map[string]any{"type": "1", "dst": "default", "dev": fields[2], "table": 206, "protocol": 3, "scope": scope, "metric": metric})
				rows = append(rows, row)
			}
			return json.Marshal(rows)
		}
		if plain == "route show table main default" {
			r.kernel.calls = append(r.kernel.calls, name+" "+strings.Join(args, " "))
			return []byte(wan), nil
		}
		if plain == "addr show dev br0" {
			r.kernel.calls = append(r.kernel.calls, name+" "+strings.Join(args, " "))
			return []byte(address), nil
		}
		if strings.HasPrefix(plain, "route get ") && len(strings.Fields(plain)) == 3 {
			source, err := netip.ParseAddr(strings.TrimPrefix(plain, "route get "))
			if err == nil && prefix.Contains(source) {
				r.kernel.calls = append(r.kernel.calls, name+" "+strings.Join(args, " "))
				if source.String() == router {
					return []byte("local " + router + " dev lo"), nil
				}
				return []byte(source.String() + " dev br0"), nil
			}
		}
		if plain == "route show table main" || plain == "route show table main scope link" || strings.HasPrefix(plain, "route show table main match ") {
			r.kernel.calls = append(r.kernel.calls, name+" "+strings.Join(args, " "))
			return []byte(connected), nil
		}
		fields := strings.Fields(plain)
		if len(fields) == 9 && fields[0] == "route" && fields[1] == "get" && fields[3] == "from" && fields[5] == "iif" && fields[6] == "br0" && fields[7] == "mark" && fields[8] == "0x20000000" {
			destination, de := netip.ParseAddr(fields[2])
			source, se := netip.ParseAddr(fields[4])
			found := false
			for _, row := range r.kernel.policy.entries {
				sourceScope, sfe := netip.ParsePrefix(row.source)
				destScope, dfe := netip.ParsePrefix(row.dest)
				if de == nil && se == nil && sfe == nil && dfe == nil && sourceScope.Contains(source) && destScope.Contains(destination) && row.ingress == "br0" && row.mark == LANPolicyGateMatch && row.table == "206" {
					found = true
				}
			}
			if found {
				r.kernel.calls = append(r.kernel.calls, name+" "+strings.Join(args, " "))
				return []byte(strings.TrimPrefix(plain, "route get ") + " dev rz-wg table 206"), nil
			}
		}
	}
	return r.base.Run(ctx, name, args...)
}

func wgNetworkLifecycleFixture(t *testing.T, ipv6 bool) (*WARPWireGuardAdapter, *warpFakeRunner, Plan, string, context.Context) {
	t.Helper()
	profile := testOwnWireGuardProfile("")
	if ipv6 {
		profile = strings.Replace(profile, "Address = 10.66.0.2/32", "Address = 10.66.0.2/32, fd66::2/128", 1)
		profile = strings.Replace(profile, "AllowedIPs = 0.0.0.0/0", "AllowedIPs = 0.0.0.0/0, ::/0", 1)
	}
	a, r, plan, root := ownWireGuardFixture(t, profile)
	firewall := &proxyFirewallFake{}
	a.Runner = wgNetworkLANReadbackRunner{base: r, kernel: r, firewall: firewall}
	a.IPTables, a.IP6Tables = "iptables", "ip6tables"
	a.networkLANBridgeMembers = func(_ context.Context, iface string) ([]string, error) {
		if iface != "br0" {
			return nil, errors.New("unknown LAN bridge")
		}
		return []string{"lan0"}, nil
	}
	plan.Routes = []Route{{ServiceID: "network", ServiceName: "network", Resolved: "wireguard", CIDRs: []string{"0.0.0.0/0"}, Sources: []string{"192.168.1.0/24"}, Ingress: []string{"br0"}, NetworkPolicyGeneration: strings.Repeat("a", 64), NetworkPolicyRole: "default", ProbeURL: "https://example.org/"}}
	if ipv6 {
		plan.Routes[0].CIDRs = append(plan.Routes[0].CIDRs, "::/0")
		plan.Routes[0].Sources = append(plan.Routes[0].Sources, "fd01::/64")
	}
	var err error
	plan.LAN, err = CompileLANPolicyRuntime(plan.Routes[0].NetworkPolicyGeneration, []LANPolicyIngress{{SegmentID: "lan", Interface: "br0", Sources: plan.Routes[0].Sources, Membership: "all"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), reviewGuardKey{}, func(context.Context) error { return nil })
	a.CanaryProbe = func(context.Context, string, string) error { return nil }
	a.networkUDPProbe = func(context.Context, netip.Addr) error { return nil }
	return a, r, plan, root, ctx
}

func TestWGNetworkStageRetainsEndpointInsideLANDefault(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		a, r, plan, root, ctx := wgNetworkLifecycleFixture(t, ipv6)
		if err := a.Snapshot(ctx, plan, root); err != nil {
			t.Fatal(err)
		}
		if err := a.Stage(ctx, plan, root); err != nil {
			t.Fatal(err)
		}
		state, err := a.readStagedPolicy(root)
		if err != nil || state.WireGuardEndpoint == nil || state.WireGuardEndpoint.Table != 213 || state.Table != 206 || state.RuleLayout != 2 || !state.NetworkDefault || state.NetworkPolicyGeneration != strings.Repeat("a", 64) || len(state.Exclusions) != 0 {
			t.Fatal("network stage lost dedicated transport shape", state, err)
		}
		if strings.Join(state.Prefixes, ",") != "0.0.0.0/0" && !ipv6 || ipv6 && len(state.Prefixes) != 2 {
			t.Fatal("endpoint was carved out of LAN default", state.Prefixes)
		}
		for _, rule := range state.Rules {
			if !rule.Managed || rule.Ingress != "br0" || rule.Source == "" {
				t.Fatal("network selectors lack positive admission", rule)
			}
		}
		assertWGCanaryNoMutations(t, r.calls, root)
	}
}

func TestWGNetworkRejectsMissingOrChangedFrozenLANSources(t *testing.T) {
	for _, cut := range []string{"missing", "generation", "ingress", "source", "checksum"} {
		t.Run(cut, func(t *testing.T) {
			a, r, plan, root, ctx := wgNetworkLifecycleFixture(t, true)
			switch cut {
			case "missing":
				plan.LAN = nil
			case "generation":
				plan.LAN, _ = CompileLANPolicyRuntime(strings.Repeat("b", 64), plan.LAN.Ingress)
			case "ingress":
				plan.Routes[0].Ingress = []string{"lan-other"}
			case "source":
				plan.Routes[0].Sources = []string{"192.168.2.0/24", "fd02::/64"}
			case "checksum":
				plan.LAN.Ingress[0].Sources[0] = "192.168.2.0/24"
			}
			if err := a.Snapshot(ctx, plan, root); err != nil {
				t.Fatal(err)
			}
			if err := a.Stage(ctx, plan, root); err == nil {
				t.Fatal("scalar/unfrozen scope admitted", cut)
			}
			assertWGCanaryNoMutations(t, r.calls, root)
		})
	}
}

func TestWGNetworkLifecycleUsesReviewedFamilyHealthAndImmutableReceipt(t *testing.T) {
	a, r, plan, root, ctx := wgNetworkLifecycleFixture(t, true)
	var calls []string
	a.CanaryProbe = func(c context.Context, _ string, source string) error {
		calls = append(calls, "tcp/"+source)
		if c.Value(wgSocketInterfaceKey{}) != "rz-wg-canary" {
			t.Fatal("candidate TCP escaped", c.Value(wgSocketInterfaceKey{}))
		}
		return nil
	}
	a.networkUDPProbe = func(c context.Context, source netip.Addr) error {
		calls = append(calls, "udp/"+source.String())
		if c.Value(wgSocketInterfaceKey{}) != "rz-wg-canary" {
			t.Fatal("candidate UDP escaped")
		}
		return nil
	}
	for _, step := range []func(context.Context, Plan, string) error{a.Snapshot, a.Stage, a.Validate} {
		if err := step(ctx, plan, root); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Canary(ctx, plan.RoutePlanFor(a.ID()), root); err != nil {
		t.Fatal(err)
	}
	if strings.Join(calls, ",") != "tcp/10.66.0.2,udp/10.66.0.2,tcp/fd66::2,udp/fd66::2" {
		t.Fatal("family/class evidence incomplete", calls)
	}
	if err := a.Activate(ctx, plan, root); err != nil {
		t.Fatal(err)
	}
	if err := a.Commit(ctx, plan, root); err != nil {
		t.Fatal(err)
	}
	state, exists, err := a.loadPolicyState()
	if err != nil || !exists {
		t.Fatal(err)
	}
	ref, err := a.committedWGPolicyReference(state)
	if err != nil || ref.NetworkHealthVersion != wgNetworkHealthVersion {
		t.Fatal("receipt lacks immutable health implementation version", ref, err)
	}
	if err := a.verifyWGEndpoint(ctx, state.WireGuardEndpoint, ref.FrozenLAN); err != nil {
		t.Fatal(err)
	}
	for _, row := range r.policy.entries {
		if row.table != "206" || row.ingress != "br0" || row.mark != LANPolicyGateMatch || row.priority != 71 {
			t.Fatal("LAN route has unreviewed selector", row)
		}
	}
	if len(r.endpoint.routes) != 1 {
		t.Fatal("transport table changed other routes", r.endpoint.routes)
	}
	for _, row := range r.endpoint.routes {
		if !wgEndpointTableMatches(row.Table, 213) {
			t.Fatal("outer pin remained in LAN service table", row)
		}
	}
	changed := ref
	changed.NetworkHealthVersion++
	changed.Checksum = wgPolicyReferenceChecksum(changed)
	if a.validWGPolicyReference(changed) == nil {
		t.Fatal("other health contract adopted")
	}
	if err := a.Deactivate(ctx); err != nil {
		t.Fatal(err)
	}
	if r.active || len(r.endpoint.routes) != 0 || len(r.policy.entries) != 0 || len(r.policy.defaults) != 0 {
		t.Fatal("network lifecycle leaked owned resources", r.calls)
	}
}

func TestWGNetworkTransportCollisionRefusesBeforeMutation(t *testing.T) {
	for _, kind := range []string{"foreign-route4", "foreign-route6", "foreign-selector", "alias", "unknown-goto", "no-review", "missing-family"} {
		t.Run(kind, func(t *testing.T) {
			a, r, plan, root, ctx := wgNetworkLifecycleFixture(t, true)
			switch kind {
			case "foreign-route4":
				r.endpoint.routes = map[string]wgEndpointRoute{"4|203.0.113.9/32": {Destination: "203.0.113.9/32", Device: "foreign", Table: json.RawMessage("213")}}
			case "foreign-route6":
				r.endpoint.routes = map[string]wgEndpointRoute{"6|2001:db8::9/128": {Destination: "2001:db8::9/128", Device: "foreign", Table: json.RawMessage("213")}}
			case "foreign-selector":
				r.policy.foreignIPv4 = []string{"100: from all lookup 213"}
			case "alias":
				r.policy.foreignIPv4 = []string{"100: from all lookup transport-wg"}
			case "unknown-goto":
				r.policy.foreignIPv4 = []string{"53: from all iif br0 goto 70"}
			case "no-review":
				ctx = context.Background()
			case "missing-family":
				plan.Routes[0].CIDRs = []string{"::/0"}
				profile := testOwnWireGuardProfile("")
				if _, err := a.Configs.Stage("wireguard", "main", profile); err != nil {
					t.Fatal(err)
				}
			}
			if err := a.Snapshot(ctx, plan, root); err != nil {
				t.Fatal(err)
			}
			if err := a.Stage(ctx, plan, root); err == nil {
				t.Fatal("unproved network transport admitted")
			}
			assertWGCanaryNoMutations(t, r.calls, root)
		})
	}
}

func TestWGNetworkValidateRejectsLegacyTransportTable(t *testing.T) {
	a, _, plan, root, ctx := wgNetworkLifecycleFixture(t, false)
	if err := a.Snapshot(ctx, plan, root); err != nil {
		t.Fatal(err)
	}
	if err := a.Stage(ctx, plan, root); err != nil {
		t.Fatal(err)
	}
	state, err := a.readStagedPolicy(root)
	if err != nil {
		t.Fatal(err)
	}
	state.WireGuardEndpoint.Table = state.Table
	data, _ := json.Marshal(state)
	if err := writeAtomic(filepath.Join(root, "policy.staged.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.Validate(ctx, plan, root); err == nil {
		t.Fatal("legacy pin can carve network default", err)
	}
}

func TestWGNetworkLateTransportCollisionRefusesCanaryAndActivate(t *testing.T) {
	for _, phase := range []string{"canary", "activate"} {
		t.Run(phase, func(t *testing.T) {
			a, r, plan, root, ctx := wgNetworkLifecycleFixture(t, false)
			for _, step := range []func(context.Context, Plan, string) error{a.Snapshot, a.Stage, a.Validate} {
				if err := step(ctx, plan, root); err != nil {
					t.Fatal(err)
				}
			}
			r.endpoint.routes = map[string]wgEndpointRoute{"4|203.0.113.9/32": {Destination: "203.0.113.9/32", Device: "foreign", Table: json.RawMessage("213")}}
			r.calls = nil
			var err error
			if phase == "canary" {
				err = a.Canary(ctx, plan.RoutePlanFor(a.ID()), root)
			} else {
				err = a.Activate(ctx, plan, root)
			}
			if err == nil {
				t.Fatal("late transport table collision admitted")
			}
			assertWGCanaryNoMutations(t, r.calls, root)
			if len(r.endpoint.routes) != 1 || r.endpoint.routes["4|203.0.113.9/32"].Device != "foreign" {
				t.Fatal("foreign pin changed")
			}
		})
	}
}

func TestWGNetworkCanarySameProfileUsesCommittedInterface(t *testing.T) {
	a, r, plan, root, ctx := wgNetworkLifecycleFixture(t, false)
	for _, step := range []func(context.Context, Plan, string) error{a.Snapshot, a.Stage, a.Activate, a.Commit} {
		if err := step(ctx, plan, root); err != nil {
			t.Fatal(err)
		}
	}
	second := filepath.Join(t.TempDir(), "transaction")
	profile := mustRead(a.RuntimeConfigPath)
	public, _ := wgRuntimePublicKey(profile)
	peer := "YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI="
	identity := &wgIdentityRunner{warpFakeRunner: r, identityTool: "wg", identities: []byte(a.interfaceName() + "\t" + public + "\n"), peerReadback: map[string]string{"peers": peer + "\n", "endpoints": peer + "\t93.184.216.34:51820\n", "allowed-ips": peer + "\t0.0.0.0/0\n", "preshared-keys": peer + "\t(none)\n"}}
	readback := a.Runner.(wgNetworkLANReadbackRunner)
	readback.base = identity
	a.Runner = readback
	for _, step := range []func(context.Context, Plan, string) error{a.Snapshot, a.Stage, a.Validate} {
		if err := step(ctx, plan, second); err != nil {
			t.Fatal(err)
		}
	}
	starts := r.starts
	a.CanaryProbe = func(c context.Context, _ string, _ string) error {
		if c.Value(wgSocketInterfaceKey{}) != a.interfaceName() {
			t.Fatal("second interface used")
		}
		return nil
	}
	if err := a.Canary(ctx, plan.RoutePlanFor(a.ID()), second); err != nil {
		t.Fatal("owned committed profile could not be checked", err)
	}
	if r.starts != starts || !r.active {
		t.Fatal("same-peer refused probe restarted runtime")
	}
}

func TestWGNetworkLiveHealthProvesExactLANSelectorsAndOwnTransports(t *testing.T) {
	a, r, plan, root, ctx := wgNetworkLifecycleFixture(t, true)
	for _, step := range []func(context.Context, Plan, string) error{a.Snapshot, a.Stage, a.Activate} {
		if err := step(ctx, plan, root); err != nil {
			t.Fatal(err)
		}
	}
	var sources []string
	a.HealthProbe = func(c context.Context, _ string) error {
		if c.Value(wgSocketInterfaceKey{}) != "rz-wg" {
			t.Fatal("live TCP escaped WG")
		}
		sources = append(sources, "tcp")
		return nil
	}
	a.networkUDPProbe = func(c context.Context, source netip.Addr) error {
		if c.Value(wgSocketInterfaceKey{}) != "rz-wg" {
			t.Fatal("live UDP escaped WG")
		}
		sources = append(sources, source.String())
		return nil
	}
	if err := a.Health(ctx, plan, root); err != nil {
		t.Fatal(err)
	}
	if strings.Join(sources, ",") != "tcp,10.66.0.2,tcp,fd66::2" {
		t.Fatal("live family/class proof incomplete", sources)
	}
	r.policy.entries[0].ingress = "br1"
	if err := a.Health(ctx, plan, root); err == nil {
		t.Fatal("changed physical LAN selector remained healthy")
	}
}
