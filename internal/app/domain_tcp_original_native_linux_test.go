//go:build linux && razvilka_native_fixture

package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/startuptools"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
	"golang.org/x/net/dns/dnsmessage"
)

func TestDomainTCPOriginalNativeAcceptedFlows(t *testing.T) {
	if os.Getenv(domainOriginalNativeEnv) != "1" {
		t.Skip("explicit disposable native original domain workflow")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	peers := domainOriginalPeers(t, ctx)
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		// Only generated local fixture logs; never dump imported profiles or
		// user state. Native errors stay observable without weakening checks.
		_ = filepath.WalkDir(peers.root, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil || entry.IsDir() || !strings.HasSuffix(entry.Name(), ".log") {
				return nil
			}
			file, err := os.Open(path)
			if err != nil {
				return nil
			}
			defer file.Close()
			data, _ := io.ReadAll(io.LimitReader(file, 8192))
			relative, _ := filepath.Rel(peers.root, path)
			t.Logf("isolated fixture %s: %s", relative, data)
			return nil
		})
	})
	provider := netidentity.NewProcProvider()
	tools, err := startuptools.AcquireNativeFixturePolicy(ctx, provider, os.Getenv("RAZVILKA_DOMAIN_TOOLS_REVIEW"))
	if err != nil {
		t.Fatalf("original protected native tool closure: %v", err)
	}
	defer tools.Close()
	descriptor, err := tools.InventoryTools()
	if err != nil {
		t.Fatal(err)
	}
	backend, err := dataplane.NewBackendInventory(provider, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	policyTools, runner, err := tools.PolicyRuntimeTools()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := provider.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	operations := &operationgate.Gate{}
	held, release, err := operations.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	controlRoot := filepath.Join(peers.root, "control")
	if _, err := operationgate.InitializeSelfUpdateControl(held, controlRoot); err != nil {
		t.Fatal(err)
	}
	control, err := operations.ReviewControlEpoch(held, controlRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	fresh := func(c context.Context) (string, error) { return "wan-0123456789ab", c.Err() }
	nodesRoot := filepath.Join(peers.root, "nodes")
	if err := os.Mkdir(nodesRoot, 0700); err != nil {
		t.Fatal(err)
	}
	nodes, err := nodestore.Open(nodesRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer nodes.Close()
	uri := fmt.Sprintf("vless://%s@%s:10443?security=tls&sni=front.example", domainOriginalUUID, domainOriginalServer)
	imported, err := nodes.Import(held, nodestore.Source{ID: "manual", Kind: "manual"}, uri, time.Now(), time.Hour, false)
	if err != nil || len(imported.Nodes) != 1 {
		t.Fatal("actual private node import", err)
	}
	nodeID := imported.Nodes[0].ID
	service := domainOriginalNativeService()
	checker := dataplane.NewExactXrayNodeCheckerSlots(filepath.Join(peers.root, "node-check"), 1)
	checker.Binary = peers.binary
	checker.Port = 29185
	checker.FreshProfile = fresh
	var checked dataplane.NodeCheckResult
	err = nodes.WithSecret(held, nodeID, func(raw []byte) error {
		var err error
		checked, err = checker.Check(held, dataplane.NodeCheckRequest{NodeID: nodeID, Outbound: raw, Service: service, NetworkProfile: "wan-0123456789ab"})
		return err
	})
	if err != nil || !checked.Available || checked.CleanupStatus != dataplane.NodeCleanupVerified {
		t.Fatalf("actual native node precheck failed: %v %+v", err, checked)
	}
	if _, err := nodes.RecordCheck(held, nodeID, nodestore.CheckRecord{ProbeID: checked.ProbeID, ServiceID: service.ID, NetworkProfile: checked.NetworkProfile, RoutePathID: checked.RoutePathID, TestLevel: checked.TestLevel, Verdict: string(checked.Verdict), State: "available", Stage: checked.Stage, CheckedAt: checked.FinishedAt, ExpiresAt: checked.ExpiresAt, LatencyMS: checked.LatencyMS, EgressIP: checked.EgressIP, HTTPStatus: checked.HTTPStatus}, time.Now()); err != nil {
		t.Fatal(err)
	}
	nodeSource, err := dataplane.ReviewNodeDefaultSource(held, nodes, "xray:"+nodeID)
	if err != nil {
		t.Fatal(err)
	}
	// SAME fixed history root and installed controller inode used by actual
	// retained-fleet admission; the script provides private tmpfs /opt.
	manager := dataplane.New("/opt/razvilka/state/dataplane")
	manager.FreshProfile = fresh
	// Physical stock/platform classification is explicitly modeled. The actual
	// topology's IP/MAC/interface equals this immutable selected-client scope.
	now := time.Now().UTC()
	policy := &config.NetworkPolicy{Schema: 2, Revision: 1, Clients: config.ClientScope{Mode: "lan_except", SegmentIDs: []string{"home"}, ExcludedDeviceIDs: []string{"excluded"}, NewDevices: "inherit"}, Traffic: config.TrafficSelection{Mode: "selected_services", Unavailable: "block"}}
	scope := autonomy.ScopeObservation{BootID: identity.BootID, NetworkID: fmt.Sprintf("namespace-%d", identity.Inode), Revision: 1, ObservedAt: now, FreshUntil: now.Add(60 * time.Second), Segments: []autonomy.HomeSegment{{ID: "home", Interface: "br0", Home: true, Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}}}, Devices: []autonomy.DeviceBinding{{ID: "selected", MAC: "02:00:00:00:00:02", Interface: "br0", SegmentID: "home", Confirmed: true}, {ID: "excluded", MAC: "02:00:00:00:00:01", Interface: "br0", SegmentID: "home", Confirmed: true}}}
	domain, err := dataplane.FreezeDomainPolicyRuntimePlan(strings.Repeat("a", 64), policy, scope, nil, []dataplane.DomainPolicyService{{ID: service.ID, Route: "xray:" + nodeID, Selected: true, Domains: service.Domains}}, now)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.SafeMode = false
	cfg.NetworkPolicy = config.CloneNetworkPolicy(policy)
	cfg.Services[service.ID] = config.ServiceState{Enabled: true, Route: "direct"}
	configPath := filepath.Join(peers.root, "config.json")
	raw, _ := json.Marshal(cfg)
	if err := os.WriteFile(configPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	store, err := config.LoadExisting(configPath)
	if err != nil {
		t.Fatal(err)
	}
	// Generate the actual persisted draft revision before freezing exclusions;
	// Default() is revision zero and cannot issue an execution transaction.
	if err := store.UpdateService(service.ID, config.ServiceState{Enabled: true, Route: "direct"}); err != nil {
		t.Fatal(err)
	}
	exclusions, err := dnscontrol.NewNetworkPolicyDNSExclusions(held, store, store.Get(), func(c context.Context, name string) ([]string, error) {
		if err := control.Current(c); err != nil {
			return nil, err
		}
		if name == "service.example.com" {
			return []string{service.ID}, nil
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	dns, err := dnscontrol.New("")
	if err != nil {
		t.Fatal(err)
	}
	frozenDNS, err := dns.FreezeNetworkPolicyDNSPlan(held, domain.Generation, "private", []dnscontrol.ClientDNSBinding{{Client: netip.MustParseAddr(domainOriginalClient), Domain: "service.example.com", ProfileID: "private"}}, exclusions)
	if err != nil {
		t.Fatal(err)
	}
	transport := &dataplane.SyntheticDNSTransportPlan{Listener: "192.168.1.1:10553", CaptureEndpoint: "192.168.1.1:10443", DomainPolicyDigest: domain.Digest, DNS: frozenDNS, Definition: dnscontrol.SyntheticDNSDefinition{Client: netip.MustParseAddr(domainOriginalClient), DeviceID: "selected", MAC: "02:00:00:00:00:02", Ingress: "br0", ExactNames: []string{"service.example.com"}}}
	authority := dnscontrol.NetworkPolicyDNSAuthority{Generation: domain.Generation, ControlEpoch: control.Reference().Sequence, BindingRevision: 1, Exclusions: exclusions.Stamp()}
	resolver, err := dns.NewNetworkPolicyDNSResolverForPlanWithOperations(held, frozenDNS, authority, operations, control.Current, func(c context.Context, client netip.Addr, name string) (dnscontrol.NetworkPolicyDNSAdmission, error) {
		if err := control.Current(c); err != nil {
			return dnscontrol.NetworkPolicyDNSAdmission{}, err
		}
		if client != transport.Definition.Client {
			return dnscontrol.NetworkPolicyDNSAdmission{}, dnscontrol.ErrNetworkPolicyDNSOutside
		}
		kind := "baseline"
		if name == "" || name == "service.example.com" {
			kind = "managed"
		}
		return dnscontrol.NetworkPolicyDNSAdmission{Authority: authority, Ingress: "br0", DeviceID: "selected", Kind: kind}, nil
	}, exclusions)
	if err != nil {
		t.Fatal(err)
	}
	physical := func(c context.Context, p *dataplane.LANPolicyRuntimePlan) error {
		if p != nil {
			return dataplane.ErrNetworkPolicyIdentity
		}
		return control.Current(c)
	}
	deny := func(context.Context, *dataplane.LANPolicyRuntimePlan, dataplane.LANPolicyEffect) error {
		return dataplane.ErrNetworkPolicyIdentity
	}
	gate, err := dataplane.NewNetworkPolicyAdapter(held, dataplane.NetworkPolicyAssemblyOptions{Provider: provider, Binding: &dataplane.LANPolicyReceiptBinding{Runtime: &dataplane.LANPolicyRuntime{Runner: runner, IP: policyTools.IP, IPTables: policyTools.IPTables, IP6Tables: policyTools.IP6Tables, ScopeCheck: physical}, ApplyGuard: deny, CleanupGuard: deny, RetireCheck: physical}, InventoryCheck: func(c context.Context, got netidentity.Identity, p *dataplane.LANPolicyRuntimePlan) error {
		if got != identity || p != nil {
			return dataplane.ErrNetworkPolicyIdentity
		}
		view, err := backend.Read(c, got)
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
	dnsAdapter := dataplane.NewScopedDNSAdapter(ctx, dns, manager.StateRoot)
	dnsAdapter.InactivityIdentity = provider
	if err := manager.Register(dnsAdapter); err != nil {
		t.Fatal(err)
	}
	xray, err := NewXrayNodeRuntime(NodeRuntimeFactoryOptions{Configs: engineconfig.New(filepath.Join(peers.root, "stage"), filepath.Join(peers.root, "backup")), Nodes: nodes, StateRoot: manager.StateRoot, FreshProfile: fresh})
	if err != nil {
		t.Fatal(err)
	}
	xray.EngineBin = peers.binary
	xray.SOCKSPort = 29285
	if err := manager.Register(xray); err != nil {
		t.Fatal(err)
	}
	route := dataplane.Route{ServiceID: service.ID, LogicalServiceID: service.ID, Resolved: "xray:" + nodeID, Selected: "xray:" + nodeID, Domains: service.Domains, Sources: []string{domainOriginalClient + "/32"}, Ingress: []string{"br0"}, ProbeURL: service.ProbeURL, ProbeService: &service}
	plan, err := dataplane.BuildAt(dataplane.Input{Revision: store.Get().Revision, DomainPolicy: domain, SyntheticDNS: transport, NetworkProfileID: "wan-0123456789ab", Routes: []dataplane.Route{route}, Engines: []dataplane.Engine{{ID: "xray", Installed: true, Configured: true, Activatable: true, Canary: true}}, Host: dataplane.HostState{IPCommand: policyTools.IP != "", IPTables: policyTools.IPTables != "", IP6Tables: policyTools.IP6Tables != ""}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Ready {
		t.Fatal("ordinary domain Apply unexpectedly enabled")
	}
	history := updatecheck.NewExecutionHistoryAdmission(dataplane.InspectRetainedExecutionReadVersion)
	succeeded := false
	var retainedOwner *dataplane.DomainTCPOriginalScope
	var retainedMapping *dnscontrol.SyntheticDNSMapping
	originalPlanRaw, _ := json.Marshal(plan)
	err = manager.WithDomainTCPProofResources(dataplane.WithReviewGuard(held, control.Current), plan, history, func(original context.Context) error {
		binding, err := manager.BindSyntheticDNSExecution(original, dnsAdapter, plan)
		if err != nil {
			return fmt.Errorf("original DNS binding: %w", err)
		}
		owner, err := manager.NewDomainTCPOriginalScope(original, binding, backend)
		if err != nil {
			return fmt.Errorf("original owner constructor: %w", err)
		}
		retainedOwner = owner
		if err := owner.StartDNS(original, resolver, control); err != nil {
			return fmt.Errorf("original unpublished DNS: %w", err)
		}
		query := dnsmessage.Message{Header: dnsmessage.Header{ID: 9, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("service.example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
		wire, _ := query.Pack()
		mapping, err := owner.Reserve(original, transport.Definition.Client, wire)
		if err != nil {
			return fmt.Errorf("original DNS reserve: %w", err)
		}
		retainedMapping = mapping
		observation, err := mapping.Observation(original)
		if err != nil || observation.PossiblyIssued || observation.RealIPv4.String() != domainOriginalServer {
			return fmt.Errorf("unexpected original unpublished reservation: %w", err)
		}
		// A real client query before capture cannot publish a synthetic answer.
		unready := peers.clientRequest(t, original, "dns-unready", "")
		if strings.HasPrefix(unready.Answer, "198.") {
			return errors.New("unprepared capture published DNS")
		}
		spec := dataplane.DomainPolicyTCPCaptureSpec{Xray: dataplane.DomainPolicyTCPXraySpec{Generation: domain.Generation, NetworkProfile: "wan-0123456789ab", ServiceID: service.ID, NodeID: nodeID, Name: "service.example.com", RealIP: observation.RealIPv4}, Client: autonomy.ClientPacket{Address: transport.Definition.Client, MAC: transport.Definition.MAC, Interface: "br0", SegmentID: "home"}, DeviceID: "selected", Listen: netip.MustParseAddrPort(transport.CaptureEndpoint), Limits: dataplane.DomainPolicySniffLimits{Bytes: 16 << 10, Timeout: time.Second}}
		material, err := dataplane.ReviewXrayDomainTCPOperationMaterial(original, binding, xray, nodeSource, mapping, service, spec)
		if err != nil {
			return fmt.Errorf("genuine operation material: %w", err)
		}
		resource, err := dataplane.AcquireXrayDomainTCPExecutionResource(original, material)
		if err != nil {
			return fmt.Errorf("original resource issuer: %w", err)
		}
		if work := os.Getenv("RAZVILKA_DOMAIN_CPU_PROFILE"); work != "" {
			info, err := os.Lstat(work)
			if err != nil {
				return err
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !filepath.IsAbs(work) || filepath.Clean(work) != work || work != os.Getenv("RAZVILKA_DOMAIN_FIXTURE_WORK") || !strings.HasPrefix(work, "/tmp/razvilka-domain-original.") || !info.IsDir() || info.Mode().Perm() != 0700 || !ok || stat.Uid != uint32(os.Geteuid()) {
				return errors.New("CPU profile requires original private CI work directory")
			}
			profile, err := os.OpenFile(filepath.Join(work, "original-run.cpu.pprof"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				return err
			}
			if err := pprof.StartCPUProfile(profile); err != nil {
				_ = profile.Close()
				return err
			}
			// Registered before the Run join defer below: StopCPUProfile runs
			// only after the original child/consumer has joined, even on failure.
			defer func() {
				pprof.StopCPUProfile()
				if err := profile.Close(); err != nil {
					t.Error(err)
				}
			}()
		}
		runCtx, stopRun := context.WithCancel(original)
		runDone := make(chan error, 1)
		go func() { runDone <- owner.Run(runCtx, resource) }()
		joined := false
		defer func() {
			stopRun()
			if !joined {
				select {
				case <-runDone:
				case <-time.After(15 * time.Second):
					t.Error("original runtime did not join after fixture failure")
				}
			}
		}()
		var published domainOriginalPeerResult
		publicationBudget := 12 * time.Second
		if diagnostic := os.Getenv("RAZVILKA_DOMAIN_DIAGNOSTIC_PUBLICATION"); diagnostic != "" {
			if diagnostic != "30" {
				return errors.New("unknown diagnostic publication window")
			}
			publicationBudget = 30 * time.Second
			t.Log("DIAGNOSTIC FUNCTIONAL WINDOW30s; original100s context and60s freshness unchanged; NOT12s performance acceptance")
		}
		deadline := time.Now().Add(publicationBudget)
		for time.Now().Before(deadline) {
			select {
			case err := <-runDone:
				joined = true
				return fmt.Errorf("original Run before publication: %w", err)
			default:
			}
			published = peers.clientRequest(t, original, "dns-wait", "")
			if strings.HasPrefix(published.Answer, "198.") {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if !strings.HasPrefix(published.Answer, "198.") {
			domainOriginalPublicationDiagnostics(t, manager.StateRoot)
			return errors.New("actual DNS publication did not become available")
		}
		same, err := owner.LookupPublished(original, transport.Definition.Client, netip.MustParseAddr(published.Answer))
		if err != nil || same != mapping {
			return fmt.Errorf("published original mapping: %w", err)
		}
		excluded := peers.clientRequest(t, original, "dns-other-client", "")
		if strings.HasPrefix(excluded.Answer, "198.") {
			return errors.New("unselected client received managed synthetic mapping")
		}
		children := domainOriginalRuntimeChildren(t, manager.StateRoot)
		if len(children) != 1 {
			return fmt.Errorf("expected actual original Xray child, got%d", len(children))
		}
		selected := peers.clientRequest(t, original, "selected", published.Answer)
		if selected.Source != domainOriginalServer || selected.Marker != "native-domain-service" {
			return fmt.Errorf("selected actual TLS flow not through native VLESS: %+v", selected)
		}
		mismatch := peers.clientRequest(t, original, "mismatch", published.Answer)
		if mismatch.Source != domainOriginalClient || mismatch.Marker != "native-domain-service" {
			return fmt.Errorf("mismatched SNI changed original baseline tuple: %+v", mismatch)
		}
		opaque := peers.clientRequest(t, original, "opaque", published.Answer)
		if opaque.Source != domainOriginalClient || opaque.Marker != "opaque-native-baseline" {
			return fmt.Errorf("opaque replay/baseline changed original source or bytes: %+v", opaque)
		}
		stopRun()
		select {
		case runErr := <-runDone:
			joined = true
			if !domainOriginalExpectedStopError(runErr) {
				return fmt.Errorf("unexpected original Run/cleanup result: %w", runErr)
			}
		case <-time.After(15 * time.Second):
			return errors.New("original Run cleanup did not join")
		}
		for _, pid := range children {
			if _, err := os.Stat(filepath.Join("/proc", pid)); !errors.Is(err, os.ErrNotExist) {
				return errors.New("original native child still exists after joined cleanup")
			}
		}
		conn, err := net.DialTimeout("tcp4", transport.CaptureEndpoint, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return errors.New("original capture listener remains after cleanup")
		}
		if err := owner.CurrentSyntheticMapping(original, mapping); err == nil {
			return errors.New("stopped owner still grants DNS publication")
		}
		// The client genuinely retains the earlier DNS answer. A fresh SYN after
		// original capture/native shutdown must use restored standby forwarding,
		// preserving the actual client tuple without starting another proxy.
		late := peers.clientRequest(t, original, "selected", published.Answer)
		if late.Source != domainOriginalClient || late.Marker != "native-domain-service" {
			return fmt.Errorf("late SYN through retained synthetic address lost standby baseline: %+v", late)
		}
		if len(domainOriginalRuntimeChildren(t, manager.StateRoot)) != 0 {
			return errors.New("late SYN restarted a native runtime")
		}
		if err := owner.RetainStandby(original, history); err != nil {
			return fmt.Errorf("original known standby handoff request: %w", err)
		}
		succeeded = true
		return nil
	})
	if !succeeded || err != nil {
		t.Fatalf("full original domain native workflow: %v blockers=%+v", err, plan.Blockers)
	}
	after, _ := json.Marshal(plan)
	if string(after) != string(originalPlanRaw) || plan.Ready {
		t.Fatal("native proof promoted or mutated ordinary Apply plan")
	}
	// The SAME original owner survives for restorative readback only after the
	// wrapper's complete handoff and release of its original exclusive gate.
	release()
	readCtx, readCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer readCancel()
	if retainedOwner == nil || retainedMapping == nil {
		t.Fatal("actual original standby custody lost after exclusive release")
	}
	if err := retainedOwner.RetainedStandbyCurrent(readCtx); err != nil {
		t.Fatalf("actual original standby custody after exclusive release: %v", err)
	}
	if retainedOwner.CurrentSyntheticMapping(readCtx, retainedMapping) == nil {
		t.Fatal("known standby custody revived forward publication")
	}
	version, seal, readErr := dataplane.InspectRetainedExecutionReadVersion(readCtx, manager.StateRoot)
	if readErr != nil || version < 4 || seal == "" {
		t.Fatalf("known standby not covered by actual reader4: version=%d error=%v", version, readErr)
	}
	// Current contract intentionally retains standby until the real original
	// cache/late-SYN settlement can be issued. TTL/empty CT is NOT that grant.
	data, readErr := os.ReadFile(filepath.Join(manager.StateRoot, "latest-execution.json"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	var execution dataplane.Execution
	if json.Unmarshal(data, &execution) != nil {
		t.Fatal("actual common receipt missing")
	}
	retained := false
	for _, r := range execution.Resources {
		if r.Kind == "synthetic-baseline" && r.State == "prepared" && r.Phase == "standby-retained" {
			retained = true
		}
		if (r.Kind == "xray-domain-tcp" || r.Kind == "domain-tcp-capture") && r.State != "removed" {
			t.Fatalf("original process/capture cleanup not published: %s %s", r.Kind, r.State)
		}
	}
	if !retained {
		t.Fatal("unissued late-SYN/cache settlement unexpectedly cleared known standby footprint")
	}
	t.Log("actual original DoH Reserve→native Xray→capture COMMON→DNS publication→selected TLS; mismatched SNI/opaque and late SYN preserve routed client source+bytes; capture/native child joined; original known standby readback survives exclusive release under reader4; full retirement remains pending, ordinary Apply stays blocked")
}

func domainOriginalPublicationDiagnostics(t *testing.T, root string) {
	t.Helper()
	buffer := make([]byte, 64<<10)
	n := runtime.Stack(buffer, true)
	t.Logf("original publication blocked; bounded goroutine stacks:\n%s", buffer[:n])
	file, err := os.Open(filepath.Join(root, "latest-execution.json"))
	if err == nil {
		var execution dataplane.Execution
		err = json.NewDecoder(io.LimitReader(file, 4<<20)).Decode(&execution)
		file.Close()
		if err == nil {
			for _, resource := range execution.Resources {
				t.Logf("actual COMMON progress kind=%s state=%s phase=%s", resource.Kind, resource.State, resource.Phase)
			}
		}
	}
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() || !strings.HasSuffix(entry.Name(), ".log") {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer file.Close()
		data, _ := io.ReadAll(io.LimitReader(file, 8192))
		relative, _ := filepath.Rel(root, path)
		t.Logf("actual generated runtime %s: %s", relative, data)
		return nil
	})
}

// Read-only independent process observation for assertions, never deletion or
// native ownership admission. No process found by scanning is signaled here.
func domainOriginalRuntimeChildren(t *testing.T, root string) []string {
	t.Helper()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatal(err)
	}
	var children []string
	for _, entry := range entries {
		if strings.Trim(entry.Name(), "0123456789") != "" {
			continue
		}
		data, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		cwd, cwdErr := os.Readlink(filepath.Join("/proc", entry.Name(), "cwd"))
		// The original process consumes stdin: from its held config FD. Its
		// immutable private working directory identifies this fixture child;
		// there is intentionally no mutable config pathname in argv.
		if err == nil && cwdErr == nil && strings.HasPrefix(cwd, root+string(filepath.Separator)) && strings.Contains(string(data), "xray") {
			children = append(children, entry.Name())
		}
	}
	return children
}
