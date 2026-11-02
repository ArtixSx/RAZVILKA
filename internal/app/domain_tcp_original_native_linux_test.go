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
	runDomainTCPOriginalNative(t, false)
}

func TestDomainTCPOriginalNativeUnpublishedRetirement(t *testing.T) {
	runDomainTCPOriginalNative(t, true)
}

func TestDomainTCPOriginalNativePublishedDNSStandby(t *testing.T) {
	t.Setenv("RAZVILKA_DOMAIN_DNS_ONLY_NATIVE", "1")
	runDomainTCPOriginalNative(t, false)
}

func TestDomainTCPOriginalNativeDNSDetachment(t *testing.T) {
	t.Setenv("RAZVILKA_DOMAIN_DNS_ONLY_NATIVE", "1")
	t.Setenv("RAZVILKA_DOMAIN_DNS_DETACH", "1")
	runDomainTCPOriginalNative(t, false)
}

func TestDomainTCPOriginalNativeDNSCoexistence(t *testing.T) {
	t.Setenv("RAZVILKA_DOMAIN_DNS_ONLY_NATIVE", "1")
	t.Setenv("RAZVILKA_DOMAIN_DNS_DETACH", "1")
	t.Setenv("RAZVILKA_DOMAIN_DNS_COEXISTENCE", "1")
	runDomainTCPOriginalNative(t, false)
}

func TestDomainTCPOriginalNativeUnstartedKeeper(t *testing.T) {
	t.Setenv("RAZVILKA_DOMAIN_DNS_ONLY_NATIVE", "1")
	t.Setenv("RAZVILKA_DOMAIN_DNS_DETACH", "1")
	t.Setenv("RAZVILKA_DOMAIN_DNS_COEXISTENCE", "1")
	runDomainTCPOriginalNative(t, false)
}

func TestDomainTCPOriginalNativeNeverIssuedKeeper(t *testing.T) {
	t.Setenv("RAZVILKA_DOMAIN_DNS_ONLY_NATIVE", "1")
	t.Setenv("RAZVILKA_DOMAIN_DNS_DETACH", "1")
	t.Setenv("RAZVILKA_DOMAIN_DNS_COEXISTENCE", "1")
	t.Setenv("RAZVILKA_DOMAIN_NEVER_ISSUED_SUCCESSOR", "1")
	runDomainTCPOriginalNative(t, false)
}

func TestDomainTCPOriginalNativeJoinedFailureKeeper(t *testing.T) {
	t.Setenv("RAZVILKA_DOMAIN_DNS_ONLY_NATIVE", "1")
	t.Setenv("RAZVILKA_DOMAIN_DNS_DETACH", "1")
	t.Setenv("RAZVILKA_DOMAIN_DNS_COEXISTENCE", "1")
	t.Setenv("RAZVILKA_DOMAIN_NEVER_ISSUED_SUCCESSOR", "1")
	t.Setenv("RAZVILKA_DOMAIN_JOINED_FAILURE", "1")
	runDomainTCPOriginalNative(t, false)
}

func TestDomainTCPOriginalNativeCanceledChildCleanup(t *testing.T) {
	t.Setenv("RAZVILKA_DOMAIN_DNS_ONLY_NATIVE", "1")
	t.Setenv("RAZVILKA_DOMAIN_DNS_DETACH", "1")
	t.Setenv("RAZVILKA_DOMAIN_DNS_COEXISTENCE", "1")
	t.Setenv("RAZVILKA_DOMAIN_CANCELED_CHILD", "1")
	runDomainTCPOriginalNative(t, false)
}

func TestDomainTCPOriginalNativeCanceledReadyRetirement(t *testing.T) {
	t.Setenv("RAZVILKA_DOMAIN_DNS_ONLY_NATIVE", "1")
	t.Setenv("RAZVILKA_DOMAIN_DNS_DETACH", "1")
	t.Setenv("RAZVILKA_DOMAIN_DNS_COEXISTENCE", "1")
	t.Setenv("RAZVILKA_DOMAIN_CANCELED_CHILD", "1")
	t.Setenv("RAZVILKA_DOMAIN_CANCELED_READY", "1")
	runDomainTCPOriginalNative(t, false)
}

func TestDomainTCPOriginalNativeCanceledPublishedStandby(t *testing.T) {
	t.Setenv("RAZVILKA_DOMAIN_DNS_ONLY_NATIVE", "1")
	t.Setenv("RAZVILKA_DOMAIN_DNS_DETACH", "1")
	t.Setenv("RAZVILKA_DOMAIN_DNS_COEXISTENCE", "1")
	t.Setenv("RAZVILKA_DOMAIN_CANCELED_CHILD", "1")
	t.Setenv("RAZVILKA_DOMAIN_CANCELED_READY", "1")
	t.Setenv("RAZVILKA_DOMAIN_CANCELED_PUBLISHED", "1")
	runDomainTCPOriginalNative(t, false)
}

func runDomainTCPOriginalNative(t *testing.T, unpublished bool) {
	detach, ack, foreign := os.Getenv("RAZVILKA_DOMAIN_DNS_DETACH"), os.Getenv("RAZVILKA_DOMAIN_DNS_DETACH_ACK"), os.Getenv("RAZVILKA_DOMAIN_DNS_DETACH_FOREIGN_HISTORY")
	dnsOnly := os.Getenv("RAZVILKA_DOMAIN_DNS_ONLY_NATIVE") == "1"
	coexist := os.Getenv("RAZVILKA_DOMAIN_DNS_COEXISTENCE") == "1"
	initialCut := os.Getenv("RAZVILKA_DOMAIN_INITIAL_ACK")
	neverIssuedSuccessor := os.Getenv("RAZVILKA_DOMAIN_NEVER_ISSUED_SUCCESSOR") == "1"
	joinedFailure := os.Getenv("RAZVILKA_DOMAIN_JOINED_FAILURE") == "1"
	canceledChild := os.Getenv("RAZVILKA_DOMAIN_CANCELED_CHILD") == "1"
	canceledReady := os.Getenv("RAZVILKA_DOMAIN_CANCELED_READY") == "1"
	canceledPublished := os.Getenv("RAZVILKA_DOMAIN_CANCELED_PUBLISHED") == "1"
	if canceledPublished && !canceledReady {
		t.Fatal("published cancellation requires its ready case")
	}
	failedACK := os.Getenv("RAZVILKA_DOMAIN_FAILURE_ACK")
	if failedACK != "" && (!canceledReady || failedACK != "process" && failedACK != "capture" && failedACK != "standby" && failedACK != "alias" && failedACK != "capture-transaction" && failedACK != "standby-transaction") {
		t.Fatal("invalid failed generation ACK cut")
	}
	if canceledReady && !canceledChild {
		t.Fatal("ready cancellation requires its separate canceled child case")
	}
	if canceledChild && (!coexist || joinedFailure || neverIssuedSuccessor || initialCut != "") {
		t.Fatal("canceled child requires its separate successor case")
	}
	if joinedFailure && !neverIssuedSuccessor {
		t.Fatal("joined error requires distinct never-issued successor")
	}
	if neverIssuedSuccessor && (!coexist || initialCut != "") {
		t.Fatal("never-issued successor requires distinct coexistence case")
	}
	if initialCut != "" && (!coexist || initialCut != "transaction" && initialCut != "global") {
		t.Fatal("invalid initial publication cut case")
	}
	if detach != "" && detach != "1" || foreign != "" && foreign != "1" || (ack != "" || foreign != "") && detach != "1" || ack != "" && foreign != "" || detach == "1" && unpublished {
		t.Fatal("invalid or combined isolated DNS detachment fixture cases")
	}
	if os.Getenv(domainOriginalNativeEnv) != "1" {
		t.Skip("explicit disposable native original domain workflow")
	}
	wholeBudget := 100 * time.Second
	if coexist {
		if detach != "1" || ack != "" || foreign != "" || unpublished || os.Getenv("RAZVILKA_DOMAIN_DIAGNOSTIC_PUBLICATION") != "30" {
			t.Fatal("coexistence requires its distinct two-operation diagnostic case")
		}
		wholeBudget = 3 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), wholeBudget)
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

	// Genuine public readonly source scope before the measured Run window.
	// An original callback failure stays a failure; its context cannot be reused
	// for even another literal observation after synchronous revocation.
	scopeWitness := errors.New("actual B readonly source callback failure")
	var expiredToolRead context.Context
	scopeErr := tools.WithReadOnlyToolObservation(ctx, identity, descriptor.ReviewSHA256, func(observed context.Context) error {
		expiredToolRead = observed
		if err := tools.Check(observed, identity); err != nil {
			return err
		}
		if _, err := tools.RunBounded(observed, descriptor.IPTables, 1<<20, "-t", "mangle", "-S"); err != nil {
			return err
		}
		return scopeWitness
	})
	var onlyScopeWitness func(error) bool
	onlyScopeWitness = func(err error) bool {
		if err == scopeWitness {
			return true
		}
		if joined, ok := err.(interface{ Unwrap() []error }); ok {
			children := joined.Unwrap()
			if len(children) == 0 {
				return false
			}
			for _, child := range children {
				if !onlyScopeWitness(child) {
					return false
				}
			}
			return true
		}
		if wrapped, ok := err.(interface{ Unwrap() error }); ok {
			return onlyScopeWitness(wrapped.Unwrap())
		}
		return false
	}
	if !onlyScopeWitness(scopeErr) {
		t.Fatal("actual B tool scope lost callback error", scopeErr)
	}
	if _, err := tools.RunBounded(expiredToolRead, descriptor.IPTables, 1<<20, "-t", "mangle", "-S"); !errors.Is(err, startuptools.ErrUnknown) {
		t.Fatal("expired original B read scope issued data", err)
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
	var retainedPublishedAlias string
	var retainedMapping *dnscontrol.SyntheticDNSMapping
	originalPlanRaw, _ := json.Marshal(plan)
	firstOperation := held
	if coexist {
		var stopFirst context.CancelFunc
		firstOperation, stopFirst = context.WithTimeout(held, 100*time.Second)
		defer stopFirst()
		t.Log("COEXISTENCE diagnostic: physical fixture3min; EACH original generation100s, fresh scope60s, publication30s/join15s unchanged; not default12s acceptance")
	}
	err = manager.WithDomainTCPProofResources(dataplane.WithReviewGuard(firstOperation, control.Current), plan, history, func(original context.Context) error {
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
		if !unpublished {
			// A real client query before capture cannot publish a synthetic answer.
			unready := peers.clientRequest(t, original, "dns-unready", "")
			if strings.HasPrefix(unready.Answer, "198.") {
				return errors.New("unprepared capture published DNS")
			}
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
		stopDomainMetrics := dataplane.StartDomainTCPNativeMeasurement()
		stopToolMetrics := startuptools.StartDomainNativeToolMeasurement()
		defer func() {
			t.Logf("actual Run through join observation counts: domain=%+v actual_tool_starts=%+v; overlapping cumulative durations, not wall speed", stopDomainMetrics(), stopToolMetrics())
		}()
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
		if unpublished {
			// No client DNS request is sent in this case. Readiness observes
			// the same original owner only; it cannot mark an answer issued.
			ready, cancelReady := context.WithTimeout(original, 30*time.Second)
			defer cancelReady()
			for {
				if owner.CurrentSyntheticMapping(ready, mapping) == nil {
					break
				}
				select {
				case err := <-runDone:
					joined = true
					return fmt.Errorf("original unpublished Run before readiness: %w", err)
				case <-ready.Done():
					return fmt.Errorf("actual unpublished original readiness: %w", ready.Err())
				case <-time.After(50 * time.Millisecond):
				}
			}
			stopRun()
			select {
			case runErr := <-runDone:
				joined = true
				if !domainOriginalExpectedStopError(runErr) {
					return fmt.Errorf("unpublished original cleanup result: %w", runErr)
				}
			case <-time.After(15 * time.Second):
				return errors.New("unpublished original Run did not join")
			}
			if err := owner.RetainStandby(original, history); err != nil {
				return fmt.Errorf("original unpublished standby transfer: %w", err)
			}
			succeeded = true
			return nil
		}
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
			// Keep this real query's source socket alive while the original
			// publication admission runs. The absolute window includes peer exec.
			published = peers.clientRequest(t, original, "dns-wait", deadline.UTC().Format(time.RFC3339Nano))
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
		retainedPublishedAlias = published.Answer
		excluded := peers.clientRequest(t, original, "dns-other-client", "")
		if strings.HasPrefix(excluded.Answer, "198.") {
			return errors.New("unselected client received managed synthetic mapping")
		}
		children := domainOriginalRuntimeChildren(t, manager.StateRoot)
		if len(children) != 1 {
			return fmt.Errorf("expected actual original Xray child, got%d", len(children))
		}
		if !dnsOnly {
			selected := peers.clientRequest(t, original, "selected", published.Answer)
			if selected.Source != domainOriginalServer || selected.Marker != "native-domain-service" {
				return fmt.Errorf("selected actual TLS flow not through native VLESS: %+v", selected)
			}
			mismatch := peers.clientRequest(t, original, "mismatch", published.Answer)
			if mismatch.SourcePort == "" || mismatch.SourcePort == "0" || mismatch.SourcePort != mismatch.ClientPort || mismatch.Source != domainOriginalClient || mismatch.Marker != "native-domain-service" {
				return fmt.Errorf("mismatched SNI changed original baseline tuple: %+v", mismatch)
			}
			opaque := peers.clientRequest(t, original, "opaque", published.Answer)
			if opaque.SourcePort == "" || opaque.SourcePort == "0" || opaque.SourcePort != opaque.ClientPort || opaque.Source != domainOriginalClient || opaque.Marker != "opaque-native-baseline" {
				return fmt.Errorf("opaque replay/baseline changed original source or bytes: %+v", opaque)
			}
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
		if late.SourcePort == "" || late.SourcePort == "0" || late.SourcePort != late.ClientPort || late.Source != domainOriginalClient || late.Marker != "native-domain-service" {
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
	if unpublished {
		cleanupCtx, cleanupRelease, err := operations.ExclusiveContext(ctx)
		if err != nil {
			t.Fatal("fresh exclusive retirement admission", err)
		}
		defer cleanupRelease()
		cleanup, err := control.ReviewExclusiveCleanup(cleanupCtx)
		if err != nil {
			t.Fatal("fresh original cleanup review", err)
		}
		if err := retainedOwner.RetireUnpublishedStandby(cleanupCtx, cleanup); err != nil {
			t.Fatal("actual never-issued original compensation", err)
		}
		if err := retainedOwner.RetireUnpublishedStandby(cleanupCtx, cleanup); err != nil {
			t.Fatal("same completed original compensation retry", err)
		}
		if retainedOwner.RetainedStandbyCurrent(ctx) == nil {
			t.Fatal("retired original standby still grants readback")
		}
		if err := manager.CheckExecutionRecovery(cleanupCtx); err != nil {
			t.Fatal("actual retired terminal journals still fence operations", err)
		}
		view, err := backend.Read(cleanupCtx, identity)
		if err != nil {
			t.Fatal("independent closing complete packet inventory", err)
		}
		for _, row := range view.Rows {
			for _, token := range row.Tokens {
				if strings.HasPrefix(token, "RZSB_") || strings.HasPrefix(token, "RZDC_") || strings.HasPrefix(token, "RZDI_") {
					t.Fatal("actual compensation left original packet footprint", row.Family, row.Table, token)
				}
			}
		}
		data, err := os.ReadFile(filepath.Join(manager.StateRoot, "latest-execution.json"))
		var execution dataplane.Execution
		if err != nil || json.Unmarshal(data, &execution) != nil || execution.State != "temporary-complete" {
			t.Fatal("actual compensation terminal journal", err, execution.State)
		}
		for _, r := range execution.Resources {
			if r.State != "removed" && r.State != "unused" {
				t.Fatal("actual compensation left a live resource", r.Kind, r.State)
			}
		}
		t.Log("actual never-issued original DNS reservation → native/capture/kernel readiness → joined original standby → fresh original exclusive cleanup → exact COMMON removal, terminal journals and released lifecycle; no client DNS send or TTL/cache assumption")
		return
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
	cleanupCtx, cleanupRelease, err := operations.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal("fresh published-alias cleanup admission", err)
	}
	defer cleanupRelease()
	cleanup, err := control.ReviewExclusiveCleanup(cleanupCtx)
	if err != nil {
		t.Fatal("fresh published-alias cleanup review", err)
	}
	if err := retainedOwner.RetireUnpublishedStandby(cleanupCtx, cleanup); !errors.Is(err, dataplane.ErrDomainPolicyTCPCaptureRetirementPending) {
		t.Fatal("published alias did not reach original possibly-issued refusal", err)
	}
	afterRefusal, err := os.ReadFile(filepath.Join(manager.StateRoot, "latest-execution.json"))
	if err != nil || string(afterRefusal) != string(data) || retainedOwner.RetainedStandbyCurrent(ctx) != nil {
		t.Fatal("published-alias refusal changed original retained custody", err)
	}
	// Separate reader7 protocol validation only. The existing finite/reader4
	// scenario and its clocks remain unchanged unless this explicit case runs.
	if os.Getenv("RAZVILKA_DOMAIN_DNS_DETACH") == "1" {
		if os.Getenv("RAZVILKA_DOMAIN_DNS_DETACH_FOREIGN_HISTORY") == "1" {
			path := filepath.Join(dnsAdapter.StateRoot, "retired-"+execution.PlanID+"-owner.json")
			foreign := []byte("native fixture reserved foreign DNS history")
			file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.Write(foreign); err != nil {
				file.Close()
				t.Fatal(err)
			}
			info, err := file.Stat()
			if err != nil {
				file.Close()
				t.Fatal(err)
			}
			if _, err := retainedOwner.DetachPublishedStandby(cleanupCtx, cleanup, history); err == nil {
				file.Close()
				t.Fatal("foreign reserved DNS history overwritten")
			}
			after, err := os.ReadFile(path)
			latest, e2 := os.ReadFile(filepath.Join(manager.StateRoot, "latest-execution.json"))
			named, e3 := os.Lstat(path)
			if err != nil || e2 != nil || e3 != nil || !os.SameFile(info, named) || string(after) != string(foreign) || string(latest) != string(data) || !manager.HasPendingManagedXraySelectedTCP() {
				file.Close()
				t.Fatal("refused original handoff lost foreign history or custody", err, e2, e3)
			}
			// Remove only this fixture's unchanged reserved file while the SAME
			// original exclusive operation remains held; production never removes it.
			if err := os.Remove(path); err != nil {
				file.Close()
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
		}
		if fault := os.Getenv("RAZVILKA_DOMAIN_DNS_DETACH_ACK"); fault != "" {
			if err := dataplane.ConfigureNativeDomainDNSDetachmentACK(cleanupCtx, retainedOwner, fault); err != nil {
				t.Fatal("original isolated lost-ACK fixture", err)
			}
			if _, err := retainedOwner.DetachPublishedStandby(cleanupCtx, cleanup, history); !errors.Is(err, dataplane.ErrNativeDomainDNSDetachmentACK) {
				t.Fatal("lost actual detachment ACK exception", err)
			}
			if !manager.HasPendingManagedXraySelectedTCP() {
				t.Fatal("lost detachment ACK released pending custody")
			}
		}
		detached, err := retainedOwner.DetachPublishedStandby(cleanupCtx, cleanup, history)
		if err != nil || detached == nil {
			t.Fatal("original published DNS-only handoff", err)
		}
		if _, err := retainedOwner.DetachPublishedStandby(cleanupCtx, cleanup, history); err != nil {
			t.Fatal("same original handoff reobservation", err)
		}
		if err := retainedOwner.RetainedStandbyCurrent(ctx); err != nil {
			t.Fatal("detached original baseline not current", err)
		}
		if err := manager.CheckExecutionRecovery(cleanupCtx); err != nil {
			t.Fatal("detached original known custody lost", err)
		}
		if v, _, err := dataplane.InspectRetainedExecutionReadVersion(ctx, manager.StateRoot); err != nil || v != 7 {
			t.Fatal("detached history reader", v, err)
		}
		late := peers.clientRequest(t, cleanupCtx, "selected", retainedPublishedAlias)
		if late.SourcePort == "" || late.SourcePort != late.ClientPort || late.Source != domainOriginalClient || late.Marker != "native-domain-service" {
			t.Fatal("DNS-only detach changed cached-alias baseline tuple", late)
		}
		if len(domainOriginalRuntimeChildren(t, manager.StateRoot)) != 0 {
			t.Fatal("DNS-only detach restarted a native runtime")
		}
		t.Log("reader7 original DNS owner detach retains exact restorative baseline and late-SYN tuple; no alias reuse/cache retirement or new Apply authority")
		if coexist {
			// End the first original admission before entering a genuinely new
			// operation. The old closed source/baseline stays owned by the pool.
			cleanupRelease()
			secondCtx, stopSecond := context.WithTimeout(ctx, 100*time.Second)
			defer stopSecond()
			secondHeld, secondRelease, err := operations.ExclusiveContext(secondCtx)
			if err != nil {
				t.Fatal("new original successor admission", err)
			}
			defer secondRelease()
			freshNow := time.Now().UTC()
			scope.ObservedAt, scope.FreshUntil = freshNow, freshNow.Add(60*time.Second)
			secondDomain, err := dataplane.FreezeDomainPolicyRuntimePlan(domain.Generation, policy, scope, nil, []dataplane.DomainPolicyService{{ID: service.ID, Route: "xray:" + nodeID, Selected: true, Domains: service.Domains}}, freshNow)
			if err != nil {
				t.Fatal(err)
			}
			secondTransport := dataplane.CloneSyntheticDNSTransportPlan(transport)
			secondTransport.DomainPolicyDigest = secondDomain.Digest
			secondPlan, err := dataplane.BuildAt(dataplane.Input{Revision: store.Get().Revision, DomainPolicy: secondDomain, SyntheticDNS: secondTransport, NetworkProfileID: "wan-0123456789ab", Routes: []dataplane.Route{route}, Engines: []dataplane.Engine{{ID: "xray", Installed: true, Configured: true, Activatable: true, Canary: true}}, Host: plan.Host}, freshNow)
			if err != nil || secondPlan.Ready {
				t.Fatal("new frozen blocked intent", err)
			}
			if initialCut != "" {
				if err := dataplane.ConfigureNativeDomainInitialACK(secondHeld, detached, initialCut); err != nil {
					t.Fatal("configure original initial ACK", err)
				}
				initialCleanup, err := control.ReviewExclusiveCleanup(secondHeld)
				if err != nil {
					t.Fatal(err)
				}
				calls := 0
				failed := manager.WithDomainTCPContinuationResources(dataplane.WithReviewGuard(secondHeld, control.Current), secondPlan, history, detached, func(context.Context) error { calls++; return errors.New("unstarted action unexpectedly entered") })
				var originalFailure *dataplane.DomainTCPUnstartedFailure
				if calls != 0 || !errors.Is(failed, dataplane.ErrNativeDomainInitialACK) || !errors.As(failed, &originalFailure) {
					t.Fatal("actual initial publication failure/capsule", calls, failed)
				}
				if err := manager.RetireUnstartedDomainTCPContinuation(secondHeld, initialCleanup, history, originalFailure); err != nil {
					t.Fatal("same original unstarted retirement", err)
				}
				if err := manager.RetireUnstartedDomainTCPContinuation(secondHeld, initialCleanup, history, originalFailure); err != nil {
					t.Fatal("same actual terminal ACK retry", err)
				}
				if err := manager.CheckExecutionRecovery(secondHeld); err != nil {
					t.Fatal("documentary keeper/current originals", err)
				}
				late := peers.clientRequest(t, secondHeld, "selected", retainedPublishedAlias)
				if late.Source != domainOriginalClient || late.SourcePort == "" || late.SourcePort != late.ClientPort || late.Marker != "native-domain-service" {
					t.Fatal("unstarted retirement changed prior baseline", late)
				}
				if len(domainOriginalRuntimeChildren(t, manager.StateRoot)) != 0 {
					t.Fatal("metadata retirement started native child")
				}
				t.Log("actual failed initial publication retired via SAME captured journal FDs; original action never entered; old cached alias still serves exact tuple; no native/new-service proof from documentary keeper")
				secondRelease()
				thirdCtx, stopThird := context.WithTimeout(ctx, 100*time.Second)
				defer stopThird()
				thirdHeld, thirdRelease, err := operations.ExclusiveContext(thirdCtx)
				if err != nil {
					t.Fatal(err)
				}
				defer thirdRelease()
				secondHeld = thirdHeld
				freshNow = time.Now().UTC()
				scope.ObservedAt, scope.FreshUntil = freshNow, freshNow.Add(60*time.Second)
				secondDomain, err = dataplane.FreezeDomainPolicyRuntimePlan(domain.Generation, policy, scope, nil, []dataplane.DomainPolicyService{{ID: service.ID, Route: "xray:" + nodeID, Selected: true, Domains: service.Domains}}, freshNow)
				if err != nil {
					t.Fatal(err)
				}
				secondTransport = dataplane.CloneSyntheticDNSTransportPlan(transport)
				secondTransport.DomainPolicyDigest = secondDomain.Digest
				secondPlan, err = dataplane.BuildAt(dataplane.Input{Revision: store.Get().Revision, DomainPolicy: secondDomain, SyntheticDNS: secondTransport, NetworkProfileID: "wan-0123456789ab", Routes: []dataplane.Route{route}, Engines: []dataplane.Engine{{ID: "xray", Installed: true, Configured: true, Activatable: true, Canary: true}}, Host: plan.Host}, freshNow)
				if err != nil || secondPlan.Ready {
					t.Fatal("fresh post-keeper blocked intent", err)
				}
			}
			var neverIssuedOwner *dataplane.DomainTCPOriginalScope
			secondCleanup, err := control.ReviewExclusiveCleanup(secondHeld)
			if err != nil {
				t.Fatal(err)
			}
			operationCtx := secondHeld
			var cancelOriginal context.CancelFunc
			var canceledAlias string
			if canceledChild {
				operationCtx, cancelOriginal = context.WithCancel(secondHeld)
				defer cancelOriginal()
			}
			err = manager.WithDomainTCPContinuationResources(dataplane.WithReviewGuard(operationCtx, control.Current), secondPlan, history, detached, func(original context.Context) error {
				if canceledChild {
					original = context.WithValue(original, domainOriginalCancelAfterStartKey{}, cancelOriginal)
					original = context.WithValue(original, domainOriginalCanceledAliasKey{}, &canceledAlias)
				}
				return runDomainOriginalSuccessor(t, original, peers, manager, dnsAdapter, backend, xray, nodeSource, resolver, control, history, secondPlan, service, nodeID, detached, retainedPublishedAlias, neverIssuedSuccessor, &neverIssuedOwner)
			})
			if canceledChild {
				var failure *dataplane.DomainTCPCleanupFailure
				if !errors.Is(err, context.Canceled) || !errors.As(err, &failure) {
					t.Fatal("original cancellation/custody capsule lost", err)
				}
				if failedACK != "" {
					if err := dataplane.ConfigureNativeDomainFailureACK(secondHeld, failure, failedACK); err != nil {
						t.Fatal("configure same original cleanup ACK", err)
					}
				}
				joinErr := manager.JoinFailedDomainTCPNative(secondHeld, secondCleanup, history, failure)
				if failedACK == "process" {
					if !errors.Is(joinErr, dataplane.ErrNativeDomainFailureACK) {
						t.Fatal("actual process ACK cut missing", joinErr)
					}
					if err := manager.CheckExecutionRecovery(secondHeld); err == nil {
						t.Fatal("lost cleanup ACK released original pending custody")
					}
				} else if joinErr != nil {
					t.Fatal("fresh cleanup original child join/row publication", joinErr)
				}
				if err := manager.JoinFailedDomainTCPNative(secondHeld, secondCleanup, history, failure); err != nil {
					t.Fatal("same original native terminal ACK retry", err)
				}
				if len(domainOriginalRuntimeChildren(t, manager.StateRoot)) != 0 {
					t.Fatal("original child survived cleanup join")
				}
				if canceledReady {
					retireErr := manager.RetireFailedDomainTCPContinuation(secondHeld, secondCleanup, history, failure)
					if failedACK != "" && failedACK != "process" {
						if !errors.Is(retireErr, dataplane.ErrNativeDomainFailureACK) {
							domainOriginalPublicationDiagnostics(t, manager.StateRoot)
							t.Fatal("actual failed retirement ACK cut missing", retireErr)
						}
						if err := manager.CheckExecutionRecovery(secondHeld); err == nil {
							t.Fatal("partial failed retirement released custody")
						}
					} else if retireErr != nil {
						domainOriginalPublicationDiagnostics(t, manager.StateRoot)
						t.Fatal("original failed ready generation retirement", retireErr)
					}
					if err := manager.RetireFailedDomainTCPContinuation(secondHeld, secondCleanup, history, failure); err != nil {
						t.Fatal("same original failed retirement ACK retry", err)
					}
					if err := manager.CheckExecutionRecovery(secondHeld); err != nil {
						t.Fatal("failed original standby/keeper current", err)
					}
					if canceledPublished {
						if neverIssuedOwner == nil || canceledAlias == "" {
							t.Fatal("published original custody missing")
						}
						if err := neverIssuedOwner.RetainedStandbyCurrent(secondHeld); err != nil {
							t.Fatal("failed published standby current", err)
						}
						if err := neverIssuedOwner.RetireUnpublishedStandby(secondHeld, secondCleanup); !errors.Is(err, dataplane.ErrDomainPolicyTCPCaptureRetirementPending) {
							t.Fatal("published failed alias was removable", err)
						}
						late := peers.clientRequest(t, secondHeld, "selected", canceledAlias)
						if late.Source != domainOriginalClient || late.SourcePort == "" || late.SourcePort != late.ClientPort || late.Marker != "native-domain-service" {
							t.Fatal("failed published alias lost restorative tuple", late)
						}
					}
					late := peers.clientRequest(t, secondHeld, "selected", retainedPublishedAlias)
					if late.Source != domainOriginalClient || late.SourcePort == "" || late.SourcePort != late.ClientPort || late.Marker != "native-domain-service" {
						t.Fatal("failed retirement changed old alias tuple", late)
					}
					if canceledPublished {
						t.Log("actual published successor canceled; source/handler/native joins and capture Remove retain original restorative standby; actual cached late-SYN tuple preserved, published alias removal refused")
					} else {
						t.Log("actual ready but never-issued successor canceled; same original source/handler/native joins, capture Remove and restorative handoff, actual zero-issued baseline Remove→keeper and repeat ACK; old published alias remains original baseline")
					}
					return
				}
				if err := manager.CheckExecutionRecovery(secondHeld); err == nil {
					t.Fatal("child-only cleanup released unresolved DNS/capture custody")
				}
				late := peers.clientRequest(t, secondHeld, "selected", retainedPublishedAlias)
				if late.Source != domainOriginalClient || late.SourcePort == "" || late.SourcePort != late.ClientPort || late.Marker != "native-domain-service" {
					t.Fatal("child cleanup changed old alias tuple", late)
				}
				t.Log("actual canceled-after-Start original child joined under fresh cleanup; same two original journal ACKs; pending DNS/capture custody retained, no pool retirement or forward grant")
				return
			}
			if joinedFailure {
				if !domainOriginalOnlyJoinedFailure(err) || neverIssuedOwner == nil {
					t.Fatal("original callback error changed or cleanup error hidden", err)
				}
				if err := neverIssuedOwner.RetainedStandbyCurrent(secondHeld); err != nil {
					t.Fatal("failed action did not retain genuinely current original standby", err)
				}
				t.Log("original callback error preserved; genuine joined native/receipt/kernel proof retained only restorative standby, failed step remains failed")
			} else if err != nil {
				t.Fatal("actual original successor/full selected workflow", err)
			}
			if version, _, err := dataplane.InspectRetainedExecutionReadVersion(secondHeld, manager.StateRoot); err != nil || version != 8 {
				t.Fatal("coexistence requires actual reader8", version, err)
			}
			if neverIssuedSuccessor {
				if neverIssuedOwner == nil {
					t.Fatal("original never-issued owner missing")
				}
				if err := neverIssuedOwner.RetireUnpublishedStandby(secondHeld, secondCleanup); err != nil {
					t.Fatal("actual never-issued successor COMMON retirement", err)
				}
				if err := neverIssuedOwner.RetireUnpublishedStandby(secondHeld, secondCleanup); err != nil {
					t.Fatal("same actual retired ACK", err)
				}
				if err := manager.CheckExecutionRecovery(secondHeld); err != nil {
					t.Fatal("retired successor keeper fresh absence", err)
				}
				late := peers.clientRequest(t, secondHeld, "selected", retainedPublishedAlias)
				if late.Source != domainOriginalClient || late.SourcePort == "" || late.SourcePort != late.ClientPort || late.Marker != "native-domain-service" {
					t.Fatal("retirement changed original published alias", late)
				}
				secondRelease()
				thirdCtx, stopThird := context.WithTimeout(ctx, 100*time.Second)
				defer stopThird()
				thirdHeld, thirdRelease, err := operations.ExclusiveContext(thirdCtx)
				if err != nil {
					t.Fatal(err)
				}
				defer thirdRelease()
				freshNow = time.Now().UTC()
				scope.ObservedAt, scope.FreshUntil = freshNow, freshNow.Add(60*time.Second)
				thirdDomain, err := dataplane.FreezeDomainPolicyRuntimePlan(domain.Generation, policy, scope, nil, []dataplane.DomainPolicyService{{ID: service.ID, Route: "xray:" + nodeID, Selected: true, Domains: service.Domains}}, freshNow)
				if err != nil {
					t.Fatal(err)
				}
				thirdTransport := dataplane.CloneSyntheticDNSTransportPlan(transport)
				thirdTransport.DomainPolicyDigest = thirdDomain.Digest
				thirdPlan, err := dataplane.BuildAt(dataplane.Input{Revision: store.Get().Revision, DomainPolicy: thirdDomain, SyntheticDNS: thirdTransport, NetworkProfileID: "wan-0123456789ab", Routes: []dataplane.Route{route}, Engines: []dataplane.Engine{{ID: "xray", Installed: true, Configured: true, Activatable: true, Canary: true}}, Host: plan.Host}, freshNow)
				if err != nil || thirdPlan.Ready {
					t.Fatal("fresh post-retirement intent", err)
				}
				if err := manager.WithDomainTCPContinuationResources(dataplane.WithReviewGuard(thirdHeld, control.Current), thirdPlan, history, detached, func(original context.Context) error {
					return runDomainOriginalSuccessor(t, original, peers, manager, dnsAdapter, backend, xray, nodeSource, resolver, control, history, thirdPlan, service, nodeID, detached, retainedPublishedAlias, false, nil)
				}); err != nil {
					t.Fatal("original next source after never-issued suffix", err)
				}
				t.Log("actual never-issued successor source never sent DNS; SAME original COMMON Remove/receipts/kernel absence and metadata keeper; new original source continues closed full suffix, new selected service and old cached-alias baseline")
			}
			t.Log("actual two original generations: published old alias retained; successor DNS/native/capture/new selected TLS and old cached-alias TLS, both original tuples checked; no cold reconstruction or ordinary Apply grant")
		}
	}
	if dnsOnly {
		t.Log("DNS-only ownership scenario: actual precheck/Reserve/native/capture/kernel/DNS client publication, then original Stop+cached-alias TLS direct baseline with original tuple; selected-runtime service workflow NOT tested here; no new Apply/cache-retirement authority")
	} else {
		t.Log("actual original DoH Reserve→native Xray→capture COMMON→DNS publication→selected TLS; mismatched SNI/opaque and late SYN preserve routed client source+bytes; capture/native child joined; original known standby readback survives exclusive release under reader4; full retirement remains pending, ordinary Apply stays blocked")
	}
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
