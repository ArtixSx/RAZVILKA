//go:build linux

package dataplane

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Genuine source/reservation/material/resource factories and actual Xray child.
// WAN, physical client admission and node check history remain explicit models;
// this proves isolated process ownership, not capture, publication or LAN Apply.
func TestDomainTCPOriginalFactoryProcessCancellation(t *testing.T) {
	if os.Getenv("RAZVILKA_DOMAIN_TCP_FACTORY_NATIVE") != "1" {
		t.Skip("opt-in disposable root namespace")
	}
	if os.Getenv("RAZVILKA_DOMAIN_TCP_FACTORY_CHILD") != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "unshare", "--net", "--fork", os.Args[0], "-test.run=^TestDomainTCPOriginalFactoryProcessCancellation$", "-test.v")
		cmd.Env = append(os.Environ(), "RAZVILKA_DOMAIN_TCP_FACTORY_CHILD=1")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("original process factory: %v %s", err, output)
		}
		t.Log(string(output))
		return
	}
	binary := os.Getenv("RAZVILKA_XRAY_NATIVE")
	if !filepath.IsAbs(binary) {
		t.Fatal("actual absolute Xray binary required")
	}
	domainTCPFactoryLocalDoH(t)
	f := newNodeDefaultSourceFixture(t, nodeDefaultSourceFixtureURI)
	transport, domain := syntheticTransportModelFixture(t)
	_, flow, _ := domainPolicyFixture(t, nil)
	domain.Scope.ObservedAt = f.now
	domain.Scope.FreshUntil = f.now.Add(time.Minute)
	domain.Services[0].Route = "xray:" + f.id
	domain.Digest = domainPolicyRuntimeDigest(domain)
	transport.DomainPolicyDigest = domain.Digest
	service := catalog.Service{ID: domain.Services[0].ID, Name: "Original domain fixture", Category: "fixture", Strategy: []string{"xray"}, Domains: []string{"service.example.com"}, ProbeURL: "https://service.example.com/"}
	check := nodeServiceProofFixtureCheck(f, "original-domain-native")
	check.ServiceID = service.ID
	nodeServiceProofFixtureRecord(t, f, check)
	source := f.review(t, "xray")
	gate := &operationgate.Gate{}
	held, release, err := gate.ExclusiveContext(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	controlRoot := filepath.Join(t.TempDir(), "control")
	if _, err := operationgate.InitializeSelfUpdateControl(held, controlRoot); err != nil {
		t.Fatal(err)
	}
	control, err := gate.ReviewControlEpoch(held, controlRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	manager := New(t.TempDir())
	manager.FreshProfile = func(context.Context) (string, error) { return check.NetworkProfile, nil }
	provider := netidentity.NewProcProvider()
	identity, err := provider.Observe(held)
	if err != nil {
		t.Fatal(err)
	}
	physical := &networkPolicyIdentity{value: identity, provider: provider, withCurrent: provider.WithCurrent}
	if err := manager.Register(&NetworkPolicyAdapter{identity: physical}); err != nil {
		t.Fatal(err)
	}
	dns, err := dnscontrol.New("")
	if err != nil {
		t.Fatal(err)
	}
	dnsAdapter := NewScopedDNSAdapter(context.Background(), dns, manager.StateRoot)
	dnsAdapter.InactivityIdentity = provider
	if err := manager.Register(dnsAdapter); err != nil {
		t.Fatal(err)
	}
	listen, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := int(listen.Addr().(*net.TCPAddr).Port)
	listen.Close()
	xray := &ProxyTunnelAdapter{EngineID: "xray", StateRoot: filepath.Join(manager.StateRoot, "xray"), EngineBin: binary, Processes: OSProcessController{}, SOCKSPort: port, xrayPlanDispatch: true, nodeRouterVerifier: true, Resolver: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}}
	if err := manager.Register(xray); err != nil {
		t.Fatal(err)
	}
	resolver := domainTCPFactoryResolver(t, held, dns, transport, domain, gate, control)
	route := Route{ServiceID: service.ID, LogicalServiceID: service.ID, Resolved: "xray:" + f.id, ProbeService: &service, ProbeURL: service.ProbeURL, Domains: service.Domains}
	plan, err := BuildAt(Input{DomainPolicy: domain, SyntheticDNS: transport, Routes: []Route{route}, NetworkProfileID: check.NetworkProfile}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	plan.Adapters = []string{"xray", scopedDNSAdapterID}
	root := filepath.Join(manager.StateRoot, "transactions", plan.PlanID)
	if err := manager.prepareExecutionRoot(root); err != nil {
		t.Fatal(err)
	}
	execution := &Execution{PlanID: plan.PlanID, Digest: plan.Digest, State: "checking"}
	guard := WithReviewGuard(held, control.Current)
	scope, err := manager.newExecutionResourceScope(guard, plan, "xray", execution, root)
	if err != nil {
		t.Fatal(err)
	}
	defer scope.close()
	original := scope.contextWith(held)
	binding, err := manager.BindSyntheticDNSExecution(original, dnsAdapter, plan)
	if err != nil {
		t.Fatal("same-scope DNS source", err)
	}
	_, mapping := domainTCPFactoryReserve(t, original, binding, resolver, control)
	spec := DomainPolicyTCPCaptureSpec{Xray: DomainPolicyTCPXraySpec{Generation: domain.Generation, NetworkProfile: check.NetworkProfile, ServiceID: service.ID, NodeID: f.id, Name: "service.example.com", RealIP: netip.MustParseAddr("1.1.1.2")}, Client: flow.Client, DeviceID: transport.Definition.DeviceID, Listen: netip.MustParseAddrPort(transport.CaptureEndpoint), Limits: DomainPolicySniffLimits{Bytes: 16 << 10, Timeout: time.Second}}
	material, err := ReviewXrayDomainTCPOperationMaterial(original, binding, xray, source, mapping, service, spec)
	if err != nil {
		t.Fatal("genuine operation material", err)
	}
	resource, err := AcquireXrayDomainTCPExecutionResource(original, material)
	if err != nil {
		t.Fatal("original issuer", err)
	}
	// An unbounded request may only borrow this already finite original phase;
	// it must not select the zero value as an earlier request deadline.
	request, cancelRequest := context.WithCancel(context.Background())
	entered := false
	err = resource.WithNative(request, func(active context.Context) error {
		if err := resource.Current(active); err != nil {
			return err
		}
		entered = true
		cancelRequest()
		<-active.Done()
		return active.Err()
	})
	cancelRequest()
	if !entered || !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled native callback did not run", entered, err)
	}
	cleanup, cancelCleanup := context.WithTimeout(context.WithoutCancel(original), 5*time.Second)
	defer cancelCleanup()
	if resource.child == nil || resource.child.Joined(cleanup) != nil {
		t.Fatal("actual original child not joined")
	}
	if execution.Resources[0].State != "removed" {
		t.Fatal("cleanup did not publish terminal state", execution.Resources[0].Phase)
	}
	if err := scope.close(); err != nil {
		t.Fatal("terminal original scope close", err)
	}
	if err := material.Close(); err != nil {
		t.Fatal("material ownership released before cleanup", err)
	}
	t.Log("genuine DNS Reserve→material→original authored journals→actual inherited-FD Xray→cancel→sole Wait→listener absence; no capture/publication/Apply grant")
}
