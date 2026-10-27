//go:build linux

package dataplane

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Opt-in extension: namespace topology, pinned engines and TLS server are the
// existing native fixture. Production receives no additional capability.
func TestNativeScopedXrayAllLAN(t *testing.T) {
	if os.Getenv("RAZVILKA_XRAY_ALL_LAN_NATIVE") != "1" {
		t.Skip("coordinator-only: explicit all-LAN native fixture")
	}
	TestNativeScopedXrayTUN(t)
}

func nativeScopedXrayAllLANLifecycle(t *testing.T, parent context.Context, construct func() *ProxyTunnelAdapter, original Plan, expectedExit string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 50*time.Second)
	defer cancel()
	root := os.Getenv("RAZVILKA_XRAY_TUN_ROOT")
	if os.Geteuid() != 0 || os.Getenv("RAZVILKA_XRAY_TUN_ROLE") != "router" || os.Getenv("RAZVILKA_XRAY_ALL_LAN_NATIVE") != "1" {
		t.Fatal("all-LAN requires original owned router fixture")
	}
	if _, err := nativeRouterHTTPSNamespace(); err != nil {
		t.Fatal(err)
	}
	adapter := func() *ProxyTunnelAdapter { a := construct(); a.NodeTUNProbe = nil; return a }
	a := adapter()
	plan := original
	plan.Routes = cloneNetworkPolicyRoutes(original.Routes)
	plan.Routes[0].Sources = nil
	plan.Routes[0].Domains = nil
	plan.Routes[0].CIDRs = []string{nativeXrayHTTPSIP + "/32"}
	var err error
	plan, err = nativeXrayDispatcherPlan(plan, expectedExit)
	if err != nil {
		t.Fatal(err)
	}
	transaction := filepath.Join(filepath.Dir(a.StateRoot), "transactions", plan.PlanID, a.ID())
	for _, step := range []struct {
		name string
		run  func(context.Context, Plan, string) error
	}{{"Snapshot", a.Snapshot}, {"Stage", a.Stage}, {"Validate", a.Validate}} {
		if err := step.run(ctx, plan, transaction); err != nil {
			t.Fatal("all-LAN", step.name, err)
		}
	}
	if err := a.Canary(ctx, plan.RoutePlanFor("xray"), transaction); err != nil {
		t.Fatal("all-LAN Canary", err)
	}
	view, _, err := a.dispatchCandidateXrayPlan(plan, transaction, true)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := view.readStagedPolicy(transaction)
	if err != nil || len(staged.Rules) != 1 || staged.Rules[0].Source != "192.168.1.0/24" || staged.Rules[0].Destination != nativeXrayHTTPSIP+"/32" || staged.Forwarding == nil || len(staged.Forwarding.Rules) != 1 || staged.Forwarding.Rules[0].Ingress != "br0" {
		t.Fatal("actual physical bridge scope differs", staged, err)
	}
	// No paired-client callback is available to substitute for the real router
	// verifier: each public health call obtains its original Manager resources.
	for _, step := range []struct {
		name string
		run  func(context.Context, Plan, string) error
	}{{"Activate", a.Activate}, {"Health", a.Health}, {"Commit", a.Commit}} {
		if err := nativeXrayDispatcherExecution(ctx, a, plan, func(c context.Context) error { return step.run(c, plan, transaction) }); err != nil {
			t.Fatal("all-LAN", step.name, err)
		}
		t.Log("all-LAN " + step.name + ": real dispatcher/Manager/router HTTPS passed")
	}
	clients := func(expected string) {
		t.Helper()
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		for _, role := range []string{"SELECTED", "CONTROL"} {
			out := filepath.Join(root, "all-lan-"+strings.ToLower(role)+".json")
			cmd := exec.CommandContext(ctx, "ip", "netns", "exec", os.Getenv("RAZVILKA_XRAY_TUN_"+role+"_NS"), exe, "-test.run=^TestNativeScopedXrayTUN$", "-test.timeout=10s")
			cmd.Env = append(os.Environ(), "RAZVILKA_XRAY_TUN_ROLE=probe", "RAZVILKA_XRAY_TUN_DESTINATION="+nativeXrayHTTPSIP, "RAZVILKA_XRAY_TUN_PROBE_OUT="+out)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("all-LAN actual %s HTTPS: %v %s", role, err, output)
			}
			raw, err := os.ReadFile(out)
			var result struct {
				IP       string `json:"ip"`
				Accepted bool   `json:"accepted"`
			}
			if err != nil || json.Unmarshal(raw, &result) != nil || !result.Accepted || result.IP != expected {
				t.Fatalf("all-LAN %s exit differs: %+v %v", role, result, err)
			}
		}
	}
	clients(expectedExit)
	a = adapter()
	if err := nativeXrayDispatcherExecution(ctx, a, plan, func(c context.Context) error { return a.CommittedNodeHealth(c, plan) }); err != nil {
		t.Fatal("all-LAN fresh adapter health", err)
	}
	view, _, err = a.dispatchCurrentXrayPlan(ctx, plan)
	if err != nil {
		t.Fatal(err)
	}
	sidecar := view.sidecarProcess()
	pid, err := readManagedPID(sidecar)
	if err != nil {
		t.Fatal(err)
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Kill(); err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(3 * time.Second)
	for view.Processes.Running(sidecar) && time.Now().Before(until) {
		time.Sleep(20 * time.Millisecond)
	}
	if err := nativeXrayDispatcherExecution(ctx, a, plan, func(c context.Context) error { return a.CommittedNodeHealth(c, plan) }); err == nil {
		t.Fatal("all-LAN killed sidecar remained healthy")
	}
	if err := nativeXrayDispatcherExecution(ctx, a, plan, func(c context.Context) error { return a.Reconcile(c, plan) }); err != nil {
		t.Fatal("all-LAN real restart", err)
	}
	clients(expectedExit)
	if err := nativeXrayDispatcherExecution(ctx, a, plan, func(c context.Context) error { return a.CommittedNodeHealth(c, plan) }); err != nil {
		t.Fatal("all-LAN restarted health", err)
	}
	if err := a.Deactivate(ctx); err != nil {
		t.Fatal("all-LAN Stop", err)
	}
	if view.Processes.Running(view.engineProcess()) || view.Processes.Running(view.sidecarProcess()) {
		t.Fatal("all-LAN Stop left original owned process")
	}
	if err := view.verifyXrayInterfaceAbsent(ctx); err != nil {
		t.Fatal("all-LAN Stop interface", err)
	}
	absent := PolicyState{Interface: view.Interface, Table: view.Table, PriorityBase: view.Priority}
	if err := view.verifyCandidateRemoved(ctx, absent, staged); err != nil {
		t.Fatal("all-LAN Stop kernel", err)
	}
	clients("93.184.216.16")
	t.Log(fmt.Sprintf("all-LAN native lifecycle: physical br0/192.168.1.0/24 only; both real LAN clients proxy=%s; fresh adapter + killed-sidecar restart; Stop→both direct; no Internet/router/HIL claim", expectedExit))
}
