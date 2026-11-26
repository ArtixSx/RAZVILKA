//go:build linux

package dataplane

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The TLS server is in a different namespace. It records the actual egress
// only when the manager has journaled a temporary rule for the current probe.
// Canary and the selected/control clients do not run with that prepared row.
func nativeCommitTransitHTTP(t *testing.T, egress string) int {
	mode := os.Getenv("RAZVILKA_XRAY_COMMIT_TRANSIT_NATIVE")
	if mode == "" {
		return http.StatusOK
	}
	root := os.Getenv("RAZVILKA_XRAY_TUN_ROOT")
	var current *Execution
	found, err := readOptionalJournal(filepath.Join(root, "router-state", "latest-execution.json"), &current)
	if err != nil {
		t.Errorf("read manager journal in fixture TLS server: %v", err)
		return http.StatusInternalServerError
	}
	if !found || len(current.Steps) == 0 || len(current.Resources) == 0 {
		return http.StatusOK
	}
	step := current.Steps[len(current.Steps)-1]
	row := current.Resources[len(current.Resources)-1]
	if step.Adapter != "xray" || step.State != "running" || (step.Phase != "health" && step.Phase != "commit-adapter") || row.Kind != "node-transit" || row.State != "prepared" {
		return http.StatusOK
	}
	status := http.StatusOK
	if mode == "commit-refusal" && step.Phase == "commit-adapter" {
		status = http.StatusServiceUnavailable
	}
	if err := os.WriteFile(filepath.Join(root, "https-"+step.Phase), []byte(fmt.Sprintf("%s %s %d", row.ID, egress, status)), 0600); err != nil {
		t.Errorf("record manager-owned HTTPS observation: %v", err)
		return http.StatusInternalServerError
	}
	return status
}

func nativeCommitTransitApply(t *testing.T, ctx context.Context, mode string, registered *ProxyTunnelAdapter, plan Plan, wantExit string) {
	t.Helper()
	if mode != "success" && mode != "commit-refusal" {
		t.Fatalf("unknown native commit scenario %q", mode)
	}
	if _, err := nativeRouterHTTPSNamespace(); err != nil {
		t.Fatal("isolated router namespace", err)
	}
	if registered.scopedXray || !registered.xrayPlanDispatch || !registered.nodeRouterVerifier || len(plan.Routes) != 1 {
		t.Fatal("expected one node route on the stock Xray dispatcher")
	}
	route := plan.Routes[0]
	if len(route.Domains) != 0 || len(route.CIDRs) != 1 || route.CIDRs[0] != nativeXrayHTTPSIP+"/32" || len(route.Sources) != 1 || route.Sources[0] != "192.168.1.25/32" {
		t.Fatal("expected a single selected client and the fixture HTTPS address")
	}
	view, err := registered.xrayModeView(proxyXrayModeNode)
	if err != nil {
		t.Fatal(err)
	}
	root := os.Getenv("RAZVILKA_XRAY_TUN_ROOT")
	m := New(filepath.Join(root, "router-state"))
	m.FreshProfile = registered.FreshProfile
	if err := m.Register(registered); err != nil {
		t.Fatal(err)
	}
	// Keep the real namespace client probes. Count only accepted observations
	// through the selected client and verify the excluded client's direct egress.
	probe := registered.NodeTUNProbe
	clientPairs := 0
	registered.NodeTUNProbe = func(c context.Context, r NodeTUNRequest) (NodeTUNObservation, error) {
		observation, err := probe(c, r)
		if err == nil && observation.ServiceAccepted && observation.SelectedEgress.String() == wantExit && observation.ControlEgress.String() == "93.184.216.16" {
			clientPairs++
		}
		return observation, err
	}
	kernelSnapshot := func() string {
		var snapshot strings.Builder
		for _, args := range [][]string{{"ip", "-4", "rule", "show"}, {"ip", "-6", "rule", "show"}, {"ip", "-4", "route", "show", "table", "all"}, {"iptables", "-t", "nat", "-S"}} {
			out, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
			if err != nil {
				t.Fatalf("read fixture kernel state %v: %v %s", args, err, out)
			}
			fmt.Fprintln(&snapshot, args, string(out))
		}
		return snapshot.String()
	}
	before := kernelSnapshot()
	directClients := func() {
		t.Helper()
		got, err := probe(ctx, NodeTUNRequest{Destination: netip.MustParseAddr(nativeXrayHTTPSIP)})
		if err != nil || !got.ServiceAccepted || got.SelectedEgress.String() != "93.184.216.16" || got.ControlEgress != got.SelectedEgress {
			t.Fatalf("both real clients must reach the fixture through the original direct exit: %+v %v", got, err)
		}
	}
	directClients()
	reviewed := WithReviewGuard(ctx, func(c context.Context) error {
		return verifyNetworkProfile(c, plan.NetworkProfileID, registered.FreshProfile)
	})
	execution, applyErr := m.Apply(reviewed, plan, nil)
	committed, exists, err := m.Committed()
	if err != nil || exists != (mode == "success") {
		t.Fatalf("commit presence=%v err=%v apply=%v steps=%+v", exists, err, applyErr, execution.Steps)
	}
	wantPairs := 1
	if mode == "success" {
		wantPairs = 2
		if applyErr != nil || execution.State != "committed" || committed.Digest != plan.Digest {
			t.Fatalf("actual Manager.Apply failed: state=%s err=%v", execution.State, applyErr)
		}
	} else {
		// The staged cold Xray snapshot had no earlier active policy to attest.
		// Its verifier reports (false,nil) after comparing runtime files and PIDs.
		// Check both rollback steps, both clients and the kernel independently.
		if applyErr == nil || execution.State != "rolled-back" || execution.RollbackVerified {
			t.Fatalf("unexpected cold rollback after commit refusal: state=%s verified=%v err=%v", execution.State, execution.RollbackVerified, applyErr)
		}
		steps := map[string]string{}
		for _, step := range execution.Steps {
			if step.Adapter == "xray" {
				steps[step.Phase] = step.State
			}
		}
		if steps["health"] != "passed" || steps["commit-adapter"] != "failed" || steps["rollback"] != "passed" || steps["verify-rollback"] != "passed" {
			t.Fatalf("wrong failure or incomplete cleanup: %+v", steps)
		}
	}
	if clientPairs != wantPairs || len(execution.Resources) != 2 || validateExecutionResources(execution, true) != nil {
		t.Fatalf("expected two settled manager resources and %d genuine client pairs; got rows=%d pairs=%d apply=%v", wantPairs, len(execution.Resources), clientPairs, applyErr)
	}
	for i, phase := range []string{"health", "commit-adapter"} {
		row := execution.Resources[i]
		if row.Kind != "node-transit" || row.State != "removed" || row.NodeTransit == nil || row.NodeTransit.Destination != netip.MustParseAddr(nativeXrayHTTPSIP) ||
			row.NodeTransit.PlanDigest != plan.Digest || row.NodeTransit.Engine != "xray" || i == 1 && (row.ID == execution.Resources[0].ID || *row.NodeTransit != *execution.Resources[0].NodeTransit) {
			t.Fatalf("unexpected resource identity or terminal state for %s: %+v", phase, row)
		}
		status := http.StatusOK
		if mode == "commit-refusal" && i == 1 {
			status = http.StatusServiceUnavailable
		}
		observation, err := os.ReadFile(filepath.Join(root, "https-"+phase))
		if err != nil || string(observation) != row.ID+" "+wantExit+" "+strconv.Itoa(status) {
			t.Fatalf("%s HTTPS observation did not match actual receipt %s, egress and HTTP %d: %q %v", phase, row.ID, status, observation, err)
		}
	}
	if mode == "success" {
		if _, err := m.Deactivate(reviewed); err != nil {
			t.Fatal("real Stop", err)
		}
	}
	if err := New(m.StateRoot).CheckExecutionRecovery(ctx); err != nil {
		t.Fatal("reopen persisted execution after Stop or rollback", err)
	}
	if before != kernelSnapshot() || view.Processes.Running(view.engineProcess()) || view.Processes.Running(view.sidecarProcess()) {
		t.Fatal("Stop or rollback did not restore original kernel routing, NAT or process state")
	}
	directClients()
	t.Logf("Xray commit transit %s: PASS", mode)
}
