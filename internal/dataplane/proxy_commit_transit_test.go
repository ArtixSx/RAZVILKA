package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCommitNodeTransitOnlyForScopedRouterVerification(t *testing.T) {
	node := "xray:node-" + strings.Repeat("a", 64)
	nodePlan := Plan{Routes: []Route{{Resolved: node, Selected: node}}}
	dispatcher := &ProxyTunnelAdapter{EngineID: "xray", xrayPlanDispatch: true, nodeRouterVerifier: true}
	for _, tc := range []struct {
		name    string
		adapter *ProxyTunnelAdapter
		plan    Plan
		want    bool
	}{
		{"stock dispatcher", dispatcher, nodePlan, true},
		{"scoped router", &ProxyTunnelAdapter{EngineID: "xray", scopedXray: true, nodeRouterVerifier: true}, nodePlan, true},
		{"generic Xray", dispatcher, Plan{Routes: []Route{{Resolved: "xray"}}}, false},
		{"mixed Xray modes", dispatcher, Plan{Routes: []Route{{Resolved: node}, {Resolved: "xray"}}}, false},
		{"invalid node", dispatcher, Plan{Routes: []Route{{Resolved: "xray:invalid"}}}, false},
		{"retirement", dispatcher, Plan{RetiringAdapters: []string{"xray"}}, false},
		{"external verifier", &ProxyTunnelAdapter{EngineID: "xray", scopedXray: true}, nodePlan, false},
		{"other engine", &ProxyTunnelAdapter{EngineID: "usque", nodeRouterVerifier: true}, nodePlan, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.adapter.commitNeedsNodeTransit(tc.plan); got != tc.want {
				t.Fatalf("commit transit = %v, want %v", got, tc.want)
			}
		})
	}
	s := &executionResourceScope{}
	ctx := s.nodeTransitContext(context.Background())
	if _, ok := ctx.Value(nodeTransitRegistrarKey{}).(nodeTransitRegistrar); !ok {
		t.Fatal("missing node transit registrar")
	}
	for _, key := range []any{nfqws2ActiveActivationRegistrarKey{}, nfqwsExecutionRegistrarKey{}, xraySelectedTCPRegistrarKey{}, xrayDomainTCPRegistrarKey{}} {
		if ctx.Value(key) != nil {
			t.Fatalf("unexpected commit authority %T", key)
		}
	}
}

// Both phase-local issuers write into one real Manager execution. The fixture
// models the kernel command runner, while the receipts and ownership checks run.
func TestCommitNodeTransitKeepsBothSettledReceipts(t *testing.T) {
	for _, cancelCommit := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "cancel-second"}[cancelCommit], func(t *testing.T) {
			f := executionResourceManagerFixture(t)
			root := filepath.Join(f.m.StateRoot, "transactions", f.p.PlanID)
			if err := os.MkdirAll(root, 0o700); err != nil {
				t.Fatal(err)
			}
			e := Execution{PlanID: f.p.PlanID, Digest: f.p.Digest, State: "started"}
			health, err := f.m.newExecutionResourceScope(f.ctx, f.p, "xray", &e, root)
			if err != nil {
				t.Fatal(err)
			}
			defer health.close()
			ctx := f.bind(t, health.context())
			if err := f.lease.Apply(ctx); err != nil {
				t.Fatal(err)
			}
			if err := f.remove(ctx); err != nil {
				t.Fatal(err)
			}
			if err := health.close(); err != nil {
				t.Fatal(err)
			}
			old := f.registration

			parent, cancel := context.WithCancel(f.ctx)
			defer cancel()
			commit, err := f.m.newExecutionResourceScope(parent, f.p, "xray", &e, root)
			if err != nil {
				t.Fatal(err)
			}
			defer commit.close()
			second, _, _ := nodeTransitFixture(t)
			second.runtime.runner = f.runner
			f.lease = second
			shielded, end := shieldLiveMutation(parent)
			defer end()
			ctx = f.bind(t, commit.nodeTransitContext(shielded))
			if old.root == f.registration.root || old.cleanupGuard(ctx) == nil {
				t.Fatal("commit reused a health-phase resource or its authority")
			}
			if err := f.lease.Apply(ctx); err != nil {
				t.Fatal(err)
			}
			if cancelCommit {
				cancel()
				if ctx.Err() != nil {
					t.Fatal("commit lost its bounded cleanup context")
				}
				cleanup := context.WithoutCancel(ctx)
				if _, err := ctx.Value(nodeTransitRegistrarKey{}).(nodeTransitRegistrar)(cleanup, f.lease.spec); !errors.Is(err, context.Canceled) {
					t.Fatal("cancelled commit still admitted a probe", err)
				}
				ctx = cleanup
			}
			if err := f.remove(ctx); err != nil {
				t.Fatal(err)
			}
			if err := commit.close(); err != nil {
				t.Fatal(err)
			}
			rows := f.latest(t).Resources
			if len(rows) != 2 || rows[0].ID == rows[1].ID || rows[0].State != "removed" || rows[1].State != "removed" || f.runner.adds != 2 || f.runner.deletes != 2 {
				t.Fatalf("both probes must settle their own rule: %+v; adds=%d deletes=%d", rows, f.runner.adds, f.runner.deletes)
			}
		})
	}
}
