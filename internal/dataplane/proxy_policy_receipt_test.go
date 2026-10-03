package dataplane

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestProxyCandidatePolicyFailurePreservesConcurrentDefaultAndFencesRollback(t *testing.T) {
	f := scopedXrayTestFixture(t)
	a := f.a
	ctx := context.Background()
	root := stageScopedFixture(t, f)
	base := a.Runner
	deletes := 0
	injected := false
	foreign := "default dev " + a.Interface + " proto boot scope link metric 1024\n"
	foreignKey := "6/" + strconv.Itoa(a.Table)
	a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		if name == "ip" && strings.HasPrefix(joined, "-6 route add default") {
			if f.runner.defaults == nil {
				f.runner.defaults = map[string]string{}
			}
			f.runner.defaults[foreignKey] = foreign
			injected = true
			return []byte("RTNETLINK answers: File exists"), errors.New("concurrent EEXIST")
		}
		if name == "ip" && (strings.Contains(joined, "route del") || strings.Contains(joined, "rule del")) {
			deletes++
		}
		return base.Run(ctx, name, args...)
	})
	if err := a.Activate(ctx, f.plan, root); err == nil || !injected {
		t.Fatal("concurrent default accepted", err)
	}
	before := deletes
	starts := len(f.processes.startSpecs)
	if err := a.Rollback(ctx, f.plan, root); !errors.Is(err, ErrProxyPolicyUnknown) {
		t.Fatal("uncertain additions allowed compensation", err)
	}
	if deletes != before || len(f.processes.startSpecs) != starts || f.runner.defaults[foreignKey] != foreign {
		t.Fatal("rollback deleted foreign default or restarted under unknown authority")
	}
	receipt, err := a.readCandidatePolicyReceipt(root, mustScopedPolicy(t, a, root))
	if err != nil || receipt.Phase != "unknown" {
		t.Fatal(receipt, err)
	}
}

func mustScopedPolicy(t *testing.T, a *ProxyTunnelAdapter, root string) PolicyState {
	t.Helper()
	state, err := a.readStagedPolicy(root)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func TestProxyCandidatePolicyMissingCorruptUnknownReceiptNeverDeletesIntent(t *testing.T) {
	for _, mode := range []string{"missing", "corrupt", "unknown", "wrong-engine", "changed-policy"} {
		t.Run(mode, func(t *testing.T) {
			f := scopedXrayTestFixture(t)
			a := f.a
			ctx := context.Background()
			root := stageScopedFixture(t, f)
			state := mustScopedPolicy(t, a, root)
			switch mode {
			case "missing":
				if err := os.Remove(proxyPolicyReceiptPath(root)); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.WriteFile(proxyPolicyReceiptPath(root), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			default:
				receipt, err := a.readCandidatePolicyReceipt(root, state)
				if err != nil {
					t.Fatal(err)
				}
				receipt.Phase = "unknown"
				if mode == "wrong-engine" {
					receipt.Engine = "sing-box"
				}
				if mode == "changed-policy" {
					receipt.Digest = strings.Repeat("0", 64)
				}
				if err := writeProxyPolicyReceipt(root, receipt); err != nil {
					t.Fatal(err)
				}
			}
			base := a.Runner
			mutated := false
			a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
				joined := strings.Join(args, " ")
				if strings.Contains(joined, "route del") || strings.Contains(joined, "rule del") || strings.Contains(joined, "rule add") {
					mutated = true
				}
				return base.Run(ctx, name, args...)
			})
			if err := a.Rollback(ctx, f.plan, root); !errors.Is(err, ErrProxyPolicyUnknown) || mutated || len(f.processes.startSpecs) != 1 { // one canary already cleaned
				t.Fatal("staged intent acquired deletion authority", err, mutated, len(f.processes.startSpecs))
			}
		})
	}
}

func TestProxyCandidatePolicyConfirmedCleanupCannotBeReplayed(t *testing.T) {
	f := scopedXrayTestFixture(t)
	a := f.a
	ctx := context.Background()
	root := stageScopedFixture(t, f)
	if err := a.Activate(ctx, f.plan, root); err != nil {
		t.Fatal(err)
	}
	if err := a.removeCandidatePolicy(ctx, root); err != nil {
		t.Fatal(err)
	}
	base := a.Runner
	a.Runner = networkCleanupRunner(func(context.Context, string, ...string) ([]byte, error) {
		t.Fatal("removed receipt replayed kernel command")
		return nil, nil
	})
	if err := a.removeCandidatePolicy(ctx, root); err != nil {
		t.Fatal(err)
	}
	a.Runner = base
	receipt, err := a.readCandidatePolicyReceipt(root, mustScopedPolicy(t, a, root))
	if err != nil || receipt.Phase != "removed" {
		t.Fatal(receipt, err)
	}
}
