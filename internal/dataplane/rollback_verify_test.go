package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type rollbackVerifierFake struct {
	*networkExecutionAdapter
	verify func(context.Context) (bool, error)
}

func (a *rollbackVerifierFake) VerifyRollback(ctx context.Context, _ Plan, _ string) (bool, error) {
	return a.verify(ctx)
}

func TestRollbackReadbackRunsAfterWholeUndoAndPersistsReceipt(t *testing.T) {
	for _, mode := range []string{"pass", "unsupported", "readback-failed", "canceled", "undo-failed"} {
		t.Run(mode, func(t *testing.T) {
			m := New(t.TempDir())
			m.FreshProfile = func(context.Context) (string, error) { return executionNetwork, nil }
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			configChanged, undone, called := false, false, false
			base := &networkExecutionAdapter{fakeAdapter: &fakeAdapter{id: "sing-box"}}
			adapter := &rollbackVerifierFake{networkExecutionAdapter: base, verify: func(c context.Context) (bool, error) {
				called = true
				if !base.rollback || !undone || configChanged || c.Err() != nil {
					t.Fatal("readback before complete restoration", base.calls, undone, configChanged, c.Err())
				}
				if mode == "readback-failed" {
					return false, errors.New("restored TUN is missing")
				}
				return mode != "unsupported", nil
			}}
			if err := m.Register(adapter); err != nil {
				t.Fatal(err)
			}
			ctx = WithReviewGuard(ctx, func(context.Context) error {
				if configChanged {
					return ErrReviewChanged
				}
				return nil
			})
			execution, err := m.Apply(ctx, networkExecutionPlan(), func() (func() error, error) {
				configChanged = true
				if mode == "canceled" {
					cancel()
				}
				return func() error {
					undone = true
					configChanged = false
					if mode == "undo-failed" {
						return errors.New("cannot persist desired state")
					}
					return nil
				}, nil
			})
			wantVerified := mode == "pass" || mode == "canceled"
			wantState := "rolled-back"
			if mode == "readback-failed" || mode == "undo-failed" {
				wantState = "rollback-failed"
			}
			if err == nil || !called || execution.State != wantState || execution.RollbackVerified != wantVerified {
				t.Fatal(execution, err, called)
			}
			status, statusErr := m.Status()
			if statusErr != nil || status.Execution == nil || status.Execution.RollbackVerified != wantVerified {
				t.Fatal(status, statusErr)
			}
			if wantState == "rollback-failed" {
				before := len(base.calls)
				_, err = m.Apply(context.Background(), networkExecutionPlan(), nil)
				if !errors.Is(err, ErrExecutionJournal) || len(base.calls) != before {
					t.Fatal("failed readback allowed a new candidate", err)
				}
			}
		})
	}
}

func TestRollbackVerifierTimeoutCannotGrantReceipt(t *testing.T) {
	m := New(t.TempDir())
	m.RollbackTimeout = 15 * time.Millisecond
	m.FreshProfile = func(context.Context) (string, error) { return executionNetwork, nil }
	a := &rollbackVerifierFake{networkExecutionAdapter: &networkExecutionAdapter{fakeAdapter: &fakeAdapter{id: "sing-box", failAt: "health"}}, verify: func(ctx context.Context) (bool, error) { <-ctx.Done(); return true, nil }}
	_ = m.Register(a)
	x, err := m.Apply(context.Background(), networkExecutionPlan(), nil)
	if err == nil || x.RollbackVerified || x.State != "rollback-failed" {
		t.Fatal(x, err)
	}
}

func TestProxyRollbackReadbackRejectsRestoredProcessFileAndKernelDrift(t *testing.T) {
	for _, mode := range []string{"pass", "process-died", "process-died-during-readback", "file-changed", "missing-rule", "missing-firewall", "cold-history"} {
		t.Run(mode, func(t *testing.T) {
			a, r, state := proxyForwardingFixture(t)
			a.Processes = r.processes
			a.EngineBin = "sing-box"
			a.SidecarBin = "sing-box"
			a.bootIdentity = func() (string, error) { return "boot-A", nil }
			a.SOCKSProbe = func(context.Context, string) error { return nil }
			initializePolicyLayout(&state)
			r.processes.running["sing-box-engine"] = true
			r.processes.running["sing-box-tun"] = true
			if err := os.MkdirAll(a.runtimeRoot(), 0o700); err != nil {
				t.Fatal(err)
			}
			data, _ := json.Marshal(state)
			for path, content := range map[string][]byte{a.policyPath(): data, a.engineConfigPath(): []byte(`{}`), a.sidecarConfigPath(): []byte(`{}`)} {
				if err := os.WriteFile(path, content, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			ctx := context.Background()
			if err := a.applyOwnedPolicy(ctx, state); err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			if err := a.Snapshot(ctx, Plan{}, root); err != nil {
				t.Fatal(err)
			}
			staged, _ := json.Marshal(state)
			if err := os.WriteFile(filepath.Join(root, "policy.staged.json"), staged, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := a.Rollback(ctx, Plan{}, root); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "process-died":
				delete(r.processes.running, "sing-box-tun")
			case "file-changed":
				_ = os.WriteFile(a.engineConfigPath(), []byte(`[]`), 0o600)
			case "missing-rule":
				r.policy.entries = nil
			case "missing-firewall":
				r.firewall.table("iptables", "filter")[state.Forwarding.Chain] = nil
			case "cold-history":
				snapshot, _ := readProxySnapshot(root)
				snapshot.PolicyWasActive = false
				data, _ := json.Marshal(snapshot)
				_ = os.WriteFile(filepath.Join(root, "snapshot.json"), data, 0o600)
			}
			r.firewall.calls = nil
			base := a.Runner
			a.Runner = networkCleanupRunner(func(c context.Context, name string, args ...string) ([]byte, error) {
				if mode == "process-died-during-readback" && strings.Join(args, " ") == "rule show" {
					delete(r.processes.running, "sing-box-tun")
				}
				if strings.Contains(strings.Join(args, " "), "rule add") || strings.Contains(strings.Join(args, " "), "rule del") {
					t.Fatal("readback changed kernel")
				}
				return base.Run(c, name, args...)
			})
			verified, err := a.VerifyRollback(ctx, Plan{}, root)
			if mode == "pass" {
				if err != nil || !verified {
					t.Fatal(verified, err)
				}
			} else if mode == "cold-history" {
				if err != nil || verified {
					t.Fatal(verified, err)
				}
			} else if err == nil || verified {
				t.Fatal("drift was confirmed", mode, verified, err)
			}
			requireOnlyFirewallReads(t, r.firewall)
		})
	}
}

func TestRollbackChecksCandidateOnlyFamilyWithoutChangingRules(t *testing.T) {
	for _, mode := range []string{"pass", "ipv6-rule-left", "ipv6-chain-left", "ipv6-reference-left", "inspection-failed", "foreign-slot"} {
		t.Run(mode, func(t *testing.T) {
			a, r, restored := proxyForwardingFixture(t)
			initializePolicyLayout(&restored)
			if err := a.applyOwnedPolicy(context.Background(), restored); err != nil {
				t.Fatal(err)
			}
			candidate := restored
			candidate.Prefixes = []string{"2001:db8:2::1/128"}
			candidate.Rules = []PolicyRule{{Source: "fd00::2/128", Destination: candidate.Prefixes[0]}}
			candidate.Forwarding = &ProxyForwardingState{Chain: restored.Forwarding.Chain, Rules: []ProxyForwardingRule{{Source: "fd00::2/128", Destination: candidate.Prefixes[0], Ingress: "br0"}}}
			v6 := r.firewall.table("ip6tables", "filter")
			if mode == "ipv6-chain-left" {
				v6[candidate.Forwarding.Chain] = nil
			}
			if mode == "ipv6-reference-left" {
				v6["FORWARD"] = append(v6["FORWARD"], []string{"-j", candidate.Forwarding.Chain})
			}
			base := a.Runner
			r.firewall.calls = nil
			a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
				command := strings.Join(args, " ")
				if command == "-6 rule show" && mode == "inspection-failed" {
					return nil, errors.New("IPv6 readback unavailable")
				}
				out, err := base.Run(ctx, name, args...)
				if command == "-6 rule show" && (mode == "ipv6-rule-left" || mode == "foreign-slot") {
					// A candidate tuple and an unknown occupant both deny proof.
					dest := "2001:db8:2::1/128"
					if mode == "foreign-slot" {
						dest = "2001:db8:3::1/128"
					}
					out = append(out, []byte(fmt.Sprintf("\n%d: from fd00::2/128 to %s lookup %d\n", candidate.SharedPriorityBase+1, dest, candidate.Table))...)
				}
				return out, err
			})
			err := a.verifyCandidateRemoved(context.Background(), restored, candidate)
			if (err == nil) != (mode == "pass") {
				t.Fatal(mode, err)
			}
			requireOnlyFirewallReads(t, r.firewall)
		})
	}
}
