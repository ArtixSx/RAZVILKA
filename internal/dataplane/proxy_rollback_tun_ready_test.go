package dataplane

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

func TestProxyTUNLinkUpReadsAdministrativeFlag(t *testing.T) {
	for _, test := range []struct {
		line string
		up   bool
	}{
		{"77: rz-sing: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1500 state UNKNOWN", true},
		{"77: rz-sing: <UP> mtu 1500 qdisc noop\n    link/[65534]", true},
		{"77: rz-sing: <POINTOPOINT,LOWER_UP> mtu 1500 state UP", false},
		{"77: other: <UP> mtu 1500", false},
		{"0: rz-sing: <UP> mtu 1500", false},
		{"77: rz-sing: <> mtu 1500\n    alias <UP>", false},
		{"", false},
	} {
		if got := proxyTUNLinkUp([]byte(test.line), "rz-sing"); got != test.up {
			t.Errorf("header %q: ready=%v, want %v", test.line, got, test.up)
		}
	}
}

func TestProxyTUNReadinessDeadlineAndOwnerExit(t *testing.T) {
	for _, mode := range []string{"deadline", "sidecar-exited"} {
		t.Run(mode, func(t *testing.T) {
			a, processes, _ := networkCleanupProxy(t)
			sidecar := a.sidecarProcess().ID
			processes.running[sidecar] = true
			a.Timeout = 40 * time.Millisecond
			a.Runner = networkCleanupRunner(func(ctx context.Context, _ string, _ ...string) ([]byte, error) {
				if mode == "deadline" {
					<-ctx.Done()
				} else {
					processes.running[sidecar] = false
				}
				return []byte("77: " + a.Interface + ": <UP> mtu 1500"), nil
			})
			err := a.waitForInterface(context.Background())
			if err == nil || (mode == "deadline" && !errors.Is(err, context.DeadlineExceeded)) {
				t.Fatalf("invalid readiness result after %s: %v", mode, err)
			}
		})
	}
}

func TestSingBoxRollbackWaitsForRestoredInterfaceBeforePolicy(t *testing.T) {
	for _, test := range []struct {
		name   string
		cancel bool
		down   bool
	}{{"delayed-interface", false, false}, {"canceled-before-interface", true, false},
		{"present-before-up", false, true}, {"cancel-while-down", true, true}} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			a, processes, _ := networkCleanupProxy(t)
			a.Configs.LiveRoot = privateScopedXrayFixtureDir(t)
			processes.running[a.engineProcess().ID], processes.running[a.sidecarProcess().ID] = true, true
			if _, err := a.Configs.Stage("sing-box", "main", `{"outbounds":[{"type":"vless","server":"203.0.113.9","server_port":443}]}`); err != nil {
				t.Fatal(err)
			}
			p := Plan{EngineDrafts: []string{"sing-box/main"}, Routes: []Route{{ServiceID: "site", Resolved: "sing-box", CIDRs: []string{"198.51.100.20/32"}, Sources: []string{"192.168.1.25/32"}}}}
			activate := func() string {
				t.Helper()
				root := privateScopedXrayFixtureDir(t)
				if err := a.Snapshot(ctx, p, root); err != nil {
					t.Fatal(err)
				}
				if err := a.Stage(ctx, p, root); err != nil {
					t.Fatal(err)
				}
				if err := a.Activate(ctx, p, root); err != nil {
					t.Fatal(err)
				}
				return root
			}
			original := activate()
			if err := a.Commit(ctx, p, original); err != nil {
				t.Fatal(err)
			}
			p.Routes[0].CIDRs = []string{"198.51.100.21/32"}
			root := activate()
			starts := len(processes.startSpecs)
			base := a.Runner
			checks, added := 0, false
			a.Timeout = time.Second
			a.Runner = networkCleanupRunner(func(c context.Context, name string, args ...string) ([]byte, error) {
				if name == "ip" && len(processes.startSpecs) >= starts+2 {
					if slices.Equal(args, []string{"link", "show", "dev", a.Interface}) {
						checks++
						if checks == 1 {
							if test.cancel {
								cancel()
							}
							if test.down {
								return []byte("77: " + a.Interface + ": <POINTOPOINT,MULTICAST,NOARP> mtu 1500 state DOWN\n"), nil
							}
							return nil, errors.New("owned TUN has not appeared yet")
						}
					}
					if len(args) >= 3 && slices.Equal(args[:3], []string{"route", "add", "default"}) {
						added = true
						if checks < 2 {
							t.Fatal("restoration added a default route before its TUN was up")
						}
					}
				}
				return base.Run(c, name, args...)
			})
			err := a.Rollback(ctx, p, root)
			if test.cancel {
				if !errors.Is(err, context.Canceled) || added || checks != 1 {
					t.Fatalf("canceled wait wrote policy: probes=%d add=%v err=%v", checks, added, err)
				}
				return
			}
			if err != nil || !added {
				t.Fatalf("restoration failed after TUN appeared: probes=%d add=%v err=%v", checks, added, err)
			}
			if ok, err := a.VerifyRollback(ctx, p, root); err != nil || !ok {
				t.Fatal("restored routes failed independent verification", err)
			}
		})
	}
}
