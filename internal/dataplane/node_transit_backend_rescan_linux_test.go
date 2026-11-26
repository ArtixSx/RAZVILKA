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
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestNodeRouterSocketInventoryRescan(t *testing.T) {
	for _, tc := range []struct {
		name, phase string
		passes      int
	}{
		{"stable", "", 1},
		{"unsafe-tcp-retired", "backend-socket-disjoint", 0},
		{"retired-unknown", "", 2},
		{"reused-fd", "", 2},
		{"moved-inode", "", 2},
		{"added-unknown", "backend-inode-unclassified", 2},
		{"persistent-unknown", "backend-inode-unclassified", 1},
		{"retained-unknown-plus-churn", "backend-inode-unclassified", 1},
		{"continued-churn", "backend-fd-unstable", 2},
		{"changed-between-passes", "backend-fd-unstable", 1},
		{"owner-changed", "backend-process-initial", 1},
		{"cancelled", "", 1},
		{"failed-table", "backend-netlink-table-read", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proc := t.TempDir()
			fd := filepath.Join(proc, "fd")
			if err := os.Mkdir(fd, 0700); err != nil {
				t.Fatal(err)
			}
			link := func(n, inode string) {
				t.Helper()
				if err := os.Symlink("socket:["+inode+"]", filepath.Join(fd, n)); err != nil {
					t.Fatal(err)
				}
			}
			drop := func(n string) {
				t.Helper()
				if err := os.Remove(filepath.Join(fd, n)); err != nil {
					t.Fatal(err)
				}
			}
			link("4", "40")
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var kinds []string
			observations := 0
			owner := func(c context.Context) error {
				observations++
				if tc.name == "owner-changed" && observations == 3 {
					return ErrNodeTransitUnavailable
				}
				if tc.name == "changed-between-passes" && observations == 3 {
					link("7", "70")
				}
				return c.Err()
			}
			read := func(path string, limit int64) ([]byte, error) {
				kind := filepath.Base(path)
				kinds = append(kinds, kind)
				switch kind {
				case "tcp":
					if tc.name == "unsafe-tcp-retired" {
						drop("4")
						return []byte("0: 01010101:01BC 08080808:01BB 01 0 0 0 0 0 40\n"), nil
					}
				case "unix":
					rows := "0000: 0 0 0 0001 03 60\n"
					switch tc.name {
					case "retired-unknown", "reused-fd", "persistent-unknown", "retained-unknown-plus-churn":
					default:
						rows += "0000: 0 0 0 0001 03 40\n"
					}
					return []byte(rows), nil
				case "netlink":
					if len(kinds) == 6 {
						switch tc.name {
						case "retired-unknown":
							drop("4")
						case "reused-fd":
							drop("4")
							link("4", "60")
						case "moved-inode":
							drop("4")
							link("6", "40")
						case "added-unknown", "retained-unknown-plus-churn":
							link("7", "70")
						case "continued-churn", "owner-changed", "changed-between-passes":
							link("6", "60")
						case "cancelled":
							cancel()
						case "failed-table":
							link("6", "60")
							return nil, os.ErrPermission
						}
					} else if len(kinds) == 12 && tc.name == "continued-churn" {
						drop("6")
					}
				}
				return nil, nil
			}
			err := inspectNodeRouterProcSockets(ctx, proc, netip.MustParseAddr("192.0.2.3"), netip.MustParseAddr("8.8.8.8"), map[netip.Addr]bool{netip.MustParseAddr("8.8.8.8"): true}, owner, nil, read)
			switch {
			case tc.name == "cancelled":
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation: %v", err)
				}
			case tc.phase == "":
				if err != nil {
					t.Fatal(err)
				}
			default:
				if !errors.Is(err, ErrNodeTransitUnavailable) || !strings.Contains(err.Error(), "phase="+tc.phase) {
					t.Fatalf("want %s, got %v", tc.phase, err)
				}
			}
			var want []string
			if tc.name == "unsafe-tcp-retired" {
				want = []string{"tcp"}
			}
			for range tc.passes {
				want = append(want, "tcp", "tcp6", "udp", "udp6", "unix", "netlink")
			}
			if !slices.Equal(want, kinds) {
				t.Fatalf("tables read %v; want %v", kinds, want)
			}
		})
	}
}

func TestNodeRouterBackendPinsOriginalLaunch(t *testing.T) {
	for _, field := range []string{"receipt", "pid"} {
		t.Run(field, func(t *testing.T) {
			adapter := &ProxyTunnelAdapter{EngineID: "xray", StateRoot: t.TempDir()}
			spec := adapter.engineProcess()
			if err := os.Mkdir(spec.Dir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(spec.PIDPath, []byte("35001"), 0600); err != nil {
				t.Fatal(err)
			}
			calls := 0
			adapter.nodeRuntimeIdentity = func(_ ProcessSpec, _ string) (string, error) {
				calls++
				if calls == 2 {
					if field == "receipt" {
						return "different-valid-launch", nil
					}
					if err := os.WriteFile(spec.PIDPath, []byte("35002"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				return "original-launch", nil
			}
			manifest := proxyNodeManifest{Endpoints: []proxyNodeEndpoint{{IP: "203.0.113.4"}}}
			err := adapter.nodeRouterBackendDisjoint(t.Context(), manifest, netip.MustParseAddr("192.0.2.3"), netip.MustParseAddr("198.51.100.8"))
			if !errors.Is(err, ErrNodeTransitUnavailable) || !strings.Contains(err.Error(), "backend-launch-changed") || calls != 2 {
				t.Fatalf("owner %s changed: calls=%d err=%v", field, calls, err)
			}
		})
	}
}

// A sleeping child has a stable descriptor table. The benchmark exercises real
// procfs reads, including all six network tables, on the same Linux guest.
func BenchmarkNodeRouterSocketInventoryStable(b *testing.B) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatal(err)
	}
	defer listener.Close()
	file, err := listener.File()
	if err != nil {
		b.Fatal(err)
	}
	defer file.Close()
	child := exec.Command("sleep", "90")
	child.ExtraFiles = []*os.File{file}
	if err := child.Start(); err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	proc := filepath.Join("/proc", strconv.Itoa(child.Process.Pid))
	owner := func(ctx context.Context) error { return ctx.Err() }
	source, pin := netip.MustParseAddr("192.0.2.3"), netip.MustParseAddr("198.51.100.8")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := inspectNodeRouterProcSockets(b.Context(), proc, source, pin, nil, owner, nil, readNodeRouterProc); err != nil {
			b.Fatal(err)
		}
	}
}
