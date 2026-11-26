package dataplane

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

const scopedIP44UnknownJSON = "Option \"-j\" is unknown, try \"ip -help\".\n"

type scopedIP44Exit int

func (e scopedIP44Exit) Error() string { return "modeled ip exit" }
func (e scopedIP44Exit) ExitCode() int { return int(e) }

func TestScopedInterfaceIP44UsesFreshValidatedOSInventory(t *testing.T) {
	for _, mode := range []string{"present", "absent", "empty", "no-loopback", "empty-name", "zero-index", "duplicate-name", "duplicate-index", "too-many", "read-error", "canceled-during-read", "changed-interface"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			a := &ProxyTunnelAdapter{Interface: "rz-xray", IP: "ip"}
			commands, observations := 0, 0
			a.Runner = networkCleanupRunner(func(_ context.Context, name string, args ...string) ([]byte, error) {
				commands++
				if name != "ip" || !reflect.DeepEqual(args, []string{"-j", "link", "show", "dev", "rz-xray"}) {
					t.Fatal("unexpected or mutating interface command", name, args)
				}
				return []byte(scopedIP44UnknownJSON), scopedIP44Exit(255)
			})
			a.nodeInterfaceInventory = func() ([]net.Interface, error) {
				observations++
				links := []net.Interface{{Index: 1, Name: "lo"}, {Index: 77, Name: "rz-xray"}}
				switch mode {
				case "absent":
					links = links[:1]
				case "empty":
					links = nil
				case "no-loopback":
					links = links[1:]
				case "empty-name":
					links[1].Name = ""
				case "zero-index":
					links[1].Index = 0
				case "duplicate-name":
					links = append(links, net.Interface{Index: 78, Name: "rz-xray"})
				case "duplicate-index":
					links = append(links, net.Interface{Index: 77, Name: "eth0"})
				case "too-many":
					links = make([]net.Interface, 4097)
				case "read-error":
					return nil, errors.New("inventory unavailable")
				case "canceled-during-read":
					cancel()
				case "changed-interface":
					a.Interface = "foreign0"
				}
				return links, nil
			}
			index, err := a.scopedInterfaceIndex(ctx)
			if mode == "present" {
				if err != nil || index != 77 {
					t.Fatal("exact interface index missing", index, err)
				}
			} else if mode == "absent" {
				if !errors.Is(err, errNodeInterfaceAbsent) || index != 0 {
					t.Fatal("complete inventory did not prove absence", index, err)
				}
			} else if err == nil || errors.Is(err, errNodeInterfaceAbsent) || index != 0 {
				t.Fatal("uncertain inventory granted presence or absence", index, err)
			}
			if commands != 1 || observations != 1 {
				t.Fatal("observation was skipped or replayed", commands, observations)
			}
		})
	}
}

func TestScopedInterfaceIP44DoesNotFallbackForOtherFailures(t *testing.T) {
	for _, test := range []struct {
		name, output string
		err          error
		cancel       bool
	}{
		{"permission", "Operation not permitted", scopedIP44Exit(255), false},
		{"diagnostic-with-extra", scopedIP44UnknownJSON + "Permission denied", scopedIP44Exit(255), false},
		{"wrong-exit", scopedIP44UnknownJSON, scopedIP44Exit(1), false},
		{"successful-diagnostic", scopedIP44UnknownJSON, nil, false},
		{"malformed-json", "not-json", nil, false},
		{"empty-json", "[]", nil, false},
		{"timeout", scopedIP44UnknownJSON, context.DeadlineExceeded, false},
		{"runner-timeout", scopedIP44UnknownJSON, errors.New("proxy command timed out"), false},
		{"canceled-command", scopedIP44UnknownJSON, scopedIP44Exit(255), true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			a := &ProxyTunnelAdapter{Interface: "rz-xray", IP: "ip"}
			a.Runner = networkCleanupRunner(func(context.Context, string, ...string) ([]byte, error) {
				if test.cancel {
					cancel()
				}
				return []byte(test.output), test.err
			})
			a.nodeInterfaceInventory = func() ([]net.Interface, error) {
				t.Fatal("failure reached OS fallback")
				return nil, nil
			}
			if _, err := a.scopedInterfaceIndex(ctx); err == nil || errors.Is(err, errNodeInterfaceAbsent) {
				t.Fatal("failed observation granted absence", err)
			}
		})
	}
}

func TestScopedInterfaceIP44PreservesJSONAndNonLinuxBoundaries(t *testing.T) {
	a := &ProxyTunnelAdapter{Interface: "rz-xray", IP: "ip"}
	a.nodeInterfaceInventory = func() ([]net.Interface, error) { t.Fatal("JSON path used OS inventory"); return nil, nil }
	a.Runner = networkCleanupRunner(func(context.Context, string, ...string) ([]byte, error) {
		return []byte(`[{"ifindex":77,"ifname":"rz-xray"}]`), nil
	})
	if index, err := a.scopedInterfaceIndex(context.Background()); err != nil || index != 77 {
		t.Fatal("existing JSON path changed", index, err)
	}
	if runtime.GOOS != "linux" {
		a.nodeInterfaceInventory = nil
		a.Runner = networkCleanupRunner(func(context.Context, string, ...string) ([]byte, error) {
			return []byte(scopedIP44UnknownJSON), scopedIP44Exit(255)
		})
		if _, err := a.scopedInterfaceIndex(context.Background()); err == nil || errors.Is(err, errNodeInterfaceAbsent) {
			t.Fatal("non-Linux host acquired OS fallback authority", err)
		}
	}
}

// Read-only native acceptance: the command dialect is modeled, but the fallback
// itself uses the production Linux netlink inventory without an injected owner.
func TestScopedInterfaceIP44NativeInventory(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("production OS fallback is Linux-only")
	}
	loopback, err := net.InterfaceByName("lo")
	if err != nil || loopback.Index < 1 {
		t.Fatal("native loopback inventory unavailable", err)
	}
	const absent = "rz-ip44-absent"
	links, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, link := range links {
		if link.Name == absent {
			t.Fatal("reserved negative test name already exists")
		}
	}
	for _, name := range []string{"lo", absent} {
		a := &ProxyTunnelAdapter{Interface: name, IP: "ip"}
		a.Runner = networkCleanupRunner(func(context.Context, string, ...string) ([]byte, error) {
			return []byte(scopedIP44UnknownJSON), scopedIP44Exit(255)
		})
		index, err := a.scopedInterfaceIndex(context.Background())
		if name == "lo" && (err != nil || index != loopback.Index) {
			t.Fatal("production Linux fallback lost actual loopback index", index, err)
		}
		if name == absent && (index != 0 || !errors.Is(err, errNodeInterfaceAbsent)) {
			t.Fatal("production Linux fallback did not prove exact absence", index, err)
		}
	}
}

// On modern Linux this exercises real ip JSON; on Entware ip4.4 it exercises
// the actual unsupported-option exit and production OS fallback. No effects.
func TestScopedInterfaceIP44NativeCommand(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("native interface command acceptance is Linux-only")
	}
	command := ""
	for _, candidate := range []string{"/opt/sbin/ip", "/opt/bin/ip", "ip"} {
		if path, err := exec.LookPath(candidate); err == nil {
			command = path
			break
		}
	}
	if command == "" {
		t.Skip("ip is unavailable")
	}
	loopback, err := net.InterfaceByName("lo")
	if err != nil || loopback.Index < 1 {
		t.Fatal("native loopback inventory unavailable", err)
	}
	const absent = "rz-ip44-absent"
	links, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, link := range links {
		if link.Name == absent {
			t.Fatal("reserved negative test name already exists")
		}
	}
	for _, name := range []string{"lo", absent} {
		a := &ProxyTunnelAdapter{Interface: name, IP: command, Runner: nfqws2ExecRunner{}}
		index, err := a.scopedInterfaceIndex(context.Background())
		if name == "lo" && (err != nil || index != loopback.Index) {
			t.Fatal("native command lost actual loopback index", index, err)
		}
		if name == absent && (index != 0 || !errors.Is(err, errNodeInterfaceAbsent)) {
			t.Fatal("native command did not prove exact absence", index, err)
		}
	}
}

func TestScopedInterfaceIP44LifecycleKeepsReplacementAndLeaseGuards(t *testing.T) {
	f := scopedXrayTestFixture(t)
	previous := f.a.Runner
	f.a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "ip" && len(args) > 0 && args[0] == "-j" {
			return []byte(scopedIP44UnknownJSON), scopedIP44Exit(255)
		}
		return previous.Run(ctx, name, args...)
	})
	index := 77
	f.a.nodeInterfaceInventory = func() ([]net.Interface, error) {
		links := []net.Interface{{Index: 1, Name: "lo"}}
		if f.processes.running["xray-tun"] {
			links = append(links, net.Interface{Index: index, Name: f.a.Interface})
		}
		return links, nil
	}
	root := stageScopedFixture(t, f)
	for _, step := range []func(context.Context, Plan, string) error{f.a.Activate, f.a.Health, f.a.Commit} {
		if err := step(context.Background(), f.plan, root); err != nil {
			t.Fatal("ip4.4 lifecycle refused trusted inventory", err)
		}
	}
	lease, err := os.ReadFile(f.a.nodeInterfacePath())
	if err != nil {
		t.Fatal(err)
	}
	index = 88
	if err := f.a.verifyScopedNodeInterface(context.Background()); err == nil {
		t.Fatal("replacement interface accepted")
	}
	f.a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "ip" && strings.Join(args, " ") == "link delete dev "+f.a.Interface {
			t.Fatal("replacement interface deletion attempted")
		}
		if name == "ip" && len(args) > 0 && args[0] == "-j" {
			return []byte(scopedIP44UnknownJSON), scopedIP44Exit(255)
		}
		return previous.Run(ctx, name, args...)
	})
	if err := f.a.removeScopedNodeInterface(context.Background()); err == nil {
		t.Fatal("replacement interface granted cleanup")
	}
	current, err := os.ReadFile(f.a.nodeInterfacePath())
	if err != nil || !reflect.DeepEqual(lease, current) {
		t.Fatal("refused replacement changed lease", err)
	}
}
