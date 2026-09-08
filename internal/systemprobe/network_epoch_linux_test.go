//go:build linux

package systemprobe

import (
	"context"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Explicit read-only HIL: no routes, DNS settings or interface state changes.
func TestNetworkEpochLinuxReadOnly(t *testing.T) {
	if os.Getenv("RAZVILKA_TEST_NET1_READONLY") != "1" {
		t.Skip("requires explicit read-only network epoch HIL opt-in")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	first, err := FreshWANProfile(ctx)
	if err != nil || !ValidWANProfileID(first.ID) {
		t.Fatalf("fresh underlay unavailable: %v", err)
	}
	second, err := FreshWANProfile(ctx)
	if err != nil || !ValidWANProfileID(second.ID) {
		t.Fatalf("second fresh underlay unavailable: %v", err)
	}
	if first.ID != second.ID {
		t.Fatal("underlay changed during read-only HIL; retry on a quiet network")
	}
	t.Logf("read-only underlay epoch available; interface=%s stable=%t", first.WANInterface, first.ID == second.ID)
}

func TestLinuxDNSEpochWatcherDetectsABAAndReplacement(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, mode := range []string{"aba", "replacement"} {
		t.Run(mode, func(t *testing.T) {
			raw, err := newPlatformEpochSource(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			s := raw.(*linuxEpochSource)
			path := filepath.Join(t.TempDir(), "resolv.conf")
			a := []byte("nameserver 127.0.0.1\n")
			if err := os.WriteFile(path, a, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := s.dnsIdentity(ctx, path, true); err != nil {
				t.Fatal(err)
			}
			if _, err := s.drainDNS(ctx); err != nil {
				t.Fatal(err)
			}
			if mode == "aba" {
				if err := os.WriteFile(path, []byte("nameserver 127.0.0.2\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, a, 0o600); err != nil {
					t.Fatal(err)
				}
			} else {
				next := path + ".new"
				if err := os.WriteFile(next, a, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(next, path); err != nil {
					t.Fatal(err)
				}
			}
			changed, err := s.drainDNS(ctx)
			// Replacing a watched inode can report IN_IGNORED: that also breaks
			// continuity and forces a new observer/session, rather than keeping A.
			if !changed && err == nil {
				t.Fatal("DNS change was missed although final contents equal A")
			}
		})
	}
}

func TestLinuxEpochEventsTrackUnderlayWithoutNameExemptions(t *testing.T) {
	order := binary.NativeEndian
	link, err := decodeEpochLink(epochTestLink(order), order)
	if err != nil {
		t.Fatal(err)
	}
	route, err := decodeEpochRoute(epochTestRoute(order, 2), order)
	if err != nil {
		t.Fatal(err)
	}
	s := &linuxEpochSource{links: map[uint32]string{4: link.canonical}, routes: map[string]bool{route.canonical: true}}
	interfaces := map[uint32]bool{4: true}
	candidate := epochTestRoute(order, 2)
	candidate.data[4] = 219
	if changed, err := s.event(candidate, interfaces); err != nil || changed {
		t.Fatal("candidate table invalidated underlay")
	}
	unrelated := epochTestLink(order)
	order.PutUint32(unrelated.data[4:8], 99)
	if changed, err := s.event(unrelated, interfaces); err != nil || changed {
		t.Fatal("unrelated interface invalidated underlay")
	}
	down := epochTestLink(order)
	order.PutUint32(down.data[8:12], 0)
	if changed, err := s.event(down, interfaces); err != nil || !changed {
		t.Fatal("WAN down event was ignored")
	}
	if changed, err := s.event(epochTestLink(order), interfaces); err != nil || !changed {
		t.Fatal("WAN return to same state was ignored")
	}
	removed := epochTestRoute(order, 2)
	removed.kind = unix.RTM_DELROUTE
	if changed, err := s.event(removed, interfaces); err != nil || !changed {
		t.Fatal("default route deletion was ignored")
	}
	if changed, err := s.event(epochTestRoute(order, 2), interfaces); err != nil || !changed {
		t.Fatal("default route return was ignored")
	}
	// A newly installed main default must be seen even when its interface is
	// not in the previous WAN set; no name or reserved interface ID exempts it.
	newDefault := epochTestRoute(order, 3)
	order.PutUint32(newDefault.data[16:20], 99) // first attribute is RTA_OIF
	if changed, err := s.event(newDefault, interfaces); err != nil || !changed {
		t.Fatal("changed main default was ignored")
	}
	if _, err := s.event(epochMessage{kind: unix.NLMSG_OVERRUN}, interfaces); err == nil {
		t.Fatal("event overflow retained continuity")
	}
}

func TestNetworkEpochLinuxNamespaceABA(t *testing.T) {
	if os.Getenv("RAZVILKA_TEST_NET1_NAMESPACE") != "1" {
		t.Skip("requires explicit isolated network-namespace HIL opt-in")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNetworkEpochLinuxNamespaceChild$", "-test.v")
	command.Env = append(os.Environ(), "RAZVILKA_NET1_NAMESPACE_CHILD=1")
	output, err := command.CombinedOutput()
	if strings.Contains(string(output), "NET1_NAMESPACE_UNAVAILABLE") {
		t.Skip("kernel/capabilities do not permit an isolated network namespace")
	}
	if err != nil {
		t.Fatalf("isolated namespace test failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "NET1_NAMESPACE_ABA_PASS") {
		t.Fatal("isolated namespace did not confirm ABA invalidation")
	}
	t.Log("isolated namespace default-route A-B-A invalidated the original epoch")
}

func TestNetworkEpochLinuxNamespaceChild(t *testing.T) {
	if os.Getenv("RAZVILKA_NET1_NAMESPACE_CHILD") != "1" {
		t.Skip("isolated child only")
	}
	// Never unlock/reuse this thread after changing its namespace. The helper
	// is a separate process and only this test is selected there.
	runtime.LockOSThread()
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		t.Skipf("NET1_NAMESPACE_UNAVAILABLE: %v", err)
	}
	// Every mutation below runs only after successful unshare. Loopback avoids
	// loading dummy/veth modules or touching any physical/router interface.
	ip, err := exec.LookPath("ip")
	if err != nil {
		t.Skip("NET1_NAMESPACE_UNAVAILABLE: no ip utility")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	run := func(args ...string) {
		t.Helper()
		if output, err := exec.CommandContext(ctx, ip, args...).CombinedOutput(); err != nil {
			t.Fatalf("isolated ip command failed: %v %s", err, output)
		}
	}
	run("link", "set", "dev", "lo", "up")
	run("-4", "addr", "add", "192.0.2.1/32", "dev", "lo")
	run("-4", "route", "add", "default", "dev", "lo")
	first, err := FreshWANProfile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	run("-4", "route", "del", "default", "dev", "lo")
	run("-4", "route", "add", "default", "dev", "lo")
	second, err := FreshWANProfile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !ValidWANProfileID(first.ID) || !ValidWANProfileID(second.ID) || first.ID == second.ID {
		t.Fatal("default route ABA reused original session")
	}
	t.Log("NET1_NAMESPACE_ABA_PASS")
}
