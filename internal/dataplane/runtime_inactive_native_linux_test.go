//go:build linux

package dataplane

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"
)

// This opt-in harness creates its own fresh network AND PID/proc namespaces.
// Run as root with util-linux unshare, iproute2 and working IPv4/IPv6 iptables
// filter/nat support. No host interfaces, rules, files or engine processes are
// changed. There is no mocked output, private observer seam or fake receipt.
func TestRuntimeInactiveColdNative(t *testing.T) {
	if os.Getenv("RAZVILKA_INACTIVE_NETNS") != "1" {
		t.Skip("explicit isolated native opt-in: RAZVILKA_INACTIVE_NETNS=1")
	}
	t.Setenv("LC_ALL", "C") // The production missing-FIB classifier is exact.
	if os.Geteuid() != 0 {
		t.Fatal("native inactivity harness requires root")
	}
	if os.Getenv("RAZVILKA_INACTIVE_NETNS_PARENT") == "" {
		parent, err := os.Readlink("/proc/self/ns/net")
		if err != nil {
			t.Fatal(err)
		}
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "unshare", "--net", "--pid", "--fork", "--mount-proc", "--", binary, "-test.run=^TestRuntimeInactiveColdNative$", "-test.count=1", "-test.v")
		cmd.Env = append(os.Environ(), "RAZVILKA_INACTIVE_NETNS_PARENT="+parent)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("fresh namespace harness failed: %v\n%s", err, output)
		}
		t.Logf("fresh namespace results:\n%s", output)
		return
	}
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil || current == os.Getenv("RAZVILKA_INACTIVE_NETNS_PARENT") || os.Getpid() != 1 {
		t.Fatal("refusing mutations outside fresh unshare network/PID namespace", err)
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatal("fresh namespace must contain loopback only", interfaces, err)
	}
	tools := map[string]string{}
	for _, name := range []string{"ip", "iptables", "ip6tables"} {
		path, err := exec.LookPath(name)
		if err != nil {
			t.Fatal("required native tool unavailable", name, err)
		}
		tools[name] = path
	}
	root := t.TempDir()
	type observer struct {
		id, iface       string
		table, priority int
		verify          func(context.Context) error
		chain           string
	}
	var observers []observer
	for _, id := range []string{"usque", "sing-box", "xray"} {
		a, err := NewProxyTunnelAdapter(id, nil, filepath.Join(root, "runtime"))
		if err != nil {
			t.Fatal(err)
		}
		a.IP, a.IPTables, a.IP6Tables = tools["ip"], tools["iptables"], tools["ip6tables"]
		observers = append(observers, observer{id: id, iface: a.Interface, table: a.Table, priority: a.Priority, verify: a.VerifyRuntimeInactive, chain: a.forwardingChain()})
	}
	for _, a := range []*WARPWireGuardAdapter{NewWARPWireGuardAdapter(nil, root), NewWireGuardAdapter(nil, root), NewAmneziaWGAdapter(nil, root)} {
		a.IP = tools["ip"]
		observers = append(observers, observer{id: a.ID(), iface: a.Interface, table: a.Table, priority: a.PriorityBase, verify: a.VerifyRuntimeInactive})
	}
	run := func(name string, args ...string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, tools[name], args...).CombinedOutput()
		if err != nil {
			t.Fatalf("native %s %v failed: %v\n%s", name, args, err, out)
		}
		return string(out)
	}
	snapshot := func() []string {
		out := []string{run("ip", "-j", "link", "show")}
		for _, family := range []string{"-4", "-6"} {
			out = append(out, run("ip", "-N", family, "rule", "show"), run("ip", "-N", family, "route", "show", "table", "all"))
		}
		for _, name := range []string{"iptables", "ip6tables"} {
			for _, table := range []string{"filter", "nat"} {
				out = append(out, run(name, "-t", table, "-S"))
			}
		}
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			out = append(out, "file:"+entry.Name())
		}
		return out
	}
	check := func(o observer, wantSuccess bool) {
		t.Helper()
		before := snapshot()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		err := o.verify(ctx)
		if (err == nil) != wantSuccess {
			t.Fatalf("%s inactivity success=%t, wanted=%t: %v", o.id, err == nil, wantSuccess, err)
		}
		if after := snapshot(); !reflect.DeepEqual(before, after) {
			t.Fatalf("%s read-only observer changed namespace/files\nbefore=%q\nafter=%q", o.id, before, after)
		}
	}
	for _, o := range observers {
		t.Log("native cold/foreign checks:", o.id)
		// Real missing FIB tables, no files and populated /proc/lo inventory.
		check(o, true)
		run("ip", "link", "add", o.iface, "type", "dummy")
		check(o, false)
		run("ip", "link", "del", o.iface)
		check(o, true)
		for _, family := range []string{"-4", "-6"} {
			priority := strconv.Itoa(o.priority)
			run("ip", family, "rule", "add", "priority", priority, "lookup", "222")
			check(o, false)
			run("ip", family, "rule", "del", "priority", priority, "lookup", "222")
			// A reference outside the adapter's reserved priority is also foreign.
			run("ip", family, "rule", "add", "priority", "10001", "lookup", strconv.Itoa(o.table))
			check(o, false)
			run("ip", family, "rule", "del", "priority", "10001", "lookup", strconv.Itoa(o.table))
			destination := "198.51.100.0/24"
			if family == "-6" {
				destination = "2001:db8::/32"
			}
			run("ip", family, "route", "add", "blackhole", destination, "table", strconv.Itoa(o.table))
			check(o, false)
			run("ip", family, "route", "del", "blackhole", destination, "table", strconv.Itoa(o.table))
			check(o, true)
		}
		if o.chain != "" {
			for _, name := range []string{"iptables", "ip6tables"} {
				for _, table := range []string{"filter", "nat"} {
					run(name, "-t", table, "-N", o.chain)
					check(o, false)
					run(name, "-t", table, "-X", o.chain)
					check(o, true)
				}
			}
		}
	}
	// All adapter roots remained cold; tests never wrote an ownership receipt.
	if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
		t.Fatal("cold state root mutated", entries, err)
	}
}
