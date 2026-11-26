//go:build linux

package dataplane

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// FIB observations only: no Internet requests. Requires a disposable empty
// network namespace, including namespace-local forwarding sysctls.
func TestNativeManagedDefaultRouteEvidence(t *testing.T) {
	if os.Getenv("RAZVILKA_POLICY_DEFAULT_NETNS") != "1" {
		t.Skip("requires an exclusively assigned empty Linux network namespace")
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatal("only loopback must exist before native network mutations")
	}
	ip, err := exec.LookPath("ip")
	if err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) {
		t.Helper()
		if output, err := exec.Command(ip, args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v: %s", args, err, output)
		}
	}
	run("link", "set", "lo", "up")
	for _, name := range []string{"rz-def-lan", "rz-xray"} {
		run("link", "add", name, "type", "dummy")
		t.Cleanup(func() { run("link", "delete", name) })
		run("link", "set", name, "up")
	}
	for path, value := range map[string]string{
		"/proc/sys/net/ipv4/ip_forward":                "1",
		"/proc/sys/net/ipv6/conf/all/forwarding":       "1",
		"/proc/sys/net/ipv4/conf/all/rp_filter":        "0",
		"/proc/sys/net/ipv4/conf/rz-def-lan/rp_filter": "0",
	} {
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	run("addr", "add", "192.168.93.1/24", "dev", "rz-def-lan")
	run("-6", "addr", "add", "fd93::1/64", "dev", "rz-def-lan", "nodad")
	// Some firmware treats the unspecified literal as local. These exact local
	// host routes make the old prefix.Addr() false failure reproducible.
	run("route", "add", "local", "0.0.0.0/32", "dev", "lo", "table", "local")
	run("-6", "route", "add", "local", "::/128", "dev", "lo", "table", "local")
	state := PolicyState{
		Interface: "rz-xray", Table: 204, PriorityBase: 24000,
		NetworkPolicyGeneration: strings.Repeat("a", 64), NetworkDefault: true,
		Prefixes: []string{"0.0.0.0/0", "::/0"},
		Rules: []PolicyRule{
			{Source: "192.168.93.0/24", Destination: "0.0.0.0/0", Ingress: "rz-def-lan", Managed: true},
			{Source: "fd93::/64", Destination: "::/0", Ingress: "rz-def-lan", Managed: true},
		},
	}
	initializePolicyLayout(&state)
	ctx := context.Background()
	runner := nfqws2ExecRunner{}
	if err := applyRecordedPolicy(ctx, runner, ip, state); err != nil {
		t.Fatal("native dual-family default apply", err)
	}
	t.Cleanup(func() {
		if err := removeRecordedPolicy(ctx, runner, ip, state); err != nil {
			t.Error("native policy cleanup", err)
		}
	})
	if err := verifyPolicyEvidence(ctx, runner, ip, state); err != nil {
		for _, args := range [][]string{{"-N", "rule", "show"}, {"-6", "-N", "rule", "show"}, {"route", "show", "table", "204"}, {"-6", "route", "show", "table", "204"}} {
			output, readErr := exec.Command(ip, args...).CombinedOutput()
			t.Logf("readback ip %v: %s (%v)", args, output, readErr)
		}
		t.Fatal("actual IPv4/IPv6 public default FIB evidence", err)
	}
	for _, args := range [][]string{
		{"route", "get", "0.0.0.0", "from", "192.168.93.2", "iif", "rz-def-lan", "mark", "0x20000000"},
		{"-6", "route", "get", "::", "from", "fd93::2", "iif", "rz-def-lan", "mark", "0x20000000"},
	} {
		output, err := runner.Run(ctx, ip, args...)
		if err == nil && !policyNonUnicast(output) && policyRouteDevice(output) == state.Interface {
			t.Fatalf("unspecified-destination regression fixture ineffective: %s", output)
		}
	}
	t.Log("IPv4 and IPv6 default FIB readback passed despite local unspecified host routes; no packets sent")
}
