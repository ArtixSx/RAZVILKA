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

// Opt-in QA for real iproute2 output and exact deletion. The caller must give
// this test its own empty network namespace; the VM's normal namespace fails
// preflight before any command that changes networking.
func TestNativePolicyCleanupPreservesForeignRoutes(t *testing.T) {
	if os.Getenv("RAZVILKA_POLICY_NETNS") != "1" {
		t.Skip("requires an exclusively assigned empty Linux network namespace")
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatal("test requires only loopback; refusing networking mutations")
	}
	ip, err := exec.LookPath("ip")
	if err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) string {
		t.Helper()
		out, err := exec.Command(ip, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("ip %v: %v: %s", args, err, out)
		}
		return string(out)
	}
	run("link", "set", "lo", "up")
	run("link", "add", "rz-sing", "type", "dummy")
	t.Cleanup(func() { run("link", "delete", "rz-sing") })
	run("link", "set", "rz-sing", "up")
	run("route", "add", "default", "dev", "rz-sing", "table", "203")
	run("-6", "route", "add", "default", "dev", "rz-sing", "table", "203")
	run("route", "add", "203.0.113.7/32", "dev", "lo", "table", "203")
	run("-6", "route", "add", "2001:db8::7/128", "dev", "lo", "table", "203")
	state := PolicyState{Interface: "rz-sing", Table: 203}
	if err := removeKernelPolicy(context.Background(), nfqws2ExecRunner{}, ip, state, nil); err != nil {
		t.Fatal(err)
	}
	for _, family := range []string{"-4", "-6"} {
		out := run(family, "route", "show", "table", "203")
		if strings.Contains(out, "default") || !strings.Contains(out, "dev lo") {
			t.Fatalf("cleanup removed foreign route or retained default: %s", out)
		}
	}
	// A different owner may have installed a default on the same interface.
	// Readback ambiguity must fail before removing either family's routes.
	run("route", "add", "default", "dev", "rz-sing", "table", "203", "proto", "static")
	before := run("route", "show", "table", "203")
	if err := removeKernelPolicy(context.Background(), nfqws2ExecRunner{}, ip, state, nil); err == nil {
		t.Fatal("foreign protocol accepted as owned")
	}
	if after := run("route", "show", "table", "203"); after != before {
		t.Fatal("ambiguous table changed")
	}
	t.Log("native IPv4/IPv6 default cleanup preserved foreign host routes; ambiguous default refused")
}
