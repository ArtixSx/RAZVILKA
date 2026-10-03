//go:build linux

package dataplane

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
)

type nativePolicyApplyRunner struct {
	beforeIPv6Add func() error
	failIPv6      bool
}

func (r nativePolicyApplyRunner) Run(ctx context.Context, command string, args ...string) ([]byte, error) {
	if strings.HasPrefix(strings.Join(args, " "), "-6 route add default ") {
		if r.beforeIPv6Add != nil {
			if err := r.beforeIPv6Add(); err != nil {
				return nil, err
			}
		}
		if r.failIPv6 {
			return nil, errors.New("injected IPv6 netlink refusal before command")
		}
	}
	return (nfqws2ExecRunner{}).Run(ctx, command, args...)
}

// Real kernel admission/cleanup in an explicitly assigned empty namespace.
// Fault hooks intercept only the IPv6 add; native route contents and failed
// EEXIST/readback, including an identical-looking foreign tuple, are real.
func TestNativePolicyApplyPreservesDefaultOccupants(t *testing.T) {
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
	for _, scenario := range []string{"foreign-default", "IPv6-failure", "concurrent-identical-tuple"} {
		t.Run(scenario, func(t *testing.T) {
			run("link", "add", "rz-policy", "type", "dummy")
			t.Cleanup(func() { run("link", "delete", "rz-policy") })
			run("link", "set", "rz-policy", "up")
			state := PolicyState{Interface: "rz-policy", Table: 225, PriorityBase: 22500, Prefixes: []string{"198.51.100.7/32"}}
			runner := nativePolicyApplyRunner{}
			foreign := ""
			switch scenario {
			case "foreign-default":
				run("route", "add", "default", "dev", "lo", "table", "225", "proto", "static", "metric", "1313")
				t.Cleanup(func() {
					run("route", "del", "default", "dev", "lo", "table", "225", "proto", "static", "metric", "1313")
				})
				foreign = run("route", "show", "table", "225")
			case "IPv6-failure":
				runner.failIPv6 = true
			case "concurrent-identical-tuple":
				runner.beforeIPv6Add = func() error {
					run("-6", "route", "add", "default", "dev", "rz-policy", "table", "225", "proto", "boot", "metric", "1024")
					foreign = run("-6", "route", "show", "table", "225")
					return nil
				}
			}
			if err := applyRecordedPolicy(context.Background(), runner, ip, state); err == nil {
				t.Fatal("conflict/failure reported successful")
			}
			read := func(family int) string {
				out, err := readPolicyTable(context.Background(), nfqws2ExecRunner{}, ip, state, family)
				if err != nil {
					t.Fatal(err)
				}
				return string(out)
			}
			if scenario == "foreign-default" {
				if read(4) != foreign || strings.TrimSpace(read(6)) != "" {
					t.Fatal("foreign table was changed")
				}
			} else {
				if strings.TrimSpace(read(4)) != "" {
					t.Fatal("successful IPv4 addition was not removed")
				}
				if scenario == "concurrent-identical-tuple" {
					if read(6) != foreign {
						t.Fatal("failed add granted deletion authority for identical foreign tuple")
					}
				} else if strings.TrimSpace(read(6)) != "" {
					t.Fatal("failed IPv6 add left a route")
				}
			}
			for _, family := range []int{4, 6} {
				lines, err := readPolicyRules(context.Background(), nfqws2ExecRunner{}, ip, family)
				if err != nil {
					t.Fatal(err)
				}
				for _, line := range lines {
					if priority, ok := policyLinePriority(line); ok && priority == state.PriorityBase {
						t.Fatal("failed apply created selectors", line)
					}
				}
			}
		})
	}
}
