//go:build linux

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"
)

func nativeAdditionState() PolicyState {
	return PolicyState{Interface: "rz-rec", Table: 229, PriorityBase: 22900,
		Prefixes: []string{"198.51.100.7/32", "2001:db8::7/128"}}
}

// The parent is run only in a coordinator-assigned, empty network namespace.
// Each child dies without defers at a durable boundary; a fresh reader must
// distinguish a known addition from intent even when kernel contents match.
func TestNativePolicyAdditionReceiptCrashBoundaries(t *testing.T) {
	if os.Getenv("RAZVILKA_POLICY_RECEIPT_NETNS") != "1" {
		t.Skip("requires an exclusively assigned empty Linux network namespace")
	}
	self, e1 := os.Readlink("/proc/self/ns/net")
	owner, e2 := os.Readlink("/proc/1/ns/net")
	if os.Geteuid() != 0 || e1 != nil || e2 != nil || self == owner {
		t.Fatal("requires root in an isolated network namespace")
	}
	ip, err := exec.LookPath("ip")
	if err != nil {
		t.Fatal(err)
	}
	state, ctx := nativeAdditionState(), context.Background()
	if os.Getenv("RAZVILKA_RECEIPT_CHILD") != "" {
		index, err := strconv.Atoi(os.Getenv("RAZVILKA_RECEIPT_INDEX"))
		if err != nil {
			t.Fatal(err)
		}
		point, root := os.Getenv("RAZVILKA_RECEIPT_POINT"), os.Getenv("RAZVILKA_RECEIPT_ROOT")
		options := policyAdditionOptions{fault: func(got string, at int) error {
			if got == point && at == index {
				os.Exit(73)
			}
			return nil
		}}
		if os.Getenv("RAZVILKA_RECEIPT_CHILD") == "apply" {
			err = applyPolicyAddition(ctx, nfqws2ExecRunner{}, ip, state, root, options)
		} else {
			err = removePolicyAddition(ctx, nfqws2ExecRunner{}, ip, state, root, options)
		}
		t.Fatalf("child missed crash boundary: %v", err)
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatal("test requires only loopback; refusing networking mutations")
	}
	run := func(args ...string) {
		t.Helper()
		out, err := exec.Command(ip, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("ip %v: %v: %s", args, err, out)
		}
	}
	run("link", "set", "lo", "up")
	run("link", "add", state.Interface, "type", "dummy")
	t.Cleanup(func() { run("link", "delete", state.Interface) })
	run("link", "set", state.Interface, "up")
	steps, err := policyAdditionExpected(state)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"apply", "remove"} {
		points := []string{"intent", "add", "added"}
		if role == "remove" {
			points = []string{"cleanup-intent", "delete", "removed"}
		}
		for _, index := range []int{0, len(steps) - 1} {
			for _, point := range points {
				t.Run(fmt.Sprintf("%s-%s-%d", role, point, index), func(t *testing.T) {
					// These exact tuples can be removed by the fixture because its
					// parent proved the namespace empty before creating this dummy.
					// This is test teardown, never production receipt reconciliation.
					t.Cleanup(func() {
						for i := len(steps) - 1; i >= 0; i-- {
							_, _ = exec.Command(ip, steps[i].Delete...).CombinedOutput()
						}
					})
					root := privateScopedXrayFixtureDir(t)
					if role == "remove" {
						if err := applyPolicyWithReceipt(ctx, nfqws2ExecRunner{}, ip, state, root); err != nil {
							t.Fatal(err)
						}
					}
					childCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
					defer cancel()
					child := exec.CommandContext(childCtx, os.Args[0], "-test.run=^TestNativePolicyAdditionReceiptCrashBoundaries$", "-test.count=1")
					child.Env = append(os.Environ(), "RAZVILKA_RECEIPT_CHILD="+role,
						"RAZVILKA_RECEIPT_POINT="+point, "RAZVILKA_RECEIPT_INDEX="+strconv.Itoa(index), "RAZVILKA_RECEIPT_ROOT="+root)
					out, childErr := child.CombinedOutput()
					var exit *exec.ExitError
					if !errors.As(childErr, &exit) || exit.ExitCode() != 73 {
						t.Fatalf("child did not stop at boundary: %v: %s", childErr, out)
					}
					status, err := inspectPolicyAdditionReceipt(ctx, state, root)
					if err != nil {
						t.Fatal(err)
					}
					unknown := point != "added" && point != "removed"
					if status.Unknown != unknown {
						t.Fatal("durable status does not match crash boundary", status)
					}
					before, err := policyAdditionPresence(ctx, nfqws2ExecRunner{}, ip, state, index)
					if err != nil {
						t.Fatal(err)
					}
					cleanupErr := removePolicyWithReceipt(ctx, nfqws2ExecRunner{}, ip, state, root)
					if unknown && !errors.Is(cleanupErr, ErrPolicyAdditionUnknown) || !unknown && cleanupErr != nil {
						t.Fatal("fresh cleanup did not retain fence", cleanupErr)
					}
					if unknown {
						after, err := policyAdditionPresence(ctx, nfqws2ExecRunner{}, ip, state, index)
						if err != nil || after != before {
							t.Fatal("fresh reader mutated unknown tuple", before, after, err)
						}
					} else {
						for i := range steps {
							if count, err := policyAdditionPresence(ctx, nfqws2ExecRunner{}, ip, state, i); err != nil || count != 0 {
								t.Fatal("known addition not cleaned", i, count, err)
							}
						}
					}
				})
			}
		}
	}
	t.Log("native durable intent/add/ack and cleanup/delete/absence boundaries checked in fresh child processes")
}
