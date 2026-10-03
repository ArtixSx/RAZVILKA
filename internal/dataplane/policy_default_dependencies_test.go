package dataplane

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestPolicyDefaultDependencyRetainsOwnAndForeignSelectors(t *testing.T) {
	for _, family := range []int{4, 6} {
		t.Run(map[int]string{4: "ipv4", 6: "ipv6"}[family], func(t *testing.T) {
			state := testEarlyPolicy()
			runner := &recordedPolicyFakeRunner{}
			if err := AssertPolicyDefaultUnreferenced(context.Background(), runner, "ip", state, family); err != nil {
				t.Fatal("empty table selectors refused", err)
			}
			entry := policyKernelEntry{family: family, priority: 40, source: "192.168.1.41/32", dest: "149.154.167.99/32", table: "203"}
			if family == 6 {
				entry.source, entry.dest = "fd00:1::41/128", "2001:db8::99/128"
			}
			runner.kernel.entries = append(runner.kernel.entries, entry)
			before := append([]policyKernelEntry(nil), runner.kernel.entries...)
			if err := AssertPolicyDefaultUnreferenced(context.Background(), runner, "ip", state, family); !errors.Is(err, ErrPolicyDefaultReferenced) {
				t.Fatal("foreign dependency ignored", err)
			}
			if !reflect.DeepEqual(before, runner.kernel.entries) || len(receiptMutationCalls(runner.calls)) != 0 {
				t.Fatal("read-only check mutated selectors")
			}
			runner.kernel.entries[0].table = "204"
			if err := AssertPolicyDefaultUnreferenced(context.Background(), runner, "ip", state, family); err != nil {
				t.Fatal("known different table blocked cleanup", err)
			}
			runner.kernel.entries = nil
			// A late dependency after a durable intent must be observed again.
			if err := AssertPolicyDefaultUnreferenced(context.Background(), runner, "ip", state, family); err != nil {
				t.Fatal(err)
			}
			runner.kernel.entries = append(runner.kernel.entries, entry)
			if err := AssertPolicyDefaultUnreferenced(context.Background(), runner, "ip", state, family); err == nil {
				t.Fatal("late dependency was cached away")
			}
		})
	}
}

func TestPolicyDefaultDependencyWGPinRequiresExactFreshHostRoute(t *testing.T) {
	state := PolicyState{Interface: "rz-warp", Table: 201, PriorityBase: 18100, WireGuardEndpoint: &WGEndpointState{Endpoint: "203.0.113.9:443", Priority: 50, Mark: 0x01000000, Table: 201, Metric: 1, Device: "wan0", Gateway: "192.0.2.1", Source: "192.0.2.2"}}
	for _, kind := range []string{"exact", "missing", "foreign-device", "foreign-protocol", "another-selector"} {
		t.Run(kind, func(t *testing.T) {
			var mutations []string
			runner := networkCleanupRunner(func(ctx context.Context, command string, args ...string) ([]byte, error) {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				joined := strings.Join(args, " ")
				if joined == "rule show" {
					out := "0: from all lookup local\n32766: from all lookup main\n32767: from all lookup default\n50: from all to 203.0.113.9 fwmark 0x1000000 lookup 201\n"
					if kind == "another-selector" {
						out += "61: from 192.168.1.41 to 149.154.167.99 lookup 201\n"
					}
					return []byte(out), nil
				}
				if joined == "-j route show table 201 exact 203.0.113.9/32" {
					if kind == "missing" {
						return []byte("[]"), nil
					}
					out := `[{"dst":"203.0.113.9/32","gateway":"192.0.2.1","dev":"wan0","prefsrc":"192.0.2.2","protocol":"static","metric":1,"table":201,"flags":["onlink"]}]`
					if kind == "foreign-device" {
						out = strings.Replace(out, "wan0", "foreign0", 1)
					}
					if kind == "foreign-protocol" {
						out = strings.Replace(out, "static", "boot", 1)
					}
					return []byte(out), nil
				}
				mutations = append(mutations, joined)
				return nil, errors.New("unexpected command")
			})
			err := AssertPolicyDefaultUnreferenced(context.Background(), runner, "ip", state, 4)
			if (err == nil) != (kind == "exact") || len(mutations) != 0 {
				t.Fatal("pin dependency proof mismatch", kind, err, mutations)
			}
		})
	}
}

func TestPolicyDefaultDependencyUnknownReadbackAndCancellationRefuse(t *testing.T) {
	state := testEarlyPolicy()
	for _, line := range []string{
		"40: from all fwmark 0x1 lookup 203",
		"40: from all fwmark 0x1 lookup 4096",
		"40: from 192.168.1.41 to 149.154.167.99 lookup owned-symbolic",
		"40: not from 192.168.1.41 to 149.154.167.99 lookup 204",
		"unrecognized kernel diagnostic",
	} {
		runner := &recordedPolicyFakeRunner{kernel: policyKernelFake{foreignIPv4: []string{line}}}
		if err := AssertPolicyDefaultUnreferenced(context.Background(), runner, "ip", state, 4); !errors.Is(err, ErrPolicyDefaultReferenced) || len(receiptMutationCalls(runner.calls)) != 0 {
			t.Fatal("unknown readback accepted", line, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner := &recordedPolicyFakeRunner{}
	if err := AssertPolicyDefaultUnreferenced(ctx, runner, "ip", state, 4); !errors.Is(err, context.Canceled) || len(runner.calls) != 0 {
		t.Fatal("cancellation ignored", err)
	}
	bad := networkCleanupRunner(func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("read failed") })
	if err := AssertPolicyDefaultUnreferenced(context.Background(), bad, "ip", state, 6); !errors.Is(err, ErrPolicyDefaultReferenced) {
		t.Fatal("failed read admitted cleanup", err)
	}
}
