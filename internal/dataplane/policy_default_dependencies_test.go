package dataplane

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type dependencyTestReader struct{ *recordedPolicyFakeRunner }

func dependencyFixture() *dependencyTestReader {
	return &dependencyTestReader{&recordedPolicyFakeRunner{}}
}

func (r *dependencyTestReader) Run(ctx context.Context, command string, args ...string) ([]byte, error) {
	if len(args) == 0 || args[0] != "-N" {
		return nil, errors.New("numeric read required")
	}
	output, err := r.recordedPolicyFakeRunner.Run(ctx, command, args[1:]...)
	text := string(output)
	for _, pair := range [][2]string{{"0: from all lookup local", "0: from all lookup 255"}, {"32766: from all lookup main", "32766: from all lookup 254"}, {"32767: from all lookup default", "32767: from all lookup 253"}} {
		text = strings.Replace(text, pair[0], pair[1], 1)
	}
	return []byte(text), err
}

func TestPolicyDefaultDependencyRetainsOwnAndForeignSelectors(t *testing.T) {
	for _, family := range []int{4, 6} {
		t.Run(map[int]string{4: "ipv4", 6: "ipv6"}[family], func(t *testing.T) {
			state := testEarlyPolicy()
			runner := dependencyFixture()
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
	for _, table := range []int{201, 211} {
		t.Run(fmt.Sprintf("pin-table=%d", table), func(t *testing.T) {
			state := PolicyState{Interface: "rz-warp", Table: 201, PriorityBase: 18100, WireGuardEndpoint: &WGEndpointState{Endpoint: "203.0.113.9:443", Priority: 50, Mark: 0x01000000, Table: 201, Metric: 1, Device: "wan0", Gateway: "192.0.2.1", Source: "192.0.2.2"}}
			state.WireGuardEndpoint.Table = table
			for _, kind := range []string{"exact", "missing", "foreign-device", "foreign-protocol", "another-selector"} {
				t.Run(kind, func(t *testing.T) {
					var mutations []string
					runner := networkCleanupRunner(func(ctx context.Context, command string, args ...string) ([]byte, error) {
						if err := ctx.Err(); err != nil {
							return nil, err
						}
						joined := strings.Join(args, " ")
						if joined == "-N rule show" {
							out := fmt.Sprintf("0: from all lookup 255\n32766: from all lookup 254\n32767: from all lookup 253\n50: from all to 203.0.113.9 fwmark 0x1000000 lookup %d\n", table)
							if kind == "another-selector" {
								out += "61: from 192.168.1.41 to 149.154.167.99 lookup 201\n"
							}
							return []byte(out), nil
						}
						if joined == fmt.Sprintf("-N -j route show table %d exact 203.0.113.9/32", table) {
							if kind == "missing" {
								return []byte("[]"), nil
							}
							out := fmt.Sprintf(`[{"dst":"203.0.113.9/32","gateway":"192.0.2.1","dev":"wan0","prefsrc":"192.0.2.2","protocol":"static","metric":1,"table":%d,"flags":["onlink"]}]`, table)
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
		})
	}
}

func TestPolicyDefaultDependencyUnknownReadbackAndCancellationRefuse(t *testing.T) {
	state := testEarlyPolicy()
	for _, line := range []string{
		"40: from all fwmark 0x1 lookup 203",
		"40: from all oif nwg0 lookup 203",
		"40: from all fwmark 0x1 lookup 4096 goto 50",
		"40: from all fwmark 0x1 blackhole lookup 4096",
		"40: from all fwmark 0x1 iif br0 iif br1 lookup 4096",
		"40: from all fwmark 0x1 lookup 4096 suppress_prefixlength 0",
		"100: from all fwmark 0x1 lookup 210",
		"60: from all fwmark 0x1 lookup 4096",
		"18100: from all oif nwg0 lookup 4096",
		"100: from all fwmark 0xffffaaa lookup 4096 blackhole",
		"40: from 192.168.1.41 to 149.154.167.99 lookup owned-symbolic",
		"40: not from 192.168.1.41 to 149.154.167.99 lookup 204",
		"unrecognized kernel diagnostic",
	} {
		runner := dependencyFixture()
		runner.kernel.foreignIPv4 = []string{line}
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

// The RPDB of a Keenetic NC-1812 always holds firmware rules RAZVILKA does not
// own. They never select table 203, so they must not retain its default.
func TestPolicyDefaultDependencyUnderstandsKeeneticFirmwareRules(t *testing.T) {
	state := testEarlyPolicy()
	for family, rules := range map[int][]string{
		4: {"100: from all fwmark 0xffffaaa lookup 4096", "101: from all fwmark 0xffffaaa blackhole", "102: from all fwmark 0xffffaab lookup 4097", "1154: from 100.64.181.129 lookup 16386", "1172: from 172.16.88.98 lookup 16395"},
		6: {"100: from all fwmark 0xffffaac lookup 4096", "1172: from all oif nwg0 lookup 16395", "1174: from fd00:10:58::62 lookup 16395"},
	} {
		runner := dependencyFixture()
		if family == 4 {
			runner.kernel.foreignIPv4 = rules
		} else {
			runner.kernel.foreignIPv6 = rules
		}
		if err := AssertPolicyDefaultUnreferenced(context.Background(), runner, "ip", state, family); err != nil {
			t.Fatal("firmware rules retained the default", family, err)
		}
		if len(receiptMutationCalls(runner.calls)) != 0 {
			t.Fatal("read-only check mutated selectors")
		}
	}
}

func TestPolicyDefaultDependencyRejectsReservedLookingAliasesAndUnsupportedNumericRead(t *testing.T) {
	state := testEarlyPolicy()
	for _, line := range []string{"0: from all lookup local", "32766: from all lookup main", "32767: from all lookup default", "40: from 192.168.1.41 to 149.154.167.99 lookup main"} {
		runner := networkCleanupRunner(func(_ context.Context, _ string, args ...string) ([]byte, error) {
			if len(args) == 0 || args[0] != "-N" {
				t.Fatal("plain symbolic read could grant permission", args)
			}
			return []byte(line), nil
		})
		if err := AssertPolicyDefaultUnreferenced(context.Background(), runner, "ip", state, 4); !errors.Is(err, ErrPolicyDefaultReferenced) {
			t.Fatal("reserved-looking alias became a builtin table", line, err)
		}
	}
	unsupported := networkCleanupRunner(func(context.Context, string, ...string) ([]byte, error) {
		return []byte("unknown option -N"), errors.New("unsupported")
	})
	if err := AssertPolicyDefaultUnreferenced(context.Background(), unsupported, "ip", state, 6); !errors.Is(err, ErrPolicyDefaultReferenced) {
		t.Fatal("unsupported numeric read admitted cleanup", err)
	}
}

func TestPolicyDefaultDependencyCommonModelHonorsNumericReads(t *testing.T) {
	runner := &recordedPolicyFakeRunner{}
	state := testEarlyPolicy()
	if err := AssertPolicyDefaultUnreferenced(context.Background(), runner, "ip", state, 4); err != nil {
		t.Fatal("common model did not honor -N", err)
	}
	if len(runner.calls) != 1 || runner.calls[0] != "ip -N rule show" {
		t.Fatal("guard used symbolic read", runner.calls)
	}
	runner.kernel.entries = []policyKernelEntry{{family: 4, priority: 65, source: "192.168.1.40/32", dest: "149.154.167.99/32", table: "203", ingress: "br0", mark: LANPolicyGateMatch}}
	if err := AssertPolicyDefaultUnreferenced(context.Background(), runner, "ip", state, 4); !errors.Is(err, ErrPolicyDefaultReferenced) {
		t.Fatal("numeric model dropped selector", err)
	}
	output, err := runner.Run(context.Background(), "ip", "-N", "rule", "show")
	if err != nil || !strings.Contains(string(output), "fwmark "+LANPolicyGateMatch+" iif br0 lookup 203") {
		t.Fatal("numeric read lost full iif/mark/table", string(output), err)
	}
}
