package devices

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type observationRunner func(context.Context, string, ...string) ([]byte, error)

func (f observationRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return f(ctx, name, args...)
}

func TestObserveBindingsFreshDualStackWithoutRegistryWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	m, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	m.IPCommand = "fixture-ip"
	m.devices["mac-02-00-00-00-00-ff"] = Device{ID: "mac-02-00-00-00-00-ff", MAC: "02:00:00:00:00:ff", IPs: []string{"192.168.1.99"}, LastSeenAt: "yesterday"}
	before, _ := os.ReadFile(path)
	stat, _ := os.Stat(path)
	calls := []string{}
	ip := "192.168.1.40"
	m.Runner = observationRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name != "fixture-ip" {
			t.Fatalf("unexpected command %s", name)
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 4*time.Second {
			t.Fatal("unbounded observation")
		}
		calls = append(calls, strings.Join(args, " "))
		if args[0] == "-6" {
			return []byte("2001:db8::40 lladdr 02:00:00:00:00:01 STALE\nfe80::40 dev br0 lladdr 02:00:00:00:00:01 REACHABLE\n"), nil
		}
		return []byte(ip + " dev br0 lladdr 02:00:00:00:00:01 REACHABLE\n192.168.1.99 FAILED\n"), nil
	})
	first, err := m.ObserveBindings(context.Background(), []string{"br0"})
	if err != nil || len(first.Bindings) != 1 || len(first.Bindings[0].Addresses) != 3 {
		t.Fatalf("%+v %v", first, err)
	}
	if !reflect.DeepEqual(calls, []string{"-4 neigh show dev br0", "-6 neigh show dev br0"}) {
		t.Fatal(calls)
	}
	if first.FreshUntil.Sub(first.ObservedAt) != 2*time.Minute {
		t.Fatal("unexpected freshness")
	}
	// Reassignment is a new observation, never a merge of stale persisted IPs.
	ip = "192.168.1.41"
	second, err := m.ObserveBindings(context.Background(), []string{"br0"})
	if err != nil || second.Bindings[0].ID != first.Bindings[0].ID || second.Bindings[0].Addresses[0].Address != ip {
		t.Fatalf("%+v %v", second, err)
	}
	second.Bindings[0].Addresses[0].Address = "modified"
	if first.Bindings[0].Addresses[0].Address != "192.168.1.40" {
		t.Fatal("aliased observations")
	}
	after, _ := os.ReadFile(path)
	afterStat, _ := os.Stat(path)
	if string(before) != string(after) || !stat.ModTime().Equal(afterStat.ModTime()) || len(m.devices) != 1 || m.devices["mac-02-00-00-00-00-ff"].LastSeenAt != "yesterday" {
		t.Fatal("read-only observation touched registry")
	}
}

func TestObserveBindingsRefusesPartialAmbiguousOrOversizedData(t *testing.T) {
	for _, tc := range []struct {
		name, v4, v6 string
		interfaces   []string
		err          error
	}{
		{"malformed", "garbage", "", nil, ErrBindingObservation},
		{"second-family", "192.168.1.40 lladdr 02:00:00:00:00:01 REACHABLE", "garbage", nil, ErrBindingObservation},
		{"conflicting-ip", "192.168.1.40 lladdr 02:00:00:00:00:01 REACHABLE\n192.168.1.40 lladdr 02:00:00:00:00:02 REACHABLE", "", nil, ErrBindingAmbiguous},
		{"duplicate-row", strings.Repeat("192.168.1.40 lladdr 02:00:00:00:00:01 REACHABLE\n", 2), "", nil, ErrBindingAmbiguous},
		{"same-mac-two-segments", "192.168.1.40 lladdr 02:00:00:00:00:01 REACHABLE", "", []string{"br0", "br1"}, ErrBindingAmbiguous},
		{"failed-budget", strings.Repeat("192.168.1.40 FAILED\n", 2200), strings.Repeat("fe80::40 INCOMPLETE\n", 2200), nil, ErrBindingObservation},
		{"byte-budget", strings.Repeat(" ", bindingOutputLimit+1), "", nil, ErrBindingObservation},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := Manager{IPCommand: "ip", Runner: observationRunner(func(_ context.Context, _ string, args ...string) ([]byte, error) {
				if args[0] == "-6" {
					return []byte(tc.v6), nil
				}
				return []byte(tc.v4), nil
			})}
			interfaces := tc.interfaces
			if interfaces == nil {
				interfaces = []string{"br0"}
			}
			got, err := m.ObserveBindings(context.Background(), interfaces)
			if !errors.Is(err, tc.err) || !reflect.DeepEqual(got, BindingObservation{}) {
				t.Fatalf("partial result %+v %v", got, err)
			}
		})
	}
}

func TestObserveBindingsInvalidInterfacesAndCancellationDoNoIO(t *testing.T) {
	calls := 0
	m := Manager{IPCommand: "ip", Runner: observationRunner(func(context.Context, string, ...string) ([]byte, error) { calls++; return nil, nil })}
	for _, interfaces := range [][]string{nil, {"lo"}, {"br0", "br0"}, {"br0;reboot"}, {"-all"}, make([]string, 17)} {
		if _, err := m.ObserveBindings(context.Background(), interfaces); err == nil {
			t.Fatalf("accepted %v", interfaces)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.ObserveBindings(ctx, []string{"br0"}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("invalid request ran utilities")
	}
	m.Runner = observationRunner(func(ctx context.Context, _ string, _ ...string) ([]byte, error) { cancel(); return nil, ctx.Err() })
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	if _, err := m.ObserveBindings(ctx, []string{"br0"}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestBindingParserRejectsInvalidIdentityAndUnknownFormats(t *testing.T) {
	for _, line := range []string{
		"127.0.0.1 lladdr 02:00:00:00:00:01 REACHABLE",
		"224.0.0.1 lladdr 02:00:00:00:00:01 REACHABLE",
		"fd00::1 lladdr 02:00:00:00:00:01 REACHABLE",
		"192.168.1.40 dev br1 lladdr 02:00:00:00:00:01 REACHABLE",
		"192.168.1.40 lladdr 01:00:00:00:00:01 REACHABLE",
		"192.168.1.40 lladdr 00:00:00:00:00:00 REACHABLE",
		"192.168.1.40 lladdr 02:00:00:00:00:01 UNKNOWN",
		"192.168.1.40 lladdr 02:00:00:00:00:01 REACHABLE STALE",
		"192.168.1.40 lladdr 02:00:00:00:00:01 dev br0 dev br0 REACHABLE",
		"192.168.1.40 lladdr 02:00:00:00:00:01 lladdr 02:00:00:00:00:02 REACHABLE",
		"192.168.1.40 lladdr 02:00:00:00:00:01 REACHABLE\x00",
	} {
		if _, err := parseBindingNeighbors([]byte(line), "br0", false); err == nil {
			t.Fatalf("accepted %q", line)
		}
	}
	for _, state := range []string{"REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT", "NOARP"} {
		got, err := parseBindingNeighbors([]byte("2001:db8::40 lladdr 02:00:00:00:00:01 "+state+" router"), "br0", true)
		if err != nil || len(got) != 1 || got[0].Addresses[0].State != strings.ToLower(state) {
			t.Fatalf("%+v %v", got, err)
		}
	}
}

func TestObserveBindingsAddressAndDeviceBudgets(t *testing.T) {
	for _, mode := range []string{"addresses", "devices"} {
		t.Run(mode, func(t *testing.T) {
			var data strings.Builder
			limit := 65
			if mode == "devices" {
				limit = 513
			}
			for i := 0; i < limit; i++ {
				mac := "02:00:00:00:00:01"
				if mode == "devices" {
					mac = fmt.Sprintf("02:00:00:00:%02x:%02x", i/256, i%256)
				}
				fmt.Fprintf(&data, "2001:db8::%x lladdr %s REACHABLE\n", i+1, mac)
			}
			m := Manager{IPCommand: "ip", Runner: observationRunner(func(_ context.Context, _ string, args ...string) ([]byte, error) {
				if args[0] == "-6" {
					return []byte(data.String()), nil
				}
				return nil, nil
			})}
			if got, err := m.ObserveBindings(context.Background(), []string{"br0"}); err == nil || len(got.Bindings) != 0 {
				t.Fatal("budget not enforced")
			}
		})
	}
}

func TestBoundedDeviceOutputDoesNotGrowOnOverflow(t *testing.T) {
	var out boundedCommandOutput
	if _, err := out.Write([]byte(strings.Repeat("x", bindingOutputLimit))); err != nil {
		t.Fatal(err)
	}
	if _, err := out.Write([]byte("x")); !errors.Is(err, ErrBindingObservation) || out.Len() != bindingOutputLimit || !out.exceeded {
		t.Fatal("unbounded command output")
	}
}

func TestDeviceCommandHelper(t *testing.T) {
	if os.Getenv("RAZVILKA_DEVICE_OUTPUT_TEST") != "large" {
		return
	}
	for i := 0; i < 32; i++ {
		if _, err := os.Stdout.WriteString(strings.Repeat("x", 64<<10)); err != nil {
			os.Exit(0)
		}
	}
	os.Exit(0)
}

func TestBoundedDeviceOutputLimitsRealProcessPipes(t *testing.T) {
	t.Setenv("RAZVILKA_DEVICE_OUTPUT_TEST", "large")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	data, err := runBoundedDeviceCommand(ctx, os.Args[0], "-test.run=^TestDeviceCommandHelper$")
	if !errors.Is(err, ErrBindingObservation) || len(data) != 0 {
		t.Fatalf("unbounded pipe: %d bytes, %v", len(data), err)
	}
}
