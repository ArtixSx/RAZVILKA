package dataplane

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestLANPolicyTransportProofPreservesServiceAdmission(t *testing.T) {
	for _, tc := range []struct {
		name   string
		family int
		line   string
	}{
		{"WG-IPv4", 4, "52: from all to 93.184.216.34/32 fwmark 0x4000000/0xffffffff lookup 213"},
		{"WG-IPv6", 6, "52: from all to 2606:4700::1111/128 fwmark 0x4000000/0xffffffff lookup 213"},
		{"AWG-IPv4", 4, "51: from all to 93.184.216.34 fwmark 0x2000000 lookup 212"},
		{"AWG-IPv6", 6, "51: from all to 2606:4700::1111 fwmark 0x2000000 lookup 212"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan := lanRuntimeFixture(t)
			before := CloneLANPolicyRuntime(plan)
			reader := lanRuntimeReadFixture(plan)
			key := "-4"
			if tc.family == 6 {
				key = "-6"
			}
			reader.ip[key] += tc.line + "\n"
			reader.ip["-4"] += "70: from 192.168.1.0/24 to 8.8.8.8 fwmark 0x20000000/0x28000000 iif br0 lookup 206\n"
			runtime := runtimeWithReadRunner(reader)
			transportCalls, consumerCalls := 0, 0
			type contextKey struct{}
			ctx := context.WithValue(context.Background(), contextKey{}, "current-operation")
			runtime.TransportCheck = func(c context.Context, frozen *LANPolicyRuntimePlan, family int, line string) error {
				transportCalls++
				if c != ctx || c.Value(contextKey{}) != "current-operation" || family != tc.family || line != tc.line || !reflect.DeepEqual(frozen, before) {
					t.Fatal("transport proof lost operation, family, full row or frozen plan")
				}
				frozen.Ingress[0].Sources[0] = "10.0.0.0/8"
				return nil // Only the model's independently owned endpoint is admitted.
			}
			runtime.ConsumerCheck = func(context.Context, *LANPolicyRuntimePlan) error {
				consumerCalls++
				return nil
			}
			if err := runtime.Verify(ctx, plan); err != nil || transportCalls != 1 || consumerCalls != 1 || !reflect.DeepEqual(plan, before) {
				t.Fatal("exact transport/service readback failed", err, transportCalls, consumerCalls)
			}
			runtime.ConsumerCheck = nil
			if err := runtime.Verify(ctx, plan); err == nil {
				t.Fatal("transport proof replaced missing service-consumer admission")
			}
		})
	}
}

func TestLANPolicyTransportRefusesIncompleteAndForeignSelectors(t *testing.T) {
	const exact = "52: from all to 93.184.216.34/32 fwmark 0x4000000/0xffffffff lookup 213"
	for _, tc := range []struct {
		name string
		line string
	}{
		{"missing-destination", "52: from all fwmark 0x4000000/0xffffffff lookup 213"},
		{"network-destination", strings.Replace(exact, "93.184.216.34/32", "93.184.216.0/24", 1)},
		{"other-family", strings.Replace(exact, "93.184.216.34/32", "2606:4700::1111/128", 1)},
		{"partial-mask", strings.Replace(exact, "/0xffffffff", "/0xff000000", 1)},
		{"different-mark", strings.Replace(exact, "0x4000000", "0x4000001", 1)},
		{"different-source", strings.Replace(exact, "from all", "from 192.168.1.0/24", 1)},
		{"wrong-slot", strings.Replace(exact, "52:", "90:", 1)},
		{"wrong-table", strings.Replace(exact, "lookup 213", "lookup 254", 1)},
		{"numeric-table-alias", strings.Replace(exact, "lookup 213", "lookup 0213", 1)},
		{"table-key-alias", strings.Replace(exact, "lookup 213", "table 213", 1)},
		{"extra-ingress", exact + " iif br0"},
		{"duplicate-mark", exact + " fwmark 0x4000000/0xffffffff"},
		{"negated", strings.Replace(exact, "from all", "not from all", 1)},
		{"unmarked-table-selector", "90: from all to 93.184.216.34/32 lookup 213"},
		{"unmarked-table-alias", "90: from all to 93.184.216.34/32 lookup 0213"},
		{"legacy-WARP-slot", "50: from all to 93.184.216.34/32 fwmark 0x1000000/0xffffffff lookup 211"},
		{"unrelated-full-mask", "90: from all to 93.184.216.34/32 fwmark 0x4000000/0xffffffff lookup 254"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan := lanRuntimeFixture(t)
			reader := lanRuntimeReadFixture(plan)
			reader.ip["-4"] += tc.line + "\n"
			runtime := runtimeWithReadRunner(reader)
			calls := 0
			runtime.TransportCheck = func(context.Context, *LANPolicyRuntimePlan, int, string) error {
				calls++
				return nil
			}
			if err := runtime.Verify(context.Background(), plan); err == nil || calls != 0 {
				t.Fatal("foreign selector reached transport grant", err, calls)
			}
		})
	}
	for _, oppositeFamily := range []bool{false, true} {
		plan := lanRuntimeFixture(t)
		reader := lanRuntimeReadFixture(plan)
		reader.ip["-4"] += exact + "\n"
		if oppositeFamily {
			reader.ip["-6"] += strings.Replace(exact, "93.184.216.34/32", "2606:4700::1111/128", 1) + "\n"
		} else {
			reader.ip["-4"] += exact + "\n"
		}
		runtime := runtimeWithReadRunner(reader)
		calls := 0
		runtime.TransportCheck = func(context.Context, *LANPolicyRuntimePlan, int, string) error { calls++; return nil }
		if err := runtime.Verify(context.Background(), plan); err == nil || calls != 1 {
			t.Fatal("duplicate endpoint table admitted", oppositeFamily, err, calls)
		}
	}
}

func TestLANPolicyTransportRequiresCurrentOwnerProof(t *testing.T) {
	const exact = "52: from all to 93.184.216.34/32 fwmark 0x4000000/0xffffffff lookup 213"
	plan := lanRuntimeFixture(t)
	reader := lanRuntimeReadFixture(plan)
	reader.ip["-4"] += exact + "\n"
	runtime := runtimeWithReadRunner(reader)
	if err := runtime.Verify(context.Background(), plan); err == nil {
		t.Fatal("nil transport provider admitted a committed-looking selector")
	}
	unknown := errors.New("endpoint ownership/receipt/inventory is unknown")
	runtime.TransportCheck = func(context.Context, *LANPolicyRuntimePlan, int, string) error { return unknown }
	if err := runtime.Verify(context.Background(), plan); !errors.Is(err, unknown) {
		t.Fatal("owner refusal was hidden", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runtime.TransportCheck = func(context.Context, *LANPolicyRuntimePlan, int, string) error { cancel(); return nil }
	if err := runtime.Verify(ctx, plan); !errors.Is(err, context.Canceled) {
		t.Fatal("revoked transport proof admitted", err)
	}
}

func TestLANPolicyTransportProofDoesNotAuthorizePreflightOrCleanup(t *testing.T) {
	const exact = "52: from all to 93.184.216.34/32 fwmark 0x4000000/0xffffffff lookup 213"
	plan := lanRuntimeFixture(t)
	reader := lanRuntimeReadFixture(plan)
	reader.ip["-4"] += exact + "\n"
	runtime := runtimeWithReadRunner(reader)
	calls := 0
	runtime.TransportCheck = func(context.Context, *LANPolicyRuntimePlan, int, string) error { calls++; return nil }
	// Start with no gate, so the endpoint itself must prevent fresh adoption.
	preflight := runtimeWithReadRunner(&lanRuntimeReadRunner{ip: map[string]string{"-4": exact + "\n"}, firewall: map[string]string{}})
	preflight.TransportCheck = runtime.TransportCheck
	if err := preflight.Preflight(context.Background(), plan); err == nil || calls != 0 {
		t.Fatal("transport exception leaked into Preflight", err, calls)
	}
	effects, err := plan.Effects()
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.BeforeDelete(context.Background(), plan, effects[0]); err == nil || calls != 0 {
		t.Fatal("transport proof bypassed anchor dependencies", err, calls)
	}
	if _, _, err := runtime.InspectEffect(context.Background(), plan, effects[0]); err != nil || calls != 0 {
		t.Fatal("receipt readback invoked active transport admission", err, calls)
	}
}
