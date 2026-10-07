package dataplane

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func wgLANTransportFixture(t *testing.T) (*WARPWireGuardAdapter, *warpFakeRunner, Plan, context.Context, string) {
	t.Helper()
	a, kernel, plan, root, ctx := wgNetworkLifecycleFixture(t, true)
	for _, step := range []func(context.Context, Plan, string) error{a.Snapshot, a.Stage, a.Activate, a.Commit} {
		if err := step(ctx, plan, root); err != nil {
			t.Fatal(err)
		}
	}
	return a, kernel, plan, ctx, kernel.endpoint.rules["4|52"]
}

func TestWGNetworkLANTransportProofIsReadOnlyAndExact(t *testing.T) {
	a, kernel, plan, ctx, line := wgLANTransportFixture(t)
	paths := []string{a.statePath(), a.RuntimeConfigPath, filepath.Join(a.StateRoot, wgPolicyReferenceFile)}
	before := make([][]byte, len(paths))
	for i, path := range paths {
		before[i] = mustRead(path)
	}
	firewall := a.Runner.(wgNetworkLANReadbackRunner).firewall
	beforeIP, beforeFW := len(kernel.calls), len(firewall.calls)
	for _, observed := range []string{line, strings.Replace(line, "/0xffffffff", "", 1), strings.Replace(line, "93.184.216.34/32", "93.184.216.34", 1)} {
		if err := a.VerifyLANPolicyTransport(ctx, plan.LAN, 4, observed); err != nil {
			t.Fatal("exact committed transport refused", err)
		}
	}
	assertWGNetworkReadOnlyCalls(t, kernel.calls[beforeIP:], firewall.calls[beforeFW:])
	for i, path := range paths {
		if !bytes.Equal(before[i], mustRead(path)) {
			t.Fatal("transport proof changed committed evidence", path)
		}
	}
	for _, cut := range []string{"family", "mask", "destination", "source", "table", "priority", "ingress", "negated", "duplicate-selector", "new-line"} {
		t.Run(cut, func(t *testing.T) {
			observed, family := line, 4
			switch cut {
			case "family":
				family = 6
			case "mask":
				observed = strings.Replace(observed, "/0xffffffff", "/0xff000000", 1)
			case "destination":
				observed = strings.Replace(observed, "93.184.216.34/32", "93.184.216.0/24", 1)
			case "source":
				observed = strings.Replace(observed, "from all", "from 192.168.1.0/24", 1)
			case "table":
				observed = strings.Replace(observed, "lookup 213", "lookup 206", 1)
			case "priority":
				observed = strings.Replace(observed, "52:", "51:", 1)
			case "ingress":
				observed += " iif br0"
			case "negated":
				observed = strings.Replace(observed, "from all", "not from all", 1)
			case "duplicate-selector":
				observed += " fwmark 0x4000000/0xffffffff"
			case "new-line":
				observed += "\n"
			}
			if observed == line && family == 4 {
				t.Fatal("ineffective observation mutation", cut)
			}
			if err := a.VerifyLANPolicyTransport(ctx, plan.LAN, family, observed); err == nil {
				t.Fatal("foreign transport observation admitted", cut)
			}
		})
	}
}

func TestWGNetworkLANTransportIPv6EndpointProof(t *testing.T) {
	a, kernel, plan, root, ctx := wgNetworkLifecycleFixture(t, true)
	a.EndpointResolver = func(context.Context, string) ([]netip.Addr, time.Time, error) {
		return []netip.Addr{netip.MustParseAddr("2606:4700::1111")}, time.Now().Add(time.Hour), nil
	}
	for _, step := range []func(context.Context, Plan, string) error{a.Snapshot, a.Stage, a.Activate, a.Commit} {
		if err := step(ctx, plan, root); err != nil {
			t.Fatal(err)
		}
	}
	line := strings.Replace(kernel.endpoint.rules["6|52"], "2606:4700::1111/128", "2606:4700::1111", 1)
	before := len(kernel.calls)
	if err := a.VerifyLANPolicyTransport(ctx, plan.LAN, 6, line); err != nil {
		t.Fatal("committed IPv6 endpoint refused", err)
	}
	if err := a.VerifyLANPolicyTransport(ctx, plan.LAN, 4, line); err == nil {
		t.Fatal("IPv6 endpoint granted IPv4 observation")
	}
	assertWGNetworkReadOnlyCalls(t, kernel.calls[before:])
}

func TestWGNetworkLANTransportRejectsUnsettledOrChangedProof(t *testing.T) {
	for _, cut := range []string{"missing-state", "missing-reference", "corrupt-reference", "reference-endpoint", "reference-runtime", "missing-ledger", "boot", "pending-operation", "runtime", "missing-interface", "live-mark", "live-public-key", "duplicate-rule", "opposite-family-rule", "additional-table-selector", "opposite-family-table-selector", "extra-route", "physical-prefix", "frozen-LAN", "typed-nil-runner"} {
		t.Run(cut, func(t *testing.T) {
			a, kernel, plan, ctx, line := wgLANTransportFixture(t)
			state, _, err := a.loadPolicyState()
			if err != nil {
				t.Fatal(err)
			}
			ref, err := a.committedWGPolicyReference(state)
			if err != nil {
				t.Fatal(err)
			}
			write := func(path string, data []byte) {
				t.Helper()
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			switch cut {
			case "missing-state":
				if err := os.Remove(a.statePath()); err != nil {
					t.Fatal(err)
				}
			case "missing-reference":
				if err := os.Remove(filepath.Join(a.StateRoot, wgPolicyReferenceFile)); err != nil {
					t.Fatal(err)
				}
			case "corrupt-reference":
				write(filepath.Join(a.StateRoot, wgPolicyReferenceFile), []byte("{}"))
			case "reference-endpoint", "reference-runtime":
				if cut == "reference-endpoint" {
					ref.Policy.WireGuardEndpoint.Endpoint = "93.184.216.35:51820"
				} else {
					ref.Policy.RuntimeConfigSHA256 = strings.Repeat("b", 64)
				}
				if err := writeWGPolicyReference(ctx, a.StateRoot, ref); err != nil {
					t.Fatal(err)
				}
			case "missing-ledger":
				if err := os.Remove(filepath.Join(a.wgPolicyGenerationRoot(ref, ""), policyAdditionFile)); err != nil {
					t.Fatal(err)
				}
			case "boot":
				a.policyReceiptOptions.boot = func() (string, error) { return "different-boot", nil }
			case "pending-operation":
				if err := os.Mkdir(filepath.Join(a.StateRoot, wgPolicyOperationDirectory), 0700); err != nil {
					t.Fatal(err)
				}
			case "runtime":
				write(a.RuntimeConfigPath, append(mustRead(a.RuntimeConfigPath), '\n'))
			case "missing-interface":
				kernel.active = false
			case "live-mark":
				kernel.endpoint.mark = "0x0"
			case "live-public-key":
				kernel.endpoint.publicKey = "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="
			case "duplicate-rule":
				kernel.endpoint.rules["4|duplicate"] = line
			case "opposite-family-rule":
				kernel.endpoint.rules["6|52"] = "52: from all to 2606:4700::1111/128 fwmark 0x4000000/0xffffffff lookup 213"
			case "additional-table-selector":
				kernel.endpoint.rules["4|90"] = "90: from all to 93.184.216.35/32 lookup 213"
			case "opposite-family-table-selector":
				kernel.endpoint.rules["6|90"] = "90: from all to 2606:4700::1111/128 lookup 213"
			case "extra-route":
				for _, row := range kernel.endpoint.routes {
					row.Destination = "93.184.216.35/32"
					kernel.endpoint.routes["4|extra"] = row
					kernel.endpoint.routeTables["4|extra"] = 213
					break
				}
			case "physical-prefix":
				base := a.Runner
				a.Runner = networkCleanupRunner(func(c context.Context, tool string, args ...string) ([]byte, error) {
					data, err := base.Run(c, tool, args...)
					if tool == "ip" && (strings.Contains(strings.Join(args, " "), "route show table main") || strings.Contains(strings.Join(args, " "), "addr show dev br0")) {
						data = []byte(strings.ReplaceAll(string(data), "/64", "/65"))
					}
					return data, err
				})
			case "frozen-LAN":
				plan.LAN, err = CompileLANPolicyRuntime(plan.LAN.Generation, []LANPolicyIngress{{SegmentID: "other", Interface: "br0", Sources: plan.LAN.Ingress[0].Sources, Membership: "all"}})
				if err != nil {
					t.Fatal(err)
				}
			case "typed-nil-runner":
				var runner *warpFakeRunner
				a.Runner = runner
			}
			beforeIP := len(kernel.calls)
			if err := a.VerifyLANPolicyTransport(ctx, plan.LAN, 4, line); err == nil {
				t.Fatal("changed or incomplete endpoint proof admitted", cut)
			}
			assertWGNetworkReadOnlyCalls(t, kernel.calls[beforeIP:])
		})
	}
}

func TestWGNetworkLANTransportRejectsUnknownCommonReceipt(t *testing.T) {
	a, kernel, plan, ctx, line := wgLANTransportFixture(t)
	state, _, _ := a.loadPolicyState()
	ref, _ := a.committedWGPolicyReference(state)
	a.policyReceiptOptions.fault = func(point string, _ int) error {
		if point == "cleanup-intent" {
			return errors.New("LAN transport proof model cut")
		}
		return nil
	}
	if err := a.removeWGPolicyReference(ctx, ref, ""); err == nil {
		t.Fatal("unknown receipt model cut missing", err)
	}
	if status, err := a.inspectWGPolicyReference(ctx, ref, ""); err != nil || !status.Unknown {
		t.Fatal("unknown receipt not retained", status, err)
	}
	if kernel.endpoint.rules["4|52"] != line {
		t.Fatal("model cut lost the committed endpoint")
	}
	before := len(kernel.calls)
	if err := a.VerifyLANPolicyTransport(ctx, plan.LAN, 4, line); !errors.Is(err, ErrPolicyAdditionUnknown) {
		t.Fatal("unknown receipt granted transport exception", err)
	}
	assertWGNetworkReadOnlyCalls(t, kernel.calls[before:])
}
