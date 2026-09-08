package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

func TestManagedTUNRequiresFullUserspaceTCPForEverySchema(t *testing.T) {
	for _, schema := range []singBoxSidecarSchema{{}, {modernAddress: true}, {modernAddress: true, dnsMode: true}} {
		data, err := buildSOCKSTunnelConfigForSchema("rz-test", "172.31.29.1/30", 18090, schema)
		if err != nil {
			t.Fatal(err)
		}
		var document struct {
			Inbounds []struct {
				Stack        string `json:"stack"`
				AutoRoute    bool   `json:"auto_route"`
				AutoRedirect bool   `json:"auto_redirect"`
			} `json:"inbounds"`
		}
		if err := json.Unmarshal(data, &document); err != nil {
			t.Fatal(err)
		}
		if len(document.Inbounds) != 1 || document.Inbounds[0].Stack != "gvisor" || document.Inbounds[0].AutoRoute || document.Inbounds[0].AutoRedirect {
			t.Fatalf("managed sidecar requires gVisor without native route/firewall ownership: %s", data)
		}
	}
}

func TestManagedTUNNativeValidationFailureHasNoStackFallback(t *testing.T) {
	root := t.TempDir()
	adapter, err := NewProxyTunnelAdapter("sing-box", engineconfig.New(filepath.Join(root, "drafts"), filepath.Join(root, "backups")), filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	adapter.EngineBin, adapter.SidecarBin, adapter.IP = "sing-box", "sing-box", "ip"
	adapter.IPTables, adapter.IP6Tables = "iptables", "ip6tables"
	processes := &proxyFakeProcesses{running: map[string]bool{"sing-box-engine": true, "sing-box-tun": true}}
	adapter.Processes = processes
	policy := PolicyState{Interface: adapter.Interface, Table: adapter.Table, PriorityBase: adapter.Priority,
		Prefixes: []string{"198.51.100.20/32"}, Rules: []PolicyRule{{Source: "192.168.1.25/32", Destination: "198.51.100.20/32"}},
		Forwarding: &ProxyForwardingState{Chain: adapter.forwardingChain(), Rules: []ProxyForwardingRule{{Source: "192.168.1.25/32", Destination: "198.51.100.20/32", Ingress: "br0"}}}}
	policyData, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	sidecar, err := buildSOCKSTunnelConfig(adapter.Interface, adapter.TunnelCIDR, adapter.SOCKSPort)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"policy.staged.json": policyData, "sidecar.staged.json": sidecar} {
		if err := os.WriteFile(filepath.Join(root, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	nativeChecks := 0
	base := &proxyFakeRunner{processes: processes, iface: adapter.Interface}
	adapter.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if strings.Join(args, " ") == "-t filter -S" {
			return []byte("-P FORWARD DROP\n"), nil
		}
		if strings.Join(args, " ") == "-t nat -S" {
			return []byte("-P POSTROUTING ACCEPT\n"), nil
		}
		if name == "sing-box" && len(args) == 3 && args[0] == "check" && args[2] == filepath.Join(root, "sidecar.staged.json") {
			nativeChecks++
			data, readErr := os.ReadFile(args[2])
			if readErr != nil || !strings.Contains(string(data), `"stack": "gvisor"`) {
				return nil, fmt.Errorf("unexpected native sidecar config: %v", readErr)
			}
			return []byte("gVisor is not included in this build"), errors.New("native validation refused unsupported stack")
		}
		return base.Run(ctx, name, args...)
	})
	err = adapter.Validate(context.Background(), Plan{}, root)
	if err == nil || !strings.Contains(err.Error(), "gVisor is not included") || nativeChecks != 1 {
		t.Fatalf("missing gVisor capability was not refused exactly once: checks=%d err=%v", nativeChecks, err)
	}
	after, err := os.ReadFile(filepath.Join(root, "sidecar.staged.json"))
	if err != nil || string(after) != string(sidecar) || len(processes.startSpecs) != 0 || len(processes.running) != 2 {
		t.Fatalf("capability refusal rewrote the stack or changed live processes: err=%v starts=%d", err, len(processes.startSpecs))
	}
}

func TestManagedTUNGVisorCapabilityRefusesCheckOnlyBuildBeforeStaging(t *testing.T) {
	for _, tags := range []string{"", "Tags: with_quic", "Tags: not_with_gvisor", "Tags: with_gvisor_disabled", "Notes: with_gvisor", "Tags: with_gvisor\nTags: with_quic"} {
		t.Run(tags, func(t *testing.T) {
			root := t.TempDir()
			configs := engineconfig.New(filepath.Join(root, "drafts"), filepath.Join(root, "backups"))
			if _, err := configs.Stage("sing-box", "main", `{"outbounds":[{"type":"vless","server":"203.0.113.9","server_port":443}]}`); err != nil {
				t.Fatal(err)
			}
			adapter, err := NewProxyTunnelAdapter("sing-box", configs, filepath.Join(root, "state"))
			if err != nil {
				t.Fatal(err)
			}
			adapter.EngineBin, adapter.SidecarBin, adapter.IP = "sing-box", "sing-box", "ip"
			adapter.IPTables, adapter.IP6Tables = "iptables", "ip6tables"
			processes := &proxyFakeProcesses{running: map[string]bool{"sing-box-engine": true, "sing-box-tun": true}}
			adapter.Processes = processes
			versions, checks := 0, 0
			base := &proxyFakeRunner{processes: processes, iface: adapter.Interface}
			adapter.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
				if name == "sing-box" && strings.Join(args, " ") == "version" {
					versions++
					return []byte("sing-box version 1.13.3\n" + tags + "\n"), nil
				}
				if name == "sing-box" && len(args) > 0 && args[0] == "check" {
					checks++
					// Upstream check can succeed without creating the actual stack.
					return nil, nil
				}
				return base.Run(ctx, name, args...)
			})
			manager := New(filepath.Join(root, "manager"))
			if err := manager.Register(adapter); err != nil {
				t.Fatal(err)
			}
			plan := Plan{SchemaVersion: SchemaVersion, PlanID: "dp-capability", Digest: strings.Repeat("a", 64), Ready: true, Adapters: []string{"sing-box"}, EngineDrafts: []string{"sing-box/main"}, Routes: []Route{{ServiceID: "telegram", Resolved: "sing-box", CIDRs: []string{"198.51.100.20/32"}, Sources: []string{"192.168.1.25/32"}}}}
			transaction := filepath.Join(manager.StateRoot, "transactions", plan.PlanID, adapter.ID())
			execution, err := manager.Apply(context.Background(), plan, nil)
			if err == nil || !strings.Contains(err.Error(), "requires sing-box built with with_gvisor") || execution.State != "canary-failed" || versions != 1 || checks != 0 {
				t.Fatalf("missing exact gVisor capability was not refused before native checks: versions=%d checks=%d err=%v", versions, checks, err)
			}
			if regularFile(filepath.Join(transaction, "sidecar.staged.json")) || regularFile(adapter.sidecarConfigPath()) || len(processes.startSpecs) != 0 || len(processes.running) != 2 {
				t.Fatal("missing capability created a sidecar or changed runtime")
			}
		})
	}
}

func TestManagedTUNGVisorExactBuildTagSupportsVersionSchemas(t *testing.T) {
	for _, tc := range []struct {
		version string
		modern  bool
		dns     bool
	}{{"1.8.0", false, false}, {"1.13.3", true, false}, {"1.14.0", true, true}} {
		t.Run(tc.version, func(t *testing.T) {
			adapter := &ProxyTunnelAdapter{SidecarBin: "sing-box", Runner: networkCleanupRunner(func(context.Context, string, ...string) ([]byte, error) {
				return []byte("sing-box version " + tc.version + "\r\nTags: with_quic, with_gvisor,with_utls\r\n"), nil
			})}
			schema, err := adapter.detectSidecarSchema(context.Background())
			if err != nil || schema.modernAddress != tc.modern || schema.dnsMode != tc.dns {
				t.Fatalf("valid gVisor capability/schema rejected: schema=%+v err=%v", schema, err)
			}
		})
	}
}
