package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func xraySelectedTCPFixtureSpec(t *testing.T, nodeID string) XraySelectedTCPRedirectSpec {
	t.Helper()
	generation := strings.Repeat("a", 64)
	lan, err := CompileLANPolicyRuntime(generation, []LANPolicyIngress{{SegmentID: "home", Interface: "br-lan", Sources: []string{"192.168.1.0/24"}, Membership: "mac",
		IncludedMACs: []string{"02:00:00:00:00:01", "02:00:00:00:00:02"}, ExcludedMACs: []string{"02:00:00:00:00:02"}, ExcludedSources: []string{"192.168.1.9/32"}}})
	if err != nil {
		t.Fatal(err)
	}
	return XraySelectedTCPRedirectSpec{Schema: 1, Generation: generation, ServiceID: "listed", NodeID: nodeID, LAN: lan,
		Destinations: []string{"1.1.1.0/24"}, ExcludedDestinations: []string{"1.1.1.9/32"}, Ports: []XraySelectedTCPPortRange{{443, 443}, {5000, 5010}},
		Listener: netip.MustParseAddrPort("192.168.1.1:16443")}
}

func TestXraySelectedTCPRedirectCompilerClosedScopeAndBodyDependencies(t *testing.T) {
	s := xraySelectedTCPFixtureSpec(t, "node-"+strings.Repeat("1", 64))
	p, err := CompileXraySelectedTCPRedirect(s)
	if err != nil {
		t.Fatal(err)
	}
	firstAttachment := -1
	for i, effect := range p.Effects {
		if effect.Tool != PolicyEffectIPTables || effect.Add[0] != "-t" || effect.Add[1] != "nat" {
			t.Fatal("compiler escaped IPv4 nat consumer scope")
		}
		text := strings.Join(effect.Add, " ")
		for _, forbidden := range []string{"mark", "CONNMARK", "TPROXY", "OUTPUT", "MASQUERADE", "DNAT", "-F"} {
			if strings.Contains(text, forbidden) {
				t.Fatal("unexpected shared/global operation", text)
			}
		}
		if effect.Add[2] == "-I" {
			if firstAttachment < 0 {
				firstAttachment = i
			}
			if effect.Add[3] != "PREROUTING" || !slices.Contains(effect.Add, "br-lan") || !slices.Contains(effect.Add, "192.168.1.0/24") || !slices.Contains(effect.Add, "--mac-source") || !slices.Contains(effect.Add, "tcp") || len(effect.Needs) != firstAttachment {
				t.Fatal("attachment lost exact ingress membership or full body dependency")
			}
			for n, dependency := range effect.Needs {
				if n != dependency {
					t.Fatal("attachment depends on incomplete body")
				}
			}
		}
	}
	if firstAttachment != 7 || len(p.Effects) != 9 {
		t.Fatal("unexpected negative/positive/terminal body", len(p.Effects), firstAttachment)
	}
	for i := 1; i <= 3; i++ {
		if !slices.Contains(p.Effects[i].Add, "RETURN") {
			t.Fatal("negative match follows redirect")
		}
	}
	// Detached caller copies cannot rewrite a previously emitted plan.
	s.LAN.Ingress[0].Sources[0], s.Destinations[0], s.Ports[0].First = "10.0.0.0/8", "8.8.8.0/24", 80
	if !slices.Contains(p.Effects[7].Add, "192.168.1.0/24") || !slices.Contains(p.Effects[4].Add, "1.1.1.0/24") || !slices.Contains(p.Effects[4].Add, "443") {
		t.Fatal("compiled effect retained caller slices")
	}
}

// Interpret the emitted closed vocabulary, not the input spec. This verifies
// the actual attachment/body combinations, including negative MAC precedence.
func xraySelectedTCPModelRedirect(t *testing.T, p PolicyEffectPlan, iface, src, mac, dst, protocol string, port uint16) bool {
	t.Helper()
	match := func(args []string) bool {
		for i := 0; i < len(args); i++ {
			switch args[i] {
			case "-i":
				if args[i+1] != iface {
					return false
				}
				i++
			case "-s", "-d":
				address := src
				if args[i] == "-d" {
					address = dst
				}
				if !netip.MustParsePrefix(args[i+1]).Contains(netip.MustParseAddr(address)) {
					return false
				}
				i++
			case "-p":
				if args[i+1] != protocol {
					return false
				}
				i++
			case "--mac-source":
				if args[i+1] != mac {
					return false
				}
				i++
			case "--dport":
				var first, last uint16
				parts := strings.Split(args[i+1], ":")
				for n, text := range parts {
					var v uint16
					for _, c := range text {
						v = v*10 + uint16(c-'0')
					}
					if n == 0 {
						first, last = v, v
					} else {
						last = v
					}
				}
				if port < first || port > last {
					return false
				}
				i++
			}
		}
		return true
	}
	attached := false
	for _, effect := range p.Effects {
		if effect.Add[2] == "-I" && match(effect.Add[5:]) {
			attached = true
		}
	}
	if !attached {
		return false
	}
	for _, effect := range p.Effects {
		if effect.Add[2] != "-A" || !match(effect.Add[4:]) {
			continue
		}
		return slices.Contains(effect.Add, "REDIRECT")
	}
	return false
}

func TestXraySelectedTCPRedirectEmittedRulesPositiveAndNegativePacketModel(t *testing.T) {
	p, err := CompileXraySelectedTCPRedirect(xraySelectedTCPFixtureSpec(t, "node-"+strings.Repeat("1", 64)))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, iface, source, mac, dest, proto string
		port                                  uint16
		want                                  bool
	}{
		{"selected", "br-lan", "192.168.1.5", "02:00:00:00:00:01", "1.1.1.1", "tcp", 443, true},
		{"range-first", "br-lan", "192.168.1.5", "02:00:00:00:00:01", "1.1.1.1", "tcp", 5000, true},
		{"range-last", "br-lan", "192.168.1.5", "02:00:00:00:00:01", "1.1.1.1", "tcp", 5010, true},
		{"excluded-source", "br-lan", "192.168.1.9", "02:00:00:00:00:01", "1.1.1.1", "tcp", 443, false},
		{"negative-MAC-wins", "br-lan", "192.168.1.5", "02:00:00:00:00:02", "1.1.1.1", "tcp", 443, false},
		{"excluded-dest", "br-lan", "192.168.1.5", "02:00:00:00:00:01", "1.1.1.9", "tcp", 443, false},
		{"foreign-iif", "br-guest", "192.168.1.5", "02:00:00:00:00:01", "1.1.1.1", "tcp", 443, false},
		{"foreign-source", "br-lan", "192.168.2.5", "02:00:00:00:00:01", "1.1.1.1", "tcp", 443, false},
		{"nonselected-MAC", "br-lan", "192.168.1.5", "02:00:00:00:00:03", "1.1.1.1", "tcp", 443, false},
		{"other-dest", "br-lan", "192.168.1.5", "02:00:00:00:00:01", "8.8.8.8", "tcp", 443, false},
		{"UDP", "br-lan", "192.168.1.5", "02:00:00:00:00:01", "1.1.1.1", "udp", 443, false},
		{"outside-port", "br-lan", "192.168.1.5", "02:00:00:00:00:01", "1.1.1.1", "tcp", 5011, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := xraySelectedTCPModelRedirect(t, p, tc.iface, tc.source, tc.mac, tc.dest, tc.proto, tc.port); got != tc.want {
				t.Fatal("emitted rules select wrong packet", got)
			}
		})
	}
}

func TestXraySelectedTCPRedirectRefusesBroadenedOrUnboundedInput(t *testing.T) {
	for _, bad := range []string{"empty-CIDRs", "empty-ports", "zero-port", "port-overlap", "noncanonical", "duplicate", "private-range", "IPv6", "mixed-LAN-family", "LAN-hash", "generation", "foreign-listener", "loopback-listener", "low-listener-port", "effect-bound"} {
		t.Run(bad, func(t *testing.T) {
			s := xraySelectedTCPFixtureSpec(t, "node-"+strings.Repeat("1", 64))
			switch bad {
			case "empty-CIDRs":
				s.Destinations = nil
			case "empty-ports":
				s.Ports = nil
			case "zero-port":
				s.Ports[0].First = 0
			case "port-overlap":
				s.Ports = []XraySelectedTCPPortRange{{443, 500}, {500, 600}}
			case "noncanonical":
				s.Destinations[0] = "1.1.1.1/24"
			case "duplicate":
				s.Destinations = append(s.Destinations, s.Destinations[0])
			case "private-range":
				s.Destinations[0] = "8.0.0.0/6"
			case "IPv6":
				s.Destinations[0] = "2606:4700::/32"
			case "mixed-LAN-family":
				s.LAN.Ingress[0].Sources = append(s.LAN.Ingress[0].Sources, "fd00::/64")
				s.LAN.Digest = lanPolicyDigest(s.LAN)
			case "LAN-hash":
				s.LAN.Digest = strings.Repeat("b", 64)
			case "generation":
				s.Generation = strings.Repeat("b", 64)
			case "foreign-listener":
				s.Listener = netip.MustParseAddrPort("192.168.2.1:16443")
			case "loopback-listener":
				s.Listener = netip.MustParseAddrPort("127.0.0.1:16443")
			case "low-listener-port":
				s.Listener = netip.MustParseAddrPort("192.168.1.1:443")
			case "effect-bound":
				for i := 0; i < 512; i++ {
					s.Destinations = append(s.Destinations, netip.PrefixFrom(netip.AddrFrom4([4]byte{9, 0, byte(i / 256), byte(i % 256)}), 32).String())
				}
				s.Ports = []XraySelectedTCPPortRange{{1, 1}, {2, 2}, {3, 3}, {4, 4}, {5, 5}, {6, 6}, {7, 7}, {8, 8}}
			}
			if _, err := CompileXraySelectedTCPRedirect(s); !errors.Is(err, ErrXraySelectedTCPRedirect) {
				t.Fatal("broadened input accepted", err)
			}
		})
	}
}

func xraySelectedTCPMaterialFixture(t *testing.T) (*nodeDefaultSourceFixture, *NodeServiceProofReview, *ProxyTunnelAdapter, XraySelectedTCPRedirectSpec) {
	t.Helper()
	f := newNodeDefaultSourceFixture(t, nodeDefaultSourceFixtureURI)
	check := nodeServiceProofFixtureCheck(f, "original")
	nodeServiceProofFixtureRecord(t, f, check)
	proof, err := reviewNodeServiceProof(f.ctx, f.review(t, "xray"), nodeServiceProofFixtureService(), check.NetworkProfile, func() time.Time { return f.now })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proof.Close() })
	a := &ProxyTunnelAdapter{EngineID: "xray", StateRoot: privateScopedXrayFixtureDir(t), EngineBin: filepath.Join(privateScopedXrayFixtureDir(t), "xray"), Processes: OSProcessController{}, xrayPlanDispatch: true, nodeRouterVerifier: true,
		Resolver: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("9.9.9.9")}, nil
		}}
	return f, proof, a, xraySelectedTCPFixtureSpec(t, f.id)
}

func TestXraySelectedTCPRedirectMaterialUsesActualStoreAndRawOriginalDestination(t *testing.T) {
	f, proof, a, spec := xraySelectedTCPMaterialFixture(t)
	path := filepath.Join(f.root, "nodes.private.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(before)
	m, err := buildXraySelectedTCPRedirectMaterial(f.ctx, a, proof, spec)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(m.config)
	var doc map[string]any
	if json.Unmarshal(m.config, &doc) != nil {
		t.Fatal("invalid config")
	}
	inbound := doc["inbounds"].([]any)[0].(map[string]any)
	settings := inbound["settings"].(map[string]any)
	if inbound["protocol"] != "dokodemo-door" || inbound["listen"] != "192.168.1.1" || settings["network"] != "tcp" || settings["followRedirect"] != true || len(settings) != 2 || inbound["sniffing"] != nil || inbound["streamSettings"].(map[string]any)["sockopt"].(map[string]any)["tproxy"] != "redirect" {
		t.Fatal("original destination ABI broadened")
	}
	outbounds := doc["outbounds"].([]any)
	if len(outbounds) != 2 || outbounds[0].(map[string]any)["protocol"] != "blackhole" {
		t.Fatal("default exit is not blackhole")
	}
	out := outbounds[1].(map[string]any)
	server := out["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)
	if server["address"] != "9.9.9.9" || out["streamSettings"].(map[string]any)["tlsSettings"].(map[string]any)["serverName"] != "source-front.example" {
		t.Fatal("pin replaced private endpoint SNI")
	}
	rules := doc["routing"].(map[string]any)["rules"].([]any)
	if rules[0].(map[string]any)["outboundTag"] != "rz-node-block" || rules[1].(map[string]any)["network"] != "tcp" || rules[2].(map[string]any)["port"] != "5000-5010" {
		t.Fatal("Xray scope lacks negatives or port restriction")
	}
	for _, raw := range rules {
		if raw.(map[string]any)["domain"] != nil {
			t.Fatal("domain rule projected into CIDR mode")
		}
	}
	after, err := os.ReadFile(path)
	defer clear(after)
	if err != nil || !slices.Equal(before, after) {
		t.Fatal("preparation wrote original store/history", err)
	}
	if !reflect.DeepEqual(m.ref, proof.state.ref) || !strings.Contains(string(m.config), "123e4567") || strings.Contains(m.String(), "123e4567") {
		t.Fatal("material lost original proof or leaked credentials")
	}
}

func TestXraySelectedTCPRedirectMaterialRejectsWrongServicePredicateAndChangedOriginal(t *testing.T) {
	for _, bad := range []string{"wrong-node", "wrong-service", "CIDR-subset", "foreign-pin", "private-answer", "record-change"} {
		t.Run(bad, func(t *testing.T) {
			f, proof, a, spec := xraySelectedTCPMaterialFixture(t)
			switch bad {
			case "wrong-node":
				spec.NodeID = "node-" + strings.Repeat("2", 64)
			case "wrong-service":
				spec.ServiceID = "other"
			case "CIDR-subset":
				spec.Destinations = []string{"1.1.1.0/25"}
			}
			m, err := buildXraySelectedTCPRedirectMaterial(f.ctx, a, proof, spec)
			if bad == "wrong-node" || bad == "wrong-service" || bad == "CIDR-subset" {
				if m != nil || !errors.Is(err, ErrXraySelectedTCPRedirect) {
					t.Fatal("borrowed or projected service predicate", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer clear(m.config)
			switch bad {
			case "foreign-pin":
				a.Resolver = func(context.Context, string) ([]netip.Addr, error) {
					return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
				}
			case "private-answer":
				a.Resolver = func(context.Context, string) ([]netip.Addr, error) {
					return []netip.Addr{m.pin, netip.MustParseAddr("127.0.0.1")}, nil
				}
			case "record-change":
				nodeServiceProofFixtureRecord(t, f, nodeServiceProofFixtureCheck(f, "replacement"))
			}
			if err := m.current(f.ctx, a); !errors.Is(err, ErrXraySelectedTCPRedirect) {
				t.Fatal("changed original stayed current", err)
			}
		})
	}
}

func TestXraySelectedTCPRedirectPinPreservesImplicitXHTTPHostFromSNI(t *testing.T) {
	f := newNodeDefaultSourceFixture(t, nodeDefaultSourceFixtureURI+"&type=xhttp&path=/split&mode=packet-up")
	check := nodeServiceProofFixtureCheck(f, "original-XHTTP")
	nodeServiceProofFixtureRecord(t, f, check)
	proof, err := reviewNodeServiceProof(f.ctx, f.review(t, "xray"), nodeServiceProofFixtureService(), check.NetworkProfile, func() time.Time { return f.now })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proof.Close() })
	a := &ProxyTunnelAdapter{EngineID: "xray", Resolver: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("9.9.9.9")}, nil
	}}
	m, err := buildXraySelectedTCPRedirectMaterial(f.ctx, a, proof, xraySelectedTCPFixtureSpec(t, f.id))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(m.config)
	var doc map[string]any
	if json.Unmarshal(m.config, &doc) != nil {
		t.Fatal("invalid config")
	}
	out := doc["outbounds"].([]any)[1].(map[string]any)
	stream := out["streamSettings"].(map[string]any)
	if stream["tlsSettings"].(map[string]any)["serverName"] != "source-front.example" || stream["xhttpSettings"].(map[string]any)["host"] != nil {
		t.Fatal("numeric pin changed implicit XHTTP Host from original SNI")
	}
}
