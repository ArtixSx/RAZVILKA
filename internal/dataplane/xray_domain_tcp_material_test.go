package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/nodestore"
)

// Actual registry and imported Store, testing only the endpoint callback's
// closing source boundary. No DNS session/binding, full factory, native child
// or readiness grant is fabricated by this lower comparison regression.
func TestXrayDomainTCPPinnedEndpointClosesAfterResolverSourceChange(t *testing.T) {
	for _, changed := range []string{"unchanged", "engine", "processes", "adapter-root", "manager-root", "registration", "node-generation"} {
		t.Run(changed, func(t *testing.T) {
			f := newNodeDefaultSourceFixture(t, nodeDefaultSourceFixtureURI)
			manager := New(t.TempDir())
			adapter := &ProxyTunnelAdapter{EngineID: "xray", StateRoot: filepath.Join(manager.StateRoot, "xray"), EngineBin: filepath.Join(manager.StateRoot, "bin", "xray"),
				Processes: OSProcessController{}, SOCKSPort: 16444, xrayPlanDispatch: true, nodeRouterVerifier: true}
			if err := manager.Register(adapter); err != nil {
				t.Fatal(err)
			}
			registration, err := manager.ReviewXrayRegistration(f.ctx, adapter)
			if err != nil {
				t.Fatal(err)
			}
			defer registration.Close()
			life, cancel := context.WithCancel(f.ctx)
			defer cancel()
			m := &XrayDomainTCPOperationMaterial{ctx: life, cancel: cancel, manager: manager, managerRoot: manager.StateRoot, adapter: adapter, adapterRoot: adapter.StateRoot,
				binaryField: adapter.EngineBin, binary: adapter.engineBinary(), processes: adapter.Processes, registration: registration, nodeSource: f.review(t, "xray"),
				private: netip.MustParseAddrPort("127.0.0.1:16444"), nodeHost: "source-node.example", nodePin: netip.MustParseAddrPort("8.8.8.8:443")}
			m.self = m
			calls := 0
			adapter.Resolver = func(ctx context.Context, _ string) ([]netip.Addr, error) {
				calls++
				switch changed {
				case "engine":
					adapter.EngineBin += "-changed"
				case "processes":
					adapter.Processes = &OSProcessController{}
				case "adapter-root":
					adapter.StateRoot += "-changed"
				case "manager-root":
					manager.StateRoot += "-changed"
				case "registration":
					if err := registration.Close(); err != nil {
						return nil, err
					}
				case "node-generation":
					if _, err := f.store.Import(ctx, nodestore.Source{ID: "closing-change", Kind: "manual"}, nodeDefaultSourceFixtureURI, f.now, time.Hour, false); err != nil {
						return nil, err
					}
				}
				return []netip.Addr{m.nodePin.Addr()}, nil
			}
			if err := m.metadataCurrent(f.ctx); err != nil {
				t.Fatal("opening source metadata comparison failed", err)
			}
			err = m.currentPinnedNodeEndpoint(f.ctx)
			if calls != 1 || (err == nil) != (changed == "unchanged") {
				t.Fatal("resolver changed the frozen source without closing refusal", calls, err)
			}
		})
	}
}

// Real imported NodeStore, original check history and canonical materializer.
// The check record is a test fixture, not live eligibility/native PC proof.
// No synthetic DNS source, process resource or execution owner is issued here.
func TestXrayDomainTCPNodeAdmissionUsesNewestExactHistoryReadOnly(t *testing.T) {
	f := newNodeDefaultSourceFixture(t, nodeDefaultSourceFixtureURI)
	check := nodeServiceProofFixtureCheck(f, "domain-exact")
	check.CheckedAt = f.now.Add(-time.Second)
	nodeServiceProofFixtureRecord(t, f, check)
	service := catalog.Service{ID: check.ServiceID, Name: "Domain fixture", Category: "fixture", Strategy: []string{"xray"}, Domains: []string{"service.example.com"}, ProbeURL: "https://service.example.com/"}
	spec := DomainPolicyTCPCaptureSpec{Xray: DomainPolicyTCPXraySpec{Generation: strings.Repeat("a", 64), NetworkProfile: check.NetworkProfile, ServiceID: service.ID, NodeID: f.id, Name: service.Domains[0], RealIP: netip.MustParseAddr("1.1.1.1")}}
	m := &XrayDomainTCPOperationMaterial{nodeSource: f.review(t, "xray"), service: service, plan: Plan{NetworkProfileID: check.NetworkProfile}, spec: spec}
	path := filepath.Join(f.root, "nodes.private.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(before)
	material, proof, err := m.readNodeAdmission(f.ctx)
	if err != nil || proof.check.ProbeID != check.ProbeID || proof.ref.ServiceSHA256 != nodeServiceProofDigest(service) || len(material) == 0 {
		t.Fatal("actual exact domain source/check was not retained", err)
	}
	defer clear(material)
	after, err := os.ReadFile(path)
	defer clear(after)
	if err != nil || string(before) != string(after) {
		t.Fatal("domain admission wrote node history", err)
	}
	failure := check
	failure.ProbeID, failure.Verdict, failure.State = "newest-domain-failure", "BLOCKED", "unavailable"
	failure.CheckedAt = f.now
	nodeServiceProofFixtureRecord(t, f, failure)
	m.nodeSource = f.review(t, "xray")
	data, _, err := m.readNodeAdmission(f.ctx)
	defer clear(data)
	if !errors.Is(err, ErrXrayDomainTCPOriginal) || data != nil {
		t.Fatal("an older PASS overrode the newest exact domain failure", err)
	}
}

func TestXrayDomainTCPConfigPinsNumericTargetAndPreservesTLSAuthority(t *testing.T) {
	f := newNodeDefaultSourceFixture(t, nodeDefaultSourceFixtureURI)
	check := nodeServiceProofFixtureCheck(f, "domain-config")
	nodeServiceProofFixtureRecord(t, f, check)
	service := catalog.Service{ID: check.ServiceID, Name: "Domain fixture", Category: "fixture", Strategy: []string{"xray"}, Domains: []string{"service.example.com"}, ProbeURL: "https://service.example.com/"}
	spec := DomainPolicyTCPXraySpec{Generation: strings.Repeat("a", 64), NetworkProfile: check.NetworkProfile, ServiceID: service.ID, NodeID: f.id, Name: service.Domains[0], RealIP: netip.MustParseAddr("1.1.1.1")}
	m := &XrayDomainTCPOperationMaterial{nodeSource: f.review(t, "xray"), service: service, plan: Plan{NetworkProfileID: check.NetworkProfile}, spec: DomainPolicyTCPCaptureSpec{Xray: spec}}
	material, _, err := m.readNodeAdmission(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(material)
	endpoint := netip.MustParseAddrPort("127.0.0.1:16444")
	pin := netip.MustParseAddrPort("8.8.8.8:443")
	data, err := compileXrayDomainTCPConfig(material, spec, endpoint, pin)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(data)
	var doc map[string]any
	if json.Unmarshal(data, &doc) != nil {
		t.Fatal("private compiled config is invalid")
	}
	inbound := doc["inbounds"].([]any)[0].(map[string]any)
	exit := doc["outbounds"].([]any)[1].(map[string]any)
	server := exit["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)
	tls := exit["streamSettings"].(map[string]any)["tlsSettings"].(map[string]any)
	rules := doc["routing"].(map[string]any)["rules"].([]any)
	selected, fallback := rules[0].(map[string]any), rules[1].(map[string]any)
	if inbound["listen"] != endpoint.Addr().String() || inbound["protocol"] != "socks" || inbound["settings"].(map[string]any)["udp"] != false || server["address"] != pin.Addr().String() || tls["serverName"] != "source-front.example" ||
		len(rules) != 2 || selected["ip"].([]any)[0] != "1.1.1.1/32" || selected["port"] != "80,443" || selected["network"] != "tcp" || fallback["outboundTag"] != "rz-node-block" || doc["dns"] != nil {
		t.Fatal("private fixed backend widened routing or changed TLS authority")
	}
	for _, bad := range []netip.AddrPort{netip.MustParseAddrPort("0.0.0.0:16444"), netip.MustParseAddrPort("192.168.1.1:16444"), netip.MustParseAddrPort("127.0.0.1:8787")} {
		if data, err := compileXrayDomainTCPConfig(material, spec, bad, pin); !errors.Is(err, ErrXrayDomainTCPOriginal) || data != nil {
			t.Fatal("another/private-panel endpoint supplied a backend", err)
		}
	}
}
