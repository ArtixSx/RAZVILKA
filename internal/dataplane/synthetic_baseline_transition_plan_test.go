package dataplane

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

// Definition-only, socket-free: actual DNS profile/catalog and Store freeze,
// explicit domain/scope models. No listener, baseline or native readiness.
func syntheticTransportModelFixture(t *testing.T) (*SyntheticDNSTransportPlan, *DomainPolicyRuntimePlan) {
	t.Helper()
	policy, flow, now := domainPolicyFixture(t, nil)
	policy.services[0].Route = "xray:one"
	domain, err := FreezeDomainPolicyRuntimePlan(policy.generation, policy.policy, policy.scope, policy.guests, policy.services, now)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.NetworkPolicy = config.CloneNetworkPolicy(domain.Policy)
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	store, err := config.LoadExisting(path)
	if err != nil {
		t.Fatal(err)
	}
	exclusions, err := dnscontrol.NewNetworkPolicyDNSExclusions(context.Background(), store, store.Get(), func(context.Context, string) ([]string, error) { return []string{"service"}, nil })
	if err != nil {
		t.Fatal(err)
	}
	dns, err := dnscontrol.New("")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := dns.FreezeNetworkPolicyDNSPlan(context.Background(), domain.Generation, "private", []dnscontrol.ClientDNSBinding{{Client: flow.Client.Address, Domain: "service.example.com", ProfileID: "private"}}, exclusions)
	if err != nil {
		t.Fatal(err)
	}
	return &SyntheticDNSTransportPlan{Listener: "192.168.1.1:10553", CaptureEndpoint: "192.168.1.1:10443", DomainPolicyDigest: domain.Digest, DNS: plan, Definition: dnscontrol.SyntheticDNSDefinition{Client: flow.Client.Address, DeviceID: "selected", MAC: flow.Client.MAC, Ingress: flow.Client.Interface, ExactNames: []string{"service.example.com"}}}, domain
}

func TestSyntheticTransportDefinitionRoundTripAndIndependentClone(t *testing.T) {
	transport, domain := syntheticTransportModelFixture(t)
	if err := ValidateSyntheticDNSTransportPlan(transport, domain); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(transport)
	if err != nil {
		t.Fatal(err)
	}
	var decoded SyntheticDNSTransportPlan
	if json.Unmarshal(data, &decoded) != nil || ValidateSyntheticDNSTransportPlan(&decoded, domain) != nil {
		t.Fatal("retained intent changed after serialization")
	}
	copy := CloneSyntheticDNSTransportPlan(transport)
	copy.Definition.ExactNames[0] = "forged.example.com"
	copy.DNS.Bindings[0].Domain = "forged.example.com"
	if transport.Definition.ExactNames[0] != "service.example.com" || transport.DNS.Bindings[0].Domain != "service.example.com" || ValidateSyntheticDNSTransportPlan(copy, domain) == nil {
		t.Fatal("detached clone widened original")
	}
	if ValidateSyntheticDNSTransportPlan(nil, domain) == nil || ValidateSyntheticDNSTransportPlan(transport, nil) == nil {
		t.Fatal("incomplete projection accepted")
	}
}

func TestSyntheticTransportDefinitionRefusesUnboundScopeFamilyNodeOrDigest(t *testing.T) {
	for _, kind := range []string{"client", "mac", "iif", "device", "listener", "port", "capture-host", "capture-port", "digest", "dns-digest", "suffix", "cidr", "second-node", "extra-name", "profile-binding", "negative-client", "negative-resource-stamp"} {
		t.Run(kind, func(t *testing.T) {
			transport, domain := syntheticTransportModelFixture(t)
			switch kind {
			case "client":
				transport.Definition.Client = netip.MustParseAddr("192.168.2.42")
			case "mac":
				transport.Definition.MAC = "02:00:00:00:00:99"
			case "iif":
				transport.Definition.Ingress = "br1"
			case "device":
				transport.Definition.DeviceID = "excluded"
			case "listener":
				transport.Listener = "127.0.0.1:10553"
			case "port":
				transport.Listener = "192.168.1.1:53"
			case "capture-host":
				transport.CaptureEndpoint = "192.168.2.1:10443"
			case "capture-port":
				transport.CaptureEndpoint = transport.Listener
			case "digest":
				transport.DomainPolicyDigest = strings.Repeat("f", 64)
			case "dns-digest":
				transport.DNS.Digest = strings.Repeat("f", 64)
			case "suffix":
				domain.Services[0].DomainSuffixes = []string{"service.example.com"}
			case "cidr":
				domain.Services[0].CIDRs = []string{"93.184.215.0/24"}
			case "second-node":
				domain.Services = append(domain.Services, DomainPolicyService{ID: "second", Selected: true, Route: "xray:other", Domains: []string{"other.example.com"}})
			case "extra-name":
				transport.Definition.ExactNames = append(transport.Definition.ExactNames, "other.example.com")
			case "profile-binding":
				transport.DNS.Bindings[0].Client = netip.MustParseAddr("192.168.1.43")
			case "negative-client":
				domain.Policy.Clients.ExcludedDeviceIDs = append(domain.Policy.Clients.ExcludedDeviceIDs, "selected")
			case "negative-resource-stamp":
				domain.Policy.Revision++
			}
			// For pure domain mutations keep hashes coherent: refusal must
			// inspect the definition, not merely notice a stale outer digest.
			if kind == "suffix" || kind == "cidr" || kind == "second-node" || kind == "negative-client" || kind == "negative-resource-stamp" {
				domain.Digest = domainPolicyRuntimeDigest(domain)
				transport.DomainPolicyDigest = domain.Digest
			}
			if err := ValidateSyntheticDNSTransportPlan(transport, domain); err == nil {
				t.Fatal("unsupported projection accepted")
			}
		})
	}
}
