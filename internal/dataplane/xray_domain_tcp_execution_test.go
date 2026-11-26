package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

func xrayDomainExecutionDefinitionFixture(t *testing.T) ExecutionXrayDomainTCPDefinition {
	t.Helper()
	transport, domain := syntheticTransportModelFixture(t)
	_, flow, now := domainPolicyFixture(t, nil)
	node := "node-" + strings.Repeat("a", 64)
	domain.Services[0].Route = "xray:" + node
	domain.Digest = domainPolicyRuntimeDigest(domain)
	transport.DomainPolicyDigest = domain.Digest
	identity, _ := networkPolicyIdentityFixture()
	service := catalog.Service{ID: domain.Services[0].ID, Name: "Domain fixture", Category: "fixture", Strategy: []string{"xray"}, Domains: []string{transport.Definition.ExactNames[0]}, ProbeURL: "https://" + transport.Definition.ExactNames[0] + "/"}
	spec := DomainPolicyTCPCaptureSpec{Xray: DomainPolicyTCPXraySpec{Generation: domain.Generation, NetworkProfile: "wan-fixture", ServiceID: service.ID, NodeID: node, Name: service.Domains[0], RealIP: netip.MustParseAddr("1.1.1.1")}, Client: flow.Client, DeviceID: transport.Definition.DeviceID, Listen: netip.MustParseAddrPort(transport.CaptureEndpoint), Limits: DomainPolicySniffLimits{Bytes: 16 << 10, Timeout: time.Second}}
	mapping := dnscontrol.SyntheticDNSMappingObservation{Authority: dnscontrol.NetworkPolicyDNSAuthority{Generation: domain.Generation, ControlEpoch: 1, BindingRevision: 1, Exclusions: transport.DNS.Exclusions}, PublicationID: strings.Repeat("b", 32), Client: spec.Client.Address, DeviceID: spec.DeviceID, MAC: spec.Client.MAC, Ingress: spec.Client.Interface, QName: spec.Xray.Name, Synthetic: netip.MustParseAddr("198.18.0.1"), RealIPv4: spec.Xray.RealIP, ExpiresAt: now.Add(time.Minute)}
	d := ExecutionXrayDomainTCPDefinition{Schema: 1, PlanID: "dp-" + strings.Repeat("a", 16), PlanDigest: strings.Repeat("b", 64), NetworkProfile: spec.Xray.NetworkProfile, Domain: domain, Transport: transport, Capture: spec, Service: service, Mapping: mapping, PrivateEndpoint: netip.MustParseAddrPort("127.0.0.1:18080"), ConfigSHA256: strings.Repeat("c", 64), NetworkIdentity: identity.value, Proof: NodeServiceProofReference{Schema: 1, EngineID: "xray", NodeID: node, ServiceID: service.ID, WANProfile: spec.Xray.NetworkProfile, NodeGeneration: 1, CompiledMaterialSHA256: strings.Repeat("d", 64), ServiceSHA256: nodeServiceProofDigest(service), ProofSHA256: strings.Repeat("e", 64), CheckedAt: now, ExpiresAt: now.Add(time.Minute)}}
	if err := d.validate(); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestXrayDomainTCPExecutionJournalNeverGrantsActiveOrForeignVariant(t *testing.T) {
	d := xrayDomainExecutionDefinitionFixture(t)
	r := ExecutionResource{ID: "xd-" + strings.Repeat("a", 32), Kind: "xray-domain-tcp", State: "prepared", Phase: "planned", Generation: d.Domain.Generation, EffectsDigest: d.ConfigSHA256, XrayDomainTCP: &d}
	execution := Execution{PlanID: d.PlanID, Digest: d.PlanDigest, Resources: []ExecutionResource{r}}
	for _, phase := range []string{"planned", "process-pending", "listener-ready", "closed"} {
		execution.Resources[0].Phase = phase
		if err := validateExecutionResources(execution, false); err != nil {
			t.Fatal(phase, err)
		}
		if err := validateExecutionResources(execution, true); err == nil {
			t.Fatal("pending process became terminal", phase)
		}
	}
	for _, phase := range []string{"removed", "unused"} {
		execution.Resources[0].Phase = phase
		execution.Resources[0].State = phase
		if err := validateExecutionResources(execution, true); err != nil {
			t.Fatal(phase, err)
		}
	}
	execution.Resources[0].Phase = "active"
	execution.Resources[0].State = "active"
	if validateExecutionResources(execution, false) == nil {
		t.Fatal("diagnostic process granted active route")
	}
	execution.Resources[0] = r
	copy := cloneExecutionResources(execution.Resources)
	copy[0].XrayDomainTCP.Domain.Services[0].Domains[0] = "changed.example"
	if execution.Resources[0].XrayDomainTCP.Domain.Services[0].Domains[0] == "changed.example" {
		t.Fatal("clone mutated retained intent")
	}
	data, err := json.Marshal(execution)
	var decoded Execution
	if err != nil || json.Unmarshal(data, &decoded) != nil || validateExecutionResources(decoded, false) != nil {
		t.Fatal("journal failed roundtrip", err)
	}
	execution.Resources[0].XraySelectedTCP = &ExecutionXraySelectedTCPDefinition{}
	if validateExecutionResources(execution, false) == nil {
		t.Fatal("mixed resource variants accepted")
	}
}

func TestXrayDomainTCPExecutionMissingOriginalOwnersRefuseBeforeEffects(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	m := &XrayDomainTCPOperationMaterial{}
	m.self = m
	if _, err := AcquireXrayDomainTCPExecutionResource(ctx, m); !errors.Is(err, ErrXrayDomainTCPOriginal) {
		t.Fatal("missing registrar accepted", err)
	}
	r := &XrayDomainTCPExecutionResource{}
	r.self = r
	if err := r.Current(ctx); !errors.Is(err, ErrXrayDomainTCPOriginal) {
		t.Fatal("reconstructed resource observed native child", err)
	}
	if _, err := AcquireXrayDomainTCPExecutionResource(context.Background(), m); !errors.Is(err, ErrXrayDomainTCPOriginal) {
		t.Fatal("unbounded context accepted", err)
	}
}
