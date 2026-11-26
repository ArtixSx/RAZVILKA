package dataplane

import (
	"context"
	"net"
	"testing"
)

func TestDomainTCPSyntheticBaselineRequiresOriginalWitnessBeyondCallbacks(t *testing.T) {
	_, p, spec, owner := syntheticTCPModelFixture(t)
	socket := syntheticTCPModelSocket(spec, owner.lease.mapping, 443)
	flow := DomainPolicyTCPFlow{Generation: p.generation, FlowID: "model-only", Source: socket.Source, Destination: socket.OriginalDestination, Client: spec.Client, synthetic: &domainPolicyTCPSyntheticBinding{mapping: owner.lease.mapping, socket: socket, spec: spec.Xray}}
	runtime := DomainPolicyTCPRuntime{BaselineDial: func(context.Context, DomainPolicyTCPFlow, DomainPolicyDecision) (net.Conn, error) {
		t.Fatal("comparison invoked dial callback")
		return nil, nil
	}}
	question := DomainPolicyFlow{Client: flow.Client, Destination: flow.synthetic.mapping.RealIP, Protocol: "tcp", Name: "different.example.com", NameState: DomainPolicyNameVisible, NameSource: "tls-sni", BeforeOutbound: true}
	// Even with a pointer claiming self identity, no capture/native owner exists.
	runtime.originalBaseline = &domainTCPBaselineKernelOwner{}
	runtime.originalBaseline.self = runtime.originalBaseline
	if _, err := p.decideTCPWithBaseline(context.Background(), flow, question, p.scope, runtime); err == nil {
		t.Fatal("callback and empty original witness granted synthetic baseline")
	}
	question.Name = spec.Xray.Name
	runtime.originalBaseline = nil
	d, err := p.decideTCPWithBaseline(context.Background(), flow, question, p.scope, runtime)
	if err != nil || !flow.synthetic.acceptsDecision(d) {
		t.Fatalf("unchanged positive exact route lost: %+v %v", d, err)
	}
	// Coalescing cannot turn a shared numeric address into a name grant.
	question.Coalesced = true
	runtime.originalBaseline = &domainTCPBaselineKernelOwner{}
	runtime.originalBaseline.self = runtime.originalBaseline
	if _, err := p.decideTCPWithBaseline(context.Background(), flow, question, p.scope, runtime); err == nil {
		t.Fatal("coalesced synthetic flow got unproven baseline")
	}

}
