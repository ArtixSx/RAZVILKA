package dnscontrol

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestNetworkPolicyDNSFrozenDefinitionRejectsChangedReview(t *testing.T) {
	m, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	m.doc.NextDNSProfileID = "abcdef"
	client := netip.MustParseAddr("192.168.1.42")
	input := []ClientDNSBinding{{Client: client, Domain: "service.example.com", ProfileID: "nextdns"}}
	generation := strings.Repeat("a", 64)
	p, err := m.FreezeNetworkPolicyDNSPlan(generation, "private", input)
	if err != nil {
		t.Fatal(err)
	}
	input[0].Domain = "edited.example.com"
	copy := CloneNetworkPolicyDNSPlan(p)
	copy.Bindings[0].ProfileDigest = strings.Repeat("b", 64)
	if p.Bindings[0].Domain != "service.example.com" || copy.Bindings[0].ProfileDigest == p.Bindings[0].ProfileDigest || ValidateNetworkPolicyDNSPlan(copy) == nil {
		t.Fatal("mutable or unsealed reviewed DNS definition")
	}
	authority := NetworkPolicyDNSAuthority{Generation: generation, ControlEpoch: 1, BindingRevision: 2}
	guard := func(ctx context.Context) error { return ctx.Err() }
	admit := func(context.Context, netip.Addr, string) (NetworkPolicyDNSAdmission, error) {
		return NetworkPolicyDNSAdmission{Authority: authority, Ingress: "br0", Kind: "managed"}, nil
	}
	if _, err := m.NewNetworkPolicyDNSResolverForPlan(p, authority, guard, admit); err != nil {
		t.Fatal("unchanged reviewed provider refused", err)
	}
	if err := m.CheckNetworkPolicyDNSPlan(p); err != nil {
		t.Fatal("read-only stage check refused frozen provider", err)
	}
	m.doc.NextDNSProfileID = "123456"
	if err := m.CheckNetworkPolicyDNSPlan(p); !errors.Is(err, ErrServiceDNSChanged) {
		t.Fatal("stage check lost reviewed identity", err)
	}
	if _, err := m.NewNetworkPolicyDNSResolverForPlan(p, authority, guard, admit); !errors.Is(err, ErrServiceDNSChanged) {
		t.Fatal("new production profile silently replaced reviewed provider", err)
	}
	authority.Generation = strings.Repeat("c", 64)
	if _, err := m.NewNetworkPolicyDNSResolverForPlan(p, authority, guard, admit); !errors.Is(err, ErrNetworkPolicyDNS) {
		t.Fatal("cross-generation DNS admitted", err)
	}
}

func TestNetworkPolicyDNSFrozenDefaultAndBindingBounds(t *testing.T) {
	m, _ := New("")
	m.doc.NextDNSProfileID = "abcdef"
	generation := strings.Repeat("a", 64)
	p, err := m.FreezeNetworkPolicyDNSPlan(generation, "nextdns", nil)
	if err != nil {
		t.Fatal(err)
	}
	m.doc.NextDNSProfileID = "123456"
	err = m.CheckNetworkPolicyDNSPlan(p)
	if !errors.Is(err, ErrServiceDNSChanged) {
		t.Fatal("default DNS identity not frozen", err)
	}
	valid := ClientDNSBinding{Client: netip.MustParseAddr("192.168.1.42"), Domain: "service.example.com", ProfileID: "private"}
	for _, bindings := range [][]ClientDNSBinding{{valid, valid}, {{Client: valid.Client, Domain: "93.184.215.14", ProfileID: "private"}}, {{Client: valid.Client, Domain: "Service.example.com", ProfileID: "private"}}, make([]ClientDNSBinding, 129)} {
		if _, err := m.FreezeNetworkPolicyDNSPlan(generation, "private", bindings); err == nil {
			t.Fatal("invalid frozen bindings accepted", bindings)
		}
	}
}
