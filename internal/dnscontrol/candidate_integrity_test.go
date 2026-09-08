package dnscontrol

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestCandidateDNSResponseIntegrity(t *testing.T) {
	name := dnsmessage.MustNewName("api.cloudflareclient.com.")
	alias := dnsmessage.MustNewName("edge.cloudflare.com.")
	query, err := buildDNSQueryFor(7, name.String(), dnsmessage.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	address := func(owner dnsmessage.Name) dnsmessage.Resource {
		return dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: owner, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}, Body: &dnsmessage.AResource{A: [4]byte{104, 16, 1, 2}}}
	}
	cname := func(owner, target dnsmessage.Name) dnsmessage.Resource {
		return dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: owner, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET}, Body: &dnsmessage.CNAMEResource{CNAME: target}}
	}
	for _, test := range []struct {
		name   string
		valid  bool
		mutate func(*dnsmessage.Message)
	}{
		{"direct", true, func(*dnsmessage.Message) {}},
		{"alias", true, func(m *dnsmessage.Message) { m.Answers = []dnsmessage.Resource{cname(name, alias), address(alias)} }},
		{"unrelated-address", false, func(m *dnsmessage.Message) { m.Answers = []dnsmessage.Resource{address(alias)} }},
		{"wrong-question", false, func(m *dnsmessage.Message) { m.Questions[0].Name = alias }},
		{"truncated", false, func(m *dnsmessage.Message) { m.Truncated = true }},
		{"wrong-id", false, func(m *dnsmessage.Message) { m.ID++ }},
		{"wrong-class", false, func(m *dnsmessage.Message) { m.Answers[0].Header.Class = dnsmessage.ClassCHAOS }},
		{"alias-loop", false, func(m *dnsmessage.Message) {
			m.Answers = []dnsmessage.Resource{cname(name, alias), cname(alias, name), address(name)}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			message := dnsmessage.Message{Header: dnsmessage.Header{ID: 7, Response: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}, Answers: []dnsmessage.Resource{address(name)}}
			test.mutate(&message)
			response, err := message.Pack()
			if err != nil {
				t.Fatal(err)
			}
			addresses, _, err := validateDNSAddressResponse(query, response)
			if test.valid && (err != nil || len(addresses) != 1) {
				t.Fatalf("addresses=%v err=%v", addresses, err)
			}
			if !test.valid && !errors.Is(err, errDNSAnswer) {
				t.Fatalf("invalid answer accepted: %v", err)
			}
		})
	}
}

func TestCandidateDNSRejectsIntegrityFailureInOtherFamily(t *testing.T) {
	m, _ := New("")
	m.candidateExchange = func(_ context.Context, _ dnsTarget, _ string, family dnsmessage.Type) ([]netip.Addr, error) {
		if family == dnsmessage.TypeAAAA {
			return nil, errDNSAnswer
		}
		return []netip.Addr{netip.MustParseAddr("104.16.1.2")}, nil
	}
	result, err := m.ResolveCandidate(context.Background(), "private", "api.cloudflareclient.com")
	if err != nil || result.Ready {
		t.Fatalf("invalid second family hidden by IPv4 success: %+v %v", result, err)
	}
}

func TestCandidateDNSCancellationDoesNotReturnSuccess(t *testing.T) {
	m, _ := New("")
	ctx, cancel := context.WithCancel(context.Background())
	var calls atomic.Int32
	m.candidateExchange = func(context.Context, dnsTarget, string, dnsmessage.Type) ([]netip.Addr, error) {
		calls.Add(1)
		cancel()
		return []netip.Addr{netip.MustParseAddr("104.16.1.2")}, nil
	}
	result, err := m.ResolveCandidate(ctx, "private", "api.cloudflareclient.com")
	if !errors.Is(err, context.Canceled) || result.Ready {
		t.Fatalf("cancellation accepted: %+v %v", result, err)
	}
	before := calls.Load()
	_, err = m.ResolveCandidate(ctx, "private", "api.cloudflareclient.com")
	if !errors.Is(err, context.Canceled) || calls.Load() != before {
		t.Fatal("canceled request performed DNS exchange")
	}
}
