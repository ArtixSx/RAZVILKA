package dnscontrol

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestServiceDNSComparisonIsBoundedAndNotServiceEvidence(t *testing.T) {
	m, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(m.Snapshot())
	calls := 0
	m.candidateExchange = func(_ context.Context, target dnsTarget, host string, family dnsmessage.Type) ([]netip.Addr, error) {
		calls++
		if host != "example.org" {
			t.Fatalf("wrong host %q", host)
		}
		if family == dnsmessage.TypeA {
			return []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("1.1.1.1")}, nil
		}
		return nil, nil
	}
	out, err := m.CompareServiceDNS(context.Background(), []string{"private", "xbox-dns", "malw"}, "example.org")
	if err != nil {
		t.Fatal(err)
	}
	if calls != 6 || len(out.Results) != 6 || out.ServiceVerified || out.RouteVerified || out.EligibleForApply {
		t.Fatalf("wrong proof or budget: %+v calls=%d", out, calls)
	}
	if out.ResolutionActor != "router" || out.RequestPath != "system-routing-unverified" || out.CheckedAt == "" {
		t.Fatal("missing limits", out)
	}
	for i, r := range out.Results {
		if r.Transport != "doh" {
			t.Fatal("fallback", r)
		}
		if i%2 == 0 {
			if r.Status != "resolved" || !reflect.DeepEqual(r.Addresses, []string{"1.1.1.1", "8.8.8.8"}) || r.AnswerFingerprint == "" {
				t.Fatal(r)
			}
		} else if r.Status != "no-address" {
			t.Fatal(r)
		}
	}
	after, _ := json.Marshal(m.Snapshot())
	if string(before) != string(after) {
		t.Fatal("diagnostic mutated state")
	}
}

func TestServiceDNSComparisonValidatesEntireBatchBeforeNetwork(t *testing.T) {
	cases := []struct {
		name string
		ids  []string
		host string
	}{
		{"empty", nil, "example.org"}, {"many", []string{"private", "malw", "comss", "xbox-dns"}, "example.org"},
		{"duplicate", []string{"private", "private"}, "example.org"}, {"unknown", []string{"private", "no-such-profile"}, "example.org"},
		{"system", []string{"automatic"}, "example.org"}, {"negative", []string{"private", "flashstart"}, "example.org"},
		{"unconfigured", []string{"private", "geohide"}, "example.org"}, {"account", []string{"controld-redirect"}, "example.org"},
		{"private-target", []string{"private"}, "127.0.0.1"}, {"url-not-host", []string{"private"}, "https://example.org/path"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, _ := New("")
			calls := 0
			m.candidateExchange = func(context.Context, dnsTarget, string, dnsmessage.Type) ([]netip.Addr, error) {
				calls++
				return nil, nil
			}
			_, err := m.CompareServiceDNS(context.Background(), c.ids, c.host)
			if err == nil || calls != 0 {
				t.Fatalf("err=%v calls=%d", err, calls)
			}
		})
	}
}

func TestServiceDNSComparisonRejectsUnsafeAndWrongFamily(t *testing.T) {
	for _, c := range []struct {
		name    string
		answers []netip.Addr
	}{
		{"mixed-private", []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("10.0.0.1")}},
		{"invalid", []netip.Addr{{}}}, {"wrong-family", []netip.Addr{netip.MustParseAddr("2606:4700:4700::1111")}},
		{"too-large", make([]netip.Addr, 65)},
	} {
		t.Run(c.name, func(t *testing.T) {
			m, _ := New("")
			m.candidateExchange = func(_ context.Context, _ dnsTarget, _ string, f dnsmessage.Type) ([]netip.Addr, error) {
				if f == dnsmessage.TypeA {
					return c.answers, nil
				}
				return nil, nil
			}
			out, err := m.CompareServiceDNS(context.Background(), []string{"private"}, "example.org")
			if err != nil {
				t.Fatal(err)
			}
			r := out.Results[0]
			if r.Status != "rejected" || len(r.Addresses) != 0 || r.AnswerFingerprint != "" || out.EligibleForApply {
				t.Fatal(out)
			}
		})
	}
}

func TestServiceDNSComparisonIntegrityAndCancellation(t *testing.T) {
	t.Run("integrity", func(t *testing.T) {
		m, _ := New("")
		m.candidateExchange = func(context.Context, dnsTarget, string, dnsmessage.Type) ([]netip.Addr, error) {
			return nil, errDNSAnswer
		}
		out, err := m.CompareServiceDNS(context.Background(), []string{"xbox-dns"}, "example.org")
		if err != nil || out.Results[0].ErrorCode != "DNS_INTEGRITY_FAILED" || out.ServiceVerified {
			t.Fatal(out, err)
		}
	})
	t.Run("cancel", func(t *testing.T) {
		m, _ := New("")
		ctx, cancel := context.WithCancel(context.Background())
		calls := 0
		m.candidateExchange = func(context.Context, dnsTarget, string, dnsmessage.Type) ([]netip.Addr, error) {
			calls++
			cancel()
			return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
		}
		out, err := m.CompareServiceDNS(ctx, []string{"private", "malw"}, "example.org")
		if !errors.Is(err, context.Canceled) || calls != 1 || out.CheckedAt != "" || out.EligibleForApply {
			t.Fatal(out, err, calls)
		}
	})
}

func TestSmartDNSRegistryCannotAuthorizeRegistrationOrAutomaticApply(t *testing.T) {
	m, _ := New("")
	calls := 0
	m.candidateExchange = func(context.Context, dnsTarget, string, dnsmessage.Type) ([]netip.Addr, error) {
		calls++
		return nil, nil
	}
	for _, p := range Providers() {
		if p.Kind != "smart-dns-gateway" {
			continue
		}
		if p.AllowedForUSQUE || p.AllowedForAutoPilot || p.ServiceHintsVerified || !p.Experimental {
			t.Fatal("unsafe template", p.ID)
		}
		_, err := m.ResolveCandidate(context.Background(), p.ID, "api.cloudflareclient.com")
		if err == nil {
			t.Fatal("registration allowed", p.ID)
		}
	}
	if calls != 0 {
		t.Fatal("registration performed DNS requests")
	}
	for _, id := range []string{"geohide", "controld-redirect"} {
		p, _ := providerByIDFor(id, m.doc)
		if p.Configured || p.DoH != "" || len(p.Endpoints) > 0 {
			t.Fatal("guessed endpoint", id)
		}
	}
}
