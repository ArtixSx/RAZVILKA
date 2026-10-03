package dnscontrol

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func endpointDNSFixture(t *testing.T) (*EndpointDNSResolver, *time.Time) {
	t.Helper()
	m, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	r, err := m.NewEndpointDNSResolver("private", func(ctx context.Context) error { return ctx.Err() })
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	r.now = func() time.Time { return now }
	r.target.detailedDoH = func(_ context.Context, _ string, q []byte, _ bool) (dohResponse, error) {
		return dohResponse{wire: scopedPack(t, endpointDNSReply(t, q, 30, 120))}, nil
	}
	return r, &now
}

func endpointDNSReply(t *testing.T, query []byte, aliasTTL, addressTTL uint32) dnsmessage.Message {
	t.Helper()
	m := scopedResponse(t, query)
	rr := m.Answers[0]
	rr.Header.Name, rr.Header.TTL = dnsmessage.MustNewName("target.example."), addressTTL
	m.Answers = []dnsmessage.Resource{
		{Header: dnsmessage.ResourceHeader{Name: m.Questions[0].Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: aliasTTL}, Body: &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("target.example.")}},
		rr,
	}
	return m
}

func TestEndpointDNSUsesCompleteAnswerExpiryAgeAndQueryLatency(t *testing.T) {
	r, now := endpointDNSFixture(t)
	start, calls := *now, 0
	r.target.detailedDoH = func(ctx context.Context, endpoint string, q []byte, local bool) (dohResponse, error) {
		calls++
		if endpoint != r.provider.DoH || local || ctx.Err() != nil {
			t.Fatal("resolver identity or context changed")
		}
		m := endpointDNSReply(t, q, 30, 120)
		if m.Questions[0].Type == dnsmessage.TypeA {
			*now = now.Add(1500 * time.Millisecond)
			return dohResponse{wire: scopedPack(t, m), age: 10}, nil
		}
		*now = now.Add(time.Second)
		return dohResponse{wire: scopedPack(t, m), age: 15}, nil
	}
	addresses, expiry, err := r.Resolve(context.Background(), "VPN.Example.COM.")
	if err != nil || calls != 2 || len(addresses) != 2 || !expiry.Equal(start.Add(16500*time.Millisecond)) {
		t.Fatal(addresses, expiry, err, calls)
	}
	addresses[0] = netip.MustParseAddr("127.0.0.1")
	if next, _, err := r.Resolve(context.Background(), "vpn.example.com"); err != nil || len(next) != 2 || next[0].IsLoopback() || calls != 4 {
		t.Fatal("result was cached or aliased", next, err, calls)
	}
}

func TestEndpointDNSZeroUnknownAndNegativeTTL(t *testing.T) {
	for _, kind := range []string{"zero alias", "high TTL bit", "consumed HTTP age", "nodata no SOA", "nodata with SOA"} {
		t.Run(kind, func(t *testing.T) {
			r, now := endpointDNSFixture(t)
			start := *now
			r.target.detailedDoH = func(_ context.Context, _ string, q []byte, _ bool) (dohResponse, error) {
				m := endpointDNSReply(t, q, 30, 120)
				var age uint64
				switch kind {
				case "zero alias":
					m.Answers[0].Header.TTL = 0
				case "high TTL bit":
					m.Answers[1].Header.TTL = 0x80000000
				case "consumed HTTP age":
					age = 30
				case "nodata no SOA", "nodata with SOA":
					if m.Questions[0].Type == dnsmessage.TypeAAAA {
						m.Answers = m.Answers[:1]
						if kind == "nodata with SOA" {
							m.Authorities = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("example."), Type: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET, TTL: 15}, Body: &dnsmessage.SOAResource{NS: dnsmessage.MustNewName("ns.example."), MBox: dnsmessage.MustNewName("admin.example."), MinTTL: 10}}}
							age = 3
						}
					}
				}
				return dohResponse{wire: scopedPack(t, m), age: age}, nil
			}
			addresses, expiry, err := r.Resolve(context.Background(), "vpn.example.com")
			if err != nil || len(addresses) == 0 {
				t.Fatal(addresses, expiry, err)
			}
			if kind == "nodata with SOA" {
				if len(addresses) != 1 || !expiry.Equal(start.Add(7*time.Second)) {
					t.Fatal("negative family did not bound the complete lease", expiry)
				}
			} else if !expiry.IsZero() {
				t.Fatal("noncacheable answer acquired a lease", expiry)
			}
		})
	}
}

func TestEndpointDNSRejectsIncompleteUnsafeAndExpiredAnswers(t *testing.T) {
	for _, kind := range []string{"AAAA timeout", "wrong ID", "truncated", "changed CD", "changed RD", "extended RCODE", "EDNS version", "duplicate OPT", "private answer", "private glue", "private authority", "wrong class glue", "CNAME loop", "CNAME mismatch", "local alias", "NXDOMAIN conflict", "empty both", "oversized both", "trailing wire", "too many records", "expiry during query", "backward clock"} {
		t.Run(kind, func(t *testing.T) {
			r, now := endpointDNSFixture(t)
			r.target.detailedDoH = func(_ context.Context, _ string, q []byte, _ bool) (dohResponse, error) {
				m := endpointDNSReply(t, q, 30, 120)
				aaaa := m.Questions[0].Type == dnsmessage.TypeAAAA
				private := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("glue.example."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 120}, Body: &dnsmessage.AResource{A: [4]byte{10, 0, 0, 1}}}
				switch kind {
				case "AAAA timeout":
					if aaaa {
						return dohResponse{}, context.DeadlineExceeded
					}
				case "wrong ID":
					m.ID++
				case "truncated":
					m.Truncated = true
				case "changed CD":
					m.CheckingDisabled = true
				case "changed RD":
					m.RecursionDesired = false
				case "extended RCODE":
					m.Additionals[0].Header.TTL |= 1 << 24
				case "EDNS version":
					m.Additionals[0].Header.TTL |= 1 << 16
				case "duplicate OPT":
					m.Additionals = append(m.Additionals, m.Additionals[0])
				case "private answer":
					if !aaaa {
						m.Answers[1].Body = private.Body
					}
				case "private glue":
					m.Additionals = append(m.Additionals, private)
				case "private authority":
					m.Authorities = []dnsmessage.Resource{private}
				case "wrong class glue":
					private.Header.Class = 3
					private.Body = &dnsmessage.AResource{A: [4]byte{1, 1, 1, 1}}
					m.Additionals = append(m.Additionals, private)
				case "CNAME loop":
					m.Answers[0].Body = &dnsmessage.CNAMEResource{CNAME: m.Questions[0].Name}
				case "CNAME mismatch", "local alias":
					if aaaa || kind == "local alias" {
						alias := "other.example."
						if kind == "local alias" {
							alias = "router.local."
						}
						m.Answers[0].Body = &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(alias)}
						m.Answers[1].Header.Name = dnsmessage.MustNewName(alias)
					}
				case "NXDOMAIN conflict":
					if aaaa {
						m.Answers, m.RCode = nil, dnsmessage.RCodeNameError
					}
				case "empty both":
					m.Answers = m.Answers[:1]
				case "oversized both":
					for i := 1; i < 17; i++ {
						m.Answers = append(m.Answers, m.Answers[1])
					}
				case "too many records":
					for i := 0; i < 257; i++ {
						m.Additionals = append(m.Additionals, m.Answers[1])
					}
				case "expiry during query":
					*now = now.Add(30 * time.Second)
				case "backward clock":
					*now = now.Add(-time.Second)
				}
				wire := scopedPack(t, m)
				if kind == "trailing wire" {
					wire = append(wire, 0)
				}
				return dohResponse{wire: wire}, nil
			}
			addresses, expiry, err := r.Resolve(context.Background(), "vpn.example.com")
			if err == nil || len(addresses) != 0 || !expiry.IsZero() {
				t.Fatal("unsafe or incomplete result published", addresses, expiry, err)
			}
		})
	}
}

func TestEndpointDNSFencesProviderEpochCancellationAndHost(t *testing.T) {
	for _, kind := range []string{"provider changed", "epoch before", "epoch after", "canceled before", "canceled after"} {
		t.Run(kind, func(t *testing.T) {
			r, _ := endpointDNSFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			r.target.detailedDoH = func(_ context.Context, _ string, q []byte, _ bool) (dohResponse, error) {
				calls++
				if kind == "provider changed" {
					r.provider.DoH = "https://changed.example/dns-query"
				}
				if kind == "epoch after" {
					r.guard = func(context.Context) error { return ErrServiceDNSChanged }
				}
				if kind == "canceled after" {
					cancel()
				}
				return dohResponse{wire: scopedPack(t, endpointDNSReply(t, q, 30, 120))}, nil
			}
			if kind == "epoch before" {
				r.guard = func(context.Context) error { return ErrServiceDNSChanged }
			}
			if kind == "canceled before" {
				cancel()
			}
			addresses, expiry, err := r.Resolve(ctx, "vpn.example.com")
			if err == nil || len(addresses) != 0 || !expiry.IsZero() || calls > 1 {
				t.Fatal(addresses, expiry, err, calls)
			}
		})
	}
	r, _ := endpointDNSFixture(t)
	calls := 0
	r.target.detailedDoH = func(context.Context, string, []byte, bool) (dohResponse, error) {
		calls++
		return dohResponse{}, errors.New("unexpected query")
	}
	for _, host := range []string{"home.arpa", "router.local", "localhost", "1.1.1.1", "vpn.example.com/path", strings.Repeat("a", 64) + ".example.com"} {
		if _, _, err := r.Resolve(context.Background(), host); err == nil {
			t.Fatal("invalid host accepted", host)
		}
	}
	if calls != 0 {
		t.Fatal("invalid host reached DoH")
	}
	if _, err := r.manager.NewEndpointDNSResolver("private", nil); err == nil {
		t.Fatal("missing epoch guard accepted")
	}
	if _, err := r.manager.NewEndpointDNSResolver("unknown", r.guard); err == nil {
		t.Fatal("unknown profile accepted")
	}
}

func TestEndpointDNSProductionFactoryAndActualProviderChange(t *testing.T) {
	m, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	guard := func(ctx context.Context) error { return ctx.Err() }
	for _, profile := range []string{"automatic", "nextdns", "xbox-dns", "custom", "geohide", "controld-redirect"} {
		if _, err := m.NewEndpointDNSResolver(profile, guard); err == nil {
			t.Fatal("unconfigured, experimental or non-DoH provider accepted", profile)
		}
	}
	if err := m.SetCustomProvider(CustomProviderInput{Name: "Fixture", DoH: "https://resolver.example/dns-query"}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.NewEndpointDNSResolver("custom", guard); err == nil {
		t.Fatal("configured custom provider was promoted to production")
	}
	if err := m.SetNextDNSProfileID("abc123"); err != nil {
		t.Fatal(err)
	}
	r, err := m.NewEndpointDNSResolver("nextdns", guard)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	r.target.detailedDoH = func(_ context.Context, _ string, q []byte, _ bool) (dohResponse, error) {
		calls++
		return dohResponse{wire: scopedPack(t, endpointDNSReply(t, q, 30, 120))}, nil
	}
	if _, _, err := r.Resolve(context.Background(), "vpn.example.com"); err != nil || calls != 2 {
		t.Fatal("configured production provider unavailable", err, calls)
	}
	if err := m.SetNextDNSProfileID("def456"); err != nil {
		t.Fatal(err)
	}
	if addresses, _, err := r.Resolve(context.Background(), "vpn.example.com"); !errors.Is(err, ErrServiceDNSChanged) || addresses != nil || calls != 2 {
		t.Fatal("actual provider change was not fenced", addresses, err, calls)
	}
}
