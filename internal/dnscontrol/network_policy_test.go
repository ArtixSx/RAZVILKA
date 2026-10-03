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

func networkDNSFixture(t *testing.T) (*NetworkPolicyDNSResolver, netip.Addr) {
	t.Helper()
	m, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	client := netip.MustParseAddr("127.0.0.1")
	authority := NetworkPolicyDNSAuthority{Generation: strings.Repeat("a", 64), ControlEpoch: 1, BindingRevision: 2}
	r, err := m.NewNetworkPolicyDNSResolver("private", []ClientDNSBinding{{Client: client, Domain: "service.example.com", ProfileID: "private"}}, authority, func(ctx context.Context) error { return ctx.Err() }, func(_ context.Context, _ netip.Addr, _ string) (NetworkPolicyDNSAdmission, error) {
		return NetworkPolicyDNSAdmission{Authority: authority, Ingress: "br0", DeviceID: "selected", Kind: "managed"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	r.now = func() time.Time { return now }
	r.service.cache.now = r.now
	return r, client
}

func networkDefaultExchange(r *NetworkPolicyDNSResolver, fn func(context.Context, []byte) (dohResponse, error)) {
	r.choice.target.detailedDoH = func(ctx context.Context, _ string, q []byte, _ bool) (dohResponse, error) { return fn(ctx, q) }
}

func TestNetworkPolicyDNSServiceMatchNoMatchAndRefused(t *testing.T) {
	r, client := networkDNSFixture(t)
	service, defaults := 0, 0
	scopedExchange(r.service, scopedDNSKey{client, "service.example.com"}, func(_ context.Context, q []byte) (dohResponse, error) {
		service++
		return dohResponse{wire: scopedPack(t, scopedResponse(t, q))}, nil
	})
	networkDefaultExchange(r, func(_ context.Context, q []byte) (dohResponse, error) {
		defaults++
		var request dnsmessage.Message
		_ = request.Unpack(q)
		answer := scopedResponse(t, q)
		if request.Questions[0].Type == dnsmessage.TypeTXT {
			answer.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: request.Questions[0].Name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 120}, Body: &dnsmessage.TXTResource{TXT: []string{"default answer"}}}}
		}
		return dohResponse{wire: scopedPack(t, answer)}, nil
	})
	if _, err := r.Resolve(context.Background(), client, scopedQuery(t, "service.example.com", dnsmessage.TypeA)); err != nil {
		t.Fatal(err)
	}
	for _, typ := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA, dnsmessage.TypeTXT} {
		if _, err := r.Resolve(context.Background(), client, scopedQuery(t, "unknown.example.com", typ)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.Resolve(context.Background(), client, scopedQuery(t, "service.example.com", dnsmessage.TypeTXT)); !errors.Is(err, ErrScopedDNS) {
		t.Fatal("matched unsupported type silently defaulted", err)
	}
	if service != 1 || defaults != 3 {
		t.Fatal(service, defaults)
	}
	failure := errors.New("provider failed")
	scopedExchange(r.service, scopedDNSKey{client, "service.example.com"}, func(context.Context, []byte) (dohResponse, error) { return dohResponse{}, failure })
	if _, err := r.Resolve(context.Background(), client, scopedQuery(t, "service.example.com", dnsmessage.TypeA)); !errors.Is(err, failure) || defaults != 3 {
		t.Fatal("service failure became NoMatch", err, defaults)
	}
}

func TestNetworkPolicyDNSExcludedAndChangedBindingCannotUseCacheOrPublish(t *testing.T) {
	r, client := networkDNSFixture(t)
	key := scopedDNSKey{client, "service.example.com"}
	calls := 0
	scopedExchange(r.service, key, func(_ context.Context, q []byte) (dohResponse, error) {
		calls++
		return dohResponse{wire: scopedPack(t, scopedResponse(t, q))}, nil
	})
	q := scopedQuery(t, key.host, dnsmessage.TypeA)
	if _, err := r.Resolve(context.Background(), client, q); err != nil {
		t.Fatal(err)
	}
	r.admit = func(context.Context, netip.Addr, string) (NetworkPolicyDNSAdmission, error) {
		return NetworkPolicyDNSAdmission{Authority: r.authority, Ingress: "br0", Kind: "outside"}, nil
	}
	if wire, err := r.Resolve(context.Background(), client, q); !errors.Is(err, ErrNetworkPolicyDNSOutside) || wire != nil || calls != 1 {
		t.Fatal("excluded client served old cache", err, calls)
	}
	published := false
	if err := r.Publish(context.Background(), client, q, func(context.Context, NetworkPolicyDNSAdmission, []byte) error { published = true; return nil }); !errors.Is(err, ErrNetworkPolicyDNSOutside) || published {
		t.Fatal(err, published)
	}
	if observations, err := r.Observations(context.Background()); err != nil || len(observations) != 0 {
		t.Fatal(observations, err)
	}
	r.admit = func(context.Context, netip.Addr, string) (NetworkPolicyDNSAdmission, error) {
		a := r.authority
		a.BindingRevision++
		return NetworkPolicyDNSAdmission{Authority: a, Ingress: "br0", Kind: "managed"}, nil
	}
	if _, err := r.Resolve(context.Background(), client, q); !errors.Is(err, ErrNetworkPolicyDNS) {
		t.Fatal(err)
	}
}

func TestNetworkPolicyDNSDefaultAgeIntegrityAndFinalGuard(t *testing.T) {
	r, client := networkDNSFixture(t)
	now := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	r.now = func() time.Time { return now }
	networkDefaultExchange(r, func(_ context.Context, q []byte) (dohResponse, error) {
		now = now.Add(time.Second)
		return dohResponse{wire: scopedPack(t, scopedResponse(t, q)), age: 3}, nil
	})
	q := scopedQuery(t, "unknown.example.com", dnsmessage.TypeA)
	wire, err := r.Resolve(context.Background(), client, q)
	if err != nil {
		t.Fatal(err)
	}
	var answer dnsmessage.Message
	_ = answer.Unpack(wire)
	if answer.Answers[0].Header.TTL != 116 {
		t.Fatal("age/residence renewed", answer.Answers[0].Header.TTL)
	}
	for name, mutate := range map[string]func(*dnsmessage.Message){"wrong ID": func(a *dnsmessage.Message) { a.ID++ }, "wrong CD": func(a *dnsmessage.Message) { a.CheckingDisabled = !a.CheckingDisabled }, "question changed": func(a *dnsmessage.Message) { a.Questions[0].Name = dnsmessage.MustNewName("other.example.com.") }} {
		t.Run(name, func(t *testing.T) {
			networkDefaultExchange(r, func(_ context.Context, q []byte) (dohResponse, error) {
				a := scopedResponse(t, q)
				mutate(&a)
				return dohResponse{wire: scopedPack(t, a)}, nil
			})
			if wire, err := r.Resolve(context.Background(), client, q); err == nil || wire != nil {
				t.Fatal("invalid default answer served")
			}
		})
	}
	networkDefaultExchange(r, func(_ context.Context, q []byte) (dohResponse, error) {
		r.admit = func(context.Context, netip.Addr, string) (NetworkPolicyDNSAdmission, error) {
			return NetworkPolicyDNSAdmission{Authority: r.authority, Ingress: "br0", Kind: "outside"}, nil
		}
		return dohResponse{wire: scopedPack(t, scopedResponse(t, q))}, nil
	})
	if wire, err := r.Resolve(context.Background(), client, q); !errors.Is(err, ErrNetworkPolicyDNSOutside) || wire != nil {
		t.Fatal("binding changed before reply accepted", err)
	}
}

func TestNetworkPolicyDNSSharedCDNObservationsAreSeparateDiagnostics(t *testing.T) {
	r, client := networkDNSFixture(t)
	other := scopedDNSKey{client, "other.example.com"}
	r.service.choices[other] = r.service.choices[scopedDNSKey{client, "service.example.com"}]
	for _, key := range []scopedDNSKey{{client, "service.example.com"}, other} {
		scopedExchange(r.service, key, func(_ context.Context, q []byte) (dohResponse, error) {
			return dohResponse{wire: scopedPack(t, scopedResponse(t, q))}, nil
		})
	}
	for _, host := range []string{"service.example.com", "other.example.com"} {
		if _, err := r.Resolve(context.Background(), client, scopedQuery(t, host, dnsmessage.TypeA)); err != nil {
			t.Fatal(err)
		}
	}
	observations, err := r.Observations(context.Background())
	if err != nil || len(observations) != 2 || observations[0].ObservationID == observations[1].ObservationID || observations[0].Details.Addresses[0] != observations[1].Details.Addresses[0] {
		t.Fatal(observations, err)
	}
	observations[0].Details.Addresses[0] = netip.MustParseAddr("8.8.8.8")
	fresh, _ := r.Observations(context.Background())
	if fresh[0].Details.Addresses[0].String() == "8.8.8.8" {
		t.Fatal("caller edited existing ledger")
	}
}

func TestNetworkPolicyDNSCNAMEAgeAndPublicationUseExistingMinimumLease(t *testing.T) {
	r, client := networkDNSFixture(t)
	start := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	now := start
	r.now = func() time.Time { return now }
	r.service.cache.now = r.now
	key := scopedDNSKey{client, "service.example.com"}
	scopedExchange(r.service, key, func(_ context.Context, q []byte) (dohResponse, error) {
		a := scopedResponse(t, q)
		terminal := dnsmessage.MustNewName("cdn.example.com.")
		a.Answers[0].Header.Name = terminal
		a.Answers[0].Header.TTL = 300
		cname := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: a.Questions[0].Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 5}, Body: &dnsmessage.CNAMEResource{CNAME: terminal}}
		a.Answers = append([]dnsmessage.Resource{cname}, a.Answers...)
		now = now.Add(time.Second)
		return dohResponse{wire: scopedPack(t, a), age: 3}, nil
	})
	var answer dnsmessage.Message
	if err := r.Publish(context.Background(), client, scopedQuery(t, key.host, dnsmessage.TypeA), func(_ context.Context, _ NetworkPolicyDNSAdmission, wire []byte) error { return answer.Unpack(wire) }); err != nil {
		t.Fatal(err)
	}
	if answer.Answers[0].Header.TTL != 1 {
		t.Fatal("CNAME minimum extended through publication", answer.Answers[0].Header.TTL)
	}
	observations, err := r.Observations(context.Background())
	if err != nil || len(observations) != 1 || len(observations[0].Details.CNAMEChain) != 1 || observations[0].Details.CNAMEChain[0] != "cdn.example.com" || !observations[0].ExpiresAt.Equal(start.Add(2*time.Second)) {
		t.Fatal(observations, err)
	}
}
