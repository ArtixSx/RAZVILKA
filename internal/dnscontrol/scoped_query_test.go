package dnscontrol

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func scopedFixture(t *testing.T) (*ScopedDNSResolver, scopedDNSKey) {
	t.Helper()
	m, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	client := netip.MustParseAddr("127.0.0.1")
	r, err := m.NewScopedDNSResolver([]ClientDNSBinding{{client, "example.com", "private"}}, func(ctx context.Context) error { return ctx.Err() })
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	r.cache.now = func() time.Time { return now }
	return r, scopedDNSKey{client, "example.com"}
}

func scopedQuery(t *testing.T, host string, typ dnsmessage.Type) []byte {
	t.Helper()
	name, err := dnsmessage.NewName(host + ".")
	if err != nil {
		t.Fatal(err)
	}
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: 41, RecursionDesired: true, CheckingDisabled: true}, Questions: []dnsmessage.Question{{Name: name, Type: typ, Class: dnsmessage.ClassINET}}, Additionals: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeOPT, Class: 1232, TTL: 0x8000}, Body: &dnsmessage.OPTResource{}}}}
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func scopedResponse(t *testing.T, query []byte) dnsmessage.Message {
	t.Helper()
	var m dnsmessage.Message
	if err := m.Unpack(query); err != nil {
		t.Fatal(err)
	}
	m.Response = true
	m.RecursionAvailable = true
	m.AuthenticData = true
	rr := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: m.Questions[0].Name, Type: m.Questions[0].Type, Class: dnsmessage.ClassINET, TTL: 120}}
	if m.Questions[0].Type == dnsmessage.TypeAAAA {
		rr.Body = &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2606:4700::1111").As16()}
	} else {
		rr.Body = &dnsmessage.AResource{A: [4]byte{93, 184, 215, 14}}
	}
	m.Answers = []dnsmessage.Resource{rr}
	return m
}

func scopedPack(t *testing.T, m dnsmessage.Message) []byte {
	t.Helper()
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func scopedExchange(r *ScopedDNSResolver, key scopedDNSKey, fn func(context.Context, []byte) (dohResponse, error)) {
	r.cache.clear() // this helper replaces the test's upstream identity
	choice := r.choices[key]
	choice.target.detailedDoH = func(ctx context.Context, _ string, q []byte, _ bool) (dohResponse, error) { return fn(ctx, q) }
	r.choices[key] = choice
}

func TestScopedDNSExactClientAndDomainAndStrictQuestion(t *testing.T) {
	r, key := scopedFixture(t)
	calls := 0
	scopedExchange(r, key, func(_ context.Context, q []byte) (dohResponse, error) {
		calls++
		return dohResponse{wire: scopedPack(t, scopedResponse(t, q))}, nil
	})
	for _, typ := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		q := scopedQuery(t, "EXAMPLE.com", typ)
		if _, err := r.Resolve(context.Background(), key.client, q); err != nil {
			t.Fatal(err)
		}
	}
	before := calls
	for _, host := range []string{"sub.example.com", "example.com.evil.org", "other.example", "api.cloudflareclient.com"} {
		if _, err := r.Resolve(context.Background(), key.client, scopedQuery(t, host, dnsmessage.TypeA)); !errors.Is(err, ErrScopedDNS) {
			t.Fatal(host, err)
		}
	}
	q := scopedQuery(t, "example.com", dnsmessage.TypeA)
	if _, err := r.Resolve(context.Background(), netip.MustParseAddr("127.0.0.2"), q); !errors.Is(err, ErrScopedDNS) {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*dnsmessage.Message){
		"type":          func(m *dnsmessage.Message) { m.Questions[0].Type = dnsmessage.TypeTXT },
		"class":         func(m *dnsmessage.Message) { m.Questions[0].Class = 3 },
		"two questions": func(m *dnsmessage.Message) { m.Questions = append(m.Questions, m.Questions[0]) },
		"answer":        func(m *dnsmessage.Message) { m.Response = true },
		"nonrecursive":  func(m *dnsmessage.Message) { m.RecursionDesired = false },
		"ECS": func(m *dnsmessage.Message) {
			m.Additionals[0].Body = &dnsmessage.OPTResource{Options: []dnsmessage.Option{{Code: 8, Data: []byte{1, 2}}}}
		},
		"EDNS version": func(m *dnsmessage.Message) { m.Additionals[0].Header.TTL |= 1 << 16 },
	} {
		t.Run(name, func(t *testing.T) {
			var m dnsmessage.Message
			_ = m.Unpack(q)
			change(&m)
			if _, err := r.Resolve(context.Background(), key.client, scopedPack(t, m)); !errors.Is(err, ErrScopedDNS) {
				t.Fatal(err)
			}
		})
	}
	for _, bad := range [][]byte{append(append([]byte(nil), q...), 0), make([]byte, 4097), q[:11]} {
		if _, err := r.Resolve(context.Background(), key.client, bad); !errors.Is(err, ErrScopedDNS) {
			t.Fatal(err)
		}
	}
	if calls != before {
		t.Fatal("denied query reached upstream", calls, before)
	}
}

func TestScopedDNSNoFallbackAndEpochProviderFencing(t *testing.T) {
	r, key := scopedFixture(t)
	q := scopedQuery(t, "example.com", dnsmessage.TypeA)
	failure := errors.New("upstream down")
	calls := 0
	scopedExchange(r, key, func(context.Context, []byte) (dohResponse, error) { calls++; return dohResponse{}, failure })
	if _, err := r.Resolve(context.Background(), key.client, q); !errors.Is(err, failure) || calls != 1 {
		t.Fatal(err, calls)
	}
	r.guard = func(context.Context) error { return ErrServiceDNSChanged }
	if _, err := r.Resolve(context.Background(), key.client, q); !errors.Is(err, ErrServiceDNSChanged) || calls != 1 {
		t.Fatal(err, calls)
	}
	guardCalls := 0
	r.guard = func(context.Context) error {
		guardCalls++
		if guardCalls == 2 {
			return ErrServiceDNSChanged
		}
		return nil
	}
	scopedExchange(r, key, func(_ context.Context, q []byte) (dohResponse, error) {
		return dohResponse{wire: scopedPack(t, scopedResponse(t, q))}, nil
	})
	if reply, err := r.Resolve(context.Background(), key.client, q); !errors.Is(err, ErrServiceDNSChanged) || reply != nil {
		t.Fatal("late stale reply", err)
	}
	r.guard = func(context.Context) error { return nil }
	choice := r.choices[key]
	choice.provider.DoH = "https://changed.example/dns-query"
	r.choices[key] = choice
	if _, err := r.Resolve(context.Background(), key.client, q); !errors.Is(err, ErrServiceDNSChanged) {
		t.Fatal(err)
	}
}

func TestScopedDNSAgesHeadersPreservesOPTAndSignedRDATA(t *testing.T) {
	r, key := scopedFixture(t)
	q := scopedQuery(t, "example.com", dnsmessage.TypeA)
	m := scopedResponse(t, q)
	m.Answers = append(m.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: m.Questions[0].Name, Type: 46, Class: dnsmessage.ClassINET, TTL: 180}, Body: &dnsmessage.UnknownResource{Type: 46, Data: []byte{0xc0, 0x0c, 0x12, 0x34, 0x56, 0x78}}})
	original := scopedPack(t, m)
	scopedExchange(r, key, func(_ context.Context, wire []byte) (dohResponse, error) {
		if !bytes.Equal(wire, q) {
			t.Fatal("query flags or DO changed")
		}
		return dohResponse{wire: original, age: 45}, nil
	})
	reply, err := r.Resolve(context.Background(), key.client, q)
	if err != nil {
		t.Fatal(err)
	}
	var got dnsmessage.Message
	if err := got.Unpack(reply); err != nil {
		t.Fatal(err)
	}
	if !got.AuthenticData || !got.CheckingDisabled || got.Additionals[0].Header.TTL != 0x8000 || got.Answers[0].Header.TTL != 75 || got.Answers[1].Header.TTL != 135 {
		t.Fatal(got)
	}
	if !bytes.Equal(got.Answers[1].Body.(*dnsmessage.UnknownResource).Data, m.Answers[1].Body.(*dnsmessage.UnknownResource).Data) {
		t.Fatal("signed data rewritten")
	}
	offsets, _ := dnsWireTTLOffsets(original)
	restored := append([]byte(nil), reply...)
	for _, offset := range offsets {
		copy(restored[offset:offset+4], original[offset:offset+4])
	}
	if !bytes.Equal(restored, original) || bytes.Equal(reply, original) {
		t.Fatal("changed bytes outside TTL headers")
	}
	if binary.BigEndian.Uint32(original[offsets[0]:]) != 120 {
		t.Fatal("mutated upstream storage")
	}
}

func TestScopedDNSNegativeAgeAndUnsafeAnswers(t *testing.T) {
	r, key := scopedFixture(t)
	q := scopedQuery(t, "example.com", dnsmessage.TypeA)
	for _, code := range []dnsmessage.RCode{dnsmessage.RCodeSuccess, dnsmessage.RCodeNameError} {
		m := scopedResponse(t, q)
		m.Answers = nil
		m.RCode = code
		soa := &dnsmessage.SOAResource{NS: dnsmessage.MustNewName("ns.example.com."), MBox: dnsmessage.MustNewName("hostmaster.example.com."), Serial: 1, MinTTL: 30}
		m.Authorities = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: m.Questions[0].Name, Type: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET, TTL: 60}, Body: soa}}
		for _, age := range []uint64{15, 90} {
			scopedExchange(r, key, func(context.Context, []byte) (dohResponse, error) {
				return dohResponse{wire: scopedPack(t, m), age: age}, nil
			})
			reply, err := r.Resolve(context.Background(), key.client, q)
			if err != nil {
				t.Fatal(err)
			}
			var got dnsmessage.Message
			_ = got.Unpack(reply)
			originalTTL := uint32(30)
			if got.RCode != code || got.Authorities[0].Header.TTL != *remainingDNSTTL(&originalTTL, age) || got.Authorities[0].Body.(*dnsmessage.SOAResource).MinTTL != 30 {
				t.Fatal(got)
			}
		}
	}
	for name, change := range map[string]func(*dnsmessage.Message){
		"wrong id":       func(m *dnsmessage.Message) { m.ID++ },
		"wrong question": func(m *dnsmessage.Message) { m.Questions[0].Name = dnsmessage.MustNewName("other.example.") },
		"private answer": func(m *dnsmessage.Message) { m.Answers[0].Body = &dnsmessage.AResource{A: [4]byte{192, 168, 1, 1}} },
		"private additional": func(m *dnsmessage.Message) {
			m.Additionals = append(m.Additionals, dnsmessage.Resource{Header: m.Answers[0].Header, Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}})
		},
		"changed CD":         func(m *dnsmessage.Message) { m.CheckingDisabled = false },
		"extended error":     func(m *dnsmessage.Message) { m.Additionals[0].Header.TTL |= 1 << 24 },
		"truncated upstream": func(m *dnsmessage.Message) { m.Truncated = true },
	} {
		t.Run(name, func(t *testing.T) {
			m := scopedResponse(t, q)
			change(&m)
			scopedExchange(r, key, func(context.Context, []byte) (dohResponse, error) { return dohResponse{wire: scopedPack(t, m)}, nil })
			if reply, err := r.Resolve(context.Background(), key.client, q); err == nil || reply != nil {
				t.Fatal("accepted unsafe reply")
			}
		})
	}
}

func TestScopedDNSConstructorRequiresExplicitBoundedBindings(t *testing.T) {
	r, key := scopedFixture(t)
	good := ClientDNSBinding{key.client, key.host, "private"}
	guard := func(context.Context) error { return nil }
	for _, binding := range []ClientDNSBinding{{netip.Addr{}, key.host, "private"}, {netip.MustParseAddr("0.0.0.0"), key.host, "private"}, {key.client, "*.example.com", "private"}, {key.client, "home.arpa", "private"}, {key.client, "192.168.1.1", "private"}, {key.client, key.host, "automatic"}, {key.client, key.host, "missing"}} {
		if _, err := r.manager.NewScopedDNSResolver([]ClientDNSBinding{binding}, guard); err == nil {
			t.Fatal(binding)
		}
	}
	for _, bindings := range [][]ClientDNSBinding{nil, {good, good}, make([]ClientDNSBinding, 129)} {
		if _, err := r.manager.NewScopedDNSResolver(bindings, guard); err == nil {
			t.Fatal("unbounded/duplicate accepted")
		}
	}
	if _, err := r.manager.NewScopedDNSResolver([]ClientDNSBinding{good}, nil); err == nil {
		t.Fatal("missing owner guard")
	}
}
