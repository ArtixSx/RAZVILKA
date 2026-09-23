package dnscontrol

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestScopedCacheLifetimeFailureAndBoundedGrace(t *testing.T) {
	r, key := scopedFixture(t)
	now := time.Now()
	r.cache.now = func() time.Time { return now }
	q := scopedQuery(t, key.host, dnsmessage.TypeA)
	calls, fail := 0, false
	scopedExchange(r, key, func(_ context.Context, query []byte) (dohResponse, error) {
		calls++
		if fail {
			return dohResponse{}, context.DeadlineExceeded
		}
		return dohResponse{wire: scopedPack(t, scopedResponse(t, query)), age: 20}, nil
	})
	first, err := r.Resolve(context.Background(), key.client, q)
	if err != nil {
		t.Fatal(err)
	}
	var answer dnsmessage.Message
	_ = answer.Unpack(first)
	if answer.Answers[0].Header.TTL != 100 {
		t.Fatal(answer)
	}
	now = now.Add(12500 * time.Millisecond)
	binary.BigEndian.PutUint16(q, 77)
	second, err := r.Resolve(context.Background(), key.client, q)
	if err != nil {
		t.Fatal(err)
	}
	_ = answer.Unpack(second)
	if answer.ID != 77 || answer.Answers[0].Header.TTL != 87 || calls != 1 {
		t.Fatal(answer, calls)
	}
	// Caller-owned slices and TTL pointers cannot change the cache/ledger.
	second[0] = 0
	entries, err := r.Observations(context.Background())
	if err != nil || len(entries) != 1 || entries[0].State != "fresh" {
		t.Fatal(entries, err)
	}
	end, forget := entries[0].ExpiresAt, entries[0].ForgetAt
	entries[0].Details.Addresses[0] = netip.MustParseAddr("8.8.8.8")
	*entries[0].Details.TTLSeconds = 999
	now, fail = end, true
	if wire, err := r.Resolve(context.Background(), key.client, q); err == nil || wire != nil {
		t.Fatal("served stale on timeout")
	}
	entries, _ = r.Observations(context.Background())
	if len(entries) != 1 || entries[0].State != "stale" || entries[0].LastFailure == "" || !entries[0].ForgetAt.Equal(forget) || *entries[0].Details.TTLSeconds != 100 || entries[0].Details.Addresses[0].String() != "93.184.215.14" {
		t.Fatal(entries)
	}
	now = forget
	entries, _ = r.Observations(context.Background())
	if len(entries) != 0 {
		t.Fatal("grace renewed by failure", entries)
	}
}

func TestScopedCacheSeparatesQuestionsFlagsAndClient(t *testing.T) {
	r, key := scopedFixture(t)
	other := scopedDNSKey{netip.MustParseAddr("127.0.0.2"), key.host}
	r.choices[other] = r.choices[key]
	calls := 0
	fn := func(_ context.Context, q []byte) (dohResponse, error) {
		calls++
		return dohResponse{wire: scopedPack(t, scopedResponse(t, q))}, nil
	}
	scopedExchange(r, key, fn)
	scopedExchange(r, other, fn)
	for _, client := range []netip.Addr{key.client, other.client} {
		for _, typ := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
			for _, flags := range []int{0, 1, 2, 3} {
				q := scopedQuery(t, key.host, typ)
				var m dnsmessage.Message
				_ = m.Unpack(q)
				m.CheckingDisabled = flags&1 != 0
				if flags&2 == 0 {
					m.Additionals[0].Header.TTL = 0
				}
				q = scopedPack(t, m)
				before := calls
				for i := 0; i < 2; i++ {
					if _, err := r.Resolve(context.Background(), client, q); err != nil {
						t.Fatal(err)
					}
				}
				if calls != before+1 {
					t.Fatal("not isolated/cached", calls, before)
				}
			}
		}
	}
	// Exact question case is preserved; a different case is a cache miss.
	q := scopedQuery(t, "EXAMPLE.com", dnsmessage.TypeA)
	before := calls
	wire, err := r.Resolve(context.Background(), key.client, q)
	var m dnsmessage.Message
	_ = m.Unpack(wire)
	if err != nil || calls != before+1 || m.Questions[0].Name.String() != "EXAMPLE.com." {
		t.Fatal(err, calls, m)
	}
}

func TestScopedCacheZeroTTLNegativeAndNXDomainReplacement(t *testing.T) {
	r, key := scopedFixture(t)
	now := time.Now()
	r.cache.now = func() time.Time { return now }
	mode, calls := "positive", 0
	scopedExchange(r, key, func(_ context.Context, q []byte) (dohResponse, error) {
		calls++
		m := scopedResponse(t, q)
		switch mode {
		case "zero":
			m.Answers[0].Header.TTL = 0
		case "nxdomain", "nodata", "no-soa":
			m.Answers = nil
			if mode == "nxdomain" {
				m.RCode = dnsmessage.RCodeNameError
			}
			if mode != "no-soa" {
				m.Authorities = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: m.Questions[0].Name, Type: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET, TTL: 180}, Body: &dnsmessage.SOAResource{NS: dnsmessage.MustNewName("ns.example.com."), MBox: dnsmessage.MustNewName("hostmaster.example.com."), MinTTL: 90}}}
			}
		}
		return dohResponse{wire: scopedPack(t, m)}, nil
	})
	a := scopedQuery(t, key.host, dnsmessage.TypeA)
	aaaa := scopedQuery(t, key.host, dnsmessage.TypeAAAA)
	if _, err := r.Resolve(context.Background(), key.client, a); err != nil {
		t.Fatal(err)
	}
	mode = "nxdomain"
	if _, err := r.Resolve(context.Background(), key.client, aaaa); err != nil {
		t.Fatal(err)
	}
	entries, _ := r.Observations(context.Background())
	if len(entries) != 1 || entries[0].Details.NegativeKind != "nxdomain" || entries[0].ExpiresAt.Sub(now) != time.Minute {
		t.Fatal(entries)
	}
	before := calls
	if _, err := r.Resolve(context.Background(), key.client, aaaa); err != nil || calls != before {
		t.Fatal(err, calls)
	}
	now = now.Add(time.Minute)
	entries, _ = r.Observations(context.Background())
	if len(entries) != 0 {
		t.Fatal("negative received positive grace", entries)
	}
	for _, value := range []string{"zero", "no-soa"} {
		mode = value
		before = calls
		for i := 0; i < 2; i++ {
			if _, err := r.Resolve(context.Background(), key.client, a); err != nil {
				t.Fatal(err)
			}
		}
		if calls != before+2 {
			t.Fatal("cached answer without lifetime", value, calls)
		}
	}
}

func TestScopedCacheGuardAlsoProtectsCacheHitsAndClearsOldEpoch(t *testing.T) {
	for _, change := range []string{"epoch", "provider", "cancel"} {
		t.Run(change, func(t *testing.T) {
			r, key := scopedFixture(t)
			calls := 0
			scopedExchange(r, key, func(_ context.Context, q []byte) (dohResponse, error) {
				calls++
				return dohResponse{wire: scopedPack(t, scopedResponse(t, q))}, nil
			})
			q := scopedQuery(t, key.host, dnsmessage.TypeA)
			_, _ = r.Resolve(context.Background(), key.client, q)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch change {
			case "epoch":
				r.guard = func(context.Context) error { return ErrServiceDNSChanged }
			case "provider":
				choice := r.choices[key]
				choice.provider.Kind = "changed"
				r.choices[key] = choice
			case "cancel":
				cancel()
			}
			if wire, err := r.Resolve(ctx, key.client, q); err == nil || wire != nil || calls != 1 {
				t.Fatal("old cached answer escaped guard", err, calls)
			}
			if change == "epoch" {
				r.guard = func(context.Context) error { return nil }
				entries, _ := r.Observations(context.Background())
				if len(entries) != 0 {
					t.Fatal(entries)
				}
				_, _ = r.Resolve(context.Background(), key.client, q)
				if calls != 2 {
					t.Fatal("old epoch reused")
				}
			}
		})
	}
}

func TestScopedCacheOutOfOrderCompletionCannotOverwriteNewerAnswer(t *testing.T) {
	r, key := scopedFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	scopedExchange(r, key, func(_ context.Context, q []byte) (dohResponse, error) {
		i := calls.Add(1)
		if i == 1 {
			close(entered)
			<-release
		}
		m := scopedResponse(t, q)
		if i == 2 {
			m.Answers[0].Body = &dnsmessage.AResource{A: [4]byte{8, 8, 8, 8}}
		}
		return dohResponse{wire: scopedPack(t, m)}, nil
	})
	q := scopedQuery(t, key.host, dnsmessage.TypeA)
	done := make(chan error, 1)
	go func() { _, err := r.Resolve(context.Background(), key.client, q); done <- err }()
	<-entered
	if _, err := r.Resolve(context.Background(), key.client, q); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	entries, _ := r.Observations(context.Background())
	if len(entries) != 1 || entries[0].Details.Addresses[0].String() != "8.8.8.8" {
		t.Fatal(entries)
	}
}

func TestScopedCacheResourceBoundsAndFailureDoesNotCreateAddresses(t *testing.T) {
	c := scopedAnswerCache{}
	start := time.Now()
	c.now = func() time.Time { return start }
	ttl := uint32(120)
	for i := 0; i < 400; i++ {
		key := scopedAnswerKey{scopedDNSKey: scopedDNSKey{client: netip.MustParseAddr("127.0.0.1"), host: fmt.Sprintf("host%d.example", i)}, typ: dnsmessage.TypeA}
		ticket, at, _ := c.begin(key, [32]byte{}, 41)
		c.accept(key, [32]byte{}, ticket, at, make([]byte, 65535), AnswerDetails{TTLSeconds: &ttl})
	}
	bytes := 0
	for _, e := range c.entries {
		bytes += len(e.wire)
	}
	if len(c.entries) > scopedCacheEntries || bytes > scopedCacheBytes {
		t.Fatal(len(c.entries), bytes)
	}
	r, key := scopedFixture(t)
	scopedExchange(r, key, func(context.Context, []byte) (dohResponse, error) { return dohResponse{}, errors.New("offline") })
	_, _ = r.Resolve(context.Background(), key.client, scopedQuery(t, key.host, dnsmessage.TypeA))
	entries, _ := r.Observations(context.Background())
	if len(entries) != 0 {
		t.Fatal(entries)
	}
}

func TestScopedCacheAliasLifetimeAndClientTTLCap(t *testing.T) {
	for _, aliasTTL := range []uint32{3, 3600} {
		r, key := scopedFixture(t)
		now := time.Now()
		r.cache.now = func() time.Time { return now }
		calls := 0
		scopedExchange(r, key, func(_ context.Context, q []byte) (dohResponse, error) {
			calls++
			m := scopedResponse(t, q)
			address := m.Answers[0]
			address.Header.Name = dnsmessage.MustNewName("alias.example.net.")
			address.Header.TTL = 3600
			m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: m.Questions[0].Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: aliasTTL}, Body: &dnsmessage.CNAMEResource{CNAME: address.Header.Name}}, address}
			return dohResponse{wire: scopedPack(t, m)}, nil
		})
		q := scopedQuery(t, key.host, dnsmessage.TypeA)
		wire, err := r.Resolve(context.Background(), key.client, q)
		if err != nil {
			t.Fatal(err)
		}
		var m dnsmessage.Message
		_ = m.Unpack(wire)
		if m.Answers[1].Header.TTL != 300 {
			t.Fatal("client TTL exceeds cap", m)
		}
		entries, _ := r.Observations(context.Background())
		if len(entries) != 1 || entries[0].ExpiresAt.Sub(now) != time.Duration(min(aliasTTL, 300))*time.Second || len(entries[0].Details.CNAMEChain) != 1 {
			t.Fatal(entries)
		}
		now = entries[0].ExpiresAt
		if _, err := r.Resolve(context.Background(), key.client, q); err != nil || calls != 2 {
			t.Fatal("alias expiry reused address", err, calls)
		}
	}
}

func TestScopedCacheClearCannotBeUndoneByPendingResponse(t *testing.T) {
	c := scopedAnswerCache{}
	key := scopedAnswerKey{scopedDNSKey: scopedDNSKey{client: netip.MustParseAddr("127.0.0.1"), host: "example.com"}, typ: dnsmessage.TypeA}
	old, at, _ := c.begin(key, [32]byte{}, 41)
	c.clear()
	current, _, _ := c.begin(key, [32]byte{}, 42)
	ttl := uint32(120)
	c.accept(key, [32]byte{}, old, at, []byte{1}, AnswerDetails{TTLSeconds: &ttl})
	if old == current || !c.entries[key].observed.IsZero() || len(c.entries[key].wire) != 0 {
		t.Fatal("old response restored cleared cache")
	}
}
