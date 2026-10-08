package dnscontrol

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func networkListAdmission(r *NetworkPolicyDNSResolver, kind func(string) string) {
	r.admit = func(_ context.Context, _ netip.Addr, name string) (NetworkPolicyDNSAdmission, error) {
		return NetworkPolicyDNSAdmission{Authority: r.authority, Ingress: "br0", DeviceID: "selected", Kind: kind(name)}, nil
	}
}

func TestNetworkPolicyDNSListMissAndEmptyUseOnlyReviewedBaseline(t *testing.T) {
	for _, empty := range []bool{false, true} {
		r, client := networkDNSFixture(t)
		owned, base := 0, 0
		selected := "service.example.com"
		networkListAdmission(r, func(name string) string {
			if !empty && name == selected {
				return "managed"
			}
			return "baseline"
		})
		networkDefaultExchange(r, func(_ context.Context, q []byte) (dohResponse, error) {
			owned++
			return dohResponse{wire: scopedPack(t, scopedResponse(t, q))}, nil
		})
		scopedExchange(r.service, scopedDNSKey{client, selected}, func(_ context.Context, q []byte) (dohResponse, error) {
			owned++
			return dohResponse{wire: scopedPack(t, scopedResponse(t, q))}, nil
		})
		if err := r.UseReviewedBaseline(func(_ context.Context, q []byte) ([]byte, error) {
			base++
			return scopedPack(t, scopedResponse(t, q)), nil
		}); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{selected, "unknown.example.com"} {
			if _, err := r.Resolve(context.Background(), client, scopedQuery(t, name, dnsmessage.TypeA)); err != nil {
				t.Fatal(err)
			}
		}
		wantOwned, wantBase := 1, 1
		if empty {
			wantOwned, wantBase = 0, 2
		}
		if owned != wantOwned || base != wantBase {
			t.Fatal("list miss or empty list acquired owned DNS", owned, base)
		}
	}
}

func TestNetworkPolicyDNSResourceExclusionBeatsPinnedBindingAndHistoricalCache(t *testing.T) {
	r, client := networkDNSFixture(t)
	key := scopedDNSKey{client, "service.example.com"}
	selected, base := 0, 0
	scopedExchange(r.service, key, func(_ context.Context, q []byte) (dohResponse, error) {
		selected++
		return dohResponse{wire: scopedPack(t, scopedResponse(t, q))}, nil
	})
	q := scopedQuery(t, key.host, dnsmessage.TypeA)
	if _, err := r.Resolve(context.Background(), client, q); err != nil {
		t.Fatal(err)
	}
	networkListAdmission(r, func(string) string { return "baseline" })
	if err := r.UseReviewedBaseline(func(_ context.Context, q []byte) ([]byte, error) {
		base++
		return scopedPack(t, scopedResponse(t, q)), nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve(context.Background(), client, q); err != nil || selected != 1 || base != 1 {
		t.Fatal("resource exclusion lost to old positive cache/binding", err, selected, base)
	}
	if observations, err := r.Observations(context.Background()); err != nil || len(observations) != 0 {
		t.Fatal("excluded resource retained a positive owner-facing observation", err)
	}
	// A broken selected provider must not turn this baseline into a DNS outage.
	r.choice.provider.Name = "changed selected provider"
	if _, err := r.Resolve(context.Background(), client, q); err != nil || selected != 1 || base != 2 {
		t.Fatal("excluded resource depends on a selected provider", err, selected, base)
	}
	networkListAdmission(r, func(string) string { return "managed" })
	if _, err := r.Resolve(context.Background(), client, q); !errors.Is(err, ErrServiceDNSChanged) || selected != 1 || base != 2 {
		t.Fatal("positive admission skipped selected provider identity", err)
	}
	networkListAdmission(r, func(string) string { return "outside" })
	if _, err := r.Resolve(context.Background(), client, q); !errors.Is(err, ErrNetworkPolicyDNSOutside) || selected != 1 || base != 2 {
		t.Fatal("excluded device entered service or baseline resolver", err)
	}
}

func TestNetworkPolicyDNSExclusionDuringAnswerCannotPublish(t *testing.T) {
	r, client := networkDNSFixture(t)
	key := scopedDNSKey{client, "service.example.com"}
	scopedExchange(r.service, key, func(_ context.Context, q []byte) (dohResponse, error) {
		networkListAdmission(r, func(string) string { return "baseline" })
		return dohResponse{wire: scopedPack(t, scopedResponse(t, q))}, nil
	})
	base, sent := false, false
	if err := r.UseReviewedBaseline(func(context.Context, []byte) ([]byte, error) { base = true; return nil, nil }); err != nil {
		t.Fatal(err)
	}
	err := r.Publish(context.Background(), client, scopedQuery(t, key.host, dnsmessage.TypeA), func(context.Context, NetworkPolicyDNSAdmission, []byte) error { sent = true; return nil })
	if !errors.Is(err, ErrNetworkPolicyDNS) || sent || base {
		t.Fatal("obsolete positive admission published or became implicit fallback", err)
	}
	if observations, err := r.Observations(context.Background()); err != nil || len(observations) != 0 {
		t.Fatal("in-flight excluded answer became a positive observation", err)
	}
}
