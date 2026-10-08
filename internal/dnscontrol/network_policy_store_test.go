package dnscontrol

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"golang.org/x/net/dns/dnsmessage"
)

// These tests use a real temporary Store/disk. Physical/positive admission and
// catalog identities are explicit models, not a production owner installation.
func networkDNSExclusionFixture(t *testing.T) (*NetworkPolicyDNSExclusions, *config.Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	cfg := config.Default()
	cfg.NetworkPolicy = &config.NetworkPolicy{Schema: 1, Revision: 1, Clients: config.ClientScope{Mode: "lan_except", SegmentIDs: []string{"home"}, NewDevices: "inherit"}, Traffic: config.TrafficSelection{Mode: "selected_services", Unavailable: "retain"}}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	store, err := config.LoadExisting(path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := NewNetworkPolicyDNSExclusions(context.Background(), store, store.Get(), func(context.Context, string) ([]string, error) { return nil, nil })
	if err != nil {
		t.Fatal(err)
	}
	return f, store, path
}

func networkDNSModelPublisher(_ context.Context, _ NetworkPolicyDNSAdmission, send func() error) error {
	return send()
}

func networkDNSStoredNegatives(t *testing.T, r *NetworkPolicyDNSResolver, manual []config.ResourceMatch, feed *config.AcceptedRussianSnapshot) *config.Store {
	t.Helper()
	store := r.exclusions.store
	patch := config.ResourceExclusionsPatch{Manual: &manual, Accepted: feed}
	if feed != nil {
		enabled := true
		patch.RussianEnabled = &enabled
	}
	if _, err := store.UpdateResourceExclusionsPatch(context.Background(), store.Get(), patch); err != nil {
		t.Fatal(err)
	}
	f, err := NewNetworkPolicyDNSExclusions(context.Background(), store, store.Get(), func(_ context.Context, name string) ([]string, error) {
		switch name {
		case "service.example.com":
			return []string{"active-service", "disabled-service"}, nil
		case "cdn.example.com":
			return []string{"cdn-service"}, nil
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	r.exclusions = f
	r.authority.Exclusions = f.Stamp()
	networkListAdmission(r, func(string) string { return "managed" })
	return store
}

func TestNetworkPolicyDNSActualStoreRequiredAndDetachedStampCannotGrant(t *testing.T) {
	f, store, _ := networkDNSExclusionFixture(t)
	wrong := store.Get()
	wrong.Listen = ":9999"
	if _, err := NewNetworkPolicyDNSExclusions(context.Background(), store, wrong, f.identities); !errors.Is(err, config.ErrRevisionChanged) {
		t.Fatal("same revision/full-preimage mismatch accepted", err)
	}
	if _, err := NewNetworkPolicyDNSExclusions(context.Background(), store, store.Get(), nil); !errors.Is(err, ErrNetworkPolicyDNS) {
		t.Fatal("missing retained catalog classifier accepted", err)
	}
	copy := &NetworkPolicyDNSExclusions{self: f, store: f.store, expected: f.expected, stamp: f.stamp, identities: f.identities}
	if err := copy.current(context.Background()); !errors.Is(err, ErrNetworkPolicyDNS) {
		t.Fatal("copied participant replaced original Store binding", err)
	}
	r, _ := networkDNSFixture(t)
	r.authority.Exclusions.Digest = strings.Repeat("f", 64)
	if _, err := r.defaultDNS.manager.NewNetworkPolicyDNSResolver(context.Background(), "private", nil, r.authority, r.guard, r.admit, r.exclusions); !errors.Is(err, ErrNetworkPolicyDNS) {
		t.Fatal("authority hash substituted for actual participant", err)
	}
	expected := store.Get()
	expected.NetworkPolicy.Clients.SegmentIDs[0] = "edited"
	if err := f.current(context.Background()); err != nil {
		t.Fatal("detached caller config mutated binding", err)
	}
}

func TestNetworkPolicyDNSActualNegativesBeatPositivePinnedProvider(t *testing.T) {
	for _, match := range []config.ResourceMatch{{Kind: "exact", Value: "service.example.com"}, {Kind: "suffix", Value: "example.com"}, {Kind: "service", Value: "disabled-service"}} {
		t.Run(match.Kind, func(t *testing.T) {
			r, client := networkDNSFixture(t)
			networkDNSStoredNegatives(t, r, []config.ResourceMatch{match}, nil)
			selected, base := 0, 0
			scopedExchange(r.service, scopedDNSKey{client, "service.example.com"}, func(context.Context, []byte) (dohResponse, error) {
				selected++
				return dohResponse{}, errors.New("must not query selected")
			})
			r.choice.provider.Name = "broken selected identity"
			_ = r.UseReviewedBaseline(func(_ context.Context, q []byte) ([]byte, error) {
				base++
				return scopedPack(t, scopedResponse(t, q)), nil
			})
			if _, err := r.Resolve(context.Background(), client, scopedQuery(t, "service.example.com", dnsmessage.TypeA)); err != nil || selected != 0 || base != 1 {
				t.Fatal("actual negative lost to positive pin/provider check", err, selected, base)
			}
		})
	}
}

func TestNetworkPolicyDNSActualAnswerNegativesCoverAliasesAddressesAndGlue(t *testing.T) {
	for _, kind := range []string{"cname-exact", "cname-suffix", "cname-service", "ipv4", "ipv4-cidr", "ipv6", "ipv6-cidr", "glue-a", "glue-aaaa", "accepted-ru"} {
		t.Run(kind, func(t *testing.T) {
			r, client := networkDNSFixture(t)
			match := config.ResourceMatch{Kind: "exact", Value: "cdn.example.com"}
			var feed *config.AcceptedRussianSnapshot
			switch kind {
			case "cname-suffix":
				match = config.ResourceMatch{Kind: "suffix", Value: "example.com"}
			case "cname-service":
				match = config.ResourceMatch{Kind: "service", Value: "cdn-service"}
			case "ipv4", "glue-a":
				match = config.ResourceMatch{Kind: "ip", Value: "93.184.215.14"}
			case "ipv4-cidr":
				match = config.ResourceMatch{Kind: "cidr", Value: "93.184.215.0/24"}
			case "ipv6", "glue-aaaa":
				match = config.ResourceMatch{Kind: "ip", Value: "2606:4700::1111"}
			case "ipv6-cidr":
				match = config.ResourceMatch{Kind: "cidr", Value: "2606:4700::/32"}
			case "accepted-ru":
				feed = &config.AcceptedRussianSnapshot{CatalogID: "reviewed-ru", Revision: 1, Entries: []config.ResourceMatch{match}}
				feed.Digest = config.RussianSnapshotDigest(feed)
			}
			manual := []config.ResourceMatch{match}
			if feed != nil {
				manual = nil
			}
			networkDNSStoredNegatives(t, r, manual, feed)
			name := "service.other.com" // the original positive itself is not excluded
			if strings.HasPrefix(kind, "glue") {
				name = "service.example.com"
			}
			key := scopedDNSKey{client, name}
			r.service.choices[key] = r.service.choices[scopedDNSKey{client, "service.example.com"}]
			scopedExchange(r.service, key, func(_ context.Context, q []byte) (dohResponse, error) {
				a := scopedResponse(t, q)
				if strings.HasPrefix(kind, "glue") {
					a.Answers[0].Body = &dnsmessage.AResource{A: [4]byte{8, 8, 8, 8}}
					glue := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("unrelated.example.net."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{93, 184, 215, 14}}}
					if kind == "glue-aaaa" {
						glue.Header.Type = dnsmessage.TypeAAAA
						glue.Body = &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2606:4700::1111").As16()}
					}
					a.Additionals = append(a.Additionals, glue)
				} else {
					terminal := dnsmessage.MustNewName("cdn.example.com.")
					a.Answers[0].Header.Name = terminal
					if strings.HasPrefix(kind, "ipv6") {
						a.Answers[0].Header.Type = dnsmessage.TypeAAAA
						a.Answers[0].Body = &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2606:4700::1111").As16()}
					}
					a.Answers = append([]dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: a.Questions[0].Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.CNAMEResource{CNAME: terminal}}}, a.Answers...)
				}
				return dohResponse{wire: scopedPack(t, a)}, nil
			})
			typ := dnsmessage.TypeA
			if strings.HasPrefix(kind, "ipv6") {
				typ = dnsmessage.TypeAAAA
			}
			base, sent := false, false
			_ = r.UseReviewedBaseline(func(context.Context, []byte) ([]byte, error) { base = true; return nil, nil })
			err := r.Publish(context.Background(), client, scopedQuery(t, name, typ), networkDNSModelPublisher, func([]byte) error { sent = true; return nil })
			if !errors.Is(err, ErrNetworkPolicyDNSExcluded) || sent || base {
				t.Fatal("excluded answer published, cached or implicitly fell back", err, sent, base)
			}
			if observations, err := r.Observations(context.Background()); err != nil || len(observations) != 0 {
				t.Fatal("denied wire acquired positive ledger entry", observations, err)
			}
		})
	}
}

func TestNetworkPolicyDNSActualStoreRevokesInFlightCacheAndFinalPublication(t *testing.T) {
	for _, phase := range []string{"exchange", "cache", "owner-send"} {
		t.Run(phase, func(t *testing.T) {
			r, client := networkDNSFixture(t)
			store := r.exclusions.store
			q := scopedQuery(t, "service.example.com", dnsmessage.TypeA)
			mutate := func() {
				manual := []config.ResourceMatch{{Kind: "exact", Value: "service.example.com"}}
				if _, err := store.UpdateResourceExclusions(context.Background(), store.Get(), &manual, nil); err != nil {
					t.Fatal(err)
				}
			}
			scopedExchange(r.service, scopedDNSKey{client, "service.example.com"}, func(_ context.Context, q []byte) (dohResponse, error) {
				if phase == "exchange" {
					mutate()
				}
				return dohResponse{wire: scopedPack(t, scopedResponse(t, q))}, nil
			})
			if phase == "cache" {
				if _, err := r.Resolve(context.Background(), client, q); err != nil {
					t.Fatal(err)
				}
				mutate()
			}
			sent := false
			owner := func(_ context.Context, _ NetworkPolicyDNSAdmission, send func() error) error {
				if phase == "owner-send" {
					mutate()
				}
				return send()
			}
			if err := r.Publish(context.Background(), client, q, owner, func([]byte) error { sent = true; return nil }); err == nil || sent {
				t.Fatal("old Store authority survived update", err, sent)
			}
			if _, err := r.Observations(context.Background()); err == nil {
				t.Fatal("obsolete cache/observation reproposed")
			}
		})
	}
}

func TestNetworkPolicyDNSDiskRestorationCannotReviveOriginalParticipant(t *testing.T) {
	r, client := networkDNSFixture(t)
	f, _, path := networkDNSExclusionFixture(t)
	r.exclusions = f
	r.authority.Exclusions = f.Stamp()
	networkListAdmission(r, func(string) string { return "managed" })
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(append([]byte(nil), original...), '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve(context.Background(), client, scopedQuery(t, "service.example.com", dnsmessage.TypeA)); !errors.Is(err, config.ErrRevisionChanged) {
		t.Fatal("disk drift accepted", err)
	}
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := r.exclusions.current(context.Background()); !errors.Is(err, ErrNetworkPolicyDNS) {
		t.Fatal("restored bytes revived original participant", err)
	}
}

func TestNetworkPolicyDNSStoreLockOrderAndFinalWriteFence(t *testing.T) {
	r, client := networkDNSFixture(t)
	store := r.exclusions.store
	// All owner/classification callbacks intentionally read the SAME Store.
	original := r.admit
	r.admit = func(ctx context.Context, c netip.Addr, name string) (NetworkPolicyDNSAdmission, error) {
		_ = store.Get()
		return original(ctx, c, name)
	}
	r.exclusions.identities = func(context.Context, string) ([]string, error) { _ = store.Get(); return nil, nil }
	scopedExchange(r.service, scopedDNSKey{client, "service.example.com"}, func(_ context.Context, q []byte) (dohResponse, error) {
		return dohResponse{wire: scopedPack(t, scopedResponse(t, q))}, nil
	})
	var ownerGate sync.Mutex
	owner := func(_ context.Context, _ NetworkPolicyDNSAdmission, send func() error) error {
		ownerGate.Lock()
		defer ownerGate.Unlock()
		_ = store.Get()
		return send()
	}
	entered, release, updated := make(chan struct{}), make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- r.Publish(context.Background(), client, scopedQuery(t, "service.example.com", dnsmessage.TypeA), owner, func([]byte) error { close(entered); <-release; return nil })
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("owner/classifier acquired Store inside observation lock")
	}
	go func() {
		defer close(updated)
		_ = store.UpdateService("service", config.ServiceState{Enabled: true, Route: "auto"})
	}()
	select {
	case <-updated:
		t.Fatal("config writer crossed final socket-write Store fence")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	select {
	case <-updated:
	case <-time.After(2 * time.Second):
		t.Fatal("writer blocked after final leaf")
	}
}

func TestNetworkPolicyDNSActualClientExclusionsPrecedeEveryResolver(t *testing.T) {
	for _, mode := range []string{"device", "cidr"} {
		t.Run(mode, func(t *testing.T) {
			r, _ := networkDNSFixture(t)
			cfg := r.exclusions.store.Get()
			client := netip.MustParseAddr("192.168.42.9")
			if mode == "device" {
				cfg.NetworkPolicy.Clients.ExcludedDeviceIDs = []string{"selected"}
			} else {
				cfg.NetworkPolicy.Clients.ExcludedCIDRs = []string{"192.168.42.0/24"}
			}
			path := filepath.Join(t.TempDir(), "client-config.json")
			data, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			store, err := config.LoadExisting(path)
			if err != nil {
				t.Fatal(err)
			}
			f, err := NewNetworkPolicyDNSExclusions(context.Background(), store, store.Get(), r.exclusions.identities)
			if err != nil {
				t.Fatal(err)
			}
			r.exclusions = f
			r.authority.Exclusions = f.Stamp()
			called := false
			r.choice.provider.Name = "broken provider"
			networkDefaultExchange(r, func(context.Context, []byte) (dohResponse, error) { called = true; return dohResponse{}, nil })
			_ = r.UseReviewedBaseline(func(context.Context, []byte) ([]byte, error) { called = true; return nil, nil })
			for _, kind := range []string{"managed", "baseline"} {
				networkListAdmission(r, func(string) string { return kind })
				if _, err := r.Resolve(context.Background(), client, scopedQuery(t, "service.example.com", dnsmessage.TypeA)); !errors.Is(err, ErrNetworkPolicyDNSOutside) || called {
					t.Fatal("stored client exclusion entered resolver", kind, err)
				}
			}
		})
	}
}

func TestNetworkPolicyDNSCanonicalExclusionsAndMissingCatalogEvidence(t *testing.T) {
	r, client := networkDNSFixture(t)
	networkDNSStoredNegatives(t, r, []config.ResourceMatch{{Kind: "exact", Value: "ПРИМЕР.РФ"}, {Kind: "suffix", Value: "excluded.example.com"}}, nil)
	for _, item := range []struct {
		name     string
		excluded bool
	}{{"xn--e1afmkfd.xn--p1ai", true}, {"sub.excluded.example.com", true}, {"notexcluded.example.com", false}, {"excluded.example.com.evil.net", false}} {
		a, err := r.admission(context.Background(), client, item.name)
		if err != nil || (a.Kind == "baseline") != item.excluded {
			t.Fatal("IDN/suffix boundary", item, err, a.Kind)
		}
	}
	r.exclusions.identities = func(context.Context, string) ([]string, error) {
		return nil, errors.New("retained catalog unavailable")
	}
	called := false
	networkDefaultExchange(r, func(context.Context, []byte) (dohResponse, error) { called = true; return dohResponse{}, nil })
	if _, err := r.Resolve(context.Background(), client, scopedQuery(t, "ordinary.example.net", dnsmessage.TypeA)); err == nil || called {
		t.Fatal("missing catalog proof became permissive", err)
	}
	// Baseline-only standard DNS names do not become managed domain identities.
	networkListAdmission(r, func(string) string { return "baseline" })
	_ = r.UseReviewedBaseline(func(_ context.Context, q []byte) ([]byte, error) {
		a := scopedResponse(t, q)
		a.Answers = nil
		return scopedPack(t, a), nil
	})
	if _, err := r.Resolve(context.Background(), client, scopedQuery(t, "_service._tcp.example.com", dnsmessage.TypeSRV)); err != nil {
		t.Fatal("ordinary baseline name required selected catalog identity", err)
	}
}

func TestNetworkPolicyDNSFrozenPlanBindsActualConfigEvenWithUnchangedNegatives(t *testing.T) {
	r, _ := networkDNSFixture(t)
	m := r.defaultDNS.manager
	p, err := m.FreezeNetworkPolicyDNSPlan(context.Background(), r.authority.Generation, "private", nil, r.exclusions)
	if err != nil {
		t.Fatal(err)
	}
	forged := CloneNetworkPolicyDNSPlan(p)
	forged.Exclusions.ConfigRevision++
	forged.Digest = networkPolicyDNSPlanDigest(forged)
	if err := m.CheckNetworkPolicyDNSPlan(context.Background(), forged, r.exclusions); !errors.Is(err, ErrNetworkPolicyDNS) {
		t.Fatal("resealed stamp became an actual Store grant", err)
	}
	legacy := CloneNetworkPolicyDNSPlan(p)
	legacy.Schema = 1
	legacy.Digest = networkPolicyDNSPlanDigest(legacy)
	if ValidateNetworkPolicyDNSPlan(legacy) == nil {
		t.Fatal("old plan without current exclusions remained executable")
	}
	if err := r.exclusions.store.UpdateService("ordinary", config.ServiceState{Enabled: true, Route: "auto"}); err != nil {
		t.Fatal(err)
	}
	if err := m.CheckNetworkPolicyDNSPlan(context.Background(), p, r.exclusions); !errors.Is(err, config.ErrRevisionChanged) {
		t.Fatal("unchanged exclusion hash ignored full config change", err)
	}
}

func TestNetworkPolicyDNSAmbiguousCNAMECannotPublish(t *testing.T) {
	for _, mode := range []string{"loop", "conflict", "address-alongside"} {
		t.Run(mode, func(t *testing.T) {
			r, client := networkDNSFixture(t)
			networkDefaultExchange(r, func(_ context.Context, q []byte) (dohResponse, error) {
				a := scopedResponse(t, q)
				name := a.Questions[0].Name
				a.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("cdn.example.com.")}}}
				switch mode {
				case "loop":
					a.Answers[0].Body = &dnsmessage.CNAMEResource{CNAME: name}
				case "conflict":
					a.Answers = append(a.Answers, dnsmessage.Resource{Header: a.Answers[0].Header, Body: &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("other.example.com.")}})
				case "address-alongside":
					a.Answers = append(a.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{8, 8, 8, 8}}})
				}
				return dohResponse{wire: scopedPack(t, a)}, nil
			})
			sent := false
			if err := r.Publish(context.Background(), client, scopedQuery(t, "ordinary.example.com", dnsmessage.TypeA), networkDNSModelPublisher, func([]byte) error { sent = true; return nil }); err == nil || sent {
				t.Fatal("ambiguous alias escaped negative boundary", mode, err)
			}
		})
	}
}
