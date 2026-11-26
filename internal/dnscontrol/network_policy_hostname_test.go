package dnscontrol

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
	"golang.org/x/net/dns/dnsmessage"
)

// The Store/disk boundary is real; positive admission, retained catalog and
// provider exchanges are explicit models, not a production owner installation.
func TestNetworkPolicyDNSObservedHostnameQNAME(t *testing.T) {
	for _, name := range []string{"discordsays.com", "discordsez.com", "github.io", "appspot.com", "co.uk"} {
		t.Run(name, func(t *testing.T) {
			r, client := networkDNSFixture(t)
			networkDNSStoredNegatives(t, r, []config.ResourceMatch{{Kind: "exact", Value: "unrelated.example"}}, nil)
			classified := 0
			r.exclusions.identities = func(_ context.Context, actual string) ([]string, error) {
				if actual != name {
					t.Fatalf("catalog received noncanonical QNAME %q", actual)
				}
				classified++
				return []string{"known-disabled"}, nil
			}
			provider, sent := 0, 0
			networkDefaultExchange(r, func(_ context.Context, q []byte) (dohResponse, error) {
				provider++
				return dohResponse{wire: scopedPack(t, scopedResponse(t, q))}, nil
			})
			q := scopedQuery(t, strings.ToUpper(name), dnsmessage.TypeA)
			if err := r.Publish(context.Background(), client, q, networkDNSModelPublisher, func([]byte) error { sent++; return nil }); err != nil || provider != 1 || sent != 1 || classified == 0 {
				t.Fatal("observed QNAME rejected before actual Store/publication", err, provider, sent, classified)
			}
			if observations, err := r.Observations(context.Background()); err != nil || len(observations) != 0 {
				t.Fatal("observed hostname acquired a service ledger binding", observations, err)
			}

			// Canonicalization must not supply the missing positive owner decision.
			networkListAdmission(r, func(string) string { return "refused" })
			if wire, err := r.Resolve(context.Background(), client, q); !errors.Is(err, ErrNetworkPolicyDNS) || wire != nil || provider != 1 {
				t.Fatal("observed hostname replaced positive owner admission", err, provider)
			}
		})
	}
}

func TestNetworkPolicyDNSObservedHostnameServiceNegativePrecedesProvider(t *testing.T) {
	for _, name := range []string{"discordsays.com", "discordsez.com", "api.discordsays.com", "api.discordsez.com"} {
		t.Run(name, func(t *testing.T) {
			r, client := networkDNSFixture(t)
			networkDNSStoredNegatives(t, r, []config.ResourceMatch{{Kind: "service", Value: "discord"}}, nil)
			r.exclusions.identities = func(_ context.Context, actual string) ([]string, error) {
				if actual != name {
					t.Fatalf("catalog received noncanonical QNAME %q", actual)
				}
				// The excluded identity remains known even when disabled.
				return []string{"enabled-other", "discord"}, nil
			}
			r.choice.provider.Name = "changed selected provider"
			provider, baseline, sent := 0, 0, 0
			networkDefaultExchange(r, func(context.Context, []byte) (dohResponse, error) {
				provider++
				return dohResponse{}, errors.New("must not query selected provider")
			})
			if err := r.UseReviewedBaseline(func(_ context.Context, q []byte) ([]byte, error) {
				baseline++
				return scopedPack(t, scopedResponse(t, q)), nil
			}); err != nil {
				t.Fatal(err)
			}
			publish := func(ctx context.Context, a NetworkPolicyDNSAdmission, leaf func() error) error {
				if a.Kind != "baseline" {
					t.Fatal("known service negative lost precedence", a.Kind)
				}
				return networkDNSModelPublisher(ctx, a, leaf)
			}
			if err := r.Publish(context.Background(), client, scopedQuery(t, strings.ToUpper(name), dnsmessage.TypeA), publish, func([]byte) error { sent++; return nil }); err != nil || provider != 0 || baseline != 1 || sent != 1 {
				t.Fatal("service negative lost to PSL/provider rejection", err, provider, baseline, sent)
			}
			if observations, err := r.Observations(context.Background()); err != nil || len(observations) != 0 {
				t.Fatal("excluded hostname acquired a positive observation", observations, err)
			}
		})
	}
}

func TestNetworkPolicyDNSObservedHostnameCNAME(t *testing.T) {
	for _, name := range []string{"discordsays.com", "discordsez.com", "github.io", "appspot.com", "co.uk"} {
		for _, excluded := range []bool{false, true} {
			label := name + "/allowed"
			if excluded {
				label = name + "/excluded"
			}
			t.Run(label, func(t *testing.T) {
				r, client := networkDNSFixture(t)
				manual := []config.ResourceMatch{{Kind: "exact", Value: "unrelated.example"}}
				if excluded {
					manual = []config.ResourceMatch{{Kind: "service", Value: "known-disabled"}}
				}
				networkDNSStoredNegatives(t, r, manual, nil)
				var classified []string
				r.exclusions.identities = func(_ context.Context, actual string) ([]string, error) {
					classified = append(classified, actual)
					if actual == name {
						return []string{"known-disabled"}, nil
					}
					return nil, nil
				}
				key := scopedDNSKey{client, "service.other.com"}
				r.service.choices[key] = r.service.choices[scopedDNSKey{client, "service.example.com"}]
				provider, baseline, sent := 0, 0, 0
				scopedExchange(r.service, key, func(_ context.Context, q []byte) (dohResponse, error) {
					provider++
					a := scopedResponse(t, q)
					terminal := dnsmessage.MustNewName(strings.ToUpper(name) + ".")
					a.Answers[0].Header.Name = terminal
					a.Answers = append([]dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: a.Questions[0].Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 120}, Body: &dnsmessage.CNAMEResource{CNAME: terminal}}}, a.Answers...)
					return dohResponse{wire: scopedPack(t, a)}, nil
				})
				if err := r.UseReviewedBaseline(func(context.Context, []byte) ([]byte, error) {
					baseline++
					return nil, errors.New("answer exclusion must not fall back")
				}); err != nil {
					t.Fatal(err)
				}
				err := r.Publish(context.Background(), client, scopedQuery(t, key.host, dnsmessage.TypeA), networkDNSModelPublisher, func([]byte) error { sent++; return nil })
				if excluded {
					if !errors.Is(err, ErrNetworkPolicyDNSExcluded) || sent != 0 {
						t.Fatal("excluded observed CNAME published", err, sent)
					}
				} else if err != nil || sent != 1 {
					t.Fatal("observed CNAME rejected", err, sent)
				}
				if provider != 1 || baseline != 0 || !slices.Contains(classified, name) {
					t.Fatal("CNAME skipped catalog or entered fallback", provider, baseline, classified)
				}
				observations, observationErr := r.Observations(context.Background())
				want := 1 // existing modeled service binding, never a new CNAME grant
				if excluded {
					want = 0
				}
				if observationErr != nil || len(observations) != want {
					t.Fatal("CNAME negative bypassed service ledger check", observations, observationErr)
				}
			})
		}
	}
}

func TestNetworkPolicyDNSObservedHostnameRetainsRuleBoundaries(t *testing.T) {
	r, _ := networkDNSFixture(t)
	store := networkDNSStoredNegatives(t, r, []config.ResourceMatch{{Kind: "exact", Value: "only.example"}, {Kind: "suffix", Value: "blocked.example"}}, nil)
	for _, tc := range []struct {
		name string
		deny bool
	}{{"discordsays.com", false}, {"discordsez.com", false}, {"only.example", true}, {"sub.only.example", false}, {"blocked.example", true}, {"sub.blocked.example", true}, {"notblocked.example", false}, {"blocked.example.attacker.test", false}} {
		t.Run(tc.name, func(t *testing.T) {
			targets, err := r.exclusions.targets(context.Background(), "selected", []string{tc.name}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if denied, err := r.exclusions.observe(context.Background(), targets, nil); err != nil || denied != tc.deny {
				t.Fatal("actual hostname changed stored rule matching", denied, err)
			}
		})
	}
	for _, name := range []string{"discordsays.com", "discordsez.com", "github.io", "appspot.com", "co.uk"} {
		for _, kind := range []string{"exact", "suffix"} {
			manual := []config.ResourceMatch{{Kind: kind, Value: name}}
			if _, err := store.UpdateResourceExclusionsPatch(context.Background(), store.Get(), config.ResourceExclusionsPatch{Manual: &manual}); !errors.Is(err, config.ErrResourceExclusions) {
				t.Fatal("observed hostname became persisted PSL rule", kind, name, err)
			}
		}
	}
	if err := r.exclusions.current(context.Background()); err != nil {
		t.Fatal("rejected rule update changed actual Store", err)
	}
	classified := 0
	r.exclusions.identities = func(context.Context, string) ([]string, error) { classified++; return nil, nil }
	for _, name := range []string{"localhost", "https://discordsays.com", "1.1.1.1", "_service._tcp.example.com", "discordsays.com\xff"} {
		if targets, err := r.exclusions.targets(context.Background(), "selected", []string{name}, nil); err == nil || targets != nil || classified != 0 {
			t.Fatal("malformed observation reached catalog/Store matcher", name, targets, err, classified)
		}
	}
	// Canonical aliases are classified once, including the existing IDNA form.
	var names []string
	r.exclusions.identities = func(_ context.Context, name string) ([]string, error) { names = append(names, name); return nil, nil }
	targets, err := r.exclusions.targets(context.Background(), "selected", []string{"DISCORDSAYS.COM.", "discordsays.com", "пример.рф", "xn--e1afmkfd.xn--p1ai"}, nil)
	if err != nil || !slices.Equal(names, []string{"discordsays.com", "xn--e1afmkfd.xn--p1ai"}) || len(targets) != 2 {
		t.Fatal("observed canonical identity was not deduplicated", names, targets, err)
	}
	if denied, err := r.exclusions.observe(context.Background(), targets, nil); err != nil || denied {
		t.Fatal("canonical actual target rejected by Store matcher", denied, err)
	}
}
