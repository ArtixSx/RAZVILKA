package dnscontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

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
		{"public-ip-not-host", []string{"private"}, "1.1.1.1"}, {"local-zone", []string{"private"}, "home.arpa"},
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

func TestServiceDNSComparisonValidatesRealHTTPSReplies(t *testing.T) {
	for _, mode := range []string{"addresses", "nodata", "nxdomain", "wrong-id", "wrong-question", "private-address", "broken-authority", "broken-additional"} {
		t.Run(mode, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				wire, err := io.ReadAll(r.Body)
				var query dnsmessage.Message
				if err != nil || query.Unpack(wire) != nil || r.Method != http.MethodPost {
					http.Error(w, "invalid test query", http.StatusBadRequest)
					return
				}
				q := query.Questions[0]
				reply := dnsmessage.Message{Header: dnsmessage.Header{ID: query.ID, Response: true}, Questions: query.Questions}
				if mode == "nxdomain" {
					reply.RCode = dnsmessage.RCodeNameError
				}
				if mode != "nodata" && mode != "nxdomain" {
					rr := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: q.Class, TTL: 30}}
					if q.Type == dnsmessage.TypeA {
						address := [4]byte{1, 1, 1, 1}
						if mode == "private-address" {
							address = [4]byte{10, 0, 0, 1}
						}
						rr.Body = &dnsmessage.AResource{A: address}
					} else {
						rr.Body = &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2606:4700:4700::1111").As16()}
					}
					reply.Answers = []dnsmessage.Resource{rr}
				}
				if mode == "wrong-id" {
					reply.ID++
				} else if mode == "wrong-question" {
					reply.Questions[0].Name = dnsmessage.MustNewName("other.example.")
				}
				wire, _ = reply.Pack()
				if mode == "broken-authority" {
					wire[9] = 1 // Claim a missing authority RR after a valid answer.
				} else if mode == "broken-additional" {
					wire[11] = 1
				}
				w.Header().Set("Content-Type", "application/dns-message")
				_, _ = w.Write(wire)
			}))
			defer server.Close()
			m, _ := New("")
			m.candidateExchange = func(ctx context.Context, target dnsTarget, host string, family dnsmessage.Type) ([]netip.Addr, error) {
				target.probe = func(ctx context.Context, _ string, wire []byte, _ bool) ([]byte, error) {
					r, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL, bytes.NewReader(wire))
					if err != nil {
						return nil, err
					}
					response, err := server.Client().Do(r)
					if err != nil {
						return nil, err
					}
					defer response.Body.Close()
					return io.ReadAll(io.LimitReader(response.Body, 65536))
				}
				return exchangeCandidateDNS(ctx, target, host, family)
			}
			out, err := m.CompareServiceDNS(context.Background(), []string{"private"}, "example.org")
			if err != nil || requests.Load() != 2 || len(out.Results) != 2 || out.ServiceVerified || out.RouteVerified || out.EligibleForApply {
				t.Fatalf("comparison failed or claimed evidence: %+v %v", out, err)
			}
			want := "error"
			switch mode {
			case "addresses":
				want = "resolved"
			case "nodata":
				want = "no-address"
			case "nxdomain":
				want = "nxdomain"
			case "private-address":
				want = "rejected"
			}
			if out.Results[0].Status != want || want == "error" && out.Results[0].ErrorCode != "DNS_INTEGRITY_FAILED" {
				t.Fatalf("wrong real wire result: %+v", out.Results[0])
			}
		})
	}
}

func TestServiceDNSComparisonStopsBetweenQueriesOnChangedContext(t *testing.T) {
	for _, change := range []string{"guard", "provider", "canceled-before", "deadline"} {
		t.Run(change, func(t *testing.T) {
			m, _ := New("")
			if err := m.SetCustomProvider(CustomProviderInput{Name: "fixture", DoH: "https://dns.example.org/dns-query"}); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if change == "canceled-before" {
				cancel()
			} else if change == "deadline" {
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(ctx, 20*time.Millisecond)
				defer stop()
			}
			calls := 0
			m.candidateExchange = func(ctx context.Context, _ dnsTarget, _ string, _ dnsmessage.Type) ([]netip.Addr, error) {
				calls++
				if change == "provider" {
					if err := m.SetCustomProvider(CustomProviderInput{Name: "fixture changed", DoH: "https://other.example.org/dns-query"}); err != nil {
						t.Fatal(err)
					}
				} else if change == "deadline" {
					<-ctx.Done()
					return nil, ctx.Err()
				}
				return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
			}
			guard := func(context.Context) error {
				if change == "guard" && calls > 0 {
					return ErrServiceDNSChanged
				}
				return nil
			}
			out, err := m.CompareServiceDNSGuarded(ctx, []string{"custom", "private"}, "example.org", guard)
			want := ErrServiceDNSChanged
			wantCalls := 1
			if change == "canceled-before" {
				want, wantCalls = context.Canceled, 0
			} else if change == "deadline" {
				want = context.DeadlineExceeded
			}
			if !errors.Is(err, want) || calls != wantCalls || out.CheckedAt != "" {
				t.Fatalf("continued or completed stale comparison: calls=%d err=%v result=%+v", calls, err, out)
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

func TestServiceDNSCustomMetadataRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns.json")
	m, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SetCustomProvider(CustomProviderInput{Name: "fixture", DoH: "https://dns.example.org/dns-query"}); err != nil {
		t.Fatal(err)
	}
	before, _ := providerByIDFor("custom", m.doc)
	if before.Kind != "custom" || before.Trust != "user-configured" || before.AllowedForAutoPilot || before.AllowedForUSQUE || before.ServiceHintsVerified {
		t.Fatal("configured custom provider lost trust metadata or gained authority")
	}
	reloaded, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := providerByIDFor("custom", reloaded.doc)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("custom provider metadata changed on reload")
	}
	view := reloaded.Snapshot()
	for index := range view.Providers {
		if len(view.Providers[index].ServiceHints) != 0 {
			view.Providers[index].ServiceHints[0] = "modified-fixture"
		}
	}
	for _, provider := range reloaded.Snapshot().Providers {
		for _, hint := range provider.ServiceHints {
			if hint == "modified-fixture" {
				t.Fatal("mutable snapshot leaked into provider metadata")
			}
		}
	}
}
