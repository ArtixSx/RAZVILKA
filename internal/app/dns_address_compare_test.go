package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/routeprobe"
)

func TestDNSAndHTTPSComparisonConsentTTLAndNetworkGuard(t *testing.T) {
	for _, mode := range []string{"pass", "expired", "no-ttl", "network-unavailable", "network-changed", "scope-changed", "consent", "too-many"} {
		t.Run(mode, func(t *testing.T) {
			a, send := awgAPITest(t)
			a.DNS, _ = dnscontrol.New("")
			network := "wan-0123456789ab"
			if mode == "network-unavailable" {
				network = ""
			}
			a.FreshProfile = func(context.Context) (string, error) { return network, nil }
			probes, queries := 0, 0
			a.dnsServiceComparer = serviceDNSCompareFunc(func(ctx context.Context, ids []string, host string, guard func(context.Context) error) (dnscontrol.ServiceDNSComparison, error) {
				queries++
				ttl := uint32(30)
				expiry := time.Now().Add(time.Second * 30)
				if mode == "expired" {
					expiry = time.Now().Add(-time.Second)
				}
				answer := dnscontrol.ServiceDNSAnswer{ProfileID: "private", Family: "ipv4", Status: "resolved", Addresses: []string{"1.1.1.1", "8.8.8.8"}, AnswerFingerprint: "sha256:fixture", TTLSeconds: &ttl, ExpiresAt: expiry.Format(time.RFC3339Nano)}
				if mode == "no-ttl" {
					answer.TTLSeconds = nil
				}
				return dnscontrol.ServiceDNSComparison{Host: host, Results: []dnscontrol.ServiceDNSAnswer{answer}}, nil
			})
			a.dnsAddressProbe = func(ctx context.Context, service catalog.Service, ip netip.Addr) routeprobe.DNSAddressResult {
				probes++
				if ip.String() != "1.1.1.1" || service.ID != "arbitrary-site" {
					t.Fatalf("wrong target %s %s", ip, service.ID)
				}
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > 31*time.Second {
					t.Fatal("probe escaped answer lifetime")
				}
				if mode == "network-changed" {
					network = "wan-fedcba987654"
				}
				if mode == "scope-changed" {
					a.Store.SetSafeMode(!a.Store.Get().SafeMode)
				}
				return routeprobe.DNSAddressResult{Address: ip.String(), Status: "pass", TLSVerified: true, ServiceVerified: true, ApplicationPath: "system-routing-unverified"}
			}
			body := map[string]any{"service_id": "arbitrary-site", "profile_ids": []string{"private"}, "config_revision": a.Store.Get().Revision, "confirm": "COMPARE_SERVICE_DNS_AND_HTTPS", "verify_service": true}
			if mode == "consent" {
				body["confirm"] = "COMPARE_SERVICE_DNS"
			}
			if mode == "too-many" {
				body["profile_ids"] = []string{"private", "malw", "xbox-dns"}
			}
			w := send(http.MethodPost, "/api/v1/dns/service-compare", body)
			if mode == "network-unavailable" {
				if w.Code != 503 || queries != 0 || probes != 0 || !strings.Contains(w.Body.String(), "DNS_COMPARE_NETWORK_UNAVAILABLE") {
					t.Fatal("missing network identity not explained", w.Code, w.Body.String())
				}
				return
			}
			if mode == "consent" || mode == "too-many" {
				if w.Code != 400 || queries != 0 || probes != 0 {
					t.Fatal("invalid request performed network IO", w.Code, queries, probes)
				}
				return
			}
			if mode == "network-changed" || mode == "scope-changed" {
				if w.Code != 409 || strings.Contains(w.Body.String(), "address_checks") {
					t.Fatal("stale result published", w.Code, w.Body.String())
				}
				return
			}
			if w.Code != 200 || queries != 1 {
				t.Fatal(w.Code, w.Body.String())
			}
			var response struct {
				Checks []serviceDNSAddressCheck `json:"address_checks"`
				Live   bool                     `json:"live_applied"`
			}
			if json.Unmarshal(w.Body.Bytes(), &response) != nil || len(response.Checks) != 1 || response.Live || response.Checks[0].AddressCount != 2 || response.Checks[0].Result.RouteVerified {
				t.Fatal("invalid proof scope", w.Body.String())
			}
			if mode == "pass" {
				if probes != 1 || !response.Checks[0].Result.ServiceVerified {
					t.Fatal("address was not tested")
				}
			} else if probes != 0 || response.Checks[0].Result.ServiceVerified || response.Checks[0].Result.ErrorCode != "DNS_ANSWER_EXPIRED" {
				t.Fatal("expired DNS answer used")
			}
		})
	}
}

func TestDNSAddressComparisonStopsAfterCanceledProbe(t *testing.T) {
	a := &App{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ttl := uint32(30)
	answer := dnscontrol.ServiceDNSAnswer{Status: "resolved", Addresses: []string{"1.1.1.1"}, TTLSeconds: &ttl, ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339Nano)}
	calls := 0
	a.dnsAddressProbe = func(context.Context, catalog.Service, netip.Addr) routeprobe.DNSAddressResult {
		calls++
		cancel()
		return routeprobe.DNSAddressResult{ServiceVerified: true}
	}
	checks, err := a.compareDNSAddresses(ctx, catalog.Service{}, dnscontrol.ServiceDNSComparison{Results: []dnscontrol.ServiceDNSAnswer{answer, answer}}, func(c context.Context) error { return c.Err() })
	if err == nil || checks != nil || calls != 1 {
		t.Fatal("partial canceled result published", checks, err, calls)
	}
}
