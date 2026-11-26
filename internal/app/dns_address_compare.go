package app

import (
	"context"
	"net/netip"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/routeprobe"
)

type serviceDNSAddressCheck struct {
	ProfileID         string                      `json:"profile_id"`
	Family            string                      `json:"family"`
	AnswerFingerprint string                      `json:"answer_fingerprint"`
	AddressCount      int                         `json:"address_count"`
	Result            routeprobe.DNSAddressResult `json:"result"`
}

// One address per reported family, at most two providers per user request.
// Unprobed siblings never inherit its result. This remains diagnostic only.
func (a *App) compareDNSAddresses(ctx context.Context, service catalog.Service, dns dnscontrol.ServiceDNSComparison, guard func(context.Context) error) ([]serviceDNSAddressCheck, error) {
	if len(dns.Results) > 4 {
		return nil, dnscontrol.ErrServiceDNSInvalid
	}
	out := make([]serviceDNSAddressCheck, 0, len(dns.Results))
	probe := a.dnsAddressProbe
	if probe == nil {
		probe = routeprobe.ProbeDNSAddress
	}
	for _, answer := range dns.Results {
		if err := guard(ctx); err != nil {
			return nil, err
		}
		if answer.Status != "resolved" || len(answer.Addresses) == 0 {
			continue
		}
		ip, err := netip.ParseAddr(answer.Addresses[0])
		if err != nil {
			return nil, dnscontrol.ErrServiceDNSInvalid
		}
		result := routeprobe.DNSAddressResult{Address: ip.String(), ApplicationPath: "system-routing-unverified", Status: "not-checked", ErrorCode: "DNS_ANSWER_EXPIRED"}
		expiry, err := time.Parse(time.RFC3339Nano, answer.ExpiresAt)
		if err == nil && answer.TTLSeconds != nil && *answer.TTLSeconds > 0 && time.Now().Before(expiry) {
			probeCtx, cancel := context.WithDeadline(ctx, expiry)
			result = probe(probeCtx, service, ip)
			cancel()
		}
		if err := guard(ctx); err != nil {
			return nil, err
		}
		out = append(out, serviceDNSAddressCheck{ProfileID: answer.ProfileID, Family: answer.Family, AnswerFingerprint: answer.AnswerFingerprint, AddressCount: len(answer.Addresses), Result: result})
	}
	return out, nil
}
