package dnscontrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// ServiceDNSComparison deliberately cannot authorize Apply or credential rotation.
// The snapshot reports DNS answers, not TLS, service semantics or client routing.
type ServiceDNSComparison struct {
	Host             string             `json:"host"`
	Results          []ServiceDNSAnswer `json:"results"`
	CheckedAt        string             `json:"checked_at"`
	ResolutionActor  string             `json:"resolution_actor"`
	RequestPath      string             `json:"request_path"`
	ServiceVerified  bool               `json:"service_verified"`
	RouteVerified    bool               `json:"route_verified"`
	EligibleForApply bool               `json:"eligible_for_apply"`
	Note             string             `json:"note"`
}
type ServiceDNSAnswer struct {
	ProfileID         string   `json:"profile_id"`
	ProviderID        string   `json:"provider_id"`
	Family            string   `json:"family"`
	Transport         string   `json:"transport"`
	Status            string   `json:"status"`
	Addresses         []string `json:"addresses"`
	AnswerFingerprint string   `json:"answer_fingerprint,omitempty"`
	LatencyMS         int64    `json:"latency_ms"`
	ErrorCode         string   `json:"error_code,omitempty"`
}

// CompareServiceDNS reuses the existing strict DoH and DNS wire validator. It
// selects exactly ONE encrypted endpoint per provider; it never falls back to
// UDP53, changes the resolver, or tests a proxy on behalf of the caller.
// The caller supplies a catalog-owned hostname and holds operation admission.
func (m *Manager) CompareServiceDNS(ctx context.Context, profiles []string, hostname string) (ServiceDNSComparison, error) {
	out := ServiceDNSComparison{Results: []ServiceDNSAnswer{}, ResolutionActor: "router", RequestPath: "system-routing-unverified", Note: "Сравнение только DNS A/AAAA по DoH. Адреса назначения, TLS, сервис и путь LAN ещё не проверены. Таймаут DNS не разрешает смену узла или регистрацию WARP."}
	host, err := normalizeCandidateHostname(hostname)
	if err != nil {
		return out, err
	}
	out.Host = host
	if len(profiles) < 1 || len(profiles) > 3 {
		return out, errors.New("выберите от одного до трёх DNS-профилей")
	}
	m.mu.RLock()
	doc := cloneDocument(m.doc)
	exchange := m.candidateExchange
	m.mu.RUnlock()
	if exchange == nil {
		exchange = exchangeCandidateDNS
	}
	type choice struct {
		profile  Profile
		provider Provider
		target   dnsTarget
	}
	choices := make([]choice, 0, len(profiles))
	seen := map[string]bool{}
	// Validate the entire batch before the FIRST external request.
	for _, id := range profiles {
		if seen[id] {
			return out, errors.New("профили не должны повторяться")
		}
		seen[id] = true
		p, ok := profileByID(id)
		if !ok {
			return out, errors.New("неизвестный DNS-профиль")
		}
		provider, ok := providerByIDFor(p.ProviderID, doc)
		if !ok || !provider.Configured || provider.Scope == "negative-control" || provider.TrustedLocal || provider.DoH == "" {
			return out, errors.New("профиль не настроен или не разрешён для публичной DoH-диагностики")
		}
		var target dnsTarget
		found := false
		for _, e := range provider.Endpoints {
			if e.Transport != "doh" {
				continue
			}
			if t, ok := endpointProbeTarget(e, false); ok {
				target = t
				found = true
				break
			}
		}
		if !found {
			return out, errors.New("у профиля нет поддержанного DoH endpoint")
		}
		choices = append(choices, choice{p, provider, target})
	}
	ctx, cancel := context.WithTimeout(ctx, 32*time.Second)
	defer cancel()
	for _, c := range choices {
		for _, f := range []struct {
			name string
			typ  dnsmessage.Type
		}{{"ipv4", dnsmessage.TypeA}, {"ipv6", dnsmessage.TypeAAAA}} {
			if err := ctx.Err(); err != nil {
				return out, err
			}
			started := time.Now()
			addrs, e := exchange(ctx, c.target, host, f.typ)
			a := ServiceDNSAnswer{ProfileID: c.profile.ID, ProviderID: c.provider.ID, Family: f.name, Transport: "doh", Status: "unknown", Addresses: []string{}, LatencyMS: time.Since(started).Milliseconds()}
			if e != nil {
				a.Status = "error"
				a.ErrorCode = "DNS_QUERY_FAILED"
				if errors.Is(e, errDNSAnswer) {
					a.ErrorCode = "DNS_INTEGRITY_FAILED"
				}
			} else {
				unique := map[netip.Addr]bool{}
				unsafe := len(addrs) > 64
				for _, ip := range addrs {
					ip = ip.Unmap()
					if !publicDNSAddress(ip) || f.name == "ipv4" && !ip.Is4() || f.name == "ipv6" && !ip.Is6() {
						unsafe = true
						break
					}
					unique[ip] = true
				}
				if unsafe {
					a.Status = "rejected"
					a.ErrorCode = "DNS_UNSAFE_ANSWER"
				} else {
					for ip := range unique {
						a.Addresses = append(a.Addresses, ip.String())
					}
					sort.Strings(a.Addresses)
					a.Status = "no-address"
					if len(a.Addresses) > 0 {
						a.Status = "resolved"
						sum := sha256.Sum256([]byte(strings.Join(a.Addresses, "\n")))
						a.AnswerFingerprint = "sha256:" + hex.EncodeToString(sum[:])
					}
				}
			}
			out.Results = append(out.Results, a)
		}
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	out.CheckedAt = time.Now().UTC().Format(time.RFC3339)
	return out, nil
}
