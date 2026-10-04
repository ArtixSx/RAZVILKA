package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/publicfetch"
	"github.com/ArtixSx/razvilka/internal/usquediag"
)

// This adapter-private seam is only replaceable by local fixtures. Production
// always defaults to the independently owned runtime/network producer.
type usqueOwnedProducer func(context.Context, usquediag.OwnedProbeOptions) (usquediag.OwnedRuntimeEvidence, error)

var errOwnedUSQUECandidate = errors.New("exact owned USQUE candidate proof is required")

// An active producer cannot acquire authority from an omitted review guard.
// The same helper is used by the caller before starting the candidate process.
func requireOwnedUSQUEReviewGuard(ctx context.Context) error {
	if ctx == nil {
		return errOwnedUSQUECandidate
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	guard, ok := ctx.Value(reviewGuardKey{}).(func(context.Context) error)
	if !ok || guard == nil {
		return errOwnedUSQUECandidate
	}
	if err := guard(ctx); err != nil {
		return err
	}
	return ctx.Err()
}

// services comes only from the trusted, frozen plan catalog accessor. It is
// deliberately explicit: neither a current catalog lookup nor a builtin/default
// URL may fill missing criteria after the plan was reviewed.
func (a *ProxyTunnelAdapter) probeOwnedUSQUECandidate(ctx context.Context, plan RoutePlan, spec ProcessSpec, address string, services []catalog.Service) (usquediag.CanaryEvidence, error) {
	var empty usquediag.CanaryEvidence
	if err := requireOwnedUSQUEReviewGuard(ctx); err != nil {
		return empty, err
	}
	if a == nil || a.ID() != "usque" || plan.Adapter != "usque" || a.FreshProfile == nil {
		return empty, errOwnedUSQUECandidate
	}
	transport, err := ownedUSQUECandidateTransport(spec, address)
	if err != nil {
		return empty, err
	}
	probeCtx, cancel := context.WithTimeout(ctx, min(a.timeout(), 30*time.Second))
	defer cancel()
	probes, err := ownedUSQUECandidateServices(probeCtx, plan, services)
	if err != nil {
		return empty, err
	}
	root, err := ownedfs.Open(spec.Dir)
	if err != nil {
		return empty, errOwnedUSQUECandidate
	}
	defer root.Close()
	config, err := root.ReadLimited("engine.json", 8<<20)
	if err != nil {
		return empty, errOwnedUSQUECandidate
	}
	defer clear(config)
	endpoint, err := usquediag.SelectedOwnedUSQUEEndpoint(config, transport)
	if err != nil {
		return empty, errOwnedUSQUECandidate
	}
	timeout := min(a.timeout(), 20*time.Second)
	options := usquediag.OwnedProbeOptions{
		Enabled: true,
		Runtime: usquediag.OwnedRuntimeRequest{
			Root: spec.Dir, Binary: spec.Binary, SOCKSAddress: address,
			Transport: transport, Endpoint: endpoint,
			Environment: usquediag.OwnedUSQUEEnvironment(a.FreshProfile),
		},
		Network:   usquediag.OwnedNetworkRequest{SOCKSAddress: address, Services: append([]usquediag.OwnedServiceProbe(nil), probes...), Timeout: timeout},
		Authority: requireOwnedUSQUEReviewGuard,
	}
	producer := a.ownedUSQUEProbe
	if producer == nil {
		producer = usquediag.ProbeOwnedUSQUE
	}
	if err := requireOwnedUSQUEReviewGuard(probeCtx); err != nil {
		return empty, err
	}
	proof, err := producer(probeCtx, options)
	if err != nil {
		return empty, err
	}
	if err := requireOwnedUSQUEReviewGuard(probeCtx); err != nil {
		return empty, err
	}
	// The producer alone owns runtime capture. This check verifies its returned
	// shape and exact requested grades; it does not observe or adopt a receipt.
	if proof.Identity.Transport != transport || proof.Identity.Endpoint != endpoint.String() ||
		!usquediag.OwnedEvidenceFresh(proof, proof.Identity, time.Now()) ||
		!ownedUSQUECandidateGrades(probes, proof) {
		return empty, errOwnedUSQUECandidate
	}
	return proof.CanaryEvidence(), nil
}

func ownedUSQUECandidateTransport(spec ProcessSpec, address string) (string, error) {
	endpoint, err := netip.ParseAddrPort(address)
	if err != nil || endpoint.Addr().String() != "127.0.0.1" || endpoint.Port() < 1024 || endpoint.String() != address ||
		!filepath.IsAbs(spec.Dir) || filepath.Clean(spec.Dir) != spec.Dir || !filepath.IsAbs(spec.Binary) ||
		spec.ID != "usque-canary" || !spec.RouteProof || spec.MatchArg != filepath.Join(spec.Dir, "engine.json") ||
		spec.PIDPath != filepath.Join(spec.Dir, "engine.pid") || spec.LogPath != filepath.Join(spec.Dir, "engine.log") {
		return "", errOwnedUSQUECandidate
	}
	prefix := []string{"-c", spec.MatchArg, "socks", "-b", "127.0.0.1", "-p", strconv.Itoa(int(endpoint.Port())), "--always-reconnect", "-S"}
	if len(spec.Args) < len(prefix) || len(spec.Args) > len(prefix)+3 {
		return "", errOwnedUSQUECandidate
	}
	for i, value := range prefix {
		if spec.Args[i] != value {
			return "", errOwnedUSQUECandidate
		}
	}
	tail := spec.Args[len(prefix):]
	if len(tail) >= 2 && tail[0] == "-s" && safeSNI.MatchString(tail[1]) {
		tail = tail[2:]
	}
	if len(tail) == 0 {
		return "QUIC", nil
	}
	if len(tail) == 1 && tail[0] == "--http2" {
		return "HTTP/2", nil
	}
	return "", errOwnedUSQUECandidate
}

func ownedUSQUECandidateServices(ctx context.Context, plan RoutePlan, services []catalog.Service) ([]usquediag.OwnedServiceProbe, error) {
	if len(plan.Routes) != len(services) || len(services) > 8 {
		return nil, errOwnedUSQUECandidate
	}
	probes := make([]usquediag.OwnedServiceProbe, 0, len(services))
	seen := make(map[string]bool, len(services))
	for i, service := range services {
		route := plan.Routes[i]
		frozen, err := FrozenProbeService(route)
		if err != nil || frozen.ID != service.ID || route.ProbeURL != service.ProbeURL || !ownedUSQUECandidateURL(service.ProbeURL) || seen[service.ID] {
			return nil, errOwnedUSQUECandidate
		}
		predicate, err := newProxyServicePredicate(service)
		if err != nil {
			return nil, err
		}
		expected, err := newProxyServicePredicate(frozen)
		if err != nil || expected.digest() != predicate.digest() {
			return nil, errOwnedUSQUECandidate
		}
		seen[service.ID] = true
		id, hash := service.ID, predicate.digest()
		probes = append(probes, usquediag.OwnedServiceProbe{ID: id, URL: service.ProbeURL,
			Validator: func(response usquediag.OwnedServiceResponse) error {
				return predicate.evaluateSample(ctx, id, response.URL, hash, response.HTTPStatus, response.ContentType, response.Body, response.BodyTruncated)
			},
		})
	}
	return probes, nil
}

func ownedUSQUECandidateURL(raw string) bool {
	if len(raw) > 2048 || publicfetch.ValidateURL(raw) != nil || strings.ContainsAny(raw, "\r\n\x00") {
		return false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.RawFragment != "" {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	for _, suffix := range []string{".internal", ".home", ".corp", ".onion", ".invalid", ".test"} {
		if strings.HasSuffix(host, suffix) {
			return false
		}
	}
	if literal, err := netip.ParseAddr(parsed.Hostname()); err == nil && (literal.Is4In6() || literal.Zone() != "" || literal.String() != parsed.Hostname()) {
		return false
	}
	return true
}

func ownedUSQUECandidateGrades(probes []usquediag.OwnedServiceProbe, proof usquediag.OwnedRuntimeEvidence) bool {
	if len(proof.ReachableRoutes) != len(probes) || len(proof.ConfirmedRoutes) != len(probes) || len(proof.ChallengeRoutes) != 0 || proof.UDPForwarding {
		return false
	}
	expected := make(map[string]bool, len(probes))
	for _, probe := range probes {
		expected[probe.ID] = true
	}
	for _, routes := range [][]string{proof.ReachableRoutes, proof.ConfirmedRoutes} {
		seen := make(map[string]bool, len(routes))
		for _, id := range routes {
			if !expected[id] || seen[id] {
				return false
			}
			seen[id] = true
		}
	}
	return true
}
