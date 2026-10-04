package dataplane

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
	"github.com/ArtixSx/razvilka/internal/usquediag"
)

var errOwnedUSQUELiveHealth = errors.New("fresh owned USQUE live health is required")

// Only local fixtures replace these callbacks. Production uses the same owned
// observer/producer as Canary, against the actual live usque-engine process.
type usqueLiveHealthIO struct {
	observe func(context.Context, usquediag.OwnedRuntimeRequest) (usquediag.OwnedRuntimeIdentity, error)
	produce usqueOwnedProducer
}

// probeOwnedUSQUELive is an explicit guarded health action, never a GET reader.
// The caller supplies the exact selected transport: staged during Health, or
// committed during Reconcile. It checks forwarding/runtime policy separately.
// No saved evidence is read, refreshed, promoted or written by this function.
func (a *ProxyTunnelAdapter) probeOwnedUSQUELive(ctx context.Context, plan RoutePlan, transport usqueTransport) (usquediag.CanaryEvidence, error) {
	return a.probeOwnedUSQUELiveWith(ctx, plan, transport, usqueLiveHealthIO{})
}

func (a *ProxyTunnelAdapter) probeOwnedUSQUELiveWith(ctx context.Context, plan RoutePlan, transport usqueTransport, inspect usqueLiveHealthIO) (usquediag.CanaryEvidence, error) {
	var empty usquediag.CanaryEvidence
	if err := requireOwnedUSQUEReviewGuard(ctx); err != nil {
		return empty, err
	}
	if a == nil || a.ID() != "usque" || a.FreshProfile == nil || a.Processes == nil || plan.Adapter != "usque" ||
		len(plan.Routes) == 0 || len(plan.Routes) > 64 || !filepath.IsAbs(a.StateRoot) || filepath.Clean(a.StateRoot) != a.StateRoot {
		return empty, errOwnedUSQUELiveHealth
	}
	// Detach the full predicates and scope before callbacks can mutate callers.
	plan.Routes = cloneNetworkPolicyRoutes(plan.Routes)
	plan.LAN = CloneLANPolicyRuntime(plan.LAN)
	window, cancel := context.WithTimeout(ctx, min(a.timeout(), 30*time.Second))
	defer cancel()
	ctx = window
	spec := a.engineProcessWithTransport(transport)
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(a.SOCKSPort))
	protocol, err := ownedUSQUELiveTransport(spec, address)
	if err != nil {
		return empty, err
	}
	authority := func(c context.Context) error {
		if err := requireOwnedUSQUEReviewGuard(c); err != nil {
			return err
		}
		if err := checkAddressRefreshAuthority(c); err != nil {
			return err
		}
		if err := verifyNetworkProfile(c, plan.NetworkProfileID, a.FreshProfile); err != nil {
			return err
		}
		if !a.Processes.Running(spec) {
			return errOwnedUSQUELiveHealth
		}
		return c.Err()
	}
	if err := authority(ctx); err != nil {
		return empty, err
	}
	semantic := plan
	semantic.Routes = nil
	var services []catalog.Service
	for _, route := range plan.Routes {
		if route.Resolved != "usque" {
			return empty, errOwnedUSQUELiveHealth
		}
		if route.NetworkPolicyRole == "default" {
			if _, err := plan.FrozenLAN(); err != nil {
				return empty, err
			}
			// A sealed default requests only the explicit owned WARP trace.
			// It never becomes a catalog ConfirmedRoute or a LAN/UDP proof.
			continue
		}
		service, err := FrozenProbeService(route)
		if err != nil {
			return empty, err
		}
		semantic.Routes = append(semantic.Routes, route)
		services = append(services, service)
	}
	probes, err := ownedUSQUECandidateServices(ctx, semantic, services)
	if err != nil {
		return empty, err
	}
	root, err := ownedfs.Open(spec.Dir)
	if err != nil {
		return empty, errOwnedUSQUELiveHealth
	}
	defer root.Close()
	config, err := root.ReadLimited("engine.json", 8<<20)
	if err != nil {
		return empty, errOwnedUSQUELiveHealth
	}
	defer clear(config)
	endpoint, err := usquediag.SelectedOwnedUSQUEEndpoint(config, protocol)
	if err != nil {
		return empty, errOwnedUSQUELiveHealth
	}
	request := usquediag.OwnedRuntimeRequest{Root: spec.Dir, Binary: spec.Binary, SOCKSAddress: address,
		Transport: protocol, Endpoint: endpoint, Environment: usquediag.OwnedUSQUEEnvironment(a.FreshProfile)}
	if inspect.observe == nil {
		inspect.observe = usquediag.ObserveOwnedUSQUE
	}
	if inspect.produce == nil {
		inspect.produce = usquediag.ProbeOwnedUSQUE
	}
	if err := authority(ctx); err != nil {
		return empty, err
	}
	before, err := inspect.observe(ctx, request)
	environment, environmentErr := request.Environment(ctx)
	argv := append([]string{spec.Binary}, spec.Args...)
	argsHash := routeidentity.Hash([]byte(strings.Join(argv, "\x00") + "\x00"))
	if err != nil || environmentErr != nil || before.EnvironmentID != environment || before.Transport != protocol || before.Endpoint != endpoint.String() ||
		before.SessionSHA256 != routeidentity.Hash(config) || before.ArgsSHA256 != argsHash {
		return empty, errOwnedUSQUELiveHealth
	}
	if err := authority(ctx); err != nil {
		return empty, err
	}
	started := time.Now()
	proof, err := inspect.produce(ctx, usquediag.OwnedProbeOptions{Enabled: true, Runtime: request,
		Network:   usquediag.OwnedNetworkRequest{SOCKSAddress: address, Services: append([]usquediag.OwnedServiceProbe(nil), probes...), Timeout: min(a.timeout(), 20*time.Second)},
		Authority: authority})
	if err != nil {
		return empty, err
	}
	if err := authority(ctx); err != nil {
		return empty, err
	}
	after, err := inspect.observe(ctx, request)
	if err != nil || after != before || proof.Identity != after {
		return empty, errOwnedUSQUELiveHealth
	}
	if err := authority(ctx); err != nil {
		return empty, err
	}
	now := time.Now()
	checked, err := time.Parse(time.RFC3339Nano, proof.CheckedAt)
	if err != nil || checked.Before(started) || now.Before(started) || now.Sub(started) > 30*time.Second ||
		!usquediag.OwnedEvidenceFresh(proof, after, now) || !ownedUSQUECandidateGrades(probes, proof) {
		return empty, errOwnedUSQUELiveHealth
	}
	return proof.CanaryEvidence(), nil
}

// Validate the actual active ProcessSpec; do not alias it to a Canary process.
func ownedUSQUELiveTransport(spec ProcessSpec, address string) (string, error) {
	if !filepath.IsAbs(spec.Binary) || filepath.Clean(spec.Dir) != spec.Dir || validateProcessSpec(spec) != nil || spec.ID != "usque-engine" || !spec.RouteProof ||
		spec.MatchArg != filepath.Join(spec.Dir, "engine.json") || spec.PIDPath != filepath.Join(spec.Dir, "engine.pid") || spec.LogPath != filepath.Join(spec.Dir, "engine.log") {
		return "", errOwnedUSQUELiveHealth
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || host != "127.0.0.1" {
		return "", errOwnedUSQUELiveHealth
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1024 || number > 65535 || strconv.Itoa(number) != port {
		return "", errOwnedUSQUELiveHealth
	}
	prefix := []string{"-c", spec.MatchArg, "socks", "-b", "127.0.0.1", "-p", port, "--always-reconnect", "-S"}
	if len(spec.Args) < len(prefix) || len(spec.Args) > len(prefix)+3 {
		return "", errOwnedUSQUELiveHealth
	}
	for i, value := range prefix {
		if spec.Args[i] != value {
			return "", errOwnedUSQUELiveHealth
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
	return "", errOwnedUSQUELiveHealth
}
