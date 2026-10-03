package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/ArtixSx/razvilka/internal/tunnelcheck"
)

// Candidate service probes originate from the temporary tunnel's own address,
// not from a forged LAN-client address. Sources remain unchanged in the plan;
// proving live client selection is a different, required post-Apply check.
func wireGuardCanaryServices(plan RoutePlan, id string) []tunnelcheck.Service {
	var out []tunnelcheck.Service
	for _, r := range plan.Routes {
		if adapterID(r.Resolved) == id && r.ProbeURL != "" {
			out = append(out, tunnelcheck.Service{Name: r.ServiceName, URL: r.ProbeURL})
		}
	}
	return out
}

func (a *WARPWireGuardAdapter) probeCanaryServices(ctx context.Context, plan RoutePlan, root string,
	probe func(context.Context, string, string) error, source string) error {
	services := wireGuardCanaryServices(plan, a.ID())
	if len(services) == 0 {
		return tunnelcheck.ErrNoService
	}
	ports, err := a.warpEndpointPorts()
	if err != nil {
		return err
	}
	var attempted []int
	var lastErr error
	for index, port := range ports {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		attempted = append(attempted, port)
		if index > 0 {
			if _, err := a.switchEndpointPort(ctx, port); err != nil {
				lastErr = err
				continue
			}
		}
		err = tunnelcheck.WireGuard(ctx, services, a.timeout(), a.ID() == "warp-wg",
			func(c context.Context, u string) error { return probe(c, u, source) },
			func(c context.Context) error { return a.confirmHandshake(c, a.interfaceName()) })
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// Once the tunnel is established, an application failure is not a reason
			// to cycle endpoint ports or claim that the WG handshake never happened.
			if errors.Is(err, tunnelcheck.ErrService) {
				return err
			}
			lastErr = err
			continue
		}
		if index > 0 && root != "" {
			endpoint, err := wgEndpoint(string(mustRead(a.RuntimeConfigPath)))
			if err != nil {
				return err
			}
			b, err := json.Marshal(warpWGSelection{Endpoint: endpoint})
			if err != nil {
				return err
			}
			if err = writeAtomic(filepath.Join(root, "selected-endpoint.json"), b, 0o600); err != nil {
				return err
			}
		}
		return nil
	}
	return errors.Join(WARPHandshakeError{Ports: attempted}, lastErr)
}

// The live interface is freshly created after a successful candidate check;
// its handshake starts at zero again when keepalive is disabled. An isolated
// local socket initiates it without forging or removing the LAN source scope.
func (a *WARPWireGuardAdapter) probeLiveWGServices(ctx context.Context, plan Plan, root string) (retErr error) {
	content, err := os.ReadFile(a.RuntimeConfigPath)
	if err != nil {
		return err
	}
	_, addresses, _, err := nativeWGConfig(string(content))
	if err != nil {
		return err
	}
	source, err := firstTunnelAddress(addresses)
	if err != nil {
		return err
	}
	probeAdapter := *a
	probeAdapter.Table, probeAdapter.PriorityBase = 219, 18050
	if root == "" {
		probeAdapter.FallbackPorts = []int{}
	}
	if err := probeAdapter.ensureCanaryPolicyFree(ctx); err != nil {
		return err
	}
	if err := probeAdapter.installCanaryPolicy(ctx, source); err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 8*time.Second)
		defer cancel()
		retErr = errors.Join(retErr, probeAdapter.cleanupCanaryPolicy(cleanup, source))
	}()
	probe := sourceBoundAWGProbe
	if a.ID() == "warp-wg" {
		probe = sourceBoundWARPProbe
	}
	if a.HealthProbe != nil {
		probe = func(ctx context.Context, url, _ string) error { return a.HealthProbe(ctx, url) }
	}
	ctx = context.WithValue(ctx, wgSocketInterfaceKey{}, a.interfaceName())
	return probeAdapter.probeCanaryServices(ctx, plan.RoutePlanFor(a.ID()), root, probe, source.String())
}
