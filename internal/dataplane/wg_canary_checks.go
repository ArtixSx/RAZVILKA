package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"

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
		if index > 0 {
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
