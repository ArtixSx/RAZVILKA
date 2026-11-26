package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"

	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

// The trusted verifier must originate two actual LAN client HTTPS requests to
// the same pinned service address. It is never populated from HTTP JSON, a
// loopback SOCKS check, or a local source impersonation. Until supplied, scoped
// Xray cannot be validated/accepted. RuntimeID fences process restarts.
type NodeTUNRequest struct {
	EngineID       string
	NetworkProfile string
	RuntimeID      string
	Interface      string
	Route          Route
	Destination    netip.Addr
}

type NodeTUNObservation struct {
	RuntimeID       string
	SelectedSource  netip.Addr
	ControlSource   netip.Addr
	SelectedEgress  netip.Addr
	ControlEgress   netip.Addr
	ServiceAccepted bool
}

type NodeTUNProbe func(context.Context, NodeTUNRequest) (NodeTUNObservation, error)

func (a *ProxyTunnelAdapter) scopedNodeHealth(ctx context.Context, plan Plan, state PolicyState, roots ...string) error {
	if a.nodeRouterVerifier {
		root := ""
		if len(roots) > 0 {
			root = roots[0]
		}
		if err := a.scopedNodeRouterHealth(ctx, plan, state, root); err != nil {
			return err
		}
		if a.NodeTUNProbe == nil {
			return nil
		}
	}
	if a.NodeTUNProbe == nil {
		return ErrNodeTUNProofRequired
	}
	if err := a.verifyScopedNodeInterface(ctx); err != nil {
		return err
	}
	m, err := a.checkScopedNodeState(ctx, plan)
	if err != nil {
		return err
	}
	before, err := a.scopedRuntimeIdentity()
	if err != nil {
		return err
	}
	manifestBytes, _ := json.Marshal(m)
	for _, route := range m.Routes {
		addresses, err := resolveNodeServiceIPv4(ctx, route.ProbeURL, a.Resolver)
		if err != nil {
			return err
		}
		for _, destination := range addresses {
			copyRoute := route
			copyRoute.Domains = append([]string{}, route.Domains...)
			copyRoute.CIDRs = append([]string{}, route.CIDRs...)
			copyRoute.Sources = append([]string{}, route.Sources...)
			request := NodeTUNRequest{EngineID: "xray", NetworkProfile: m.NetworkProfile, RuntimeID: before, Interface: a.Interface, Route: copyRoute, Destination: destination}
			observation, err := a.NodeTUNProbe(ctx, request)
			if err != nil {
				return errors.New("selected/control TUN probe unavailable")
			}
			if observation.RuntimeID != before || !observation.ServiceAccepted || !publicNodeAddresses([]netip.Addr{observation.SelectedEgress, observation.ControlEgress}) || observation.SelectedEgress == observation.ControlEgress || !observation.SelectedSource.IsValid() || !observation.ControlSource.IsValid() || observation.SelectedSource == observation.ControlSource {
				return ErrNodeTUNProofRequired
			}
			selected := false
			for _, source := range route.Sources {
				prefix, err := netip.ParsePrefix(source)
				if err == nil && prefix.Contains(observation.SelectedSource) {
					selected = true
				}
			}
			if !selected {
				return errors.New("TUN selected client differs from route scope")
			}
			for _, other := range m.Routes {
				for _, source := range other.Sources {
					prefix, err := netip.ParsePrefix(source)
					if err != nil || prefix.Contains(observation.ControlSource) {
						return errors.New("TUN control client is inside selected scope")
					}
				}
			}
			if err := a.verifyNodeClientRoute(ctx, state, observation.SelectedSource, destination, true); err != nil {
				return err
			}
			if err := a.verifyNodeClientRoute(ctx, state, observation.ControlSource, destination, false); err != nil {
				return err
			}
		}
	}
	after, err := a.scopedRuntimeIdentity()
	if err != nil || after != before {
		return errors.New("scoped live runtime changed across TUN probes")
	}
	current, err := a.checkScopedNodeState(ctx, plan)
	if err != nil {
		return err
	}
	currentBytes, _ := json.Marshal(current)
	if routeidentity.Hash(currentBytes) != routeidentity.Hash(manifestBytes) {
		return errors.New("scoped manifest changed across TUN probes")
	}
	if err := a.verifyHealthRuntime(ctx, state); err != nil {
		return err
	}
	if err := a.verifyScopedNodeInterface(ctx); err != nil {
		return err
	}
	return a.checkPlanNetwork(ctx, plan)
}

func (a *ProxyTunnelAdapter) verifyNodeClientRoute(ctx context.Context, state PolicyState, source, destination netip.Addr, selected bool) error {
	ingress, err := policySourceIngress(ctx, a.Runner, a.ip(), source, a.Interface)
	if err != nil {
		return err
	}
	args := []string{"route", "get", destination.String(), "from", source.String(), "iif", ingress}
	if destination.Is6() {
		args = append([]string{"-6"}, args...)
	}
	output, err := a.run(ctx, a.ip(), args...)
	if err != nil || len(output) > 4096 {
		return errors.New("TUN client route readback unavailable")
	}
	fields := strings.Fields(string(output))
	device := ""
	for i, v := range fields {
		if v == "dev" && i+1 < len(fields) {
			if device != "" {
				return errors.New("ambiguous TUN client route")
			}
			device = fields[i+1]
		}
	}
	if device == "" || (device == a.Interface) != selected {
		return errors.New("selected/control client routing is unconfirmed")
	}
	return ctx.Err()
}
