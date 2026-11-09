package app

import (
	"context"
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/providerprofile"
	"github.com/ArtixSx/razvilka/internal/publicfetch"
)

var errMihomoNodeScope = errors.New("Mihomo requires one explicit VLESS/TCP/TLS node, public IPv4 service prefixes and selected private IPv4 clients")

// Separate syntax from legacy node eligibility: an imported or previously
// healthy node has earned no Mihomo service, TUN or automatic-selection proof.
func mihomoNodeRouteID(route string) (string, bool) {
	id, ok := strings.CutPrefix(route, "mihomo:node-")
	if !ok || len(id) != 64 || id != strings.ToLower(id) {
		return "", false
	}
	if _, err := hex.DecodeString(id); err != nil {
		return "", false
	}
	return "node-" + id, true
}

func mihomoNodeServiceScope(cfg config.Config, service catalog.Service, sources []string) error {
	if cfg.SafeMode || cfg.NetworkPolicy != nil || cfg.AppliedNetworkPolicy != nil {
		return errMihomoNodeScope
	}
	if _, err := config.NormalizeMihomoNodeSources(sources); err != nil {
		return errors.Join(errMihomoNodeScope, err)
	}
	for id, state := range cfg.Services {
		if state.Enabled && id != service.ID {
			return errMihomoNodeScope
		}
	}
	return mihomoNodePublicService(service)
}

func mihomoNodePublicService(service catalog.Service) error {
	if len(service.Domains) != 0 || len(service.CIDRs) == 0 {
		return errMihomoNodeScope
	}
	for _, raw := range service.CIDRs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.String() != raw || !publicfetch.PublicPrefix(prefix) {
			return errMihomoNodeScope
		}
	}
	_, err := dataplane.FrozenProbeService(dataplane.Route{LogicalServiceID: service.ID, ProbeService: &service, ProbeURL: service.ProbeURL})
	return err
}

func (a *App) mihomoNodeEngineFact(ctx context.Context, routes []dataplane.Route) (dataplane.Engine, error) {
	if a.Components == nil || a.Dataplane == nil || !a.Dataplane.MihomoLiveRuntimeRegistered() {
		return dataplane.Engine{}, errMihomoNodeScope
	}
	views, err := a.Components.Observe(ctx)
	if err != nil {
		return dataplane.Engine{}, err
	}
	for _, view := range views {
		if view.ID == "mihomo" && view.Installed && view.InstalledVersion == "1.19.33" && view.InstalledVersionSource == "receipt" {
			supported := false
			if value := ctx.Value(mihomoNodePlanningKey{}); value != nil {
				ticket, ok := value.(*mihomoNodePlanningTicket)
				if !ok {
					return dataplane.Engine{}, dataplane.ErrReviewChanged
				}
				if err := ticket.current(ctx, a, routes); err != nil {
					return dataplane.Engine{}, err
				}
				supported = true
			}
			return dataplane.Engine{ID: "mihomo", Installed: true, Configured: true, Activatable: supported, Canary: supported}, nil
		}
	}
	return dataplane.Engine{}, errMihomoNodeScope
}

func (a *App) reviewMihomoNode(ctx context.Context, route string) (*dataplane.NodeDefaultSourceReview, error) {
	if _, ok := mihomoNodeRouteID(route); !ok || a.Nodes == nil || a.Dataplane == nil || !a.Dataplane.MihomoLiveRuntimeRegistered() {
		return nil, errMihomoNodeScope
	}
	node, err := dataplane.ReviewNodeDefaultSource(ctx, a.Nodes, route)
	if err != nil {
		return nil, err
	}
	err = node.WithMaterial(ctx, func(raw []byte) error {
		profile, err := providerprofile.VLESSProfileFromJSON(raw)
		if err != nil || profile.Transport != "tcp" || profile.Security != "tls" || profile.Insecure {
			return errMihomoNodeScope
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return node, nil
}
