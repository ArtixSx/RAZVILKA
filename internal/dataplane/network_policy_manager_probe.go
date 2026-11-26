package dataplane

import (
	"errors"

	"github.com/ArtixSx/razvilka/internal/catalog"
)

var ErrNetworkPolicyProbe = errors.New("frozen catalog service and exact selected probe are required")

// FrozenProbeService binds a synthetic policy cell to its original catalog
// identity and complete selected scenario. The full payload is sealed by the
// input/plan digest. The accepted shared predicate compiler additionally owns
// an independent defensive copy and validates its complete semantic hash.
// A DEFAULT transport probe is not a catalog service availability assertion.
func FrozenProbeService(route Route) (catalog.Service, error) {
	if route.ProbeService == nil || route.NetworkPolicyRole == "default" {
		return catalog.Service{}, ErrNetworkPolicyProbe
	}
	id := route.LogicalServiceID
	if id == "" {
		if route.NetworkPolicyGeneration != "" {
			return catalog.Service{}, ErrNetworkPolicyProbe
		}
		id = route.ServiceID
	}
	if route.ProbeService.ID != id || route.ProbeURL != route.ProbeService.ProbeURL {
		return catalog.Service{}, ErrNetworkPolicyProbe
	}
	predicate, err := newProxyServicePredicate(*route.ProbeService)
	if err != nil || !predicate.matches(id, route.ProbeURL) {
		return catalog.Service{}, errors.Join(ErrNetworkPolicyProbe, err)
	}
	return copyProxyPredicateService(predicate.service), nil
}
