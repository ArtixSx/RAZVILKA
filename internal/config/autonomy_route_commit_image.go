package config

import (
	"errors"
	"time"

	"github.com/ArtixSx/razvilka/internal/routekind"
)

// ReviewedAutonomyRouteCommitImage is comparison data only. The actual writer
// uses this same constructor; a predicted image issues no publication receipt,
// approval, source/probe evidence or runtime permission.
func ReviewedAutonomyRouteCommitImage(before Config, id, route string, sources []string, appliedAt time.Time) (Config, error) {
	valid := routekind.IsExecutor(route)
	if _, node, exact := routekind.ParseNodeRoute(route); exact && validPolicyNode(node) {
		valid = true
	}
	if !policyIdentifier.MatchString(id) || !valid {
		return Config{}, errors.New("invalid autonomous route")
	}
	normalized, err := NormalizeSources(sources)
	if err != nil {
		return Config{}, err
	}
	if appliedAt.IsZero() || before.Revision == ^uint64(0) || before.SafeMode || before.ServiceControl.Stopped || before.ServiceControl.EffectiveMode() == "manual" {
		return Config{}, ErrRevisionChanged
	}
	next := cloneConfig(before)
	desired := next.Services[id]
	desired.Enabled, desired.Route, desired.Mode = true, route, route
	desired.WireGuardProfileRevision = ""
	desired.Sources = normalized
	next.Services[id], next.AppliedServices[id] = desired, desired
	// Only the target's superseded manual/legacy authority is fenced. Foreign
	// drafts, policies, applied scope, negatives and approval remain exact.
	fenceServicePolicy(&next, id, route, normalized)
	next.Revision++
	next.AppliedRevision = next.Revision
	next.LastAppliedAt = appliedAt.UTC().Format(time.RFC3339)
	return next, nil
}

// The first Home route publishes its exact applied scope together with the
// verified service. Existing/suspended routes require their original owner.
func ReviewedInitialHomeXrayCommitImage(before Config, id, route string, sources []string, appliedAt time.Time) (Config, error) {
	engine, _, exact := routekind.ParseNodeRoute(route)
	p := before.NetworkPolicy
	if !exact || engine != "xray" || len(sources) != 0 || before.AppliedNetworkPolicy != nil ||
		!CurrentDefaultRouteScopeConsent(before) || ValidateAppliedNetworkPolicy(p) != nil ||
		p.Clients.Mode != "lan_except" || p.Clients.NewDevices != "inherit" || len(p.Clients.SegmentIDs) != 1 ||
		p.Traffic.Mode != "selected_services" || len(before.ServiceControl.SuspendedServices) != 0 || len(before.ServiceControl.SuspendedRoutes) != 0 {
		return Config{}, ErrRevisionChanged
	}
	target := normalizeState(before.Services[id])
	if !target.Enabled || target.Route != "auto" && target.Route != route || len(target.Sources) != 0 {
		return Config{}, ErrRevisionChanged
	}
	for other, service := range before.Services {
		if other != id && service.Enabled && normalizeState(service).Route != "direct" {
			return Config{}, ErrRevisionChanged
		}
	}
	for _, applied := range before.AppliedServices {
		if applied.Enabled {
			return Config{}, ErrRevisionChanged
		}
	}
	next, err := ReviewedAutonomyRouteCommitImage(before, id, route, nil, appliedAt)
	if err != nil {
		return Config{}, err
	}
	next.AppliedNetworkPolicy = CloneNetworkPolicy(p)
	return next, nil
}
