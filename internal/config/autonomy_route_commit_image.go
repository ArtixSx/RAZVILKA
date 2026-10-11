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
