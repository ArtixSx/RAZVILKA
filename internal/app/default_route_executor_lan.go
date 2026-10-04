package app

import (
	"slices"
	"strings"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// LAN returns the exact frozen shared gate for this policy generation. It is
// intent for the same Manager transaction, never evidence of installed rules.
func (c *DefaultRouteCompilation) LAN() *dataplane.LANPolicyRuntimePlan {
	if c == nil {
		return nil
	}
	return dataplane.CloneLANPolicyRuntime(c.lan)
}

func defaultRouteCompileLAN(generation string, gates []DefaultRouteIngress) (*dataplane.LANPolicyRuntimePlan, error) {
	var ingress []dataplane.LANPolicyIngress
	for _, gate := range gates {
		g := dataplane.LANPolicyIngress{SegmentID: gate.SegmentID, Interface: gate.Interface, Membership: "all"}
		if len(gate.IncludedMACs) > 0 {
			g.Membership = "mac"
		}
		for _, prefix := range gate.Sources {
			g.Sources = append(g.Sources, prefix.String())
		}
		for _, prefix := range gate.ExcludedSources {
			g.ExcludedSources = append(g.ExcludedSources, prefix.String())
		}
		g.IncludedMACs = defaultRouteLANMACs(gate.IncludedMACs)
		g.ExcludedMACs = defaultRouteLANMACs(gate.ExcludedMACs)
		ingress = append(ingress, g)
	}
	return dataplane.CompileLANPolicyRuntime(generation, ingress)
}

func defaultRouteLANMACs(values []string) []string {
	result := slices.Clone(values)
	for i := range result {
		result[i] = strings.ToUpper(result[i])
	}
	return result
}
