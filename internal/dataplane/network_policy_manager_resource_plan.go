package dataplane

import "slices"

func cloneExecutionResourcePlan(plan Plan) Plan {
	plan.LAN = CloneLANPolicyRuntime(plan.LAN)
	plan.DomainPolicy = CloneDomainPolicyRuntimePlan(plan.DomainPolicy)
	plan.SyntheticDNS = CloneSyntheticDNSTransportPlan(plan.SyntheticDNS)
	if plan.DNS != nil {
		dns := *plan.DNS
		dns.Bindings = slices.Clone(dns.Bindings)
		dns.Probe.Expect.StatusCodes = slices.Clone(dns.Probe.Expect.StatusCodes)
		dns.Probe.Expect.RedirectHosts = slices.Clone(dns.Probe.Expect.RedirectHosts)
		dns.Probe.Expect.ContentTypes = slices.Clone(dns.Probe.Expect.ContentTypes)
		dns.Probe.Expect.JSONFields = slices.Clone(dns.Probe.Expect.JSONFields)
		dns.Probe.Expect.BodyContains = slices.Clone(dns.Probe.Expect.BodyContains)
		plan.DNS = &dns
	}
	plan.Routes = cloneNetworkPolicyRoutes(plan.Routes)
	plan.EngineDrafts = slices.Clone(plan.EngineDrafts)
	plan.ResourceConflicts = slices.Clone(plan.ResourceConflicts)
	for i := range plan.ResourceConflicts {
		plan.ResourceConflicts[i].Engines = slices.Clone(plan.ResourceConflicts[i].Engines)
	}
	plan.Adapters = slices.Clone(plan.Adapters)
	plan.RetiringAdapters = slices.Clone(plan.RetiringAdapters)
	plan.CanaryAdapters = slices.Clone(plan.CanaryAdapters)
	plan.Actions = slices.Clone(plan.Actions)
	plan.Blockers = slices.Clone(plan.Blockers)
	plan.Warnings = slices.Clone(plan.Warnings)
	plan.RouteEvidence = slices.Clone(plan.RouteEvidence)
	plan.Protocol = slices.Clone(plan.Protocol)
	return plan
}
