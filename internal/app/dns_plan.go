package app

import (
	"context"
	"errors"
	"slices"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

var errScopedDNSReview = errors.New("DNS_SCOPE_REVIEW_REQUIRED: изменились DNS, сценарий или устройства сервиса; проверьте привязку DNS перед применением")

// A nil change retains current applied DNS. Only the runtime Stop/resume path
// supplies Suspend/Resume. An explicit DNS action supplies the reviewed policy.
type scopedDNSChange struct {
	Explicit bool
	Policy   *dataplane.ScopedDNSPlan
	Suspend  bool
	Resume   bool
	Discard  bool
}

func (a *App) composeScopedDNS(cfg config.Config, previous *dataplane.Plan, in *dataplane.Input, change *scopedDNSChange) error {
	if previous != nil && previous.SuspendDNS && (change == nil || !change.Resume && !change.Discard) {
		// Replacing the stopped journal would lose the sole scope snapshot.
		// A reviewed resume owns that transition; editor drafts remain editable.
		return errScopedDNSReview
	}
	var policy *dataplane.ScopedDNSPlan
	if previous != nil {
		policy = previous.DNS
	}
	if change != nil {
		if change.Discard {
			if !change.Explicit || change.Policy != nil || !cfg.ServiceControl.Stopped || previous == nil || !previous.SuspendDNS || len(in.Routes) != 0 {
				return errScopedDNSReview
			}
			in.DiscardDNS = true
			in.RetiringAdapters = append(in.RetiringAdapters, "dns-scoped")
			policy = nil
		} else if change.Suspend {
			if len(in.Routes) != 0 {
				return errScopedDNSReview
			}
			in.SuspendDNS = policy != nil
			policy = nil
		} else if change.Resume && previous != nil && previous.SuspendDNS {
			if !cfg.ServiceControl.Stopped || a.Dataplane == nil {
				return errScopedDNSReview
			}
			var err error
			policy, err = a.Dataplane.SuspendedDNS(*previous)
			if err != nil {
				return err
			}
		} else if change.Explicit {
			policy = change.Policy
		}
	}
	if policy != nil {
		if len(policy.Bindings) == 0 || a.DNS == nil || a.Dataplane == nil || !a.Dataplane.Capable("dns-scoped") {
			return errScopedDNSReview
		}
		id := policy.Bindings[0].ServiceID
		var route *dataplane.Route
		for i := range in.Routes {
			if in.Routes[i].ServiceID == id {
				route = &in.Routes[i]
				break
			}
		}
		if route == nil {
			// Disabling the service retires its DNS in the same transaction.
			// An explicit DNS/resume action cannot silently drop its own target.
			if change != nil && (change.Explicit || change.Resume) {
				return errScopedDNSReview
			}
			policy = nil
		} else {
			if route.Resolved != "direct" || len(route.Sources) != 1 || route.Sources[0] != policy.Bindings[0].Client+"/32" {
				return errScopedDNSReview
			}
			var service *catalog.Service
			for _, s := range a.catalogSnapshot().Services {
				if s.ID == id {
					copy := s
					service = &copy
					break
				}
			}
			if service == nil || !nodeRecoveryServiceMatches(*route, *service) || !scopedDNSScenarioMatches(*service, policy.Probe) {
				return errScopedDNSReview
			}
			if cfg.ServicePolicies[id].TerminalAction != "" && cfg.ServicePolicies[id].TerminalAction != "direct" {
				return errScopedDNSReview
			}
			for _, b := range policy.Bindings {
				identity, err := a.DNS.ScopedProfileIdentity(b.ProfileID)
				if err != nil || identity != b.ProfileDigest {
					return errScopedDNSReview
				}
			}
			profile, err := a.freshNetworkProfile(context.Background())
			if err != nil {
				return err
			}
			if in.NetworkProfileID != "" && in.NetworkProfileID != profile {
				return dataplane.ErrNetworkChanged
			}
			in.NetworkProfileID = profile
		}
	}
	in.DNS = policy
	if previous != nil && previous.DNS != nil && policy == nil && !slices.Contains(in.RetiringAdapters, "dns-scoped") {
		in.RetiringAdapters = append(in.RetiringAdapters, "dns-scoped")
	}
	if policy != nil || slices.Contains(in.RetiringAdapters, "dns-scoped") {
		capable := a.Dataplane != nil && a.Dataplane.Capable("dns-scoped")
		in.Engines = append(in.Engines, dataplane.Engine{ID: "dns-scoped", Installed: capable, Configured: true, Activatable: capable})
	}
	return nil
}

func scopedDNSScenarioMatches(service catalog.Service, probe catalog.Probe) bool {
	probes := service.Probes
	if len(probes) == 0 && service.ProbeURL != "" {
		probes = []catalog.Probe{{ID: "web", Label: "Web", URL: service.ProbeURL, Required: true}}
	}
	for _, current := range probes {
		if current.Required && current.URL == service.ProbeURL && applyReviewHash(current) == applyReviewHash(probe) {
			return true
		}
	}
	return false
}
