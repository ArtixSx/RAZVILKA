package app

import (
	"net"
	"net/http"
	"net/netip"
	"sort"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

// Read-only suggestions. The apply worker independently verifies LAN ownership.
type scopedDNSView struct {
	Available  bool                 `json:"available"`
	State      string               `json:"state"`
	Revision   uint64               `json:"config_revision"`
	ServiceID  string               `json:"service_id,omitempty"`
	ProfileID  string               `json:"profile_id,omitempty"`
	Client     string               `json:"client,omitempty"`
	Listener   string               `json:"listener,omitempty"`
	Ingress    string               `json:"ingress,omitempty"`
	Profiles   []string             `json:"profile_ids"`
	Candidates []scopedDNSCandidate `json:"candidates"`
}
type scopedDNSCandidate struct {
	ServiceID string `json:"service_id"`
	Client    string `json:"client"`
}
type dnsPanelSnapshot struct {
	dnscontrol.Snapshot
	Scoped scopedDNSView `json:"scoped"`
}

func (a *App) dnsPanelSnapshot(r *http.Request) dnsPanelSnapshot {
	v := dnsPanelSnapshot{Snapshot: a.DNS.Snapshot(), Scoped: scopedDNSView{State: "unavailable", Profiles: []string{}, Candidates: []scopedDNSCandidate{}}}
	if a.Store == nil || a.Dataplane == nil || !a.Dataplane.Capable("dns-scoped") {
		return v
	}
	cfg := a.Store.Get()
	v.Scoped.Available, v.Scoped.Revision, v.Scoped.State = true, cfg.Revision, "unknown"
	for _, p := range v.Profiles {
		if _, err := a.DNS.ScopedProfileIdentity(p.ID); err == nil {
			v.Scoped.Profiles = append(v.Scoped.Profiles, p.ID)
		}
	}
	previous, exists, err := a.Dataplane.Committed()
	if err != nil || !exists || previous.State != "committed" || previous.Revision != cfg.AppliedRevision {
		return v
	}
	v.Scoped.State = "empty"
	policy := previous.DNS
	if previous.SuspendDNS {
		policy, err = a.Dataplane.SuspendedDNS(previous)
		if err != nil {
			v.Scoped.State = "unknown"
			return v
		}
	}
	if policy != nil && len(policy.Bindings) > 0 {
		b := policy.Bindings[0]
		v.Scoped.ServiceID, v.Scoped.ProfileID, v.Scoped.Client = b.ServiceID, b.ProfileID, b.Client
		v.Scoped.Listener, v.Scoped.Ingress = policy.Listener, policy.Ingress
		v.Scoped.State = "configured" // A saved policy is not a live health assertion.
		if previous.SuspendDNS || cfg.ServiceControl.Stopped {
			v.Scoped.State = "stopped"
		}
	}
	if cfg.ServiceControl.Stopped {
		return v
	}
	for id, s := range cfg.AppliedServices {
		if !s.Enabled || s.Route != "direct" || len(s.Sources) != 1 {
			continue
		}
		p, err := netip.ParsePrefix(s.Sources[0])
		if err != nil || !p.Addr().Is4() || !p.Addr().IsPrivate() || p.Bits() != 32 {
			continue
		}
		v.Scoped.Candidates = append(v.Scoped.Candidates, scopedDNSCandidate{ServiceID: id, Client: p.Addr().String()})
	}
	sort.Slice(v.Scoped.Candidates, func(i, j int) bool { return v.Scoped.Candidates[i].ServiceID < v.Scoped.Candidates[j].ServiceID })
	if v.Scoped.Listener == "" {
		host, _, _ := net.SplitHostPort(r.Host)
		address, err := netip.ParseAddr(host)
		if err == nil && address.Is4() && address.IsPrivate() {
			interfaces, _ := net.Interfaces()
			for _, iface := range interfaces {
				if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
					continue
				}
				addresses, _ := iface.Addrs()
				for _, a := range addresses {
					if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr() == address {
						v.Scoped.Listener, v.Scoped.Ingress = net.JoinHostPort(host, "10553"), iface.Name
					}
				}
			}
		}
	}
	return v
}
