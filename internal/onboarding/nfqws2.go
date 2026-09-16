// Package onboarding prepares first-setup permissions. It performs no network
// or filesystem writes; the app commits the returned maps with its policy CAS.
package onboarding

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"sort"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
)

// State has exactly the JSON shape of config.ServiceState, including omitted fields.
type State struct {
	Enabled bool     `json:"enabled"`
	Mode    string   `json:"mode,omitempty"`
	Route   string   `json:"route,omitempty"`
	Sources []string `json:"sources,omitempty"`
}
type ConfigView struct {
	Revision        uint64
	Services        map[string]State
	AppliedServices map[string]State
	ServicePolicies map[string]bool
	ServiceControl  struct {
		SuspendedServices map[string]State
		SuspendedRoutes   map[string]string
	}
}

var ErrStarterChanged = errors.New("starter review changed")

type StarterItem struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Domains int    `json:"domains"`
}
type StarterReview struct {
	Eligible       bool          `json:"eligible"`
	Route          string        `json:"route"`
	SHA256         string        `json:"sha256"`
	Items          []StarterItem `json:"items"`
	Skipped        int           `json:"skipped"`
	ConfigRevision uint64        `json:"config_revision"`
}

func digest(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func untouched(cfg ConfigView, id string) bool {
	s, exists := cfg.Services[id]
	if exists && (s.Enabled || len(s.Sources) != 0 || s.Route != "" && s.Route != "nfqws2" || s.Mode != "" && s.Mode != "nfqws2") {
		return false
	}
	if _, exists = cfg.AppliedServices[id]; exists {
		return false
	}
	if _, exists = cfg.ServicePolicies[id]; exists {
		return false
	}
	if _, exists = cfg.ServiceControl.SuspendedServices[id]; exists {
		return false
	}
	if _, exists = cfg.ServiceControl.SuspendedRoutes[id]; exists {
		return false
	}
	return true
}

func Starter(c catalog.Catalog, cfg ConfigView, p autonomy.Policy, managed map[string]autonomy.Service) StarterReview {
	r := StarterReview{Route: "nfqws2", ConfigRevision: cfg.Revision, Items: []StarterItem{}}
	if p.SetupComplete {
		return r
	}
	known := map[string]bool{}
	for _, s := range c.Services {
		if !catalog.IsNFQWS2Starter(s) {
			continue
		}
		if known[s.ID] {
			return StarterReview{Route: "nfqws2", Items: []StarterItem{}}
		}
		known[s.ID] = true
		if _, present := managed[s.ID]; present || !untouched(cfg, s.ID) {
			r.Skipped++
			continue
		}
		r.Items = append(r.Items, StarterItem{ID: s.ID, Name: s.Name, Domains: len(s.Domains)})
	}
	sort.Slice(r.Items, func(i, j int) bool { return r.Items[i].ID < r.Items[j].ID })
	r.Eligible = len(r.Items) > 0
	if r.Eligible {
		r.SHA256 = digest(struct {
			Catalog catalog.Catalog
			Config  ConfigView
			Policy  autonomy.Policy
			Managed map[string]autonomy.Service
			Review  StarterReview
		}{c, cfg, p, managed, r})
	}
	return r
}

// Enroll joins exactly the reviewed, untouched default definitions to the first
// setup. Existing desired/applied selections and all other services are retained.
func Enroll(c catalog.Catalog, cfg ConfigView, old, next autonomy.Policy, managed map[string]autonomy.Service, runtime map[string]autonomy.Runtime, review string, extras []string) (map[string]autonomy.Service, map[string]autonomy.Runtime, error) {
	r := Starter(c, cfg, old, managed)
	if !r.Eligible || review == "" || review != r.SHA256 || !next.SetupComplete || autonomy.Validate(next) != nil {
		return nil, nil, ErrStarterChanged
	}
	if len(managed)+len(r.Items)+len(extras) > autonomy.MaxServices {
		return nil, nil, ErrStarterChanged
	}
	services := make(map[string]autonomy.Service, len(managed)+len(r.Items))
	observations := make(map[string]autonomy.Runtime, len(runtime)+len(r.Items))
	for id, s := range managed {
		s.Sources = slices.Clone(s.Sources)
		services[id] = s
	}
	for id, v := range runtime {
		observations[id] = v.Clone()
	}
	byID := map[string]catalog.Service{}
	for _, s := range c.Services {
		byID[s.ID] = s
	}
	sources, err := normalizeSources(next.DefaultSources)
	if err != nil {
		return nil, nil, err
	}
	// Optional definitions are separate explicit choices, never the whole catalogue.
	seenExtras := map[string]bool{}
	for _, id := range extras {
		definition, ok := byID[id]
		if !ok || !autonomy.ValidID(id) || catalog.IsNFQWS2Starter(definition) || seenExtras[id] || !untouched(cfg, id) {
			return nil, nil, ErrStarterChanged
		}
		if _, exists := managed[id]; exists {
			return nil, nil, ErrStarterChanged
		}
		seenExtras[id] = true
		services[id] = autonomy.Service{ID: id, Enabled: true, AllLAN: next.AllLAN, Sources: slices.Clone(sources), Definition: digest(definition), DraftFingerprint: digest(cfg.Services[id]), ExpectedRoute: "auto"}
		observations[id] = autonomy.Runtime{State: "pending", Message: "Дополнительный сервис выбран явно. Ожидает проверки и подбора разрешённого пути."}
	}
	for _, item := range r.Items {
		id := item.ID
		services[id] = autonomy.Service{ID: id, Enabled: true, AllLAN: next.AllLAN, Sources: slices.Clone(sources), Definition: digest(byID[id]), DraftFingerprint: digest(cfg.Services[id]), ExpectedRoute: "nfqws2"}
		observations[id] = autonomy.Runtime{State: "pending", Message: "Базовый сервис назначен NFQWS2. Ожидается проверка и применение в выбранной области."}
	}
	return services, observations, nil
}

// Match the stored canonical source strings; do not expand an address to a subnet.
func normalizeSources(input []string) ([]string, error) {
	seen := map[string]bool{}
	result := []string{}
	for _, text := range input {
		value := ""
		if p, e := netip.ParsePrefix(text); e == nil {
			value = p.Masked().String()
		} else if ip, e := netip.ParseAddr(text); e == nil {
			value = netip.PrefixFrom(ip.Unmap(), ip.Unmap().BitLen()).String()
		} else {
			return nil, ErrStarterChanged
		}
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result, nil
}
