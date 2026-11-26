package catalog

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
)

var serviceIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

type Service struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Category    string      `json:"category"`
	Icon        string      `json:"icon"`
	Description string      `json:"description"`
	Domains     []string    `json:"domains"`
	CIDRs       []string    `json:"cidrs,omitempty"`
	Strategy    []string    `json:"strategy"`
	ProbeURL    string      `json:"probe_url,omitempty"`
	Probes      []Probe     `json:"probes,omitempty"`
	SourceRefs  []string    `json:"source_refs,omitempty"`
	Note        string      `json:"note,omitempty"`
	Provenance  *Provenance `json:"provenance,omitempty"`
}

// Probe is a fixed, catalog-owned service scenario. The browser may select a
// service ID, but it can never supply these URLs, which keeps Test Lab from
// becoming an arbitrary request primitive on the router.
type Probe struct {
	ID       string           `json:"id"`
	Label    string           `json:"label"`
	URL      string           `json:"url"`
	Required bool             `json:"required"`
	Expect   ProbeExpectation `json:"expect,omitempty"`
}

// ProbeExpectation describes the minimum service semantics that must be
// observed before a route is called working. Empty expectations intentionally
// keep a safe web default: final HTTP 2xx on a service-owned host and no known
// block page.
type ProbeExpectation struct {
	StatusCodes    []int    `json:"status_codes,omitempty"`
	RedirectPolicy string   `json:"redirect_policy,omitempty"` // same-service (default), none, allowlist
	RedirectHosts  []string `json:"redirect_hosts,omitempty"`
	ContentTypes   []string `json:"content_types,omitempty"`
	JSON           bool     `json:"json,omitempty"`
	JSONFields     []string `json:"json_fields,omitempty"`
	BodyContains   []string `json:"body_contains,omitempty"`
}

type Provenance struct {
	Provider  string `json:"provider"`
	EntryID   string `json:"entry_id"`
	URL       string `json:"url"`
	License   string `json:"license,omitempty"`
	SHA256    string `json:"sha256"`
	FetchedAt string `json:"fetched_at"`
}
type Catalog struct {
	Services []Service `json:"services"`
}

func Load(path string) (Catalog, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Catalog{}, err
	}
	var c Catalog
	if err := json.Unmarshal(b, &c); err != nil {
		return Catalog{}, err
	}
	if err := Validate(c); err != nil {
		return Catalog{}, err
	}
	return c, nil
}
func Validate(c Catalog) error {
	seen := map[string]bool{}
	for _, s := range c.Services {
		if s.ID == "" || s.Name == "" || s.Category == "" {
			return fmt.Errorf("service requires id/name/category")
		}
		if !serviceIDPattern.MatchString(s.ID) {
			return fmt.Errorf("service %q has invalid id", s.ID)
		}
		if seen[s.ID] {
			return fmt.Errorf("duplicate service id %q", s.ID)
		}
		seen[s.ID] = true
		if len(s.Strategy) == 0 {
			return fmt.Errorf("service %s has empty strategy", s.ID)
		}
		for _, d := range s.Domains {
			if strings.ContainsAny(d, " /\\:") || !strings.Contains(d, ".") || strings.HasPrefix(d, ".") || strings.HasSuffix(d, ".") {
				return fmt.Errorf("service %s invalid domain %q", s.ID, d)
			}
		}
		for _, cidr := range s.CIDRs {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				return fmt.Errorf("service %s invalid cidr %q", s.ID, cidr)
			}
		}
		if s.ProbeURL != "" {
			u, err := url.Parse(s.ProbeURL)
			if err != nil || u.Scheme != "https" || u.Host == "" {
				return fmt.Errorf("service %s invalid probe url", s.ID)
			}
		}
		probeIDs := map[string]bool{}
		requiredProbes := 0
		for _, probe := range s.Probes {
			if !serviceIDPattern.MatchString(probe.ID) || strings.TrimSpace(probe.Label) == "" {
				return fmt.Errorf("service %s has invalid probe identity", s.ID)
			}
			if probeIDs[probe.ID] {
				return fmt.Errorf("service %s has duplicate probe %q", s.ID, probe.ID)
			}
			probeIDs[probe.ID] = true
			if probe.Required {
				requiredProbes++
			}
			u, err := url.Parse(probe.URL)
			if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
				return fmt.Errorf("service %s has invalid probe %q URL", s.ID, probe.ID)
			}
			if err := validateProbeExpectation(s.ID, probe); err != nil {
				return err
			}
		}
		if len(s.Probes) > 0 && requiredProbes == 0 {
			return fmt.Errorf("service %s has no required probe", s.ID)
		}
	}
	return nil
}

func validateProbeExpectation(serviceID string, probe Probe) error {
	switch probe.Expect.RedirectPolicy {
	case "", "same-service", "none", "allowlist":
	default:
		return fmt.Errorf("service %s probe %s has invalid redirect policy", serviceID, probe.ID)
	}
	if probe.Expect.RedirectPolicy == "allowlist" && len(probe.Expect.RedirectHosts) == 0 {
		return fmt.Errorf("service %s probe %s redirect allowlist is empty", serviceID, probe.ID)
	}
	for _, status := range probe.Expect.StatusCodes {
		if status < 200 || status > 299 {
			return fmt.Errorf("service %s probe %s has invalid HTTP status %d", serviceID, probe.ID, status)
		}
	}
	for _, host := range probe.Expect.RedirectHosts {
		host = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(host)), "*.")
		if host == "" || strings.ContainsAny(host, " /\\:") || !strings.Contains(host, ".") {
			return fmt.Errorf("service %s probe %s has invalid redirect host", serviceID, probe.ID)
		}
	}
	for _, contentType := range probe.Expect.ContentTypes {
		if strings.TrimSpace(contentType) == "" || strings.ContainsAny(contentType, "\r\n") {
			return fmt.Errorf("service %s probe %s has invalid content type", serviceID, probe.ID)
		}
	}
	for _, field := range probe.Expect.JSONFields {
		if strings.TrimSpace(field) == "" {
			return fmt.Errorf("service %s probe %s has empty JSON field predicate", serviceID, probe.ID)
		}
	}
	if len(probe.Expect.JSONFields) > 0 && !probe.Expect.JSON {
		return fmt.Errorf("service %s probe %s JSON fields require the JSON predicate", serviceID, probe.ID)
	}
	for _, marker := range probe.Expect.BodyContains {
		if strings.TrimSpace(marker) == "" {
			return fmt.Errorf("service %s probe %s has empty body predicate", serviceID, probe.ID)
		}
	}
	return nil
}
