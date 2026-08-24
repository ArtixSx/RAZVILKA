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
	ID       string `json:"id"`
	Label    string `json:"label"`
	URL      string `json:"url"`
	Required bool   `json:"required"`
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
		}
		if len(s.Probes) > 0 && requiredProbes == 0 {
			return fmt.Errorf("service %s has no required probe", s.ID)
		}
	}
	return nil
}
