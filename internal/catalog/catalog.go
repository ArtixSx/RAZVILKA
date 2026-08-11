package catalog

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
)

type Service struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	Icon        string   `json:"icon"`
	Description string   `json:"description"`
	Domains     []string `json:"domains"`
	CIDRs       []string `json:"cidrs,omitempty"`
	Strategy    []string `json:"strategy"`
	ProbeURL    string   `json:"probe_url,omitempty"`
	SourceRefs  []string `json:"source_refs,omitempty"`
	Note        string   `json:"note,omitempty"`
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
		if seen[s.ID] {
			return fmt.Errorf("duplicate service id %q", s.ID)
		}
		seen[s.ID] = true
		if len(s.Strategy) == 0 {
			return fmt.Errorf("service %s has empty strategy", s.ID)
		}
		for _, d := range s.Domains {
			if strings.ContainsAny(d, " /\\") || !strings.Contains(d, ".") {
				return fmt.Errorf("service %s invalid domain %q", s.ID, d)
			}
		}
		if s.ProbeURL != "" {
			u, err := url.Parse(s.ProbeURL)
			if err != nil || u.Scheme != "https" || u.Host == "" {
				return fmt.Errorf("service %s invalid probe url", s.ID)
			}
		}
	}
	return nil
}
