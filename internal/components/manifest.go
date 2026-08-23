package components

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const ManifestSchemaVersion = 1

func init() {
	if err := ValidateManifest(Specs()); err != nil {
		panic(err)
	}
}

// ResourceBudget is deliberately conservative and describes the expected
// steady-state cost of a configured component. It is guidance for preflight,
// not a promise: measured runtime values take precedence in the UI.
type ResourceBudget struct {
	RAMMiB   uint64 `json:"ram_mib,omitempty"`
	FlashMiB uint64 `json:"flash_mib,omitempty"`
	CPUClass string `json:"cpu_class,omitempty"` // light, medium or heavy
}

type Claim struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

type PlanIssue struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	Resolution string `json:"resolution,omitempty"`
}

type PlanStep struct {
	Order   int    `json:"order"`
	Phase   string `json:"phase"`
	Summary string `json:"summary"`
}

type Plan struct {
	SchemaVersion    int            `json:"schema_version"`
	Component        string         `json:"component"`
	Name             string         `json:"name"`
	Action           string         `json:"action"`
	Provider         string         `json:"provider"`
	Package          string         `json:"package,omitempty"`
	Installed        bool           `json:"installed"`
	InstalledVersion string         `json:"installed_version,omitempty"`
	AvailableVersion string         `json:"available_version,omitempty"`
	Ready            bool           `json:"ready"`
	Budget           ResourceBudget `json:"resource_budget"`
	Claims           []Claim        `json:"claims,omitempty"`
	Steps            []PlanStep     `json:"steps"`
	Blockers         []PlanIssue    `json:"blockers,omitempty"`
	Warnings         []PlanIssue    `json:"warnings,omitempty"`
}

func (p *Plan) AddBlocker(code, message, resolution string) {
	p.Blockers = append(p.Blockers, PlanIssue{Code: code, Message: message, Resolution: resolution})
	p.Ready = false
}

var componentIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

func ValidateManifest(specs []Spec) error {
	seen := make(map[string]bool, len(specs))
	for _, spec := range specs {
		if spec.SchemaVersion != ManifestSchemaVersion {
			return fmt.Errorf("component %s uses manifest schema %d, expected %d", spec.ID, spec.SchemaVersion, ManifestSchemaVersion)
		}
		if !componentIDPattern.MatchString(spec.ID) {
			return fmt.Errorf("component has invalid id %q", spec.ID)
		}
		if seen[spec.ID] {
			return fmt.Errorf("component id %q is duplicated", spec.ID)
		}
		seen[spec.ID] = true
		if strings.TrimSpace(spec.Name) == "" || strings.TrimSpace(spec.Description) == "" {
			return fmt.Errorf("component %s has incomplete display metadata", spec.ID)
		}
		switch spec.Provider {
		case "opkg":
			if strings.TrimSpace(spec.Package) == "" {
				return fmt.Errorf("opkg component %s has no fixed package", spec.ID)
			}
		case "github-release":
			if strings.TrimSpace(spec.Repository) == "" || strings.TrimSpace(spec.Binary) == "" {
				return fmt.Errorf("release component %s has incomplete source metadata", spec.ID)
			}
		case "platform", "external":
		default:
			return fmt.Errorf("component %s has unsupported provider %q", spec.ID, spec.Provider)
		}
		switch spec.Budget.CPUClass {
		case "", "light", "medium", "heavy":
		default:
			return fmt.Errorf("component %s has invalid cpu class %q", spec.ID, spec.Budget.CPUClass)
		}
		for _, dependency := range spec.Dependencies {
			if dependency == spec.ID || !componentIDPattern.MatchString(dependency) {
				return fmt.Errorf("component %s has invalid dependency %q", spec.ID, dependency)
			}
		}
	}
	for _, spec := range specs {
		for _, dependency := range spec.Dependencies {
			if !seen[dependency] {
				return fmt.Errorf("component %s references unknown dependency %s", spec.ID, dependency)
			}
		}
	}
	return nil
}

func normalizeManifest(specs []Spec) []Spec {
	out := append([]Spec(nil), specs...)
	for i := range out {
		out[i].Capabilities = append([]string(nil), out[i].Capabilities...)
		out[i].Dependencies = append([]string(nil), out[i].Dependencies...)
		out[i].Claims = append([]Claim(nil), out[i].Claims...)
		sort.Strings(out[i].Capabilities)
		sort.Strings(out[i].Dependencies)
	}
	return out
}
