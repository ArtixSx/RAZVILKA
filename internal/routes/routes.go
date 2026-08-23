package routes

import (
	"github.com/ArtixSx/razvilka/internal/engine"
	"strings"
)

type Option struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Description string `json:"description"`
	Installed   bool   `json:"installed"`
	Running     bool   `json:"running"`
	Selectable  bool   `json:"selectable"`
	Ready       bool   `json:"ready"`
}

func Options() []Option {
	out := []Option{
		{ID: "auto", Name: "AUTO", Kind: "policy", Description: "RAZVILKA выбирает рабочий маршрут", Installed: true, Running: true, Selectable: true, Ready: true},
		{ID: "direct", Name: "DIRECT", Kind: "direct", Description: "Без обхода", Installed: true, Running: true, Selectable: true, Ready: true},
	}
	for _, e := range engine.Visible((engine.Detector{}).Inventory()) {
		selectable := e.RuntimeReady
		out = append(out, Option{ID: e.ID, Name: e.Name, Kind: e.Kind, Description: e.Description, Installed: e.Installed, Running: e.Running, Selectable: selectable, Ready: selectable && e.Running})
	}
	return out
}

func Valid(id string) bool {
	return ValidWithOptions(id, Options())
}

func ValidWithOptions(id string, options []Option) bool {
	if id == "" {
		return false
	}
	base, _, profiled := strings.Cut(id, ":")
	// Profile routes are accepted only after a profile registry can prove that
	// the referenced node exists. Accepting syntactically valid but unresolved
	// IDs would make AUTO and isolated probes report a route they cannot use.
	if profiled {
		return false
	}

	selectable := false
	for _, option := range options {
		if option.ID == base && option.Selectable {
			selectable = true
			break
		}
	}
	if !selectable {
		return false
	}
	return true
}

func ReadyWithOptions(id string, options []Option) bool {
	if strings.Contains(id, ":") {
		return false
	}
	for _, option := range options {
		if option.ID == id {
			return option.Ready
		}
	}
	return false
}

func validProfile(profile string) bool {
	if len(profile) == 0 || len(profile) > 64 || !isAlphaNumeric(profile[0]) {
		return false
	}
	for i := 1; i < len(profile); i++ {
		c := profile[i]
		if !isAlphaNumeric(c) && c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

func isAlphaNumeric(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}
