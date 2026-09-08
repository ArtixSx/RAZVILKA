package routes

import (
	"github.com/ArtixSx/razvilka/internal/engine"
)

type Option struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Description string `json:"description"`
	Installed   bool   `json:"installed"`
	Configured  bool   `json:"configured"`
	Running     bool   `json:"running"`
	Selectable  bool   `json:"selectable"`
	Ready       bool   `json:"ready"`
	// Services is empty for ordinary engine routes. Node-scoped routes list
	// the services for which an exact, unexpired canary exists on this WAN.
	Services []string `json:"services,omitempty"`
}

func Options() []Option {
	out := []Option{
		{ID: "auto", Name: "AUTO", Kind: "policy", Description: "RAZVILKA выбирает рабочий маршрут", Installed: true, Running: true, Selectable: true, Ready: true},
		{ID: "direct", Name: "DIRECT", Kind: "direct", Description: "Без обхода", Installed: true, Running: true, Selectable: true, Ready: true},
	}
	for _, e := range engine.Visible((engine.Detector{}).Inventory()) {
		selectable := e.RuntimeReady
		out = append(out, Option{ID: e.ID, Name: e.Name, Kind: e.Kind, Description: e.Description, Installed: e.Installed, Configured: e.Configured, Running: e.Running, Selectable: selectable, Ready: selectable && e.Running})
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
	for _, option := range options {
		if option.ID == id && option.Selectable {
			return true
		}
	}
	// A profiled route is valid only when the registry supplied that exact ID.
	// Never fall back from sing-box:unknown to the base engine option.
	return false
}

func ReadyWithOptions(id string, options []Option) bool {
	for _, option := range options {
		if option.ID == id {
			return option.Ready
		}
	}
	return false
}

func ValidForServiceWithOptions(id, serviceID string, options []Option) bool {
	for _, option := range options {
		if option.ID != id || !option.Selectable {
			continue
		}
		if len(option.Services) == 0 {
			return true
		}
		for _, allowed := range option.Services {
			if allowed == serviceID {
				return true
			}
		}
		return false
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
