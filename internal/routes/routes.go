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
}

func Options() []Option {
	out := []Option{
		{ID: "auto", Name: "AUTO", Kind: "policy", Description: "RAZVILKA выбирает рабочий маршрут", Installed: true, Running: true, Selectable: true},
		{ID: "direct", Name: "DIRECT", Kind: "direct", Description: "Без обхода", Installed: true, Running: true, Selectable: true},
	}
	for _, e := range (engine.Detector{}).All() {
		out = append(out, Option{ID: e.ID, Name: e.Name, Kind: e.Kind, Description: e.Description, Installed: e.Installed, Running: e.Running, Selectable: e.Installed})
	}
	return out
}

func Valid(id string) bool {
	if id == "" {
		return false
	}
	for _, o := range Options() {
		if o.ID == id {
			return true
		}
	}
	for _, p := range []string{"sing-box:", "xray:", "usque:", "warp:", "awg:"} {
		if strings.HasPrefix(id, p) && len(id) > len(p) {
			return true
		}
	}
	return false
}
