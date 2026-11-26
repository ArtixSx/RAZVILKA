package app

import (
	"context"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
)

const installProgressPath = "/api/v1/components/install-progress"
const installProgressHeader = "X-Razvilka-Install-ID"
const maxInstallReports = 16
const maxInstallEvents = 32

type installEvent struct {
	At      time.Time `json:"at"`
	Message string    `json:"message"`
}

type installReport struct {
	id     string
	events []installEvent
}
type installProgress struct {
	mu      sync.Mutex
	reports []*installReport // insertion order, newest last
}

func validInstallID(id string) bool {
	if len(id) != 32 || strings.ToLower(id) != id {
		return false
	}
	var decoded [16]byte
	_, err := hex.Decode(decoded[:], []byte(id))
	return err == nil
}

func (p *installProgress) findLocked(id string) *installReport {
	for _, r := range p.reports {
		if r.id == id {
			return r
		}
	}
	return nil
}

func (p *installProgress) begin(ctx context.Context, id string) context.Context {
	if !validInstallID(id) {
		return ctx
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	// Duplicate client IDs must never interleave two requests' evidence.
	if p.findLocked(id) != nil {
		return ctx
	}
	if len(p.reports) == maxInstallReports {
		p.reports = p.reports[1:]
	}
	r := &installReport{id: id, events: []installEvent{{At: time.Now().UTC(), Message: components.InstallPreflight.Message()}}}
	p.reports = append(p.reports, r)
	return components.WithInstallProgress(ctx, func(stage components.InstallStage) { p.record(r, stage) })
}

func (p *installProgress) record(r *installReport, stage components.InstallStage) {
	message := stage.Message()
	if message == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(r.events) > 0 && r.events[len(r.events)-1].Message == message {
		return
	}
	if len(r.events) == maxInstallEvents {
		r.events = r.events[1:]
	}
	r.events = append(r.events, installEvent{At: time.Now().UTC(), Message: message})
}

func (p *installProgress) snapshot(id string) []installEvent {
	p.mu.Lock()
	defer p.mu.Unlock()
	events := []installEvent{}
	if r := p.findLocked(id); r != nil {
		events = append(events, r.events...)
	}
	return events
}

func (a *App) componentInstallProgress(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if a.Security == nil || !a.Security.Authenticated(r) {
		http.Error(w, "administrator login is required", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": a.installProgress.snapshot(r.Header.Get(installProgressHeader))})
}
