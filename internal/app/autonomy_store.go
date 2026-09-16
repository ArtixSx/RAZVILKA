package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/providerfeed"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

const autonomyOwner = "razvilka-autonomy-v1"
const maxAutonomyBytes = 256 << 10

type autonomyDocument struct {
	Schema      int                         `json:"schema"`
	Owner       string                      `json:"owner"`
	Policy      autonomy.Policy             `json:"policy"`
	Services    map[string]autonomy.Service `json:"services"`
	Runtime     map[string]autonomy.Runtime `json:"runtime"`
	Maintenance map[string]string           `json:"maintenance"`
}
type autonomyState struct {
	mu                  sync.Mutex
	loaded              bool
	blocked             bool
	path                string
	image               restorejournal.Image
	doc                 autonomyDocument
	refillState         providerfeed.RefillDecision
	maintenanceMessage  string
	maintenanceAttempts map[string]maintenanceAttempt
	maintenanceTestRun  func(context.Context, string, autonomy.Window, bool) (bool, bool, string)
}

func newAutonomyDocument() autonomyDocument {
	return autonomyDocument{Schema: 1, Owner: autonomyOwner, Policy: autonomy.Default(), Services: map[string]autonomy.Service{}, Runtime: map[string]autonomy.Runtime{}, Maintenance: map[string]string{}}
}
func decodeAutonomy(data []byte) (autonomyDocument, error) {
	var d autonomyDocument
	if len(data) == 0 || len(data) > maxAutonomyBytes {
		return d, restorejournal.ErrInvalid
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if dec.Decode(&d) != nil || dec.Decode(&struct{}{}) != io.EOF || d.Schema != 1 || d.Owner != autonomyOwner || autonomy.Validate(d.Policy) != nil || len(d.Services) > autonomy.MaxServices || len(d.Runtime) > autonomy.MaxServices || len(d.Maintenance) > 2 {
		return d, restorejournal.ErrInvalid
	}
	for id, s := range d.Services {
		if !autonomy.ValidID(id) || s.ID != id || autonomy.ValidateScope(s.AllLAN, s.Sources) != nil || len(s.DraftFingerprint) != 64 || strings.Trim(s.DraftFingerprint, "0123456789abcdef") != "" || len(s.Definition) != 64 || strings.Trim(s.Definition, "0123456789abcdef") != "" || len(s.ExpectedRoute) > 192 {
			return d, restorejournal.ErrInvalid
		}
	}
	for id, r := range d.Runtime {
		if _, ok := d.Services[id]; !ok || len(r.State) > 64 || len(r.Message) > 512 || len(r.Reserves) > 4 || len(r.Switches) > 20 || r.Cursor < 0 || r.Cursor > 1000000 || r.Failures < 0 || r.Failures > 2 || len(r.Network) > 128 {
			return d, restorejournal.ErrInvalid
		}
		for _, node := range r.Reserves {
			if len(node) != 69 || !strings.HasPrefix(node, "node-") || strings.Trim(node[5:], "0123456789abcdef") != "" {
				return d, restorejournal.ErrInvalid
			}
		}
	}
	for key, value := range d.Maintenance {
		if key != "application" && key != "components" || len(value) > 64 {
			return d, restorejournal.ErrInvalid
		}
	}
	if d.Services == nil {
		d.Services = map[string]autonomy.Service{}
	}
	if d.Runtime == nil {
		d.Runtime = map[string]autonomy.Runtime{}
	}
	if d.Maintenance == nil {
		d.Maintenance = map[string]string{}
	}
	return d, nil
}

// The sidecar deliberately does not change the rc.2 config schema. It contains
// only local consent/references, no keys. An old release ignores this feature.
// Private profile imports do NOT import consent; the wizard must authorize it.
func (a *App) loadAutonomy(ctx context.Context) error {
	r := &a.autonomy
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.loaded {
		if r.blocked {
			return restorejournal.ErrRecovery
		}
		return nil
	}
	if a.Store == nil {
		return errors.New("configuration unavailable")
	}
	r.path = a.Store.AutomationStatePath() + ".autonomy.json"
	image, e := restorejournal.ReadFileImage(ctx, r.path)
	if e != nil {
		return e
	}
	d := newAutonomyDocument()
	if image.Exists {
		d, e = decodeAutonomy(image.Data)
		if e != nil {
			r.loaded = true
			r.blocked = true
			return e
		}
	}
	r.image, r.doc, r.loaded = image, d, true
	// Old observations are not reused as PASS or as a failure quorum after boot.
	for id, entry := range r.doc.Runtime {
		entry.NextCheck = time.Time{}
		entry.Failures = 0
		entry.FirstFailure = time.Time{}
		entry.LastFailure = time.Time{}
		entry.State = "pending"
		entry.Message = "После запуска нужна свежая проверка."
		r.doc.Runtime[id] = entry
	}
	return nil
}
func (a *App) persistAutonomyLocked(ctx context.Context) (result error) {
	r := &a.autonomy
	defer func() {
		if result != nil {
			r.blocked = true
		}
	}()
	if r.blocked || !r.loaded {
		return restorejournal.ErrRecovery
	}
	data, e := json.Marshal(r.doc)
	if e != nil {
		return e
	}
	if _, e = decodeAutonomy(data); e != nil {
		return e
	}
	target, e := restorejournal.OpenFileTarget(r.path)
	if e != nil {
		return e
	}
	defer target.Close()
	after := restorejournal.Image{Exists: true, Data: data}
	if e = target.CompareAndSwap(ctx, r.image, after); e != nil {
		r.blocked = true
		return e
	}
	r.image = after
	return nil
}
func (a *App) autonomyPolicy() autonomy.Policy {
	a.autonomy.mu.Lock()
	defer a.autonomy.mu.Unlock()
	return autonomy.Clone(a.autonomy.doc.Policy)
}
func (a *App) autonomyRuntime(id string, entry autonomy.Runtime) {
	a.autonomy.mu.Lock()
	defer a.autonomy.mu.Unlock()
	if _, ok := a.autonomy.doc.Services[id]; ok {
		a.autonomy.doc.Runtime[id] = entry.Clone()
		_ = a.persistAutonomyLocked(context.Background())
	}
}

// Refuse stale local consent if another process or a restore replaced its file.
// Compare before transaction guards, not only after a network mutation.
func (a *App) autonomyDiskCurrent(ctx context.Context) error {
	a.autonomy.mu.Lock()
	defer a.autonomy.mu.Unlock()
	if a.autonomy.blocked || !a.autonomy.loaded {
		return restorejournal.ErrRecovery
	}
	image, err := restorejournal.ReadFileImage(ctx, a.autonomy.path)
	if err != nil || image.Exists != a.autonomy.image.Exists || !bytes.Equal(image.Data, a.autonomy.image.Data) {
		a.autonomy.blocked = true
		return restorejournal.ErrRecovery
	}
	return nil
}

// Ownership is retained while a service is paused. Malformed consent prevents
// legacy fallback from silently taking it back over.
func (a *App) autonomyOwnsService(id string) bool {
	a.autonomy.mu.Lock()
	defer a.autonomy.mu.Unlock()
	if a.autonomy.blocked {
		return true
	}
	_, ok := a.autonomy.doc.Services[id]
	return a.autonomy.loaded && a.autonomy.doc.Policy.SetupComplete && ok
}
