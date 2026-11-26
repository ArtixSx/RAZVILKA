package nodestore

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"runtime"
	"time"
)

const priorityFile = "node-priority.json"
const maxPriorityBytes = 64 << 10

var (
	ErrPriorityChecks      = errors.New("local priority checks unavailable")
	ErrPriorityNotPersonal = errors.New("priority check requires a personal profile")
)

// This scheduling preference is local to the original library. Existing
// readers, ordinary node restore and encrypted profile backups keep their
// original format and do not import this preference.
type priorityDocument struct {
	Schema  int                  `json:"schema"`
	Binding string               `json:"binding"`
	Nodes   map[string]time.Time `json:"nodes"`
}

func (s Source) PersonalProfile() bool {
	return s.Kind == "manual" || s.Kind == "file"
}

// All private file access is under the Store mutex and its original writer
// lease. The retained root keeps optional priority metadata inside that store.
func (s *Store) readPriorityChecks(ctx context.Context) (priorityDocument, error) {
	if err := ctx.Err(); err != nil {
		return priorityDocument{}, err
	}
	if s.root == nil {
		return priorityDocument{}, ErrPriorityChecks
	}
	info, err := s.root.Stat(priorityFile)
	if errors.Is(err, os.ErrNotExist) {
		return priorityDocument{Schema: 1, Binding: s.binding, Nodes: map[string]time.Time{}}, nil
	}
	if err != nil || !info.Mode().IsRegular() || !privateMode(info) {
		return priorityDocument{}, ErrPriorityChecks
	}
	data, err := s.root.ReadLimited(priorityFile, maxPriorityBytes)
	var prefs priorityDocument
	if err != nil || decodeStrict(data, &prefs) != nil || prefs.Schema != 1 || prefs.Binding != s.binding ||
		prefs.Nodes == nil || len(prefs.Nodes) > MaxNodes {
		return priorityDocument{}, ErrPriorityChecks
	}
	for id, added := range prefs.Nodes {
		if !validNodeID(id) || added.IsZero() {
			return priorityDocument{}, ErrPriorityChecks
		}
	}
	return prefs, ctx.Err()
}

func personalOrigins(sources []Source) map[string]bool {
	personal := make(map[string]bool, len(sources))
	for _, source := range sources {
		if source.PersonalProfile() {
			personal[source.ID] = true
		}
	}
	return personal
}

func hasPersonalOrigin(origins []Origin, personal map[string]bool) bool {
	for _, origin := range origins {
		if personal[origin.SourceID] {
			return true
		}
	}
	return false
}

func (s *Store) attachPriorityChecks(ctx context.Context, view *Snapshot) {
	personal := personalOrigins(view.Sources)
	prefs, err := s.readPriorityChecks(ctx)
	view.PriorityChecksAvailable = err == nil
	for i := range view.Nodes {
		node := &view.Nodes[i]
		node.PriorityCheckAvailable = hasPersonalOrigin(node.Origins, personal)
		node.PriorityCheck = node.PriorityCheckAvailable && err == nil && prefs.Nodes[node.ID].Equal(node.AddedAt)
	}
}

// SetPriorityCheck edits only scheduling metadata. It neither changes source
// consent nor creates freshness, health, a pin or a runtime binding.
func (s *Store) SetPriorityCheck(ctx context.Context, id string, priority bool) error {
	if !validNodeID(id) {
		return ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, _, err := s.load(ctx)
	if err != nil {
		return err
	}
	for _, node := range doc.Nodes {
		if node.ID != id {
			continue
		}
		if !hasPersonalOrigin(node.Origins, personalOrigins(doc.Sources)) {
			return ErrPriorityNotPersonal
		}
		added := node.AddedAt
		if !priority {
			added = time.Time{}
		}
		return s.updatePriorityChecks(ctx, doc, map[string]time.Time{id: added})
	}
	return ErrNotFound
}

func (s *Store) finishImport(ctx context.Context, doc document, now time.Time, marks map[string]time.Time) (Snapshot, error) {
	view := snapshot(doc, now)
	if len(marks) > 0 {
		if err := s.updatePriorityChecks(ctx, doc, marks); err != nil {
			return view, errors.Join(ErrPriorityChecks, err)
		}
	}
	return view, nil
}

func (s *Store) updatePriorityChecks(ctx context.Context, doc document, marks map[string]time.Time) error {
	prefs, err := s.readPriorityChecks(ctx)
	if err != nil {
		return err
	}
	live := make(map[string]time.Time, len(doc.Nodes))
	for _, node := range doc.Nodes {
		live[node.ID] = node.AddedAt
	}
	changed := false
	for id, added := range prefs.Nodes {
		if !live[id].Equal(added) {
			delete(prefs.Nodes, id)
			changed = true
		}
	}
	for id, added := range marks {
		if prefs.Nodes[id].Equal(added) {
			continue
		}
		if added.IsZero() {
			delete(prefs.Nodes, id)
		} else {
			prefs.Nodes[id] = added
		}
		changed = true
	}
	if !changed {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	data, err := json.Marshal(prefs)
	if err != nil || len(data) > maxPriorityBytes || s.root.WriteAtomic(priorityFile, data, 0o600) != nil {
		return ErrPriorityChecks
	}
	if runtime.GOOS != "windows" && s.root.Sync() != nil {
		return ErrPriorityChecks
	}
	return nil
}
