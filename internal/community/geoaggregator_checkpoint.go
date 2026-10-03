package community

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalogsnapshot"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

const geoCheckpointName = "geo-aggregator.snapshot.json"
const geoBrowseMaxAge = 30 * 24 * time.Hour
const geoFailureBackoff = time.Minute

// This status is explicitly about the public index, not any service's health.
type GeoAggregatorCacheStatus struct {
	Available  bool      `json:"available"`
	CapturedAt time.Time `json:"captured_at,omitempty"`
	Stale      bool      `json:"stale"`
	Refreshing bool      `json:"refreshing"`
	ErrorCode  string    `json:"error_code,omitempty"`
}

func (m *Manager) GeoAggregatorCacheStatus() GeoAggregatorCacheStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	age := time.Since(m.geoAt)
	return GeoAggregatorCacheStatus{Available: len(m.geo) > 0, CapturedAt: m.geoAt, Stale: m.geoAt.IsZero() || age < 0 || age >= geoAggregatorTTL, Refreshing: m.geoRefreshing, ErrorCode: m.geoError}
}
func (m *Manager) loadGeoCheckpoint(registryPath string) {
	absolute, err := filepath.Abs(registryPath)
	if err != nil {
		return
	}
	m.geoCacheDir = filepath.Dir(absolute)
	root, err := ownedfs.Open(m.geoCacheDir)
	if err != nil {
		return
	}
	defer root.Close()
	b, err := root.ReadLimited(geoCheckpointName, catalogsnapshot.MaxEnvelope)
	if err != nil {
		return
	}
	s, err := catalogsnapshot.Decode(b, geoAggregatorCatalog, time.Now(), geoBrowseMaxAge)
	if err != nil {
		return
	}
	entries, err := geoEntries(s.Body)
	if err != nil {
		return
	}
	m.geo, m.geoAt = entries, s.CapturedAt // Reload does NOT grant a new freshness TTL.
}
func (m *Manager) saveGeoCheckpoint(body []byte, now time.Time) error {
	if m.geoCacheDir == "" {
		return nil
	} // New(in-memory fixtures) does not create files.
	b, err := catalogsnapshot.Encode(geoAggregatorCatalog, body, now)
	if err != nil {
		return err
	}
	root, err := ownedfs.Open(m.geoCacheDir)
	if err != nil {
		return err
	}
	defer root.Close()
	if err = root.WriteAtomic(geoCheckpointName, b, 0o600); err != nil {
		return err
	}
	return root.Sync()
}

// One fetch per manager at a time. Concurrent readers with an LKG do not wait
// for another request's network IO. Failure cooldown prevents repeated UI GETs
// from becoming a fetch storm. No unbounded goroutine or second scheduler.
func (m *Manager) refreshGeoCheckpoint(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	if m.geoRefreshGate == nil {
		m.geoRefreshGate = make(chan struct{}, 1)
	}
	gate := m.geoRefreshGate
	have := len(m.geo) > 0
	m.mu.Unlock()
	select {
	case gate <- struct{}{}:
	default:
		if have {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case gate <- struct{}{}:
		}
	}
	defer func() { <-gate }()
	m.mu.Lock()
	now := time.Now()
	age := now.Sub(m.geoAt)
	if !m.geoAt.IsZero() && age >= 0 && age < geoAggregatorTTL {
		m.mu.Unlock()
		return nil
	}
	if now.Before(m.geoRetryAfter) {
		m.mu.Unlock()
		return errors.New("Geo-Aggregator refresh is in cooldown")
	}
	m.geoRefreshing = true
	m.mu.Unlock()
	defer func() { m.mu.Lock(); m.geoRefreshing = false; m.mu.Unlock() }()
	body, err := m.fetch(ctx, geoAggregatorCatalog)
	if err == nil && ctx.Err() != nil {
		err = ctx.Err()
	}
	var entries []Entry
	if err == nil {
		entries, err = geoEntries(body)
	}
	if err != nil {
		m.mu.Lock()
		m.geoError = "refresh_failed"
		m.geoRetryAfter = time.Now().Add(geoFailureBackoff)
		m.mu.Unlock()
		return err
	}
	captured := time.Now()
	persistErr := m.saveGeoCheckpoint(body, captured)
	m.mu.Lock()
	m.geo, m.geoAt = entries, captured
	m.geoRetryAfter = time.Time{}
	m.geoError = ""
	if persistErr != nil {
		m.geoError = "checkpoint_failed"
	}
	m.mu.Unlock()
	// The valid in-memory response remains usable even if persistence failed;
	// the status never pretends it is durable. The old disk LKG is not deleted.
	return persistErr
}
