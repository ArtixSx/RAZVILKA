// Package providerfeed explicitly fetches passive node candidates. It never
// checks nodes, extends their health, selects a route or modifies a live engine.
package providerfeed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/providerprofile"
	"github.com/ArtixSx/razvilka/internal/publicfetch"
)

const (
	MaxBytes      = 1 << 20
	MaxEntries    = 2048
	MaxCandidates = 128
	MaxFeeds      = 32
	OriginTTL     = 24 * time.Hour
	Timeout       = 20 * time.Second
)

var (
	ErrRequest  = errors.New("invalid provider feed request")
	ErrBusy     = errors.New("provider feed sync already running")
	ErrFetch    = errors.New("provider feed HTTPS fetch failed")
	ErrSize     = errors.New("provider feed exceeds bounded limits")
	ErrFormat   = errors.New("provider feed format is invalid or unsupported")
	ErrPartial  = errors.New("provider feed contains rejected entries; explicit partial acceptance required")
	ErrStore    = errors.New("provider feed candidates could not be saved")
	ErrNotFound = errors.New("provider feed not found")
	ErrConflict = errors.New("provider feed changed; refresh before editing")
	ErrDeferred = errors.New("provider feed retry is deferred")
	ErrCapacity = errors.New("local node catalog capacity reached")
)

type Preset struct {
	ID                            string `json:"id"`
	Name                          string `json:"name"`
	URL                           string `json:"url"`
	Format                        string `json:"format"`
	License                       string `json:"license"`
	Verification                  string `json:"verification"`
	CountryCode                   string `json:"country_code,omitempty"`
	DefaultRefreshIntervalMinutes int    `json:"default_refresh_interval_minutes"`
}

// These are links, not redistributed node credentials or copied site code.
// Repository licenses describe the upstream project, not every third-party node.
func Builtins() []Preset {
	presets := []Preset{
		{ID: "tiagorrg-vless", Name: "VLESS Key Checker", URL: "https://tiagorrg.github.io/vless-checker/keys.json", Format: "keys-json", License: "MIT", Verification: "upstream TCP only; local exact check required"},
		{ID: "goida-vless", Name: "Goida VPN · VLESS", URL: "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/githubmirror/23.txt", Format: "uri-lines", License: "GPL-3.0", Verification: "upstream collection; local exact check required"},
		{ID: "goida-extra", Name: "Goida VPN · дополнительный каталог", URL: "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/githubmirror/6.txt", Format: "uri-lines", License: "GPL-3.0", Verification: "upstream collection; local exact check required"},
		{ID: "au1rxx-nl", Name: "Free VPN Subscriptions · Нидерланды", URL: "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/by-country/singbox-NL.json", Format: "profile", License: "see upstream", Verification: "country is a publisher label; local exact check required", CountryCode: "NL"},
		{ID: "kort0881-ru-sni", Name: "Kort0881 · RU SNI", URL: "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/data/githubmirror/ru-sni/vless.txt", Format: "uri-lines", License: "GPL-3.0", Verification: "publisher SNI selection, not measured location or local availability; local exact check required", DefaultRefreshIntervalMinutes: 240},
	}
	for i := range presets {
		if presets[i].DefaultRefreshIntervalMinutes == 0 {
			presets[i].DefaultRefreshIntervalMinutes = DefaultRefreshMinutes
		}
	}
	return presets
}

type Request struct {
	PresetID      string `json:"preset_id,omitempty"`
	URL           string `json:"url,omitempty"`
	Format        string `json:"format,omitempty"`
	Limit         int    `json:"limit,omitempty"`
	AcceptPartial bool   `json:"accept_partial,omitempty"`
}

func (Request) String() string   { return "[private provider feed request]" }
func (Request) GoString() string { return "[private provider feed request]" }

type Result struct {
	SourceID        string                       `json:"source_id"`
	Status          string                       `json:"status"`
	Imported        int                          `json:"imported"`
	Rejected        int                          `json:"rejected"`
	Duplicates      int                          `json:"duplicates"`
	Omitted         int                          `json:"omitted"`
	NodeIDs         []string                     `json:"node_ids,omitempty"`
	Issues          []providerprofile.EntryIssue `json:"issues,omitempty"`
	NotModified     bool                         `json:"not_modified"`
	OriginExpiresAt time.Time                    `json:"origin_expires_at,omitempty"`
	TotalEntries    int                          `json:"total_entries"`
	AcceptedEntries int                          `json:"accepted_entries"`
}

type State struct {
	RetryAfterAt           time.Time `json:"retry_after_at,omitempty"`
	SourceID               string    `json:"source_id"`
	Name                   string    `json:"name"`
	URL                    string    `json:"url"` // Redacted to origin; no token-bearing path/query.
	Format                 string    `json:"format"`
	Status                 string    `json:"status"`
	LastAttemptAt          time.Time `json:"last_attempt_at"`
	LastSuccessAt          time.Time `json:"last_success_at,omitempty"`
	OriginExpiresAt        time.Time `json:"origin_expires_at,omitempty"`
	Imported               int       `json:"imported"`
	ErrorCode              string    `json:"error_code,omitempty"`
	LastKnownGood          bool      `json:"last_known_good"`
	Saved                  bool      `json:"saved"`
	Enabled                bool      `json:"enabled"`
	RefreshIntervalMinutes int       `json:"refresh_interval_minutes"`
	AcceptPartial          bool      `json:"accept_partial"`
	Limit                  int       `json:"limit"`
	Revision               uint64    `json:"revision"`
	NextRefreshAt          time.Time `json:"next_refresh_at,omitempty"`
	TotalEntries           int       `json:"total_entries"`
	AcceptedEntries        int       `json:"accepted_entries"`
	Omitted                int       `json:"omitted"`
	Rejected               int       `json:"rejected"`
	Duplicates             int       `json:"duplicates"`
	JobID                  string    `json:"job_id,omitempty"`
}

type source struct {
	id, name, url, format, kind, identity string
	country                               string
	limit                                 int
	revision                              uint64
}
type cache struct {
	state                    State
	identity, etag, modified string
}

type Manager struct {
	mu      sync.Mutex
	gate    chan struct{}
	nodes   *nodestore.Store
	client  *http.Client
	now     func() time.Time
	states  map[string]cache
	storage *storage
	closed  bool
	fenced  bool
	jobs    jobState
}

func (*Manager) String() string   { return "[private provider feed manager]" }
func (*Manager) GoString() string { return "[private provider feed manager]" }

func New(nodes *nodestore.Store) *Manager {
	return &Manager{nodes: nodes, client: publicfetch.NewClient(Timeout), now: time.Now, gate: make(chan struct{}, 1), states: map[string]cache{}}
}

// Public views never contain subscription paths, queries or conditional tokens.
func (m *Manager) List() []State {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	states := make([]State, 0, len(m.states))
	for _, entry := range m.states {
		s := entry.state
		for _, job := range m.jobs.entries {
			if job.view.SourceID == s.SourceID && (job.view.Status == "queued" || job.view.Status == "running") {
				s.JobID = job.view.ID
				break
			}
		}
		if !s.OriginExpiresAt.IsZero() && !now.Before(s.OriginExpiresAt) {
			s.Status = "stale"
		}
		states = append(states, s)
	}
	sort.Slice(states, func(i, j int) bool { return states[i].SourceID < states[j].SourceID })
	return states
}

func resolve(request Request) (source, error) {
	if request.Limit == 0 {
		request.Limit = 32
	}
	if request.Limit < 1 || request.Limit > MaxCandidates {
		return source{}, ErrRequest
	}
	s := source{url: strings.TrimSpace(request.URL), format: request.Format, kind: "subscription", name: "Explicit HTTPS subscription", limit: request.Limit}
	if request.PresetID != "" {
		if request.URL != "" || request.Format != "" {
			return source{}, ErrRequest
		}
		found := false
		for _, p := range Builtins() {
			if p.ID == request.PresetID {
				s.id = "feed-" + p.ID
				s.name = p.Name
				s.url = p.URL
				s.format = p.Format
				s.kind = "community"
				if validCountry(p.CountryCode) {
					s.country = p.CountryCode
				}
				found = true
				break
			}
		}
		if !found {
			return source{}, ErrRequest
		}
	}
	if s.format == "" {
		s.format = "uri-lines"
	}
	if len(s.url) > 4096 || publicfetch.ValidateURL(s.url) != nil || (s.format != "uri-lines" && s.format != "keys-json" && s.format != "profile") {
		return source{}, ErrRequest
	}
	digest := sha256.Sum256([]byte(s.url + "\x00" + s.format))
	urlIdentity := hex.EncodeToString(digest[:])
	if s.id == "" {
		s.id = "feed-" + urlIdentity[:24]
	}
	s.identity = urlIdentity + ":" + strconv.Itoa(s.limit)
	return s, nil
}

// ValidateRequest checks a subscription's shape without performing I/O or
// persisting credentials. Sync repeats validation before any fetch.
func ValidateRequest(request Request) error {
	_, err := resolve(request)
	return err
}

func (m *Manager) Sync(parent context.Context, request Request) (Result, error) {
	s, err := resolve(request)
	if err != nil || m == nil || m.nodes == nil {
		return Result{}, ErrRequest
	}
	m.mu.Lock()
	saved := m.sourceIndexLocked(s.id) >= 0
	m.mu.Unlock()
	if saved {
		return m.SyncSaved(parent, s.id)
	}
	return m.sync(parent, s, request.AcceptPartial)
}

func (m *Manager) sync(parent context.Context, s source, acceptPartial bool) (Result, error) {
	ctx, cancel := context.WithTimeout(parent, Timeout)
	defer cancel()
	select {
	case m.gate <- struct{}{}:
		defer func() { <-m.gate }()
	default:
		return Result{}, ErrBusy
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	m.mu.Lock()
	if m.closed || m.fenced || !m.currentSourceLocked(s) {
		m.mu.Unlock()
		return Result{}, ErrConflict
	}
	previous, exists := m.states[s.id]
	if m.now().Before(previous.state.RetryAfterAt) {
		m.mu.Unlock()
		return Result{SourceID: s.id, Status: "deferred", OriginExpiresAt: previous.state.OriginExpiresAt}, ErrDeferred
	}
	if !exists && len(m.states) >= MaxFeeds {
		m.mu.Unlock()
		return Result{}, ErrSize
	}
	if previous.identity != s.identity {
		// A wider selection needs a complete body, but a failed attempt must
		// still report the previously imported passive candidates as retained.
		previous.etag, previous.modified = "", ""
	}
	m.mu.Unlock()
	state := previous.state
	state.SourceID, state.Name, state.URL, state.Format = s.id, s.name, publicfetch.RedactedURL(s.url), s.format
	state.LastAttemptAt = m.now().UTC()
	// Persist a bounded reservation BEFORE fetching. A crash may leave a pending
	// attempt, but cannot turn it into an immediate restart/retry storm.
	if m.storage != nil && s.revision != 0 {
		m.mu.Lock()
		if !m.currentSourceLocked(s) {
			m.mu.Unlock()
			return Result{}, ErrConflict
		}
		pending := previous
		pending.state = state
		pending.state.Status = "fetching"
		pending.state.ErrorCode = ""
		pending.state.NextRefreshAt = state.LastAttemptAt.Add(MinRefreshMinutes * time.Minute)
		m.states[s.id] = pending
		err := m.persistLocked(ctx)
		m.mu.Unlock()
		if err != nil {
			return Result{}, ErrStore
		}
	}
	result := Result{SourceID: s.id}
	finish := func(status string, cause error) (Result, error) {
		state.Status, state.ErrorCode = status, ErrorCode(cause)
		result.Status, result.OriginExpiresAt = status, state.OriginExpiresAt
		previous.state, previous.identity = state, s.identity
		m.mu.Lock()
		defer m.mu.Unlock()
		if !m.currentSourceLocked(s) {
			return result, ErrConflict
		}
		m.states[s.id] = previous
		if m.storage != nil {
			if s.revision != 0 {
				m.completeSavedLocked(s.id, cause)
			}
			if err := m.persistLocked(context.WithoutCancel(parent)); err != nil {
				return result, ErrStore
			}
		}
		return result, cause
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return finish("failed", ErrRequest)
	}
	req.Header.Set("Accept", "text/plain, application/json, application/octet-stream")
	req.Header.Set("User-Agent", "RAZVILKA/providerfeed")
	// Same exact URL+format only. Never send these validators to a new source.
	conditionalSent := previous.state.LastKnownGood && m.now().Before(previous.state.OriginExpiresAt) && (previous.etag != "" || previous.modified != "")
	if conditionalSent {
		if previous.etag != "" {
			req.Header.Set("If-None-Match", previous.etag)
		}
		if previous.modified != "" {
			req.Header.Set("If-Modified-Since", previous.modified)
		}
	}
	client := publicfetch.WithPolicy(m.client, s.url, nil)
	// Subscription tokens may occur in paths: reject even same-origin redirects
	// instead of allowing an upstream to steer a credential-bearing request.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return publicfetch.ErrRedirect }
	response, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return finish("stale", ctx.Err())
		}
		return finish("stale", ErrFetch)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotModified {
		if !conditionalSent {
			return finish("failed", ErrFetch)
		}
		result.NotModified = true
		status := "not_modified"
		if !m.now().Before(state.OriginExpiresAt) {
			status = "stale"
		}
		// Deliberately no Store.Import: 304 extends neither origin TTL nor health.
		return finish(status, nil)
	}
	if response.StatusCode == 429 || response.StatusCode == 503 && !retryAfter(response.Header.Get("Retry-After"), m.now()).IsZero() {
		state.RetryAfterAt = retryAfter(response.Header.Get("Retry-After"), m.now())
		return finish("stale", ErrRateLimited)
	}
	if response.StatusCode != http.StatusOK {
		return finish("stale", ErrFetch)
	}
	if response.ContentLength > MaxBytes {
		return finish("stale", ErrSize)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, MaxBytes+1))
	if err != nil {
		if ctx.Err() != nil {
			return finish("stale", ctx.Err())
		}
		return finish("stale", ErrFetch)
	}
	if len(raw) > MaxBytes {
		return finish("stale", ErrSize)
	}
	batch, err := parse(ctx, raw, s.format, s.limit)
	result.Rejected, result.Duplicates, result.Omitted, result.Issues = batch.rejected, batch.duplicates, batch.omitted, batch.issues
	result.TotalEntries, result.AcceptedEntries = batch.total, batch.accepted
	if err != nil {
		return finish("stale", err)
	}
	if batch.rejected > 0 && !acceptPartial {
		return finish("needs_acceptance", ErrPartial)
	}
	if err := ctx.Err(); err != nil {
		return finish("stale", err)
	}
	now := m.now().UTC()
	// Keep subscription edits and deletion from racing the import after its
	// network response. This lock is bounded local I/O, never network work.
	m.mu.Lock()
	if m.closed || m.fenced || !m.currentSourceLocked(s) {
		m.mu.Unlock()
		return result, ErrConflict
	}
	snapshot, err := m.nodes.Import(ctx, nodestore.Source{ID: s.id, Kind: s.kind}, batch.raw, now, OriginTTL, false)
	if err == nil && m.storage != nil {
		ids, metadataErr := m.nodes.MatchImportedMaterials(ctx, batch.materials)
		if metadataErr != nil {
			err = metadataErr
		} else {
			if m.storage.doc.Countries == nil {
				m.storage.doc.Countries = map[string]string{}
			}
			present := map[string]bool{}
			originSources := map[string][]string{}
			for _, node := range snapshot.Nodes {
				present[node.ID] = true
				for _, origin := range node.Origins {
					originSources[node.ID] = append(originSources[node.ID], origin.SourceID)
				}
			}
			for id := range m.storage.doc.Countries {
				if !present[id] {
					delete(m.storage.doc.Countries, id)
				}
			}
			for i, id := range ids {
				country := batch.countries[i]
				if country == "" {
					// Only an explicit built-in country collection can supply a
					// publisher label when its individual tags omit geography.
					// Custom URLs and source names never grant this metadata.
					country = s.country
				}
				if id != "" && country != "" {
					m.storage.doc.Countries[id] = country
				} else if id != "" && onlyCountrySource(originSources[id], s.id) {
					// A successful complete response may retract its own label.
					// Older images do not attribute a country to one origin, so
					// preserve it when another source could own the same claim.
					delete(m.storage.doc.Countries, id)
				}
			}
		}
	}
	m.mu.Unlock()
	if err != nil {
		if errors.Is(err, nodestore.ErrCapacity) {
			return finish("capacity", ErrCapacity)
		}
		return finish("stale", ErrStore)
	}
	result.Imported = batch.accepted
	for _, node := range snapshot.Nodes {
		for _, origin := range node.Origins {
			if origin.SourceID == s.id && origin.ReceivedAt.Equal(now) {
				result.NodeIDs = append(result.NodeIDs, node.ID)
				break
			}
		}
	}
	state.RetryAfterAt = time.Time{}
	state.LastSuccessAt, state.OriginExpiresAt, state.LastKnownGood, state.Imported = now, now.Add(OriginTTL), true, batch.accepted
	state.TotalEntries, state.AcceptedEntries, state.Omitted, state.Rejected, state.Duplicates = batch.total, batch.accepted, batch.omitted, batch.rejected, batch.duplicates
	previous.etag, previous.modified = safeValidator(response.Header.Get("ETag")), safeValidator(response.Header.Get("Last-Modified"))
	return finish("synced", nil)
}

func safeValidator(value string) string {
	if len(value) > 512 || strings.IndexFunc(value, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
		return ""
	}
	return value
}

func ErrorCode(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrRequest):
		return "FEED_REQUEST"
	case errors.Is(err, ErrRateLimited), errors.Is(err, ErrDeferred):
		return "FEED_RATE_LIMIT"
	case errors.Is(err, ErrBusy):
		return "FEED_BUSY"
	case errors.Is(err, ErrSize):
		return "FEED_LIMIT"
	case errors.Is(err, ErrFormat):
		return "FEED_FORMAT"
	case errors.Is(err, ErrPartial):
		return "FEED_PARTIAL"
	case errors.Is(err, ErrStore):
		return "FEED_STORE"
	case errors.Is(err, ErrNotFound):
		return "FEED_NOT_FOUND"
	case errors.Is(err, ErrConflict):
		return "FEED_CHANGED"
	case errors.Is(err, ErrCapacity):
		return "FEED_CAPACITY"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "FEED_CANCELED"
	default:
		return "FEED_FETCH"
	}
}
