package sources

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/publicfetch"
)

type Provenance struct {
	URL       string `json:"url"`
	FinalURL  string `json:"final_url"`
	RawSHA256 string `json:"raw_sha256,omitempty"`
	TrustTier string `json:"trust_tier"`
}

type DiffSummary struct {
	Added          int    `json:"added"`
	Removed        int    `json:"removed"`
	PreviousSHA256 string `json:"previous_sha256,omitempty"`
}

// Content and its receipt commit in one atomic rename. A failed download or
// interrupted commit cannot replace only half of the last-known-good cache.
type cacheDocument struct {
	Schema     int         `json:"schema"`
	ID         string      `json:"id"`
	Kind       string      `json:"kind"`
	SourceHash string      `json:"source_hash"`
	Content    string      `json:"content"`
	Entries    int         `json:"entries"`
	SHA256     string      `json:"sha256"`
	FetchedAt  time.Time   `json:"fetched_at"`
	ExpiresAt  time.Time   `json:"expires_at"`
	Provenance Provenance  `json:"provenance"`
	Diff       DiffSummary `json:"diff"`
}

type quarantineDocument struct {
	Schema     int       `json:"schema"`
	SourceHash string    `json:"source_hash"`
	CheckedAt  time.Time `json:"checked_at"`
	Reason     string    `json:"reason"`
}

func validateSource(s Source) error {
	if !validSourceID(s.ID) {
		return errors.New("invalid source ID")
	}
	if s.Kind != "domains" && s.Kind != "cidrs" && s.Kind != "reference" {
		return errors.New("unsupported source kind")
	}
	if err := publicfetch.ValidateURL(s.URL); err != nil {
		return err
	}
	u, _ := url.Parse(s.URL)
	// Source Hub currently accepts public lists, not authenticated proxy
	// subscriptions. Signed CDN redirect queries are transient transport data;
	// they are never accepted as configured source credentials or persisted.
	if u.RawQuery != "" || u.ForceQuery {
		return errors.New("source registry URLs cannot contain query parameters or subscription credentials")
	}
	if s.MaxBytes < 0 || s.MaxBytes > 16<<20 || s.MinEntries < 0 {
		return errors.New("invalid source size limits")
	}
	if s.MaxEntries < 0 || s.MaxEntries > 500000 || s.MinEntries > sourceEntryLimit(s) {
		return errors.New("invalid source entry limits")
	}
	if s.TTLHours < 0 || s.TTLHours > 720 {
		return errors.New("source TTL must be between 1 and 720 hours (0 uses 24)")
	}
	if s.TrustTier != "" && s.TrustTier != "official" && s.TrustTier != "community" && s.TrustTier != "user" {
		return errors.New("unknown source trust tier")
	}
	if s.ExpectedSHA256 != "" && !validDigest(s.ExpectedSHA256) {
		return errors.New("invalid source SHA256 pin")
	}
	if len(s.RedirectHosts) > 8 {
		return errors.New("too many source redirect hosts")
	}
	for _, host := range s.RedirectHosts {
		u, err := url.Parse("https://" + host + "/")
		if err != nil || u.Hostname() != host || u.Port() != "" || publicfetch.ValidateURL(u.String()) != nil {
			return errors.New("invalid source redirect host")
		}
	}
	return nil
}

func sourceTTL(s Source) time.Duration {
	if s.TTLHours <= 0 {
		return 24 * time.Hour
	}
	return time.Duration(s.TTLHours) * time.Hour
}

func sourceMax(s Source) int64 {
	if s.MaxBytes <= 0 {
		return 8 << 20
	}
	return s.MaxBytes
}

func sourceEntryLimit(s Source) int {
	if s.MaxEntries <= 0 {
		return 200000
	}
	return s.MaxEntries
}

func trustTier(s Source) string {
	if s.TrustTier == "" {
		return "community"
	}
	return s.TrustTier
}

func contentHash(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func sourceHash(s Source) string     { data, _ := json.Marshal(s); return contentHash(data) }
func validDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func (m *Manager) readCache(src Source) (cacheDocument, error) {
	if err := validateSource(src); err != nil {
		return cacheDocument{}, err
	}
	root, err := ownedfs.Open(m.cacheDir)
	if err != nil {
		return cacheDocument{}, err
	}
	defer root.Close()
	data, err := root.ReadLimited(src.ID+".cache.json", sourceMax(src)*2+8192)
	var cached cacheDocument
	if errors.Is(err, os.ErrNotExist) {
		// Legacy cache is read, never silently upgraded to fetched provenance.
		// Its mtime provides a conservative expiry until a real HTTPS refresh.
		data, err = root.ReadLimited(src.ID+".lst", sourceMax(src))
		if err != nil {
			return cached, err
		}
		if src.ExpectedSHA256 != "" {
			return cached, errors.New("legacy cache cannot verify a source pin; refresh required")
		}
		info, err := root.Stat(src.ID + ".lst")
		if err != nil {
			return cached, err
		}
		cached = cacheDocument{Schema: 1, ID: src.ID, Kind: src.Kind, Content: string(data), FetchedAt: info.ModTime().UTC(), SHA256: contentHash(data), Provenance: Provenance{URL: publicfetch.RedactedURL(src.URL), TrustTier: "legacy-unverified"}}
		cached.ExpiresAt = cached.FetchedAt.Add(sourceTTL(src))
	} else {
		if err != nil {
			return cached, err
		}
		if json.Unmarshal(data, &cached) != nil || cached.Schema != 2 || cached.ID != src.ID || cached.Kind != src.Kind || cached.SourceHash != sourceHash(src) {
			return cacheDocument{}, errors.New("cache receipt does not match source configuration")
		}
		if !validDigest(cached.Provenance.RawSHA256) || src.ExpectedSHA256 != "" && !strings.EqualFold(src.ExpectedSHA256, cached.Provenance.RawSHA256) {
			return cacheDocument{}, errors.New("cache raw digest does not match source pin")
		}
		if cached.Provenance.URL != publicfetch.RedactedURL(src.URL) || cached.Provenance.TrustTier != trustTier(src) {
			return cacheDocument{}, errors.New("cache provenance does not match source")
		}
		if cached.Diff.Added < 0 || cached.Diff.Added > cached.Entries || cached.Diff.Removed < 0 || cached.Diff.Removed > sourceEntryLimit(src) || cached.Diff.PreviousSHA256 != "" && !validDigest(cached.Diff.PreviousSHA256) {
			return cacheDocument{}, errors.New("cache diff has invalid counts or digest")
		}
		// Never replay a persisted URL verbatim into the UI.
		cached.Provenance.FinalURL = publicfetch.RedactedURL(cached.Provenance.FinalURL)
	}
	if cached.FetchedAt.IsZero() || cached.FetchedAt.After(time.Now().Add(5*time.Minute)) || !cached.ExpiresAt.Equal(cached.FetchedAt.Add(sourceTTL(src))) {
		return cacheDocument{}, errors.New("cache receipt has invalid dates")
	}
	if int64(len(cached.Content)) > sourceMax(src) {
		return cacheDocument{}, errors.New("cache content exceeds source size limit")
	}
	entries, err := validateLinesLimited(src.Kind, cached.Content, sourceEntryLimit(src))
	if err != nil {
		return cacheDocument{}, err
	}
	if len(entries) < src.MinEntries {
		return cacheDocument{}, errors.New("cached list has too few entries")
	}
	if cached.Content != strings.Join(entries, "\n")+"\n" {
		return cacheDocument{}, errors.New("cache is not canonical")
	}
	if cached.SHA256 != contentHash([]byte(cached.Content)) {
		return cacheDocument{}, errors.New("cache content digest mismatch")
	}
	if cached.Schema == 2 && cached.Entries != len(entries) {
		return cacheDocument{}, errors.New("cache entry count mismatch")
	}
	cached.Entries = len(entries)
	return cached, nil
}

func stateFromCache(state State, cached cacheDocument) State {
	state.Ready, state.LastKnownGood = true, false
	state.Entries, state.SHA256 = cached.Entries, cached.SHA256
	state.UpdatedAt, state.ExpiresAt = cached.FetchedAt, cached.ExpiresAt
	state.LegacyCache = cached.Schema == 1
	state.Provenance = &cached.Provenance
	state.Diff = &cached.Diff
	if state.LegacyCache {
		state.Diff = nil
	}
	state.CacheStatus, state.LastError = "fresh", ""
	if state.LegacyCache {
		state.CacheStatus = "legacy"
	}
	return currentState(state, time.Now())
}

func cacheDiff(previous cacheDocument, entries []string) DiffSummary {
	old := make(map[string]bool, previous.Entries)
	for _, value := range strings.Split(strings.TrimSpace(previous.Content), "\n") {
		if value != "" {
			old[value] = true
		}
	}
	diff := DiffSummary{PreviousSHA256: previous.SHA256}
	for _, value := range entries {
		if old[value] {
			delete(old, value)
		} else {
			diff.Added++
		}
	}
	diff.Removed = len(old)
	return diff
}

func currentState(state State, now time.Time) State {
	if !state.ExpiresAt.IsZero() && !now.Before(state.ExpiresAt) {
		state.Ready = false
		state.CacheStatus = "stale"
	}
	return state
}

// AutomaticUseReady prevents a background route switch from silently dropping
// expired service enrichment or promoting an unauthenticated legacy cache.
// Already-committed policies remain intact. Unused/global reference lists do
// not block services they do not explicitly enrich.
func (m *Manager) AutomaticUseReady(serviceIDs []string) bool {
	m.mu.RLock()
	enabled := cloneBoolMap(m.settings.Applied)
	m.mu.RUnlock()
	for _, src := range m.reg.Sources {
		if !enabled[src.ID] || src.Kind == "reference" {
			continue
		}
		used := false
		for _, id := range serviceIDs {
			used = used || containsFold(src.Services, id)
		}
		if !used {
			continue
		}
		cached, err := m.readCache(src)
		if err != nil || cached.Schema != 2 || !time.Now().Before(cached.ExpiresAt) {
			return false
		}
	}
	return true
}

func (m *Manager) writeQuarantine(src Source, failure error) {
	if !validSourceID(src.ID) {
		return
	}
	if err := os.MkdirAll(m.cacheDir, 0o700); err != nil {
		return
	}
	root, err := ownedfs.Open(m.cacheDir)
	if err != nil {
		return
	}
	defer root.Close()
	// Keep one bounded metadata record, not a copy of untrusted response data.
	reason := failure.Error()
	if len(reason) > 200 {
		reason = "source update rejected"
	}
	data, _ := json.Marshal(quarantineDocument{Schema: 2, SourceHash: sourceHash(src), CheckedAt: time.Now().UTC(), Reason: reason})
	_ = root.WriteAtomic(src.ID+".quarantine.json", data, 0o600)
}

func (m *Manager) inspectQuarantine(src Source, fetched time.Time) {
	root, err := ownedfs.Open(m.cacheDir)
	if err != nil {
		return
	}
	defer root.Close()
	data, err := root.ReadLimited(src.ID+".quarantine.json", 4096)
	if err != nil {
		return
	}
	var q quarantineDocument
	if json.Unmarshal(data, &q) != nil || q.Schema != 2 || q.SourceHash != sourceHash(src) || !q.CheckedAt.After(fetched) || q.CheckedAt.After(time.Now().Add(5*time.Minute)) {
		return
	}
	state := m.states[src.ID]
	state.LastError = "Последнее обновление отклонено; сохранена предыдущая проверенная копия."
	state.LastKnownGood = state.Ready
	if state.Ready {
		state.CacheStatus = "last-known-good"
	}
	m.states[src.ID] = state
}
