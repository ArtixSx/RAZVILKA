package sources

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// Actual Source Manager/Refresh/cache/registry objects. The HTTP response is a
// local wire fixture, not online provenance or a router/transport acceptance.
func serviceCIDRFixture(t *testing.T) (*Manager, Source, context.Context) {
	t.Helper()
	s := Source{ID: "reviewed-networks", Name: "Reviewed networks", Kind: "cidrs", URL: "https://source.example/networks", Enabled: true, Services: []string{"listed"}, MinEntries: 2, TTLHours: 1, TrustTier: "official"}
	m := NewManager(Registry{Schema: 2, Sources: []Source{s}}, t.TempDir())
	m.SetHTTPClient(listClient("# received wire\n8.8.8.0/24\n1.1.1.0/24\n", "text/plain"))
	if err := m.Refresh(context.Background(), s.ID); err != nil {
		t.Fatal(err)
	}
	c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return m, s, c
}

func TestServiceCIDRReviewOriginalAppliedRevisionAndDetachedObservation(t *testing.T) {
	m, s, ctx := serviceCIDRFixture(t)
	path := filepath.Join(m.cacheDir, s.ID+".cache.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	settings := cloneSettings(m.settings)
	r, err := m.ReviewServiceCIDRs(ctx, "listed", []string{s.ID})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	o, err := r.Observation(ctx)
	if err != nil || !reflect.DeepEqual(o.CIDRs, []string{"1.1.1.0/24", "8.8.8.0/24"}) || len(o.Revisions) != 1 || o.Revisions[0].SourceHash != sourceHash(s) || o.Revisions[0].ContentSHA256 == o.Revisions[0].RawSHA256 || o.Revisions[0].FetchedAt.IsZero() || o.Revisions[0].ExpiresAt.Sub(o.Revisions[0].FetchedAt) != time.Hour {
		t.Fatal("original revision missing", o, err)
	}
	o.CIDRs[0], o.SourceIDs[0], o.Revisions[0].SourceHash = "0.0.0.0/0", "foreign", "foreign"
	if err := r.Current(ctx); err != nil {
		t.Fatal("DTO mutated original", err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) || !reflect.DeepEqual(settings, m.settings) {
		t.Fatal("review wrote cache or settings")
	}
	copy := &ServiceCIDRReview{self: r}
	if err := copy.Current(ctx); !errors.Is(err, ErrServiceCIDRReview) {
		t.Fatal("copied owner admitted", err)
	}
	if err := copy.Close(); !errors.Is(err, ErrServiceCIDRReview) {
		t.Fatal("copy closed original", err)
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() { defer wg.Done(); _ = r.Current(ctx); _ = r.Close() }()
	}
	wg.Wait()
	if _, err := r.Observation(ctx); !errors.Is(err, ErrServiceCIDRReview) {
		t.Fatal("closed review emitted observation", err)
	}
	if domains, cidrs := m.EntriesForService("listed"); len(domains) != 0 || len(cidrs) != 2 {
		t.Fatal("closing review closed shared Manager")
	}
}

func TestServiceCIDRReviewChangedRevisionIsSticky(t *testing.T) {
	for _, kind := range []string{"same-content-refresh", "disable", "registry", "raw-sha", "quarantine", "root", "ancestor"} {
		t.Run(kind, func(t *testing.T) {
			m, s, ctx := serviceCIDRFixture(t)
			// Nest a cache so ancestor incarnation can change independently.
			if kind == "ancestor" {
				parent := filepath.Join(t.TempDir(), "parent")
				root := filepath.Join(parent, "cache")
				if err := os.MkdirAll(root, 0700); err != nil {
					t.Fatal(err)
				}
				data, _ := os.ReadFile(filepath.Join(m.cacheDir, s.ID+".cache.json"))
				if err := os.WriteFile(filepath.Join(root, s.ID+".cache.json"), data, 0600); err != nil {
					t.Fatal(err)
				}
				m = NewManager(m.reg, root)
			}
			r, err := m.ReviewServiceCIDRs(ctx, "listed", []string{s.ID})
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			path := filepath.Join(m.cacheDir, s.ID+".cache.json")
			before, _ := os.ReadFile(path)
			switch kind {
			case "same-content-refresh":
				if err := m.Refresh(ctx, s.ID); err != nil {
					t.Fatal(err)
				}
			case "disable":
				if err := m.SetDraft(s.ID, false); err != nil {
					t.Fatal(err)
				}
				if err := m.Apply(); err != nil {
					t.Fatal(err)
				}
			case "registry":
				m.mu.Lock()
				m.reg.Sources[0].Services = []string{"different"}
				m.mu.Unlock()
			case "raw-sha":
				var c cacheDocument
				if json.Unmarshal(before, &c) != nil {
					t.Fatal("fixture cache")
				}
				c.Provenance.RawSHA256 = strings.Repeat("b", 64)
				data, _ := json.Marshal(c)
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			case "quarantine":
				q := quarantineDocument{Schema: 2, SourceHash: sourceHash(s), CheckedAt: time.Now(), Reason: "invalid-response"}
				data, _ := json.Marshal(q)
				if err := os.WriteFile(filepath.Join(m.cacheDir, s.ID+".quarantine.json"), data, 0600); err != nil {
					t.Fatal(err)
				}
			case "root", "ancestor":
				target := m.cacheDir
				if kind == "ancestor" {
					target = filepath.Dir(target)
				}
				if err := os.Rename(target, target+"-retained"); err != nil {
					t.Skipf("directory rename unavailable: %v", err)
				}
				if err := os.MkdirAll(m.cacheDir, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, before, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := r.Current(ctx); !errors.Is(err, ErrServiceCIDRReview) {
				t.Fatal("changed original survived", kind, err)
			}
			if kind == "disable" {
				if err := m.SetDraft(s.ID, true); err != nil {
					t.Fatal(err)
				}
				if err := m.Apply(); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "registry" {
				m.mu.Lock()
				m.reg.Sources[0] = s
				m.mu.Unlock()
			}
			if kind == "raw-sha" {
				if err := os.WriteFile(path, before, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := r.Current(ctx); !errors.Is(err, ErrServiceCIDRReview) {
				t.Fatal("restored tuple revived poisoned review", kind, err)
			}
		})
	}
}

func TestServiceCIDRReviewRefusesLegacyIncompleteAndMalformedSources(t *testing.T) {
	for _, kind := range []string{"legacy", "missing-id", "duplicate-id", "unbounded", "domain", "unknown-key", "duplicate-key", "future", "expiry", "noncanonical", "unheld-source"} {
		t.Run(kind, func(t *testing.T) {
			m, s, ctx := serviceCIDRFixture(t)
			ids := []string{s.ID}
			path := filepath.Join(m.cacheDir, s.ID+".cache.json")
			before, _ := os.ReadFile(path)
			switch kind {
			case "legacy":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(m.cacheDir, s.ID+".lst"), []byte("1.1.1.0/24\n8.8.8.0/24\n"), 0600); err != nil {
					t.Fatal(err)
				}
				m = NewManager(m.reg, m.cacheDir)
				if _, cidrs := m.EntriesForService("listed"); len(cidrs) != 2 {
					t.Fatal("legacy display read no longer available")
				}
			case "missing-id":
				ids = []string{"absent"}
			case "duplicate-id":
				ids = append(ids, s.ID)
			case "unbounded":
				ctx = context.Background()
			case "domain":
				m.mu.Lock()
				m.reg.Sources[0].Kind = "domains"
				m.mu.Unlock()
			case "unknown-key":
				before = append([]byte(`{"permission":true,`), before[1:]...)
				if err := os.WriteFile(path, before, 0600); err != nil {
					t.Fatal(err)
				}
			case "duplicate-key":
				before = append([]byte(`{"schema":1,`), before[1:]...)
				if err := os.WriteFile(path, before, 0600); err != nil {
					t.Fatal(err)
				}
			case "future", "expiry", "noncanonical":
				var c cacheDocument
				_ = json.Unmarshal(before, &c)
				if kind == "future" {
					c.FetchedAt = time.Now().Add(time.Minute)
					c.ExpiresAt = c.FetchedAt.Add(time.Hour)
				}
				if kind == "expiry" {
					c.FetchedAt = time.Now().Add(-2 * time.Hour)
					c.ExpiresAt = c.FetchedAt.Add(time.Hour)
				}
				if kind == "noncanonical" {
					c.Content = "1.1.1.1/24\n8.8.8.0/24\n"
					c.SHA256 = contentHash([]byte(c.Content))
				}
				data, _ := json.Marshal(c)
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
				m = NewManager(m.reg, m.cacheDir)
			case "unheld-source":
				extra := s
				extra.ID = "unheld"
				m.mu.Lock()
				m.reg.Sources = append(m.reg.Sources, extra)
				m.settings.Applied[extra.ID] = true
				m.states[extra.ID] = m.states[s.ID]
				m.mu.Unlock()
			}
			if r, err := m.ReviewServiceCIDRs(ctx, "listed", ids); !errors.Is(err, ErrServiceCIDRReview) || r != nil {
				t.Fatal("incomplete source granted review", kind, err)
			}
		})
	}
}

func TestServiceCIDRReviewExpiresWithoutFileOrSettingsChange(t *testing.T) {
	m, s, ctx := serviceCIDRFixture(t)
	path := filepath.Join(m.cacheDir, s.ID+".cache.json")
	data, _ := os.ReadFile(path)
	var cache cacheDocument
	if err := json.Unmarshal(data, &cache); err != nil {
		t.Fatal(err)
	}
	cache.FetchedAt = time.Now().UTC().Add(-time.Hour + time.Second)
	cache.ExpiresAt = cache.FetchedAt.Add(time.Hour)
	data, err := json.Marshal(cache)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	m = NewManager(m.reg, m.cacheDir)
	r, err := m.ReviewServiceCIDRs(ctx, "listed", []string{s.ID})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	deadline, cancel := context.WithDeadline(ctx, cache.ExpiresAt)
	defer cancel()
	<-deadline.Done()
	if err := r.Current(ctx); !errors.Is(err, ErrServiceCIDRReview) {
		t.Fatal("expired immutable source survived", err)
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(data) {
		t.Fatal("expiry test rewrote cache")
	}
}
