package sources

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestMirrorProvenanceRejectsUnapprovedOriginWithoutDeletingReceipt(t *testing.T) {
	m, src := cachedFixture(t)
	path := filepath.Join(m.cacheDir, src.ID+".cache.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, origin := range []string{"https://unapproved.example/", "http://source.example/", "https://127.0.0.1/", "", "https://cdn.example/"} {
		t.Run(origin, func(t *testing.T) {
			var receipt cacheDocument
			if err := json.Unmarshal(before, &receipt); err != nil {
				t.Fatal(err)
			}
			receipt.Provenance.FinalURL = origin
			data, _ := json.Marshal(receipt)
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			reloaded := NewManager(m.reg, m.cacheDir)
			if reloaded.List()[0].Ready || reloaded.AutomaticUseReady([]string{"telegram"}) {
				t.Fatal("unapproved mirror accepted")
			}
			after, err := os.ReadFile(path)
			if err != nil || string(after) != string(data) {
				t.Fatal("rejected receipt destroyed")
			}
		})
	}
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	// A trusted client can supply a mismatched final response URL. Validate the
	// receipt boundary too, even when the redirect handler was not involved.
	client := listClient("new.example\n", "text/plain")
	next := client.Transport
	client.Transport = fixtureTransport(func(req *http.Request) (*http.Response, error) {
		response, err := next.RoundTrip(req)
		response.Request, _ = http.NewRequest(http.MethodGet, "https://unapproved.example/private-path", nil)
		return response, err
	})
	m.SetHTTPClient(client)
	if err := m.Refresh(context.Background(), src.ID); err == nil {
		t.Fatal("unapproved final origin committed")
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(before) {
		t.Fatal("unapproved fetch replaced LKG")
	}
}

func TestOfflineCatalogIsDetachedReadOnlyAndNeverFresh(t *testing.T) {
	m, src := cachedFixture(t)
	path := filepath.Join(m.cacheDir, src.ID+".cache.json")
	before, _ := os.ReadFile(path)
	m.SetHTTPClient(&http.Client{Transport: fixtureTransport(func(*http.Request) (*http.Response, error) {
		t.Fatal("offline read performed network I/O")
		return nil, errors.New("unexpected")
	})})
	for restart := 0; restart < 2; restart++ {
		states := m.OfflineCatalog()
		if states[0].Ready || !states[0].Offline || states[0].CacheStatus != "offline-cache" || states[0].Entries != 1 || !states[0].LastKnownGood {
			t.Fatalf("offline state: %+v", states)
		}
		states[0].Provenance.FinalURL = "changed"
		states[0].Diff.Added = 999
		live := m.List()[0]
		if !live.Ready || live.Offline || live.Provenance.FinalURL == "changed" || live.Diff.Added == 999 {
			t.Fatal("offline view modified manager")
		}
		after, _ := os.ReadFile(path)
		if string(after) != string(before) {
			t.Fatal("offline read changed cache")
		}
		m = NewManager(m.reg, m.cacheDir)
	}
	var receipt cacheDocument
	if err := json.Unmarshal(before, &receipt); err != nil {
		t.Fatal(err)
	}
	receipt.FetchedAt = time.Now().UTC().Add(-2 * time.Hour)
	receipt.ExpiresAt = receipt.FetchedAt.Add(sourceTTL(src))
	data, _ := json.Marshal(receipt)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	m = NewManager(m.reg, m.cacheDir)
	stale := m.OfflineCatalog()[0]
	if stale.Ready || !stale.Offline || stale.CacheStatus != "stale" || stale.Entries != 1 {
		t.Fatalf("stale promoted offline: %+v", stale)
	}
	if m.AutomaticUseReady([]string{"telegram"}) {
		t.Fatal("offline stale cache authorized route change")
	}
}

type canceledSourceBody struct {
	reader io.Reader
	stop   func()
}

func (b *canceledSourceBody) Read(p []byte) (int, error) {
	n, err := b.reader.Read(p)
	if n > 0 {
		b.stop()
	}
	return n, err
}

func (*canceledSourceBody) Close() error { return nil }

func TestSourceCancellationAfterSuccessfulBodyRetainsReceiptAndTTL(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "empty-cache", true: "last-known-good"}[existing], func(t *testing.T) {
			m, src := cachedFixture(t)
			if !existing {
				m = NewManager(m.reg, filepath.Join(t.TempDir(), "not-created"))
			}
			path := filepath.Join(m.cacheDir, src.ID+".cache.json")
			before, beforeErr := os.ReadFile(path)
			stateBefore := m.List()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			m.SetHTTPClient(&http.Client{Transport: fixtureTransport(func(req *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/plain"}},
					Body: &canceledSourceBody{reader: strings.NewReader("new.example\n"), stop: cancel}, Request: req}, nil
			})})
			if err := m.Refresh(ctx, src.ID); !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled successful response committed: %v", err)
			}
			after, afterErr := os.ReadFile(path)
			if !reflect.DeepEqual(stateBefore, m.List()) || string(before) != string(after) ||
				!existing && (!errors.Is(beforeErr, os.ErrNotExist) || !errors.Is(afterErr, os.ErrNotExist)) ||
				existing && (beforeErr != nil || afterErr != nil) {
				t.Fatal("cancellation changed cache, freshness, provenance or TTL")
			}
			if _, err := os.Stat(filepath.Join(m.cacheDir, src.ID+".quarantine.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("cancellation wrote quarantine metadata")
			}
			if !existing {
				if _, err := os.Stat(m.cacheDir); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("cancellation created an empty cache directory")
				}
			} else if restored := NewManager(m.reg, m.cacheDir).List(); !reflect.DeepEqual(stateBefore, restored) {
				t.Fatal("restart renewed or replaced the retained receipt")
			}
		})
	}
}

func TestSourceRegistryEditsCannotChangeApprovedFetchPolicy(t *testing.T) {
	src := Source{ID: "frozen", Name: "Frozen", Kind: "domains", URL: "https://source.example/list", Enabled: true,
		MinEntries: 1, TTLHours: 1, Services: []string{"telegram"}, RedirectHosts: []string{"cdn.example"}}
	reg := Registry{Schema: 2, Sources: []Source{src}}
	m := NewManager(reg, t.TempDir())
	mutated := false
	m.SetHTTPClient(&http.Client{Transport: fixtureTransport(func(req *http.Request) (*http.Response, error) {
		if req.URL.Hostname() == "source.example" {
			// Edits while the request is in flight must not change its approved
			// mirrors or the policy hash/TTL used for the eventual receipt.
			reg.Sources[0].URL = "https://other.example/list"
			reg.Sources[0].TTLHours = 720
			reg.Sources[0].Services[0] = "youtube"
			reg.Sources[0].RedirectHosts[0] = "unapproved.example"
			mutated = true
			return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{"https://cdn.example/list"}},
				Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
		}
		if req.URL.Hostname() != "cdn.example" {
			t.Fatal("registry edit changed the requested source or mirror")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/plain"}},
			Body: io.NopCloser(strings.NewReader("approved.example\n")), Request: req}, nil
	})})
	if err := m.Refresh(context.Background(), src.ID); err != nil || !mutated {
		t.Fatalf("original approved fetch policy was not retained: %v", err)
	}
	state := m.List()[0]
	if !state.Ready || state.Provenance.FinalURL != "https://cdn.example/" || state.ExpiresAt.Sub(state.UpdatedAt) != time.Hour {
		t.Fatal("external registry edit changed receipt provenance or TTL")
	}
	domains, _ := m.EntriesForService("telegram")
	other, _ := m.EntriesForService("youtube")
	if !reflect.DeepEqual(domains, []string{"approved.example"}) || len(other) != 0 || !m.AutomaticUseReady([]string{"telegram"}) {
		t.Fatal("external registry edit changed approved service enrichment")
	}
	before, err := os.ReadFile(filepath.Join(m.cacheDir, src.ID+".cache.json"))
	if err != nil {
		t.Fatal(err)
	}
	m.SetHTTPClient(&http.Client{Transport: fixtureTransport(func(req *http.Request) (*http.Response, error) {
		if req.URL.Hostname() != "source.example" {
			t.Fatal("external registry edit changed the source URL")
		}
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{"https://unapproved.example/list"}},
			Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
	})})
	if err := m.Refresh(context.Background(), src.ID); err == nil {
		t.Fatal("external registry edit granted a new mirror")
	}
	after, err := os.ReadFile(filepath.Join(m.cacheDir, src.ID+".cache.json"))
	if err != nil || string(after) != string(before) {
		t.Fatal("unapproved mirror replaced the retained receipt")
	}
}
