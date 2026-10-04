package sources

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
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
