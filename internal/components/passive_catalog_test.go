package components

import (
	"context"
	"testing"
)

func countCalls(r *fakeRunner, command string) int {
	count := 0
	for _, call := range r.calls {
		if len(call) > 1 && call[1] == command {
			count++
		}
	}
	return count
}

func TestPassiveObservationReusesCatalogUntilUpdate(t *testing.T) {
	r := &fakeRunner{output: map[string]string{
		"list-installed": "sing-box-go - 1.13.3-2 - existing\n",
		"list":           "sing-box-go - 1.14.0-1 - available\n",
		"update":         "ok",
	}}
	m := &Manager{Opkg: "opkg", Runner: r, RepoDir: t.TempDir(), InitDir: t.TempDir(), BinDir: t.TempDir(), Client: offlineReleases()}
	for range 3 {
		views, err := m.Observe(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if v := componentView(t, views, "sing-box"); v.AvailableVersion != "1.14.0-1" || v.InstalledVersion != "1.13.3-2" {
			t.Fatal(v)
		}
	}
	if got := countCalls(r, "list"); got != 1 {
		t.Fatalf("passive observations ran opkg list %d times, want 1", got)
	}
	if got := countCalls(r, "list-installed"); got != 3 {
		t.Fatalf("installed packages must be read on every observation: %d", got)
	}
	// Explicit reads never use the passive cache.
	if _, err := m.List(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if got := countCalls(r, "list"); got != 2 {
		t.Fatalf("explicit list reused passive cache: %d", got)
	}
	// opkg update changes the package lists: the next observation re-reads them.
	r.output["list"] = "sing-box-go - 1.15.0-1 - available\n"
	if _, err := m.run(context.Background(), "update"); err != nil {
		t.Fatal(err)
	}
	views, err := m.Observe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if v := componentView(t, views, "sing-box"); v.AvailableVersion != "1.15.0-1" || countCalls(r, "list") != 3 {
		t.Fatalf("catalog not re-read after update: %+v calls=%d", v, countCalls(r, "list"))
	}
}
