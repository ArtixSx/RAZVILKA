package components

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// countingUpdateRunner fails the first N `opkg update` calls with output.
type countingUpdateRunner struct {
	*fakeRunner
	failures int
	output   string
	updates  int
}

func (r *countingUpdateRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if len(args) == 1 && args[0] == "update" {
		r.updates++
		if r.updates <= r.failures {
			return []byte(r.output), errors.New("fixture failure")
		}
	}
	return r.fakeRunner.Run(ctx, name, args...)
}

const nfqwsFeedFailure = "Downloading http://bin.entware.net/aarch64-k3.10/Packages.gz\n" +
	"Downloading https://nfqws.github.io/nfqws2-keenetic/all/Packages.gz\n" +
	"*** Failed to download the package list from https://nfqws.github.io/nfqws2-keenetic/all/Packages.gz\n"

func componentsFixture(r Runner) *Manager {
	return &Manager{Opkg: "opkg", Runner: r, Client: offlineReleases()}
}

// One unreachable third-party source must not hide updates of components that
// come from sources which refreshed successfully.
func TestFailedFeedMarksOnlyItsComponentsStale(t *testing.T) {
	r := &countingUpdateRunner{fakeRunner: &fakeRunner{output: map[string]string{
		"list-installed": "sing-box-go - 1.13.3-2 - x\nnfqws2-keenetic - 1.3.1 - x\n",
		"list":           "sing-box-go - 1.14.0-1 - x\nnfqws2-keenetic - 1.3.2 - x\n",
		"update":         "ok",
	}}, failures: 2, output: nfqwsFeedFailure}
	m := componentsFixture(r)
	m.RepoDir = t.TempDir()
	views, err := m.List(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if r.updates != 2 {
		t.Fatalf("refresh was not retried once: %d", r.updates)
	}
	sing := componentView(t, views, "sing-box")
	if sing.CatalogStale || !sing.CanUpdate || sing.UpdateCheckError != "" || sing.CheckedAt == "" {
		t.Fatalf("Entware component blocked by a third-party feed: %+v", sing)
	}
	nfq := componentView(t, views, "nfqws2")
	if !nfq.CatalogStale || nfq.CanUpdate || nfq.UpdateCheckError == "" {
		t.Fatalf("failed feed not reported for its component: %+v", nfq)
	}
	if _, err := m.Apply(context.Background(), "nfqws2"); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("update from a failed feed allowed: %v", err)
	}
}

func TestTransientRefreshFailureIsRetried(t *testing.T) {
	r := &countingUpdateRunner{fakeRunner: &fakeRunner{output: map[string]string{
		"list-installed": "sing-box-go - 1.13.3-2 - x\n",
		"list":           "sing-box-go - 1.14.0-1 - x\n",
		"update":         "ok",
	}}, failures: 1, output: nfqwsFeedFailure}
	m := componentsFixture(r)
	m.RepoDir = t.TempDir()
	views, err := m.List(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if v := componentView(t, views, "nfqws2"); v.CatalogStale || r.updates != 2 {
		t.Fatalf("transient failure not retried: updates=%d %+v", r.updates, v)
	}
}

func TestUnattributedRefreshFailureStillMarksAllStale(t *testing.T) {
	r := &countingUpdateRunner{fakeRunner: &fakeRunner{output: map[string]string{
		"list-installed": "sing-box-go - 1.13.3-2 - x\n",
		"list":           "sing-box-go - 1.14.0-1 - x\n",
		"update":         "ok",
	}}, failures: 5, output: "opkg: unexpected failure"}
	m := componentsFixture(r)
	m.RepoDir = t.TempDir()
	views, err := m.List(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if v := componentView(t, views, "sing-box"); !v.CatalogStale || v.CanUpdate {
		t.Fatalf("unattributed failure treated as partial: %+v", v)
	}
}
