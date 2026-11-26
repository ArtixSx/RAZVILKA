package app

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

// A version the installer rolled back is not installed again automatically;
// the running version and newer ones are not affected.
func TestAutoInstallSkipsRolledBackVersion(t *testing.T) {
	a := &App{}
	a.autonomy.doc.Maintenance = map[string]string{autoInstallReceipt: autoInstallAttemptPrefix + "9.9.9"}
	if !a.autoInstallFailed("9.9.9") {
		t.Fatal("rolled-back version would be installed again")
	}
	if a.autoInstallFailed("9.9.10") || a.autoInstallFailed("") {
		t.Fatal("newer version blocked")
	}
	a.autonomy.doc.Maintenance[autoInstallReceipt] = autoInstallAttemptPrefix + Version
	if a.autoInstallFailed(Version) {
		t.Fatal("successfully installed version reported as failed")
	}
}

// A package is installed only for the exact settings and channel it was
// prepared for, and never while the network is protected, stopped or has
// unapplied changes.
func TestAutoInstallAllowedOnlyForPreparedCurrentPackage(t *testing.T) {
	p := autonomy.Default()
	job := updatecheck.Job{ID: "job", ReviewToken: "token", State: "ready", ConfigRevision: 7, Channel: "stable", Release: &updatecheck.Release{Version: "9.9.9"}}
	cfg := config.Config{Revision: 7}
	if !autoInstallAllowed(job, cfg, false, false, p) {
		t.Fatal("prepared package refused")
	}
	for name, mutate := range map[string]func(*updatecheck.Job, *config.Config, *bool){
		"other settings":  func(j *updatecheck.Job, c *config.Config, _ *bool) { c.Revision = 8 },
		"not ready":       func(j *updatecheck.Job, _ *config.Config, _ *bool) { j.State = "preparing" },
		"no release":      func(j *updatecheck.Job, _ *config.Config, _ *bool) { j.Release = nil },
		"no review token": func(j *updatecheck.Job, _ *config.Config, _ *bool) { j.ReviewToken = "" },
		"other channel":   func(j *updatecheck.Job, _ *config.Config, _ *bool) { j.Channel = "preview" },
		"safe mode":       func(_ *updatecheck.Job, c *config.Config, _ *bool) { c.SafeMode = true },
		"stopped":         func(_ *updatecheck.Job, c *config.Config, _ *bool) { c.ServiceControl.Stopped = true },
		"draft":           func(_ *updatecheck.Job, _ *config.Config, d *bool) { *d = true },
	} {
		j, c, d := job, cfg, false
		mutate(&j, &c, &d)
		if autoInstallAllowed(j, c, d, false, p) {
			t.Errorf("%s: installation allowed", name)
		}
	}
}

// Without a prepared package the round keeps its admission.
func TestAutoInstallWithoutPackageDoesNothing(t *testing.T) {
	a := &App{}
	if a.runAutoInstall(context.Background(), autonomy.Default()) {
		t.Fatal("installation started without a prepared package")
	}
}

func TestAutoUpdateComponentsSummary(t *testing.T) {
	a := &App{}
	views := []components.View{
		{Spec: components.Spec{ID: "sing-box", Name: "Sing-box"}, Installed: true, CanUpdate: false},
		{Spec: components.Spec{ID: "xray", Name: "Xray"}, Installed: false, CanUpdate: true},
	}
	if got := a.autoUpdateComponents(context.Background(), views); got != "Менеджер компонентов или настройки недоступны." {
		t.Fatalf("summary %q", got)
	}
	// Missing manager refuses work before IO; it does not prove any installed version.
	views = append(views, components.View{Spec: components.Spec{ID: "nfqws2", Name: "NFQWS2"}, Installed: true, CanUpdate: true})
	if got := a.autoUpdateComponents(context.Background(), views); !strings.Contains(got, "недоступны") || strings.Contains(got, "прежние версии сохранены") {
		t.Fatalf("summary %q", got)
	}
}

// Run 457: a clean 0.20.0 starts in Safe Mode and keeps a saved, unapplied
// policy. With no committed live plan the update preserves both, so neither
// may block it; every other condition still refuses.
func TestAutoInstallOnQuietNetworkIgnoresSafeModeAndDraft(t *testing.T) {
	p := autonomy.Default()
	job := updatecheck.Job{ID: "job", ReviewToken: "token", State: "ready", ConfigRevision: 7, Channel: "stable", Release: &updatecheck.Release{Version: "9.9.9"}}
	cfg := config.Config{Revision: 7, SafeMode: true}
	if !autoInstallAllowed(job, cfg, true, true, p) {
		t.Fatal("quiet clean install refused")
	}
	if autoInstallAllowed(job, cfg, false, false, p) || autoInstallAllowed(job, config.Config{Revision: 7}, true, false, p) {
		t.Fatal("live network lost the Safe Mode or draft refusal")
	}
	for name, mutate := range map[string]func(*updatecheck.Job, *config.Config){
		"other settings": func(_ *updatecheck.Job, c *config.Config) { c.Revision = 8 },
		"other channel":  func(j *updatecheck.Job, _ *config.Config) { j.Channel = "preview" },
		"stopped":        func(_ *updatecheck.Job, c *config.Config) { c.ServiceControl.Stopped = true },
		"not ready":      func(j *updatecheck.Job, _ *config.Config) { j.State = "preparing" },
	} {
		j, c := job, cfg
		mutate(&j, &c)
		if autoInstallAllowed(j, c, true, true, p) {
			t.Errorf("%s: quiet network allowed installation", name)
		}
	}
}

func TestSelfUpdateAuthorityInSafeModeFollowsCommittedPlan(t *testing.T) {
	store, err := config.Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	// A leftover flag (older build, offline restore marker) on a clean configuration.
	if err := store.SetSafeMode(true); err != nil {
		t.Fatal(err)
	}
	manager := dataplane.New(t.TempDir())
	a := &App{Store: store, Dataplane: manager}
	revision := store.Get().Revision
	if err := a.selfUpdateFileAuthority(context.Background(), revision); err != nil {
		t.Fatal("clean Safe Mode installation refused its update", err)
	}
	if err := manager.Record(dataplane.Plan{PlanID: "dp-1111111111111111", Digest: strings.Repeat("a", 64), State: "committed", Revision: revision, Adapters: []string{"nfqws2"}}); err != nil {
		t.Fatal(err)
	}
	if err := a.selfUpdateFileAuthority(context.Background(), revision); !errors.Is(err, updatecheck.ErrReviewChanged) {
		t.Fatal("Safe Mode over a committed live plan allowed the installer", err)
	}
	if err := store.SetSafeMode(false); err != nil {
		t.Fatal(err)
	}
	if err := a.selfUpdateFileAuthority(context.Background(), revision); !errors.Is(err, updatecheck.ErrReviewChanged) {
		t.Fatal("changed Safe Mode kept the job's revision binding", err)
	}
	if err := a.selfUpdateFileAuthority(context.Background(), store.Get().Revision); err != nil {
		t.Fatal("ordinary live update refused", err)
	}
}
