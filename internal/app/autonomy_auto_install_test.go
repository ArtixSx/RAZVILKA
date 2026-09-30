package app

import (
	"context"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

// A version the installer rolled back is not installed again automatically;
// the running version and newer ones are not affected.
func TestAutoInstallSkipsRolledBackVersion(t *testing.T) {
	a := &App{}
	a.autonomy.doc.Maintenance = map[string]string{autoInstallReceipt: "9.9.9"}
	if !a.autoInstallFailed("9.9.9") {
		t.Fatal("rolled-back version would be installed again")
	}
	if a.autoInstallFailed("9.9.10") || a.autoInstallFailed("") {
		t.Fatal("newer version blocked")
	}
	a.autonomy.doc.Maintenance[autoInstallReceipt] = Version
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
	if !autoInstallAllowed(job, cfg, false, p) {
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
		if autoInstallAllowed(j, c, d, p) {
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
	if got := a.autoUpdateComponents(context.Background(), views); got != "Каталог компонентов проверен. Обновлений нет." {
		t.Fatalf("summary %q", got)
	}
	// Without a component manager the update fails and the old version stays.
	views = append(views, components.View{Spec: components.Spec{ID: "nfqws2", Name: "NFQWS2"}, Installed: true, CanUpdate: true})
	if got := a.autoUpdateComponents(context.Background(), views); !strings.Contains(got, "Не обновлено (прежние версии сохранены): NFQWS2") {
		t.Fatalf("summary %q", got)
	}
}
