package updatecheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

func fileExclusionConfig(t *testing.T) config.Config {
	t.Helper()
	snapshot := &config.AcceptedRussianSnapshot{CatalogID: "ru-source", Revision: 6, Entries: []config.ResourceMatch{{Kind: "suffix", Value: "example.ru"}}}
	snapshot.Digest = config.RussianSnapshotDigest(snapshot)
	p := &config.NetworkPolicy{Schema: 1, Revision: 3,
		Clients:    config.ClientScope{Mode: "lan_except", SegmentIDs: []string{"home"}, NewDevices: "inherit", ExcludedDeviceIDs: []string{"device-private"}, ExcludedCIDRs: []string{"192.168.2.0/24"}},
		Traffic:    config.TrafficSelection{Mode: "selected_services", Unavailable: "retain"},
		Rules:      []config.NetworkRule{{ID: "private-direct", Revision: 1, Kind: "exact", Value: "private.example.com", Action: "direct", Mandatory: true, DeviceIDs: []string{"device-private"}}},
		Exclusions: &config.ResourceExclusions{Schema: 1, Revision: 2, Manual: []config.ResourceMatch{{Kind: "exact", Value: "manual.example.com"}}, RussianSnapshot: snapshot}}
	cfg := config.Default()
	cfg.SafeMode, cfg.Revision = false, 7
	cfg.NetworkPolicy, cfg.AppliedNetworkPolicy = p, config.CloneNetworkPolicy(p)
	return cfg
}

func sealFileExclusionFixture(t *testing.T, a *SelfUpdateFileAdapter, u *Updater, r fileReview, old, staged []byte) fileReview {
	t.Helper()
	if err := os.WriteFile(u.Deployment.Paths["config"], old, 0600); err != nil {
		t.Fatal(err)
	}
	job := filepath.Join(a.directory, r.ID)
	if err := os.WriteFile(filepath.Join(job, "staged/config.json"), staged, 0600); err != nil {
		t.Fatal(err)
	}
	r.OldConfigSHA256, r.MigratedConfigSHA256 = digestBytes(old), digestBytes(staged)
	r.Files = reviewedFileList(job, *u.record.Job.Release, u.record.Files, r.MigratedConfigSHA256)
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(job, "file-review.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	u.mu.Lock()
	u.record.FileReviewSHA256 = digestBytes(data)
	err = u.persistLocked()
	u.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// A model uses the actual six-file journal and original old bytes. This is
// filesystem/CAS coverage, not process, Linux, Store or restored-route proof.
func prepareFileExclusionJournal(t *testing.T, a *SelfUpdateFileAdapter, u *Updater, r fileReview) *selfupdatejournal.Store {
	t.Helper()
	oldConfig, err := os.ReadFile(u.Deployment.Paths["config"])
	if err != nil {
		t.Fatal(err)
	}
	oldBinary, err := os.ReadFile(u.Deployment.Executable)
	if err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string][]byte{"bin/razvilka": oldBinary, "etc/init.d/S99razvilka": []byte("trusted old init"), "etc/razvilka/config.json": oldConfig} {
		retainedFile(t, a.installation, path, data)
	}
	if err := os.MkdirAll(a.fileJournal, 0700); err != nil {
		t.Fatal(err)
	}
	u.mu.Lock()
	u.record.Deployment.Paths["config"] = filepath.Join(a.installation, "etc/razvilka/config.json")
	u.Deployment = u.record.Deployment
	err = u.persistLocked()
	u.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	s, err := selfupdatejournal.Open(a.installation, a.fileJournal)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	check := func(context.Context) error { return nil }
	if err := s.Prepare(context.Background(), r.ID, r.Files, check, check); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestFileConfigExclusionsRefuseLossBeforeEffect(t *testing.T) {
	for _, change := range []string{"manual", "disabled-ru", "ru-revision", "device", "client-cidr", "scoped-direct", "applied"} {
		t.Run(change, func(t *testing.T) {
			a, u, r := fileAdapterFixture(t)
			cfg := fileExclusionConfig(t)
			old, _ := json.Marshal(cfg)
			switch change {
			case "manual":
				cfg.NetworkPolicy.Exclusions.Manual = []config.ResourceMatch{}
			case "disabled-ru":
				cfg.NetworkPolicy.Exclusions.RussianSnapshot = nil
			case "ru-revision":
				cfg.NetworkPolicy.Exclusions.RussianSnapshot.Revision++
				cfg.NetworkPolicy.Exclusions.RussianSnapshot.Digest = config.RussianSnapshotDigest(cfg.NetworkPolicy.Exclusions.RussianSnapshot)
			case "device":
				cfg.NetworkPolicy.Clients.ExcludedDeviceIDs = nil
			case "client-cidr":
				cfg.NetworkPolicy.Clients.ExcludedCIDRs = nil
			case "scoped-direct":
				cfg.NetworkPolicy.Rules[0].DeviceIDs = []string{"device-other"}
			case "applied":
				cfg.AppliedNetworkPolicy.Exclusions.Manual = []config.ResourceMatch{}
			}
			staged, _ := json.Marshal(cfg)
			if _, _, err := config.InspectBytes(staged); err != nil {
				t.Fatal("test needs valid candidate intent", err)
			}
			r = sealFileExclusionFixture(t, a, u, r, old, staged)
			calls := 0
			if err := a.EffectAdmission(context.Background(), r.ID, "replace-to-rollback", "rollback-file-5", func() error { calls++; return nil }); !errors.Is(err, ErrReviewChanged) || calls != 0 {
				t.Fatal("changed saved exclusion reached effect", err, calls)
			}
			current, _ := os.ReadFile(u.Deployment.Paths["config"])
			candidate, _ := os.ReadFile(filepath.Join(a.directory, r.ID, "staged/config.json"))
			if !bytes.Equal(current, old) || !bytes.Equal(candidate, staged) {
				t.Fatal("refusal silently merged or repaired config")
			}
		})
	}
}

func TestFileConfigExclusionsStrictMigrationAndHistory(t *testing.T) {
	cfg := fileExclusionConfig(t)
	old, _ := json.Marshal(cfg)
	pretty, _ := json.MarshalIndent(cfg, "", "  ")
	if _, err := inspectFileMigration(old, pretty, cfg.Revision); err != nil {
		t.Fatal("format-only migration lost saved exclusion state", err)
	}
	for _, invalid := range [][]byte{append(append([]byte(nil), old...), []byte(" {}")...), bytes.Replace(old, []byte(`"schema_version":2`), []byte(`"future_exclusions":{},"schema_version":2`), 1)} {
		if _, err := inspectFileMigration(old, invalid, cfg.Revision); err == nil {
			t.Fatal("unknown exclusion shape or trailing JSON was laundered")
		}
	}
	a, u, r := fileAdapterFixture(t)
	cfg.NetworkPolicy.Traffic = config.TrafficSelection{Mode: "all_except", DefaultRoute: "usque", AllExceptAllowed: true, Unavailable: "retain"}
	cfg.AppliedNetworkPolicy = config.CloneNetworkPolicy(cfg.NetworkPolicy)
	history, _ := json.Marshal(cfg)
	r = sealFileExclusionFixture(t, a, u, r, history, append(append([]byte(nil), history...), '\n'))
	if err := a.AuthorityAction(context.Background(), r.ID, r.Revision, "replace-to-rollback"); err != nil {
		t.Fatal("historical typed data could not be observed for rollback", err)
	}
	calls := 0
	if err := a.EffectAdmission(context.Background(), r.ID, "start/live", "command-child-start-rollback-panel", func() error { calls++; return nil }); !errors.Is(err, ErrReviewChanged) || calls != 0 {
		t.Fatal("historical full-tunnel image authorized forward start", err, calls)
	}
}

func TestFileConfigExclusionsAfterInstallRequireExactPriorJournal(t *testing.T) {
	a, u, r := fileAdapterFixture(t)
	cfg := fileExclusionConfig(t)
	old, _ := json.Marshal(cfg)
	next, _ := json.MarshalIndent(cfg, "", "  ")
	r = sealFileExclusionFixture(t, a, u, r, old, next)
	s := prepareFileExclusionJournal(t, a, u, r)
	check := func(context.Context) error { return nil }
	if err := s.InstallAdmitted(context.Background(), r.ID, check, check, func(_ context.Context, _ string, begin func() error) error { return begin() }); err != nil {
		t.Fatal(err)
	}
	if err := a.AuthorityAction(context.Background(), r.ID, r.Revision, "replace-to-rollback"); err != nil {
		t.Fatal("preserved negatives with actual prior journal refused", err)
	}
	path := u.Deployment.Paths["config"]
	cfg.NetworkPolicy.Exclusions.Manual = append(cfg.NetworkPolicy.Exclusions.Manual, config.ResourceMatch{Kind: "exact", Value: "newly-excluded.example.com"})
	cfg.Revision++
	latest, _ := json.Marshal(cfg)
	if err := os.WriteFile(path, latest, 0600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	if err := a.EffectAdmission(context.Background(), r.ID, "replace-to-rollback", "rollback-file-5", func() error { calls++; return nil }); !errors.Is(err, ErrReviewChanged) || calls != 0 {
		t.Fatal("latest exclusion edit bypassed third-image fence", err, calls)
	}
	actual, _ := os.ReadFile(path)
	if !bytes.Equal(actual, latest) {
		t.Fatal("latest manual exclusion was overwritten")
	}
	if err := os.WriteFile(path, next, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a.fileJournal, r.ID, "old-5"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.EffectAdmission(context.Background(), r.ID, "replace-to-rollback", "rollback-file-5", func() error { calls++; return nil }); err == nil || calls != 0 {
		t.Fatal("corrupt original snapshot reached rollback effect", err, calls)
	}
}

func TestFileConfigExclusionsUnappliedNegativesRefuseStart(t *testing.T) {
	a, u, r := fileAdapterFixture(t)
	cfg := fileExclusionConfig(t)
	cfg.NetworkPolicy.Exclusions.Manual = append(cfg.NetworkPolicy.Exclusions.Manual, config.ResourceMatch{Kind: "exact", Value: "newly-excluded.example.com"})
	cfg.NetworkPolicy.Exclusions.Revision++
	cfg.NetworkPolicy.Revision++
	data, _ := json.Marshal(cfg)
	r = sealFileExclusionFixture(t, a, u, r, data, append(append([]byte(nil), data...), '\n'))
	if err := a.AuthorityAction(context.Background(), r.ID, r.Revision, "replace-to-rollback"); err != nil {
		t.Fatal("preserved current exclusions could not be checked for data rollback", err)
	}
	calls := 0
	if err := a.EffectAdmission(context.Background(), r.ID, "start/live", "command-child-start-rollback-panel", func() error { calls++; return nil }); !errors.Is(err, ErrReviewChanged) || calls != 0 {
		t.Fatal("old applied policy ignored newly saved exclusion", err, calls)
	}
	actual, _ := os.ReadFile(u.Deployment.Paths["config"])
	if !bytes.Equal(actual, data) {
		t.Fatal("unapplied exclusion was silently cleared")
	}
}

func TestFileConfigInactiveExclusionsPreservedBeforeEffect(t *testing.T) {
	for _, change := range []string{"preserved", "dropped", "replaced", "revision", "promoted"} {
		t.Run(change, func(t *testing.T) {
			a, u, r := fileAdapterFixture(t)
			cfg := config.Default()
			cfg.SafeMode, cfg.Revision = false, 7
			cfg.InactiveResourceExclusions = &config.ResourceExclusions{Schema: 1, Revision: 2, Manual: []config.ResourceMatch{{Kind: "exact", Value: "manual.example.com"}}}
			old, _ := json.Marshal(cfg)
			switch change {
			case "dropped":
				cfg.InactiveResourceExclusions = nil
			case "replaced":
				cfg.InactiveResourceExclusions.Manual[0].Value = "other.example.com"
			case "revision":
				cfg.InactiveResourceExclusions.Revision--
			case "promoted":
				cfg.NetworkPolicy = fileExclusionConfig(t).NetworkPolicy
				cfg.NetworkPolicy.Exclusions = cfg.InactiveResourceExclusions
				cfg.InactiveResourceExclusions = nil
			}
			staged, _ := json.MarshalIndent(cfg, "", "  ")
			if _, _, err := config.InspectBytes(staged); err != nil {
				t.Fatal("test needs a strictly valid staged document", err)
			}
			r = sealFileExclusionFixture(t, a, u, r, old, staged)
			calls := 0
			err := a.EffectAdmission(context.Background(), r.ID, "replace-to-rollback", "rollback-file-5", func() error { calls++; return nil })
			if change == "preserved" {
				if err != nil || calls != 1 {
					t.Fatal("exact inactive document refused for data-only rollback", err, calls)
				}
				// Whole-network site exclusions travel in the committed plan the
				// restored version applies, so they no longer close its start.
				calls = 0
				if err = a.EffectAdmission(context.Background(), r.ID, "start/live", "command-child-start-rollback-panel", func() error { calls++; return nil }); err != nil || calls != 1 {
					t.Fatal("exact inactive document refused a live start", err, calls)
				}
			} else if !errors.Is(err, ErrReviewChanged) || calls != 0 {
				t.Fatal("changed inactive document reached a file effect", err, calls)
			}
			actual, _ := os.ReadFile(u.Deployment.Paths["config"])
			if !bytes.Equal(actual, old) {
				t.Fatal("inactive document was silently cleared or promoted")
			}
		})
	}
}

func TestFileConfigInactiveExclusionsLatestEditKeepsThirdImageFence(t *testing.T) {
	a, u, r := fileAdapterFixture(t)
	cfg := config.Default()
	cfg.SafeMode, cfg.Revision = false, 7
	cfg.InactiveResourceExclusions = &config.ResourceExclusions{Schema: 1, Revision: 1, Manual: []config.ResourceMatch{{Kind: "exact", Value: "manual.example.com"}}}
	old, _ := json.Marshal(cfg)
	next, _ := json.MarshalIndent(cfg, "", "  ")
	r = sealFileExclusionFixture(t, a, u, r, old, next)
	s := prepareFileExclusionJournal(t, a, u, r)
	check := func(context.Context) error { return nil }
	if err := s.InstallAdmitted(context.Background(), r.ID, check, check, func(_ context.Context, _ string, begin func() error) error { return begin() }); err != nil {
		t.Fatal(err)
	}
	if err := a.AuthorityAction(context.Background(), r.ID, r.Revision, "replace-to-rollback"); err != nil {
		t.Fatal("actual prior inactive image was not readable", err)
	}
	cfg.InactiveResourceExclusions.Manual = append(cfg.InactiveResourceExclusions.Manual, config.ResourceMatch{Kind: "cidr", Value: "203.0.113.0/24"})
	cfg.InactiveResourceExclusions.Revision++
	cfg.Revision++
	latest, _ := json.Marshal(cfg)
	path := u.Deployment.Paths["config"]
	if err := os.WriteFile(path, latest, 0600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	if err := a.EffectAdmission(context.Background(), r.ID, "replace-to-rollback", "rollback-file-5", func() error { calls++; return nil }); !errors.Is(err, ErrReviewChanged) || calls != 0 {
		t.Fatal("latest inactive edit reached old rollback effect", err, calls)
	}
	actual, _ := os.ReadFile(path)
	if !bytes.Equal(actual, latest) {
		t.Fatal("latest inactive edit was overwritten")
	}
}
