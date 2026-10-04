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
	"github.com/ArtixSx/razvilka/internal/restorejournal"
	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

func fileAdapterFixture(t *testing.T) (*SelfUpdateFileAdapter, *Updater, fileReview) {
	t.Helper()
	u := readyUpdater(t)
	u.helperOwned = func(string) error { return nil } // isolated file fixture only
	u.FileEffectAdmission = func(ctx context.Context, id, installation string, sequence uint64, action, effect string, begin func() error) error {
		return begin()
	}
	installation := t.TempDir()
	configPath := filepath.Join(installation, "config.json")
	cfg := config.Config{Revision: 7}
	old, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, old, 0600); err != nil {
		t.Fatal(err)
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.record.Deployment.Paths = map[string]string{"config": configPath}
	u.Deployment = u.record.Deployment
	id := u.record.Job.ID
	jobPath := filepath.Join(u.Directory, id)
	if err := os.MkdirAll(filepath.Join(jobPath, "staged"), 0700); err != nil {
		t.Fatal(err)
	}
	staged := append(append([]byte(nil), old...), '\n')
	if err := os.WriteFile(filepath.Join(jobPath, "staged", "config.json"), staged, 0600); err != nil {
		t.Fatal(err)
	}
	r := fileReview{Schema: SelfUpdateReadVersion, ID: id, Revision: 7, OldConfigSHA256: digestBytes(old), MigratedConfigSHA256: digestBytes(staged), OldExecutableSHA256: u.record.ExecutableHash, OldInitSHA256: digestBytes([]byte("trusted old init")), OldVersion: u.Current, NewVersion: u.record.Job.Release.Version, ReleaseID: u.record.Job.Release.ID}
	r.AuthoritySequence = 1
	r.AuthorityInstallationID = "fedcba9876543210fedcba9876543210"
	r.Files = reviewedFileList(jobPath, *u.record.Job.Release, u.record.Files, r.MigratedConfigSHA256)
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(jobPath, "file-review.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	u.record.FileReviewSHA256 = digestBytes(data)
	if err := u.persistLocked(); err != nil {
		t.Fatal(err)
	}
	a := &SelfUpdateFileAdapter{directory: u.Directory, installation: installation, fileJournal: filepath.Join(installation, "file-journal"), owned: func(string) error { return nil }, layout: func(Deployment) error { return nil }, capabilities: func(context.Context, string) error { return nil }, stopCheck: func(context.Context, string) (bool, error) { return false, nil }}
	a.admission = func(ctx context.Context, id, installationID string, sequence uint64, action, effect string, begin func() error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return begin()
	}
	a.runtimeInactive = func(context.Context, string) error { return nil }
	a.filesystem = func(context.Context) error { return nil } // Model fixture, never native filesystem acceptance.
	return a, u, r
}

func TestPrivateSnapshotExcludesRetainedNativeRuntimeAndLKG(t *testing.T) {
	a, _, r := fileAdapterFixture(t)
	ctx := context.Background()
	for _, rel := range []string{"etc/razvilka", "var/lib/razvilka"} {
		if err := os.MkdirAll(filepath.Join(a.installation, filepath.FromSlash(rel)), 0700); err != nil {
			t.Fatal(err)
		}
	}
	retained := map[string][]byte{
		"var/lib/razvilka/warp/native-enrollment.private.json":              []byte("unknown authoritative native intent"),
		"var/lib/razvilka/warp/native-enrollment/attempt-1/private-key.bin": []byte("immutable retained key"),
		"var/lib/razvilka/warp/health-policy.json":                          []byte("latest accounting"),
		"etc/razvilka/cloudflare-private/accounts.private.json":             []byte("latest provider state"),
		"etc/razvilka/private-restore-native-v1/restore.private.json":       []byte("retained generation"),
		"etc/razvilka/private-restore-feeds-v1/restore.private.json":        []byte("retained feeds generation"),
		"var/lib/razvilka/dataplane/journal":                                []byte("latest owned network receipt"),
		"var/lib/razvilka/backups/final-lkg/record":                         []byte("final LKG"),
	}
	for path, data := range retained {
		retainedFile(t, a.installation, path, data)
	}
	if err := a.preparePrivateSnapshot(ctx, r.ID); err != nil {
		t.Fatal(err)
	}
	snapshot, err := a.privateSnapshot(ctx, r.ID)
	if err != nil || snapshot.Schema != 2 || len(snapshot.Images) != 10 {
		t.Fatal("mutable snapshot contract", err)
	}
	for _, name := range []string{"warp", "cloudflare", "runtime", "lkg"} {
		if _, ok := snapshot.Images[name]; ok {
			t.Fatal("retained domain entered mutable snapshot", name)
		}
	}
	for path, before := range retained {
		after, err := os.ReadFile(filepath.Join(a.installation, filepath.FromSlash(path)))
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("retained history changed", path, err)
		}
	}
	// Old whole-domain images remain readable evidence but never executable
	// restore instructions, even when their images were absent.
	legacy := privateFileSnapshot{Schema: 1, ID: r.ID, Images: map[string]restorejournal.Image{}}
	for name := range filePrivateDirectories {
		legacy.Images[name] = restorejournal.Image{}
	}
	for name := range filePrivateFiles {
		legacy.Images[name] = restorejournal.Image{}
	}
	if err := validatePrivateSnapshot(legacy); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(legacy)
	job := filepath.Join(a.directory, r.ID)
	if err := os.WriteFile(filepath.Join(job, "private-snapshot.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(job, "private-snapshot.sha256"), []byte(digestBytes(data)), 0600); err != nil {
		t.Fatal(err)
	}
	if a.restorePrivateSnapshot(ctx, r.ID) == nil {
		t.Fatal("whole-domain legacy snapshot authorized restore")
	}
}

func TestTerminalFileInspectionAllowsLaterTypedConfigButKeepsArtifacts(t *testing.T) {
	a, u, r := fileAdapterFixture(t)
	ctx := context.Background()
	for _, rel := range []string{"bin", "etc/init.d", "etc/razvilka", "file-journal"} {
		if err := os.MkdirAll(filepath.Join(a.installation, filepath.FromSlash(rel)), 0700); err != nil {
			t.Fatal(err)
		}
	}
	store, err := selfupdatejournal.Open(a.installation, a.fileJournal)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	check := func(context.Context) error { return nil }
	if err := store.Prepare(ctx, r.ID, r.Files, check, check); err != nil {
		t.Fatal(err)
	}
	if err := store.InstallAdmitted(ctx, r.ID, check, check, func(c context.Context, effect string, begin func() error) error { return begin() }); err != nil {
		t.Fatal(err)
	}
	if err := store.Accept(ctx, r.ID, false, check, check); err != nil {
		t.Fatal(err)
	}
	u.mu.Lock()
	u.record.Job.State = "completed"
	u.record.Deployment.Paths["config"] = filepath.Join(a.installation, "etc/razvilka/config.json")
	if err := archiveHelperRecord(u.Directory, u.record); err != nil {
		t.Fatal(err)
	}
	if err := u.persistLocked(); err != nil {
		t.Fatal(err)
	}
	u.mu.Unlock()
	path := u.record.Deployment.Paths["config"]
	for _, cfg := range []config.Config{{Revision: 8}, {Revision: 9, SafeMode: true}, {Revision: 10, ServiceControl: config.ServiceControl{Stopped: true}}} {
		data, _ := json.Marshal(cfg)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		if err := a.Inspect(ctx, r.ID); err != nil {
			t.Fatal("terminal journal fenced ordinary later config", err)
		}
	}
	for _, cfg := range []config.Config{{Revision: 6}, {Revision: 10, SchemaVersion: 999}} {
		data, _ := json.Marshal(cfg)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		if a.Inspect(ctx, r.ID) == nil {
			t.Fatal("invalid later config accepted")
		}
	}
	data, _ := json.Marshal(config.Config{Revision: 10})
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a.installation, "bin/razvilka"), []byte("foreign"), 0755); err != nil {
		t.Fatal(err)
	}
	if a.Inspect(ctx, r.ID) == nil {
		t.Fatal("terminal receipt concealed changed executable")
	}
}

func TestFileReviewImmutableAndFreshAuthority(t *testing.T) {
	a, u, r := fileAdapterFixture(t)
	ctx := context.Background()
	if err := a.Ready(ctx, r.ID); err != nil {
		t.Fatal(err)
	}
	revision, hash, files, err := a.Review(ctx, r.ID)
	if err != nil || revision != 7 || hash != r.MigratedConfigSHA256 || len(files) != 6 {
		t.Fatal("sealed six-file review unavailable")
	}
	files[0].Target = "foreign"
	_, _, again, err := a.Review(ctx, r.ID)
	if err != nil || again[0].Target == "foreign" {
		t.Fatal("caller mutated immutable review")
	}
	path := u.Deployment.Paths["config"]
	for _, mutate := range []func(*config.Config){func(c *config.Config) { c.Revision++ }, func(c *config.Config) { c.SafeMode = true }, func(c *config.Config) { c.ServiceControl.Stopped = true }} {
		cfg := config.Config{Revision: 7}
		mutate(&cfg)
		data, _ := json.Marshal(cfg)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		if !errors.Is(a.Authority(ctx, r.ID, 7), ErrReviewChanged) {
			t.Fatal("live authority accepted changed configuration")
		}
		_, got, _, err := a.Review(ctx, r.ID)
		if err != nil || got != hash {
			t.Fatal("live change rewrote the staged digest")
		}
	}
	// A valid configuration with equal revision but different unreviewed bytes
	// remains a third image, including an otherwise harmless whitespace edit.
	old, _ := json.Marshal(config.Config{Revision: 7})
	if err := os.WriteFile(path, append(old, ' '), 0600); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(a.Authority(ctx, r.ID, 7), ErrReviewChanged) {
		t.Fatal("third file image was accepted")
	}
	if err := os.WriteFile(path, append(old, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.Authority(ctx, r.ID, 7); err != nil {
		t.Fatal("frozen migrated image refused", err)
	}
}

func TestFileStopConsumerFailClosedAndActionSensitive(t *testing.T) {
	a, _, r := fileAdapterFixture(t)
	ctx := context.Background()
	a.stopCheck = nil
	if !errors.Is(a.Authority(ctx, r.ID, 7), ErrFileProtocol) {
		t.Fatal("missing Stop consumer authorized effects")
	}
	a.stopCheck = func(context.Context, string) (bool, error) { return true, nil }
	if !errors.Is(a.Authority(ctx, r.ID, 7), ErrFileAuthorityStopped) {
		t.Fatal("Stop did not revoke live authority")
	}
	for _, action := range []string{"read/observe", "replace-to-rollback", "stop-owned"} {
		if err := a.AuthorityAction(ctx, r.ID, 7, action); err != nil {
			t.Fatal("bounded stopped recovery denied", err)
		}
	}
	if a.AuthorityAction(ctx, r.ID, 7, "arbitrary") == nil {
		t.Fatal("arbitrary effect authorized")
	}
	corrupt := errors.New("stop evidence corrupt")
	a.stopCheck = func(context.Context, string) (bool, error) { return false, corrupt }
	if !errors.Is(a.AuthorityAction(ctx, r.ID, 7, "replace-to-rollback"), corrupt) {
		t.Fatal("corrupt revocation bypassed by rollback")
	}
}

func TestFileReviewTamperAndLegacyReceiptFence(t *testing.T) {
	for _, tamper := range []string{"staged", "review", "legacy", "duplicate"} {
		t.Run(tamper, func(t *testing.T) {
			a, u, r := fileAdapterFixture(t)
			job := filepath.Join(u.Directory, r.ID)
			switch tamper {
			case "staged":
				if err := os.WriteFile(filepath.Join(job, "staged", "config.json"), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "review":
				data, _ := os.ReadFile(filepath.Join(job, "file-review.json"))
				if err := os.WriteFile(filepath.Join(job, "file-review.json"), append(data, ' '), 0600); err != nil {
					t.Fatal(err)
				}
			case "legacy":
				u.mu.Lock()
				u.record.FileReviewSHA256 = ""
				err := u.persistLocked()
				u.mu.Unlock()
				if err != nil {
					t.Fatal(err)
				}
			case "duplicate":
				u.mu.Lock()
				data, _ := json.Marshal(u.record)
				u.mu.Unlock()
				data = bytes.Replace(data, []byte("{"), []byte("{\"owner\":\"foreign\","), 1)
				if err := os.WriteFile(filepath.Join(u.Directory, "current.json"), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, _, err := a.Review(context.Background(), r.ID); err == nil {
				t.Fatal("untrusted file review accepted")
			}
		})
	}
}

func TestSubsequentPrepareRetainsReviewedEvidence(t *testing.T) {
	a, u, r := fileAdapterFixture(t)
	u.mu.Lock()
	u.record.Job.State = "completed"
	u.record.Job.CanApply = false
	err := u.persistLocked()
	u.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(u.Directory, r.ID, "file-review.json"))
	if err != nil {
		t.Fatal(err)
	}
	job, err := u.Prepare(8, "new-review")
	if err != nil {
		t.Fatal(err)
	}
	<-u.done
	if job.ID == r.ID {
		t.Fatal("job ID reused")
	}
	after, err := os.ReadFile(filepath.Join(u.Directory, r.ID, "file-review.json"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("retained recovery evidence deleted")
	}
	if _, _, err := a.loadBoundReview(context.Background(), r.ID, true, true); err != nil {
		t.Fatal("retained review lost binding", err)
	}
	if _, _, _, err := a.Review(context.Background(), r.ID); err == nil {
		t.Fatal("historical review became active authority")
	}
}

func TestFileEffectAdmissionUsesSealedEpochAndExactEffectKind(t *testing.T) {
	a, _, r := fileAdapterFixture(t)
	ctx := context.Background()
	calls, begins := 0, 0
	stopped := errors.New("Stop won the control lock")
	a.admission = func(ctx context.Context, id, installationID string, sequence uint64, action, effect string, begin func() error) error {
		calls++
		if id != r.ID || installationID != r.AuthorityInstallationID || sequence != r.AuthoritySequence || action != "start/live" || effect != "command-child-start-candidate-panel" {
			t.Fatal("unsealed effect binding")
		}
		return stopped
	}
	if !errors.Is(a.EffectAdmission(ctx, r.ID, "start/live", "command-child-start-candidate-panel", func() error { begins++; return nil }), stopped) || calls != 1 || begins != 0 {
		t.Fatal("late spawn admitted after Stop")
	}
	if a.EffectAdmission(ctx, r.ID, "replace-to-rollback", "command-child-start-candidate-panel", func() error { begins++; return nil }) == nil || calls != 1 || begins != 0 {
		t.Fatal("start borrowed rollback authority")
	}
	a.admission = nil
	if a.EffectAdmission(ctx, r.ID, "start/live", "install-file-0", func() error { begins++; return nil }) == nil || begins != 0 {
		t.Fatal("readonly Stop check used as spawn admission")
	}
}
