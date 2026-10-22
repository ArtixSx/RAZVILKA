package updatecheck

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOrdinaryPreparationCapabilitiesNeverGrantGeneralSchema2(t *testing.T) {
	metadata := map[string]string{"-self-update-schema": "0\n", "-self-update-read-version": "4\n", "-component-update-schema": "3\n", "-node-history-read-version": "3\n", "-native-enrollment-schema": "1\n", "-subscription-schema": "1\n"}
	probe := func(_ context.Context, _ string, flag string) (string, error) { return metadata[flag], nil }
	if err := checkOrdinaryPreparationCapabilities(context.Background(), "verified-image", 3, 3, probe); err != nil {
		t.Fatal(err)
	}
	if checkFileCapabilitiesForHistories(context.Background(), "verified-image", 3, 3, probe) == nil {
		t.Fatal("schema0 metadata authorized the general schema2 consumer")
	}
	for _, tc := range []struct{ flag, value string }{
		{"-self-update-schema", "2\n"}, {"-self-update-schema", "0"}, {"-self-update-schema", "0\nextra"},
		{"-self-update-read-version", "3\n"}, {"-self-update-read-version", "5\n"}, {"-self-update-read-version", " 4\n"},
		{"-component-update-schema", "2\n"}, {"-component-update-schema", "5\n"},
		{"-node-history-read-version", "2\n"}, {"-node-history-read-version", "4\n"},
		{"-native-enrollment-schema", "0\n"}, {"-subscription-schema", "0\n"},
	} {
		t.Run(tc.flag+tc.value, func(t *testing.T) {
			previous := metadata[tc.flag]
			metadata[tc.flag] = tc.value
			defer func() { metadata[tc.flag] = previous }()
			if checkOrdinaryPreparationCapabilities(context.Background(), "verified-image", 3, 3, probe) == nil {
				t.Fatal("malformed or insufficient metadata accepted")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	err := checkOrdinaryPreparationCapabilities(ctx, "verified-image", 3, 3, func(context.Context, string, string) (string, error) { called = true; return "", nil })
	if !errors.Is(err, context.Canceled) || called {
		t.Fatal("revoked context executed metadata", err)
	}
}

func TestOrdinaryPreparationDiagnosticsDoNotExposePrivateCause(t *testing.T) {
	cause := errors.New("private-token-value /private/path original stderr")
	for _, stage := range []string{"owner", "version", "histories", "capabilities", "journals", "candidate-check", "script-syntax", "migration", "ready", "private-token-value"} {
		err := ordinaryPreparationFailed(stage, cause)
		if !errors.Is(err, cause) || strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "stderr") || !errorCodePattern.MatchString(err.Error()) || safeUpdateCode(err) != err.Error() {
			t.Fatal("diagnostic disclosed private cause or lost fixed code", err)
		}
	}
	if ordinaryPreparationFailed("owner", nil) != nil {
		t.Fatal("success became failure")
	}
}

func lifetimePreparation(t *testing.T) (*ordinaryPreparation, context.Context, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	done := make(chan struct{})
	u := &Updater{record: updateRecord{Owner: updaterOwner, Job: Job{ID: strings.Repeat("a", 32), State: "preparing", Stage: "preflight"}}, done: done, cancel: cancel}
	p := &ordinaryPreparation{updater: u, adapter: &SelfUpdateFileAdapter{}, original: ctx, done: done, record: u.record}
	p.self = p
	p.active.Store(true)
	return p, ctx, cancel
}

func TestOrdinaryPreparationGenerationCannotBeCopiedRenewedOrRevived(t *testing.T) {
	for _, kind := range []string{"original", "copied", "released", "cancelled", "other-context", "no-deadline", "wrong-generation", "finished", "handoff", "no-cancel", "changed-record"} {
		t.Run(kind, func(t *testing.T) {
			p, ctx, cancel := lifetimePreparation(t)
			defer cancel()
			switch kind {
			case "copied":
				original := p
				p = &ordinaryPreparation{self: original, updater: p.updater, adapter: p.adapter, original: p.original, done: p.done, record: p.record}
				p.active.Store(true)
			case "released":
				p.active.Store(false)
			case "cancelled":
				cancel()
			case "other-context":
				ctx = context.WithValue(ctx, struct{}{}, "copied")
			case "no-deadline":
				ctx = context.Background()
				p.original = ctx
			case "wrong-generation":
				p.updater.done = make(chan struct{})
			case "finished":
				close(p.done)
			case "handoff":
				p.updater.handoffActive = true
			case "no-cancel":
				p.updater.cancel = nil
			case "changed-record":
				p.updater.record.Job.Stage = "ready"
			}
			err := p.lifetime(ctx)
			if (kind == "original") != (err == nil) {
				t.Fatal(kind, err)
			}
		})
	}
	if _, err := newOrdinaryPreparation(context.Background(), &Updater{Directory: t.TempDir()}, nil, make(chan struct{})); err == nil {
		t.Fatal("caller-created fixture minted production owner")
	}
}

func ordinaryReadyFixture(t *testing.T) (updateRecord, fileReview, fileProcess) {
	t.Helper()
	review, record, identity, _, _ := ordinaryRoleFixture(t)
	parent := identity.OldPanel
	review.PreparationParent = &parent
	record.Job.State, record.Job.Stage = "ready", "ready"
	record.Job.CanApply, record.Job.CanCancel = true, false
	record.Job.HelperPID = 0
	record.Job.ReviewToken = "reviewed-token"
	record.Job.UpdatedAt = time.Now().UTC()
	return record, review, parent
}

func TestOrdinaryReadyUsesOriginalParentBeforeHelperBirth(t *testing.T) {
	for _, kind := range []string{"original", "birth", "boot", "inode", "device", "executable", "pid", "missing", "invalid-present", "bootstrap", "reader3", "old-version", "same-version", "revision", "release", "helper-born", "cancelable", "future-time", "expired", "preparing"} {
		t.Run(kind, func(t *testing.T) {
			record, review, parent := ordinaryReadyFixture(t)
			switch kind {
			case "birth":
				parent.Start = "99"
			case "boot":
				parent.Boot = "11111111-1111-1111-1111-111111111111"
			case "inode":
				parent.Inode++
			case "device":
				parent.Device++
			case "executable":
				parent.ExecutableSHA256 = strings.Repeat("f", 64)
			case "pid":
				parent.PID++
			case "missing":
				review.PreparationParent = nil
			case "invalid-present":
				review.PreparationParent = &fileProcess{}
			case "bootstrap":
				review.Bootstrap = &fileBootstrapBinding{Role: externalOld193InstallerRole}
			case "reader3":
				review.JournalReaders.Schema, review.JournalReaders.RequiredReader = 3, 3
			case "old-version":
				record.CurrentVersion, review.OldVersion = "0.19.3", "0.19.3"
			case "same-version":
				record.Job.Release.Version, review.NewVersion = review.OldVersion, review.OldVersion
			case "revision":
				record.Job.ConfigRevision++
			case "release":
				record.Job.Release.ID++
			case "helper-born":
				record.Job.HelperPID = 42
			case "cancelable":
				record.Job.CanCancel = true
			case "future-time":
				record.Job.UpdatedAt = time.Now().Add(time.Minute)
			case "expired":
				record.Job.UpdatedAt = time.Now().Add(-16 * time.Minute)
			case "preparing":
				record.Job.State = "preparing"
			}
			if (kind == "original") != ordinaryReadyParentMatches(record, review, parent) {
				t.Fatal("wrong parent boundary accepted", kind)
			}
		})
	}
}

func TestOrdinaryReadyAbsentParentKeepsCap2AndInvalidPresentNeverFallsBack(t *testing.T) {
	for _, kind := range []string{"absent", "invalid-present", "unknown-field"} {
		t.Run(kind, func(t *testing.T) {
			a, u, review := fileAdapterFixture(t)
			review.OldVersion, review.NewVersion = "0.20.0", "0.20.1"
			u.record.CurrentVersion, u.record.Job.Release.Version = review.OldVersion, review.NewVersion
			_, proofReview, _ := ordinaryReadyFixture(t)
			review.JournalReaders = proofReview.JournalReaders
			if kind == "invalid-present" {
				review.PreparationParent = &fileProcess{}
			}
			data, _ := json.Marshal(review)
			if kind == "unknown-field" {
				data = append(append([]byte(nil), data[:len(data)-1]...), []byte(",\"preparation_parent_v2\":{}}")...)
			}
			if err := os.WriteFile(filepath.Join(a.directory, review.ID, "file-review.json"), data, 0600); err != nil {
				t.Fatal(err)
			}
			u.record.FileReviewSHA256 = digestBytes(data)
			if err := u.persistLocked(); err != nil {
				t.Fatal(err)
			}
			called := false
			a.capabilities = func(ctx context.Context, path string) error {
				called = true
				return checkFileCapabilitiesForHistories(ctx, path, 2, 2, func(_ context.Context, _ string, flag string) (string, error) {
					if flag == "-self-update-schema" {
						return "0\n", nil
					}
					return "2\n", nil
				})
			}
			if err := a.Ready(context.Background(), review.ID); err == nil {
				t.Fatal("schema0 or invalid parent admitted")
			}
			if called != (kind == "absent") {
				t.Fatal("invalid-present fell back or absent lost cap2 path", called)
			}
		})
	}
}

func TestOrdinaryHelperIdentityRetainsPreparationParent(t *testing.T) {
	review, record, identity, _, _ := ordinaryRoleFixture(t)
	parent := identity.OldPanel
	review.PreparationParent = &parent
	if _, err := bindHelperIdentity(review.ID, review, record, identity); err != nil {
		t.Fatal(err)
	}
	identity.OldPanel.Start = "99"
	if _, err := bindHelperIdentity(review.ID, review, record, identity); err == nil {
		t.Fatal("helper identity replaced the original preparing parent")
	}
}

func TestOrdinaryPrivateReviewPublicationCutRequiresOriginalLiveGeneration(t *testing.T) {
	a, u, review := preparingReaderFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	done := make(chan struct{})
	u.done, u.cancel = done, cancel
	data := []byte("exact private completed review")
	path := filepath.Join(a.directory, review.ID, "file-review.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	p := &ordinaryPreparation{updater: u, adapter: a, original: ctx, done: done, record: u.record, reviewSHA: digestBytes(data)}
	p.self = p
	p.active.Store(true)
	a.ordinaryPreparation = p
	if ok, err := a.preparingHelper(ctx, u.record); err != nil || !ok {
		t.Fatal("original private publication cut refused", err)
	}
	for _, kind := range []string{"cold", "derived-context", "released", "modified"} {
		t.Run(kind, func(t *testing.T) {
			checkCtx := ctx
			check := a
			switch kind {
			case "cold":
				cold := *a
				cold.ordinaryPreparation = nil
				check = &cold
			case "derived-context":
				checkCtx = context.WithValue(ctx, struct{}{}, true)
			case "released":
				p.active.Store(false)
				defer p.active.Store(true)
			case "modified":
				if err := os.WriteFile(path, append(data, 'x'), 0600); err != nil {
					t.Fatal(err)
				}
				defer os.WriteFile(path, data, 0600)
			}
			if _, err := check.preparingHelper(checkCtx, u.record); err == nil {
				t.Fatal("uncommitted cut granted public/cold reader admission")
			}
		})
	}
	if _, err := a.requiredJournalReadVersion(context.Background()); err == nil {
		t.Fatal("private generation became public scanner authority")
	}
}

func TestOrdinaryCandidateArgumentsConfineEveryMutableInput(t *testing.T) {
	job := filepath.Join(t.TempDir(), "job")
	for _, mode := range []string{"-check", "-migrate-config"} {
		cfg := filepath.Join(job, "staged/config.json")
		args := ordinaryPreparationArguments(job, mode, cfg)
		if args[0] != mode || len(args) != 21 {
			t.Fatal(args)
		}
		seen := map[string]bool{}
		for i := 1; i < len(args); i += 2 {
			flag, path := args[i], args[i+1]
			if seen[flag] {
				t.Fatal("duplicate input", flag)
			}
			seen[flag] = true
			base := filepath.Join(job, "staged")
			if flag == "-catalog" || flag == "-sources" || flag == "-community-catalog" {
				base = filepath.Join(job, "bundle/configs")
			}
			rel, err := filepath.Rel(base, path)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
				t.Fatal("candidate escaped job", flag, path)
			}
		}
	}
	for _, tc := range []struct {
		old, next string
		accepted  bool
	}{{"0.20.0", "0.20.1", true}, {"0.20.1", "1.0.0", true}, {"0.19.3", "0.20.0", false}, {"0.20.0", "0.20.0", false}, {"0.21.0", "0.20.1", false}, {"garbage", "0.20.1", false}} {
		if ordinaryFutureVersions(tc.old, tc.next) != tc.accepted {
			t.Fatal(tc)
		}
	}
	if !ordinaryPreparationReport(`{"ok":true,"version":"0.20.1","migrated":false}`, "0.20.1", true) {
		t.Fatal("genuine no-op migration refused")
	}
	for _, output := range []string{`{"ok":false,"version":"0.20.1"}`, `{"ok":true,"version":"0.20.0"}`, `{"ok":true,"version":"0.20.1"} extra`, `{"ok":true,"version":"0.20.1","migrated":true}`} {
		if ordinaryPreparationReport(output, "0.20.1", false) {
			t.Fatal("invalid read-only report admitted", output)
		}
	}
}

func TestOrdinaryPreparationCommandsAreClosedToRawApplyAndPathSubstitution(t *testing.T) {
	job := filepath.Join(t.TempDir(), "job")
	p := &ordinaryPreparation{adapter: &SelfUpdateFileAdapter{directory: filepath.Dir(job)}, record: updateRecord{Job: Job{ID: filepath.Base(job), Release: &Release{Binary: Asset{Name: "razvilka-linux-amd64"}}}, Deployment: Deployment{Executable: filepath.Join(t.TempDir(), "current"), Paths: map[string]string{"config": filepath.Join(t.TempDir(), "config.json")}}}}
	image := filepath.Join(job, "bundle/dist", p.record.Job.Release.Binary.Name)
	args := ordinaryPreparationArguments(job, "-migrate-config", filepath.Join(job, "staged/config.json"))
	if !p.commandMatches(image, args, "ordinary-prepare-migration") {
		t.Fatal("exact migration refused")
	}
	for _, tc := range []struct {
		path   string
		args   []string
		effect string
	}{
		{p.record.Deployment.Executable, args, "ordinary-prepare-migration"},
		{image, []string{"self-update-helper", p.record.Job.ID}, "ordinary-prepare-metadata"},
		{image, []string{"-self-update-schema", "2"}, "ordinary-prepare-metadata"},
		{filepath.Join(job, "unreviewed"), []string{"-version"}, "ordinary-prepare-metadata"},
		{image, args, "installer-helper"},
		{image, ordinaryPreparationArguments(job, "-migrate-config", p.record.Deployment.Paths["config"]), "ordinary-prepare-migration"},
	} {
		if p.commandMatches(tc.path, tc.args, tc.effect) {
			t.Fatal("unbounded preparation command admitted", tc)
		}
	}
	for i := 1; i < len(args); i += 2 {
		changed := append([]string(nil), args...)
		changed[i+1] = filepath.Join(t.TempDir(), "outside")
		if p.commandMatches(image, changed, "ordinary-prepare-migration") {
			t.Fatal("substituted flag escaped staging", changed[i])
		}
	}
}
