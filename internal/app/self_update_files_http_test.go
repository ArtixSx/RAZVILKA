package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/security"
	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

// Real HTTP/auth/Store/file journal. Process supervision and independent native
// live observations are deliberately simulated; these are not native D11 PASS.
type fileUpdateProof struct {
	revision                                                     uint64
	sha                                                          string
	files                                                        []selfupdatejournal.File
	runs                                                         []string
	lives                                                        []bool
	finishes                                                     []bool
	runError, liveError, inspectError, observeError, finishError error
	liveHook                                                     func()
	quiescenceHook                                               func()
	finishHook                                                   func(bool)
	runHook                                                      func(string) error
	effects                                                      []string
	effectError                                                  error
}

func (p *fileUpdateProof) Inspect(context.Context, string) error { return p.inspectError }
func (p *fileUpdateProof) Ready(context.Context, string) error   { return nil }
func (p *fileUpdateProof) Review(context.Context, string) (uint64, string, []selfupdatejournal.File, error) {
	return p.revision, p.sha, p.files, nil
}
func (p *fileUpdateProof) Authority(context.Context, string, uint64) error               { return nil }
func (p *fileUpdateProof) AuthorityAction(context.Context, string, uint64, string) error { return nil }
func (p *fileUpdateProof) EffectAdmission(_ context.Context, _ string, action, effect string, begin func() error) error {
	p.effects = append(p.effects, action+":"+effect)
	if p.effectError != nil {
		return p.effectError
	}
	return begin()
}
func (p *fileUpdateProof) Quiescence(context.Context, string) error {
	if p.quiescenceHook != nil {
		p.quiescenceHook()
	}
	return nil
}
func (p *fileUpdateProof) Run(_ context.Context, _ string, command string) error {
	p.runs = append(p.runs, command)
	if p.runHook != nil {
		return p.runHook(command)
	}
	return p.runError
}
func (p *fileUpdateProof) Observe(context.Context, string, string) error { return p.observeError }
func (p *fileUpdateProof) Live(_ context.Context, _ string, rollback bool) error {
	p.lives = append(p.lives, rollback)
	if p.liveHook != nil {
		p.liveHook()
	}
	if !rollback {
		return p.liveError
	}
	return nil
}
func (p *fileUpdateProof) Startup(context.Context, string, int) error { return nil }
func (p *fileUpdateProof) Finish(_ context.Context, _ string, rollback bool) error {
	p.finishes = append(p.finishes, rollback)
	if p.finishError == nil && p.finishHook != nil {
		p.finishHook(rollback)
	}
	return p.finishError
}

const fileUpdateID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func fileUpdateHTTPFixture(t *testing.T) (*App, *fileUpdateProof) {
	t.Helper()
	work := t.TempDir()
	installation := filepath.Join(work, "installation")
	candidates := filepath.Join(work, "candidate")
	for _, dir := range []string{installation, candidates, filepath.Join(work, "journals")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	store, err := config.Load(filepath.Join(work, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Installed configurations start at revision 1 (configs/config.example.json);
	// a stopped rollback binding requires a non-zero revision.
	if err := store.SetSafeMode(true); err != nil {
		t.Fatal(err)
	}
	if err := store.SetSafeMode(false); err != nil {
		t.Fatal(err)
	}
	gate, err := security.NewGate(componentRecoveryToken)
	if err != nil {
		t.Fatal(err)
	}
	p := &fileUpdateProof{revision: store.Get().Revision}
	for i, target := range []string{"bin/razvilka", "etc/init.d/S99razvilka", "etc/razvilka/config.json", "etc/razvilka/service-catalog.json", "etc/razvilka/community-catalog.json", "etc/razvilka/sources.json"} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(installation, target)), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(installation, target), []byte("old-"+target), 0600); err != nil {
			t.Fatal(err)
		}
		data := []byte("reviewed-new-" + target)
		sum := sha256.Sum256(data)
		candidate := filepath.Join(candidates, string(rune('a'+i)))
		if err := os.WriteFile(candidate, data, 0600); err != nil {
			t.Fatal(err)
		}
		sha := hex.EncodeToString(sum[:])
		p.files = append(p.files, selfupdatejournal.File{Target: target, Candidate: candidate, SHA256: sha})
		if target == "etc/razvilka/config.json" {
			p.sha = sha
		}
	}
	a := &App{Store: store, Security: gate, SelfUpdateFiles: &SelfUpdateFiles{Installation: installation, Directory: filepath.Join(work, "journals", "file-update"), Adapter: p}}
	if err := a.InitializeComponentRecoveryGate(); err != nil {
		t.Fatal(err)
	}
	return a, p
}

func fileUpdateAction(t *testing.T, a *App, action string) error {
	t.Helper()
	return a.SelfUpdateFiles.Action(context.Background(), fileUpdateID, action, a.Store.Get().Revision, func(c context.Context) error { return a.selfUpdateFileAuthority(c, a.Store.Get().Revision) })
}

func fileUpdateBody(a *App, action string) map[string]any {
	return map[string]any{"transaction_id": fileUpdateID, "action": action, "expected_revision": a.Store.Get().Revision, "confirm": "REPAIR_SELF_UPDATE_TRANSACTION"}
}

func TestSelfUpdateFilesHTTPMatchingAndAdmission(t *testing.T) {
	a, p := fileUpdateHTTPFixture(t)
	if err := fileUpdateAction(t, a, "prepare"); err != nil {
		t.Fatal(err)
	}
	s := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer s.Close()
	for _, test := range []struct {
		token, origin string
		code          int
	}{{"", s.URL, 401}, {componentRecoveryToken, "https://foreign.example", 403}} {
		if code, _ := componentHTTP(t, s, "POST", "/api/v1/self-update/recovery", fileUpdateBody(a, "install"), test.token, test.origin); code != test.code {
			t.Fatal(code, test.code)
		}
	}
	for _, change := range []string{"id", "revision", "confirm", "callback"} {
		body := fileUpdateBody(a, "install")
		want := 409
		switch change {
		case "id":
			body["transaction_id"] = strings.Repeat("b", 32)
		case "revision":
			body["expected_revision"] = a.Store.Get().Revision + 1
		case "confirm":
			body["confirm"] = "WRONG"
			want = 400
		case "callback":
			body["quiescence_check"] = true
			want = 400
		}
		if code, data := componentHTTP(t, s, "POST", "/api/v1/self-update/recovery", body, componentRecoveryToken, s.URL); code != want {
			t.Fatalf("%s: %d %s", change, code, data)
		}
	}
	if code, data := componentHTTP(t, s, "GET", "/api/v1/status", nil, componentRecoveryToken, s.URL); code != 503 || !bytes.Contains(data, []byte("SELF_UPDATE_RECOVERY_REQUIRED")) {
		t.Fatalf("ordinary admission: %d %s", code, data)
	}
	for _, key := range []string{"", "durable-stop-key"} {
		body := map[string]any{"action": "stop", "confirm": "STOP_OWNED_ROUTES", "expected_revision": a.Store.Get().Revision, "idempotency_key": key}
		before := a.Store.Get().Revision
		if code, _ := componentHTTP(t, s, "POST", "/api/v1/service-control/runtime", body, componentRecoveryToken, s.URL); code != 503 || a.Store.Get().Revision != before {
			t.Fatal("ordinary Stop wrote third config image", code)
		}
	}
	if code, data := componentHTTP(t, s, "GET", "/api/v1/self-update/recovery", nil, componentRecoveryToken, s.URL); code != 200 || !bytes.Contains(data, []byte(`"phase":"prepared"`)) {
		t.Fatalf("read: %d %s", code, data)
	}
	for _, action := range []string{"stop-old-panel", "prepare-private-state", "quiesce-old-runtime", "install", "start-candidate-panel", "accept-live"} {
		if code, data := componentHTTP(t, s, "POST", "/api/v1/self-update/recovery", fileUpdateBody(a, action), componentRecoveryToken, s.URL); code != 200 {
			t.Fatalf("%s: %d %s", action, code, data)
		}
	}
	if len(p.runs) != 4 || len(p.lives) != 1 || p.lives[0] || len(p.finishes) != 1 || a.PendingSelfUpdateRecovery() {
		t.Fatal("incorrect acceptance", p.runs, p.lives, p.finishes)
	}
	if code, _ := componentHTTP(t, s, "POST", "/api/v1/self-update/recovery", fileUpdateBody(a, "accept-live"), componentRecoveryToken, s.URL); code != 409 || len(p.lives) != 1 || len(p.runs) != 4 {
		t.Fatal("terminal replay", code)
	}
	p.inspectError = errors.New("retained terminal images unavailable")
	if release, err := a.Operations.Enter(context.Background()); release != nil || !errors.Is(err, errSelfUpdateRecovery) {
		t.Fatal("terminal images not fenced", err)
	}
}

func TestSelfUpdateFilesHTTPUnknownNeverReplays(t *testing.T) {
	a, p := fileUpdateHTTPFixture(t)
	for _, action := range []string{"prepare"} {
		if err := fileUpdateAction(t, a, action); err != nil {
			t.Fatal(err)
		}
	}
	p.runError = errors.New("detached command outcome unknown")
	s := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer s.Close()
	for range 2 {
		if code, _ := componentHTTP(t, s, "POST", "/api/v1/self-update/recovery", fileUpdateBody(a, "stop-old-panel"), componentRecoveryToken, s.URL); code != 409 {
			t.Fatal(code)
		}
	}
	if len(p.runs) != 1 {
		t.Fatal("unknown command replay", p.runs)
	}
	p.observeError = errors.New("supervision not proved")
	if code, _ := componentHTTP(t, s, "POST", "/api/v1/self-update/recovery", fileUpdateBody(a, "resolve-unknown"), componentRecoveryToken, s.URL); code != 409 {
		t.Fatal(code)
	}
	p.observeError = nil
	p.runError = nil
	if code, _ := componentHTTP(t, s, "POST", "/api/v1/self-update/recovery", fileUpdateBody(a, "resolve-unknown"), componentRecoveryToken, s.URL); code != 200 || len(p.runs) != 1 {
		t.Fatal("resolve executed command", code)
	}
	if code, _ := componentHTTP(t, s, "POST", "/api/v1/self-update/recovery", fileUpdateBody(a, "stop-old-panel"), componentRecoveryToken, s.URL); code != 409 || len(p.runs) != 1 {
		t.Fatal("resolved command replay", code)
	}
}

func TestSelfUpdateFilesHelperIndependentRollbackAndForeignFile(t *testing.T) {
	t.Run("known live failure", func(t *testing.T) {
		a, p := fileUpdateHTTPFixture(t)
		p.liveError = errors.New("candidate failed independent live proof")
		if err := a.SelfUpdateFiles.RunHelper(context.Background(), fileUpdateID, func(context.Context) error { return nil }); err == nil {
			t.Fatal("rollback reported successful upgrade")
		}
		r, present, err := a.SelfUpdateFiles.Current()
		if err != nil || !present || r.Phase != "rolled-back" {
			t.Fatal(r, err)
		}
		wantRuns := []string{"stop-old-panel", "prepare-private-state", "quiesce-old-runtime", "start-candidate-panel", "stop-candidate-panel", "restore-private-state", "start-rollback-panel"}
		if !reflect.DeepEqual(p.runs, wantRuns) || len(p.lives) != 2 || p.lives[0] || !p.lives[1] || len(p.finishes) != 1 || !p.finishes[0] {
			t.Fatal(p.runs, p.lives, p.finishes)
		}
		if err := a.SelfUpdateFiles.RunHelper(context.Background(), fileUpdateID, func(context.Context) error { return nil }); err == nil || len(p.runs) != 7 {
			t.Fatal("helper resumed terminal transaction", err)
		}
	})
	t.Run("foreign third image", func(t *testing.T) {
		a, _ := fileUpdateHTTPFixture(t)
		for _, action := range []string{"prepare", "stop-old-panel", "prepare-private-state", "quiesce-old-runtime", "install", "start-candidate-panel", "stop-candidate-panel"} {
			if err := fileUpdateAction(t, a, action); err != nil {
				t.Fatal(action, err)
			}
		}
		path := filepath.Join(a.SelfUpdateFiles.Installation, "bin", "razvilka")
		foreign := []byte("operator-third-image")
		if err := os.WriteFile(path, foreign, 0755); err != nil {
			t.Fatal(err)
		}
		if err := fileUpdateAction(t, a, "restore"); err == nil {
			t.Fatal("third image overwritten")
		}
		actual, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(actual, foreign) {
			t.Fatal("foreign image changed", err)
		}
	})
}

func TestSelfUpdateFilesHTTPFreshStopSafeModeAndIndependentFence(t *testing.T) {
	for _, revocation := range []string{"safe-mode", "stop", "private-network"} {
		t.Run(revocation, func(t *testing.T) {
			a, p := fileUpdateHTTPFixture(t)
			if revocation == "stop" {
				if err := a.Store.UpdateService("youtube", config.ServiceState{Enabled: true, Route: "nfqws2"}); err != nil {
					t.Fatal(err)
				}
				if err := a.Store.ApplyDraft(); err != nil {
					t.Fatal(err)
				}
				p.revision = a.Store.Get().Revision
			}
			for _, action := range []string{"prepare", "stop-old-panel", "prepare-private-state", "quiesce-old-runtime", "install", "start-candidate-panel"} {
				if err := fileUpdateAction(t, a, action); err != nil {
					t.Fatal(action, err)
				}
			}
			before := a.Store.Get().Revision
			p.liveHook = func() {
				switch revocation {
				case "safe-mode":
					if err := a.Store.SetSafeMode(true); err != nil {
						t.Fatal(err)
					}
				case "stop":
					if _, err := a.Store.CommitServiceRuntime(true, map[string]string{"youtube": "nfqws2"}, before); err != nil {
						t.Fatal(err)
					}
				case "private-network":
					a.SelfUpdateFiles.RecoveryGuard = func(context.Context) error { return errors.New("independent journal remains fenced") }
				}
			}
			s := httptest.NewServer(a.Handler(http.NotFoundHandler()))
			defer s.Close()
			if code, _ := componentHTTP(t, s, "POST", "/api/v1/self-update/recovery", fileUpdateBody(a, "accept-live"), componentRecoveryToken, s.URL); code != 409 {
				t.Fatal("revoked acceptance", code)
			}
			r, _, err := a.SelfUpdateFiles.Current()
			if err != nil || r.Phase != "command-finished" || len(p.finishes) != 0 {
				t.Fatal("accepted stale authority", r, err)
			}
		})
	}
}

func TestSelfUpdateFilesPrepareRequiresStagedMigratedDigestBeforeWrites(t *testing.T) {
	a, p := fileUpdateHTTPFixture(t)
	p.sha = strings.Repeat("0", 64)
	if err := fileUpdateAction(t, a, "prepare"); err == nil {
		t.Fatal("unreviewed migrated image accepted")
	}
	if _, err := os.Stat(a.SelfUpdateFiles.Directory); !os.IsNotExist(err) {
		t.Fatal("journal created before review", err)
	}
	p.sha = p.files[2].SHA256
	p.files = p.files[:5]
	if err := fileUpdateAction(t, a, "prepare"); err == nil {
		t.Fatal("partial installation accepted")
	}
	if len(p.runs) != 0 {
		t.Fatal("preparation executed native command")
	}
}

func TestSelfUpdateFilesHTTPFinishesOnlyRetainedHelperGap(t *testing.T) {
	a, p := fileUpdateHTTPFixture(t)
	helper := filepath.Join(t.TempDir(), "helper")
	if err := os.MkdirAll(helper, 0700); err != nil {
		t.Fatal(err)
	}
	writeHelper := func(state string) {
		data, _ := json.Marshal(map[string]any{"owner": "razvilka-self-update-v1", "job": updatecheck.Job{ID: fileUpdateID, State: state}})
		if err := os.WriteFile(filepath.Join(helper, "current.json"), data, 0600); err != nil {
			t.Error(err)
		}
	}
	writeHelper("requires-review")
	a.SelfUpdateFiles.Helper = updatecheck.NewUpdater(Version, filepath.Dir(helper), updatecheck.Deployment{})
	a.SelfUpdateFiles.Helper.Directory = helper
	for _, action := range []string{"prepare", "stop-old-panel", "prepare-private-state", "quiesce-old-runtime", "install", "start-candidate-panel"} {
		if err := fileUpdateAction(t, a, action); err != nil {
			t.Fatal(action, err)
		}
	}
	p.finishError = errors.New("helper settlement interrupted")
	s := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer s.Close()
	if code, _ := componentHTTP(t, s, "POST", "/api/v1/self-update/recovery", fileUpdateBody(a, "accept-live"), componentRecoveryToken, s.URL); code != 409 {
		t.Fatal(code)
	}
	r, _, err := a.SelfUpdateFiles.Current()
	if err != nil || r.Phase != "accepted" || !a.PendingSelfUpdateRecovery() {
		t.Fatal("terminal gap not retained", r, err)
	}
	p.finishError = nil
	p.finishHook = func(bool) { writeHelper("completed") }
	if code, data := componentHTTP(t, s, "POST", "/api/v1/self-update/recovery", fileUpdateBody(a, "accept-live"), componentRecoveryToken, s.URL); code != 200 || !bytes.Contains(data, []byte(`"recovery_required":false`)) {
		t.Fatalf("gap: %d %s", code, data)
	}
	if len(p.runs) != 4 || len(p.lives) != 1 || len(p.finishes) != 2 {
		t.Fatal("file/command acceptance replay", p.runs, p.lives, p.finishes)
	}
	if code, _ := componentHTTP(t, s, "POST", "/api/v1/self-update/recovery", fileUpdateBody(a, "accept-live"), componentRecoveryToken, s.URL); code != 409 || len(p.finishes) != 2 {
		t.Fatal("settled helper replay", code)
	}
}

func TestSelfUpdateFilesMissingProviderRefusesManualAndScheduledBeforeIntent(t *testing.T) {
	a, _ := fileUpdateHTTPFixture(t)
	a.SelfUpdateFiles.Adapter = nil
	helper := filepath.Join(t.TempDir(), "helper")
	a.SelfUpdate = updatecheck.NewUpdater(Version, filepath.Dir(helper), updatecheck.Deployment{})
	a.SelfUpdate.Directory = helper
	s := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer s.Close()
	body := map[string]any{"job_id": fileUpdateID, "review_token": "retained-reviewed-token", "config_revision": a.Store.Get().Revision, "confirm": "INSTALL_APP_UPDATE"}
	if code, _ := componentHTTP(t, s, "POST", "/api/v1/self-update/apply", body, componentRecoveryToken, s.URL); code != 409 {
		t.Fatal("manual missing provider admitted", code)
	}
	p := autonomy.Default()
	now := time.Now().UTC()
	p.Application.Start = now.Add(-time.Minute).Format("15:04")
	p.Application.End = now.Add(time.Minute).Format("15:04")
	job := updatecheck.Job{ID: fileUpdateID, State: "ready", ConfigRevision: a.Store.Get().Revision, ReviewToken: "retained-reviewed-token", Release: &updatecheck.Release{Version: "9.9.9"}, Channel: "stable"}
	a.autonomy.doc.Policy = p
	a.autonomy.doc.Maintenance = map[string]string{}
	a.autonomy.autoInstall = &job
	if a.runAutoInstall(context.Background(), p) || len(a.autonomy.doc.Maintenance) != 0 {
		t.Fatal("scheduled intent persisted before provider readiness")
	}
	if _, err := os.Stat(helper); !os.IsNotExist(err) {
		t.Fatal("missing provider launched helper/wrote receipt", err)
	}
	if _, err := os.Stat(a.SelfUpdateFiles.Directory); !os.IsNotExist(err) {
		t.Fatal("missing provider wrote file journal", err)
	}
}

func TestSelfUpdateFilesOrphanPreparationKeepsRestartFence(t *testing.T) {
	a, _ := fileUpdateHTTPFixture(t)
	if err := os.MkdirAll(filepath.Join(a.SelfUpdateFiles.Directory, fileUpdateID), 0700); err != nil {
		t.Fatal(err)
	}
	if _, present, err := a.SelfUpdateFiles.Current(); err == nil || present {
		t.Fatal("orphan preparation hidden", present, err)
	}
	if release, err := a.Operations.Enter(context.Background()); release != nil || !errors.Is(err, errSelfUpdateRecovery) {
		t.Fatal("orphan startup admitted", err)
	}
	if _, err := os.Stat(filepath.Join(a.SelfUpdateFiles.Directory, fileUpdateID)); err != nil {
		t.Fatal("orphan images removed", err)
	}
}
