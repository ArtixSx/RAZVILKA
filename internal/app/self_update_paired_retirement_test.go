package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

// Only the provider's native App/process observation is modeled. The journal,
// original exclusive operation, config and protected control epoch are real.
// This fixture is not completed-live or native upgrade acceptance.
type appPairedRetirementProof struct {
	*boundFileUpdateProof
	helperSHA string
	calls     int
	before    func(context.Context) error
	after     func(context.Context) error
	skipOwner bool
}

func (p *appPairedRetirementProof) RetireCompletedPairedState(ctx context.Context, id string, worker int, owner updatecheck.SelfUpdateRuntimeObservation) error {
	p.calls++
	if p.skipOwner {
		return nil
	}
	if id != fileUpdateID || worker != 41 {
		return selfupdatejournal.ErrMismatch
	}
	if err := owner(ctx, id); err != nil {
		return err
	}
	if p.before != nil {
		if err := p.before(ctx); err != nil {
			return err
		}
	}
	s, err := p.OpenFileJournal()
	if err != nil {
		return err
	}
	defer s.Close()
	check := func(c context.Context) error { return owner(c, id) }
	err = s.RetirePairedPriorState(ctx, id, p.helperSHA, check, check, func(c context.Context, _ string, begin func() error) error {
		if err := check(c); err != nil {
			return err
		}
		return begin()
	})
	if err == nil && p.after != nil {
		return p.after(ctx)
	}
	return err
}

func appPairedRetirementFixture(t *testing.T) (*App, *appPairedRetirementProof, func()) {
	t.Helper()
	a, original := fileUpdateHTTPFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	control := filepath.Join(t.TempDir(), "control")
	epoch, err := operationgate.InitializeSelfUpdateControl(ctx, control)
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"prepare", "stop-old-panel", "prepare-private-state", "quiesce-old-runtime"} {
		if err := fileUpdateAction(t, a, action); err != nil {
			t.Fatal(err)
		}
	}
	p := &appPairedRetirementProof{boundFileUpdateProof: &boundFileUpdateProof{fileUpdateProof: original, installation: a.SelfUpdateFiles.Installation, journal: a.SelfUpdateFiles.Directory}}
	s, err := p.OpenFileJournal()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	okay := func(c context.Context) error { return c.Err() }
	admit := func(c context.Context, _ string, begin func() error) error {
		if err := c.Err(); err != nil {
			return err
		}
		return begin()
	}
	err = s.SealPairedPriorState(ctx, fileUpdateID, okay, okay, func(c context.Context, prepared selfupdatejournal.Receipt) (selfupdatejournal.PairedBinding, error) {
		data, _ := json.Marshal(prepared)
		sum := sha256.Sum256(data)
		return selfupdatejournal.PairedBinding{ManifestSHA256: strings.Repeat("a", 64), PreparedSHA256: hex.EncodeToString(sum[:]), ReviewSHA256: strings.Repeat("b", 64), InstallationID: epoch.InstallationID, Sequence: epoch.Sequence, Revision: a.Store.Get().Revision}, c.Err()
	}, admit)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.InstallAdmitted(ctx, fileUpdateID, okay, okay, admit); err != nil {
		t.Fatal(err)
	}
	if err := s.Execute(ctx, fileUpdateID, "start-candidate-panel", okay, okay); err != nil {
		t.Fatal(err)
	}
	helper := updatecheck.NewUpdater(Version, t.TempDir(), updatecheck.Deployment{})
	if err := os.MkdirAll(helper.Directory, 0700); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(map[string]any{"owner": "razvilka-self-update-v1", "job": updatecheck.Job{ID: fileUpdateID, State: "restarting", Stage: "file-protocol", HelperPID: 40}})
	if err := os.WriteFile(filepath.Join(helper.Directory, "current.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	a.SelfUpdate, a.SelfUpdateFiles.Helper = helper, helper
	a.SelfUpdateStartupJobID, a.SelfUpdateStartupHelperPID = fileUpdateID, 41
	a.SelfUpdateFiles.Adapter, a.SelfUpdateFiles.ControlRoot = p, control
	a.SelfUpdateFiles.RecoveryGuard = okay
	finish := func() {
		c, stop := context.WithTimeout(context.Background(), time.Minute)
		defer stop()
		s, err := p.OpenFileJournal()
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if err := s.Accept(c, fileUpdateID, false, okay, okay); err != nil {
			t.Fatal(err)
		}
		data, _ := json.Marshal(map[string]any{"owner": "razvilka-self-update-v1", "job": updatecheck.Job{ID: fileUpdateID, State: "completed", Stage: "completed", HelperPID: 40}})
		if err := os.WriteFile(filepath.Join(helper.Directory, "current.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		p.helperSHA = hex.EncodeToString(sum[:])
	}
	return a, p, finish
}

func TestAppPairedRetirementRequiresOriginalOperationAndClosingPublication(t *testing.T) {
	a, p, finish := appPairedRetirementFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if retired, err := a.RetireCompletedPairedSelfUpdate(ctx); err == nil || retired || p.calls != 0 {
		t.Fatal("ordinary context acquired retirement")
	}
	ctx = context.WithValue(ctx, selfUpdateFileAdmissionKey{}, selfUpdateFileAdmission{id: fileUpdateID})
	owned, release, err := a.Operations.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if retired, err := a.RetireCompletedPairedSelfUpdate(owned); err == nil || retired || p.calls != 0 {
		t.Fatal("an unbound exclusive operation acquired retirement")
	}
	bound, err := a.bindPairedSelfUpdateRetirement(owned)
	if err != nil {
		t.Fatal(err)
	}
	finish()
	if retired, err := a.RetireCompletedPairedSelfUpdate(bound); err != nil || !retired || p.calls != 1 {
		t.Fatal("original modeled operation did not retire", err)
	}
	r, present, err := a.SelfUpdateFiles.Current()
	if err != nil || !present || r.Phase != "archived" || r.Retired == nil || pairedSelfUpdateRetirementPending(r) {
		t.Fatal("closing archive publication was not verified", err)
	}
	release()
	if retired, err := a.RetireCompletedPairedSelfUpdate(bound); err == nil || retired || p.calls != 1 {
		t.Fatal("released operation reacquired retirement")
	}
	newLease, releaseNew, err := a.Operations.ExclusiveContext(bound)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseNew()
	if retired, err := a.RetireCompletedPairedSelfUpdate(newLease); err == nil || retired || p.calls != 1 {
		t.Fatal("a new lease reconstructed the original retirement owner")
	}
	if _, err := a.bindPairedSelfUpdateRetirement(newLease); err == nil {
		t.Fatal("a new lease rebound the old startup owner")
	}
}

func TestAppPairedRetirementPreservesFenceOnOwnerDrift(t *testing.T) {
	for _, change := range []string{"cold-App", "offline", "Stop", "config", "helper", "skip-owner", "fresh-context", "provider", "cancel", "control-root"} {
		t.Run(change, func(t *testing.T) {
			a, p, finish := appPairedRetirementFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			ctx = context.WithValue(ctx, selfUpdateFileAdmissionKey{}, selfUpdateFileAdmission{id: fileUpdateID})
			owned, release, err := a.Operations.ExclusiveContext(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			bound, err := a.bindPairedSelfUpdateRetirement(owned)
			if err != nil {
				t.Fatal(err)
			}
			finish()
			switch change {
			case "cold-App":
				a.SelfUpdateStartupJobID = ""
			case "offline":
				if err := a.Store.SetSafeMode(true); err != nil {
					t.Fatal(err)
				}
			case "Stop":
				p.before = func(c context.Context) error {
					_, err := operationgate.RequestSelfUpdateStop(c, a.SelfUpdateFiles.ControlRoot, fileUpdateID, a.Store.Get().Revision)
					return err
				}
			case "config":
				p.before = func(context.Context) error { return a.Store.SetSafeMode(true) }
			case "helper":
				p.before = func(context.Context) error {
					return os.WriteFile(filepath.Join(a.SelfUpdate.Directory, "current.json"), []byte(`{"owner":"razvilka-self-update-v1","job":{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"requires-review","stage":"requires-review"}}`), 0600)
				}
			case "skip-owner":
				p.skipOwner = true
			case "fresh-context":
				p.before = func(context.Context) error {
					fresh, stop := context.WithTimeout(context.Background(), time.Minute)
					defer stop()
					_, err := a.RetireCompletedPairedSelfUpdate(fresh)
					return err
				}
			case "provider":
				p.before = func(context.Context) error { a.SelfUpdateFiles.Adapter = p.boundFileUpdateProof; return nil }
			case "cancel":
				p.before = func(context.Context) error { cancel(); return nil }
			case "control-root":
				p.before = func(context.Context) error {
					a.SelfUpdateFiles.ControlRoot = filepath.Join(t.TempDir(), "foreign-control")
					return nil
				}
			}
			if retired, err := a.RetireCompletedPairedSelfUpdate(bound); err == nil || retired {
				t.Fatal("changed owner cleared retirement fence")
			}
			r, present, err := a.SelfUpdateFiles.Current()
			if err != nil || !present || r.Phase != "accepted" || r.Retired != nil || !pairedSelfUpdateRetirementPending(r) {
				t.Fatal("owner refusal published a retirement", err)
			}
		})
	}
}

func TestAppPairedRetirementCannotBindAfterCompletion(t *testing.T) {
	a, p, finish := appPairedRetirementFixture(t)
	finish()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ctx = context.WithValue(ctx, selfUpdateFileAdmissionKey{}, selfUpdateFileAdmission{id: fileUpdateID})
	owned, release, err := a.Operations.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err := a.bindPairedSelfUpdateRetirement(owned); err == nil {
		t.Fatal("completed receipt reconstructed startup lifetime")
	}
	if retired, err := a.RetireCompletedPairedSelfUpdate(owned); err == nil || retired || p.calls != 0 {
		t.Fatal("completed receipt alone acquired retirement")
	}
}

func TestAppPairedRetirementClosingCancellationNeverReturnsSuccess(t *testing.T) {
	a, p, finish := appPairedRetirementFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ctx = context.WithValue(ctx, selfUpdateFileAdmissionKey{}, selfUpdateFileAdmission{id: fileUpdateID})
	owned, release, err := a.Operations.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	bound, err := a.bindPairedSelfUpdateRetirement(owned)
	if err != nil {
		t.Fatal(err)
	}
	finish()
	p.after = func(context.Context) error { cancel(); return nil }
	if retired, err := a.RetireCompletedPairedSelfUpdate(bound); err == nil || retired || !errors.Is(err, context.Canceled) {
		t.Fatal("a canceled closing owner returned retirement success", err)
	}
	r, present, err := a.SelfUpdateFiles.Current()
	if err != nil || !present || r.Phase != "archived" || r.Retired == nil {
		t.Fatal("closing cancellation discarded the already published receipt", err)
	}
}

func TestAppPairedRetirementPendingNeverTreatsAcceptanceAsRetirement(t *testing.T) {
	for _, phase := range []string{"installed", "command-finished", "accepted", "archived"} {
		if !pairedSelfUpdateRetirementPending(selfupdatejournal.Receipt{Schema: selfupdatejournal.PairedSchema, Phase: phase}) {
			t.Fatal("unretired pair released writes", phase)
		}
	}
	if pairedSelfUpdateRetirementPending(selfupdatejournal.Receipt{Schema: selfupdatejournal.Schema, Phase: "accepted"}) {
		t.Fatal("ordinary schema2 flow acquired paired retirement")
	}
	var p *appPairedRetirementOwner
	if !errors.Is(p.current(context.Background(), fileUpdateID), updatecheck.ErrPairedRetirementOwner) {
		t.Fatal("missing original owner was accepted")
	}
}
