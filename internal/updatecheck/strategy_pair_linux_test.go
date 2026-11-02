package updatecheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

func strategyPairFixture(t *testing.T) (*SelfUpdateFileAdapter, *Updater, fileReview, []byte) {
	t.Helper()
	a, u, review := fileAdapterFixture(t)
	for _, rel := range []string{"bin", "etc/init.d", "etc/razvilka", "razvilka/state", "file-journal"} {
		if err := os.MkdirAll(filepath.Join(a.installation, rel), 0700); err != nil {
			t.Fatal(err)
		}
	}
	old, err := os.ReadFile(u.Deployment.Executable)
	if err != nil {
		t.Fatal(err)
	}
	retainedFile(t, a.installation, "bin/razvilka", old)
	retainedFile(t, filepath.Join(a.directory, review.ID), "control.bin", old)
	raw := []byte("{\n \"schema_version\":4,\"candidates\":{},\"evidence\":[],\"selections\":{}\n}\n")
	retainedFile(t, a.installation, "razvilka/state/strategy-lab.json", raw)
	a.strategyProbe = func(ctx context.Context, image selfupdatejournal.BinaryImage, flag string) (string, error) {
		if flag == "-strategy-lab-read-version" {
			return "5\n", nil
		}
		return "3\n", nil
	}
	proof, err := a.sealStrategyPair(context.Background(), review)
	if err != nil {
		t.Fatal(err)
	}
	review.StrategyPair = proof
	publishStrategyReview(t, a, u, review)
	return a, u, review, raw
}

func publishStrategyReview(t *testing.T, a *SelfUpdateFileAdapter, u *Updater, review fileReview) {
	t.Helper()
	data, err := json.Marshal(review)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a.directory, review.ID, "file-review.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.record.FileReviewSHA256 = digestBytes(data)
	if err := u.persistLocked(); err != nil {
		t.Fatal(err)
	}
}

func TestStrategyPairCapturesVersionedSnapshotAcrossBinaryReplacement(t *testing.T) {
	a, _, review, raw := strategyPairFixture(t)
	ctx := context.Background()
	if err := a.preparePrivateSnapshot(ctx, review.ID); err != nil {
		t.Fatal(err)
	}
	snapshot, err := a.privateSnapshot(ctx, review.ID)
	if err != nil || snapshot.Schema != 3 || !bytes.Equal(snapshot.Images["strategy"].Data, raw) {
		t.Fatal("pair image not captured", err)
	}
	for _, file := range review.Files {
		if file.Target == "bin/razvilka" {
			candidate, err := os.ReadFile(file.Candidate)
			if err != nil {
				t.Fatal(err)
			}
			retainedFile(t, a.installation, "bin/razvilka", candidate)
		}
	}
	if err := a.AuthorityAction(ctx, review.ID, review.Revision, "start/live"); err != nil {
		t.Fatal("candidate binary broke pair", err)
	}
	if err := a.AuthorityAction(ctx, review.ID, review.Revision, "replace-to-rollback"); err != nil {
		t.Fatal("rollback binary pair unavailable", err)
	}
	retainedFile(t, a.installation, "razvilka/state/strategy-lab.json", append(bytes.Clone(raw), '\n'))
	if err := a.AuthorityAction(ctx, review.ID, review.Revision, "replace-to-rollback"); !errors.Is(err, ErrStrategyStateAdmission) {
		t.Fatal("post-start mutation was erased by rollback", err)
	}
}

func TestStrategyPairRefusesForgedSnapshotAndReaderOrStateDrift(t *testing.T) {
	a, u, review, raw := strategyPairFixture(t)
	ctx := context.Background()
	if err := a.preparePrivateSnapshot(ctx, review.ID); err != nil {
		t.Fatal(err)
	}
	snapshot, err := a.privateSnapshot(ctx, review.ID)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Images["strategy"] = restorejournal.Image{Exists: true, Data: append(bytes.Clone(raw), '\n')}
	data, _ := json.Marshal(snapshot)
	job := filepath.Join(a.directory, review.ID)
	retainedFile(t, job, "private-snapshot.json", data)
	retainedFile(t, job, "private-snapshot.sha256", []byte(digestBytes(data)))
	if _, err := a.privateSnapshot(ctx, review.ID); !errors.Is(err, ErrStrategyStateAdmission) {
		t.Fatal("rehashed forged state accepted", err)
	}
	a.strategyProbe = func(context.Context, selfupdatejournal.BinaryImage, string) (string, error) { return "1\n", nil }
	if _, err := a.sealStrategyPair(ctx, review); !errors.Is(err, ErrStrategyStateAdmission) {
		t.Fatal("incompatible reader accepted", err)
	}
	review.StrategyPair = nil
	publishStrategyReview(t, a, u, review)
	if _, err := a.privateSnapshot(ctx, review.ID); !errors.Is(err, ErrStrategyStateAdmission) {
		t.Fatal("schema3 without pair accepted", err)
	}
}

func TestStrategyPairLegacySnapshotRegistriesRemainReadable(t *testing.T) {
	for _, schema := range []int{1, 2} {
		snapshot := privateFileSnapshot{Schema: schema, ID: "0123456789abcdef0123456789abcdef", Images: map[string]restorejournal.Image{}}
		dirs := filePrivateDirectories
		if schema == 2 {
			dirs = fileMutablePrivateDirectories
		}
		for name := range dirs {
			snapshot.Images[name] = restorejournal.Image{}
		}
		for name := range filePrivateFiles {
			snapshot.Images[name] = restorejournal.Image{}
		}
		if err := validatePrivateSnapshot(snapshot); err != nil {
			t.Fatal("legacy schema changed", schema, err)
		}
	}
}

func TestStrategyPairFailedInstallRestoresExactOldBinaryAndState(t *testing.T) {
	a, _, review, raw := strategyPairFixture(t)
	ctx := context.Background()
	oldBinary, err := os.ReadFile(filepath.Join(a.installation, "bin/razvilka"))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.preparePrivateSnapshot(ctx, review.ID); err != nil {
		t.Fatal(err)
	}
	store, err := selfupdatejournal.Open(a.installation, a.fileJournal)
	if err != nil {
		t.Fatal(err)
	}
	check := func(c context.Context) error { return a.strategyStateAdmission(c, review.ID) }
	quiescent := func(c context.Context) error { return c.Err() }
	admit := func(c context.Context, effect string, begin func() error) error { return begin() }
	if err := a.WithStrategyPairPreparation(ctx, review.ID, func(scoped context.Context) error {
		return store.Prepare(scoped, review.ID, review.Files, func(c context.Context) error {
			return a.StrategyPairPreparationAuthority(c, review.ID, review.Revision)
		}, quiescent)
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.InstallAdmitted(ctx, review.ID, check, quiescent, admit); err != nil {
		t.Fatal(err)
	}
	store.Close()
	// Model a failed candidate's ordinary private write; StrategyLab itself is
	// frozen by the pair guard, so no post-start evidence can be discarded.
	retainedFile(t, a.installation, "etc/razvilka/admin.token", []byte("candidate-only-token"))
	cold := *a
	if err := cold.restorePrivateSnapshot(ctx, review.ID); err != nil {
		t.Fatal("cold private restore", err)
	}
	if err := cold.restorePrivateSnapshot(ctx, review.ID); err != nil {
		t.Fatal("idempotent retry", err)
	}
	store, err = selfupdatejournal.Open(a.installation, a.fileJournal)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.RestoreAdmitted(ctx, review.ID, check, quiescent, admit); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(a.installation, "bin/razvilka"))
	if err != nil || !bytes.Equal(got, oldBinary) {
		t.Fatal("old binary not restored", err)
	}
	got, err = os.ReadFile(filepath.Join(a.installation, "razvilka/state/strategy-lab.json"))
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatal("old StrategyLab bytes not restored", err)
	}
	if _, err := os.Lstat(filepath.Join(a.installation, "etc/razvilka/admin.token")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("private rollback did not restore absence", err)
	}
}

// Opt-in fixture executes real digest-pinned controller copies. It never runs
// an installer, starts a daemon, or changes the host's installed application.
func TestStrategyPairActualBinaryReaders(t *testing.T) {
	currentPath, oldPath := os.Getenv("RAZVILKA_STRATEGY_PAIR_BINARY"), os.Getenv("RAZVILKA_STRATEGY_PAIR_OLD_BINARY")
	if currentPath == "" || oldPath == "" {
		t.Skip("actual controller fixture paths not supplied")
	}
	a, _, review, raw := strategyPairFixture(t)
	probe := func(image selfupdatejournal.BinaryImage, flag string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		started := time.Now()
		out, err := a.probeStrategyReader(ctx, review, image, flag)
		t.Logf("actual reader flag=%s elapsed=%s", flag, time.Since(started))
		return out, err
	}
	seal := func() (*strategyPairProof, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		started := time.Now()
		proof, err := a.sealStrategyPair(ctx, review)
		t.Logf("actual pair seal elapsed=%s", time.Since(started))
		return proof, err
	}
	current, err := os.ReadFile(currentPath)
	if err != nil {
		t.Fatal(err)
	}
	old, err := os.ReadFile(oldPath)
	if err != nil {
		t.Fatal(err)
	}
	probeRoot := t.TempDir()
	retainedFile(t, probeRoot, "current", current)
	retainedFile(t, probeRoot, "old", old)
	for _, test := range []struct{ flag, want string }{{"-strategy-lab-read-version", strconv.Itoa(StrategyLabReadVersion) + "\n"}, {"-self-update-private-snapshot-read-version", strconv.Itoa(PrivateSnapshotReadVersion) + "\n"}} {
		got, err := probe(selfupdatejournal.BinaryImage{Path: filepath.Join(probeRoot, "current"), SHA256: digestBytes(current)}, test.flag)
		if err != nil || got != test.want {
			t.Fatalf("current actual %s: %q %v", test.flag, got, err)
		}
		if _, err := probe(selfupdatejournal.BinaryImage{Path: filepath.Join(probeRoot, "old"), SHA256: digestBytes(old)}, test.flag); err == nil {
			t.Fatal("old controller falsely advertised pair reader", test.flag)
		}
	}
	// Seal a real current/current controller pair through the production probe,
	// then replace the immutable old controller copy with the true old binary.
	a.strategyProbe = nil
	review.OldExecutableSHA256 = digestBytes(current)
	retainedFile(t, a.installation, "bin/razvilka", current)
	retainedFile(t, filepath.Join(a.directory, review.ID), "control.bin", current)
	for i, file := range review.Files {
		if file.Target == "bin/razvilka" {
			retainedFile(t, filepath.Dir(file.Candidate), filepath.Base(file.Candidate), current)
			review.Files[i].SHA256 = digestBytes(current)
		}
	}
	proof, err := seal()
	if err != nil || proof == nil {
		t.Fatal("actual compatible pair not admitted", err)
	}
	if reader5Path := os.Getenv("RAZVILKA_STRATEGY_PAIR_V5_BINARY"); reader5Path != "" {
		settled, err := os.ReadFile("testdata/strategy-pair-modeled-settled5.json")
		if err != nil {
			t.Fatal(err)
		}
		retainedFile(t, a.installation, "razvilka/state/strategy-lab.json", settled)
		if _, err := seal(); err != nil {
			t.Fatal("actual reader7 pair rejected settled schema5", err)
		}
		reader5, err := os.ReadFile(reader5Path)
		if err != nil {
			t.Fatal(err)
		}
		retainedFile(t, filepath.Join(a.directory, review.ID), "control.bin", reader5)
		review.OldExecutableSHA256 = digestBytes(reader5)
		retainedFile(t, a.installation, "bin/razvilka", reader5)
		if _, err := seal(); !errors.Is(err, ErrStrategyStateAdmission) {
			t.Fatal("actual standalone reader5 became a supervised pair reader", err)
		}
		retainedFile(t, a.installation, "razvilka/state/strategy-lab.json", raw)
	}
	retainedFile(t, filepath.Join(a.directory, review.ID), "control.bin", old)
	review.OldExecutableSHA256 = digestBytes(old)
	retainedFile(t, a.installation, "bin/razvilka", old)
	if _, err := seal(); !errors.Is(err, ErrStrategyStateAdmission) {
		t.Fatal("actual old/new incompatible pair admitted", err)
	}
	got, err := os.ReadFile(filepath.Join(a.installation, "razvilka/state/strategy-lab.json"))
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatal("reader capability probes mutated state", err)
	}
}

func TestStrategyPairPreparationScopeCannotAuthorizeReplacementOrSurviveReturn(t *testing.T) {
	a, _, review, raw := strategyPairFixture(t)
	var saved context.Context
	err := a.WithStrategyPairPreparation(context.Background(), review.ID, func(scoped context.Context) error {
		saved = scoped
		// Reproduce the real Prepare cut: its original owner has created the
		// current directory, but no complete receipt exists yet.
		if err := os.Mkdir(filepath.Join(a.fileJournal, review.ID), 0700); err != nil {
			return err
		}
		if err := a.StrategyPairPreparationAuthority(scoped, review.ID, review.Revision); err != nil {
			t.Fatal("original prepare read refused", err)
		}
		for _, action := range []string{"start/live", "replace-to-rollback"} {
			if err := a.AuthorityAction(scoped, review.ID, review.Revision, action); err == nil {
				t.Fatal("prepare token granted replacement", action)
			}
		}
		token := a.strategyPreparationFor(scoped, review.ID)
		copied := strategyPreparation{self: token.self, adapter: token.adapter, ctx: token.ctx, review: token.review}
		copied.active.Store(token.active.Load())
		forged := context.WithValue(scoped, strategyPreparationKey{}, &copied)
		if _, err := a.strategyPairCheckImages(forged, review, true); err == nil {
			t.Fatal("copied token accepted")
		}
		if a.strategyPreparationFor(scoped, "ffffffffffffffffffffffffffffffff") != nil {
			t.Fatal("unrelated job borrowed token")
		}
		return nil
	})
	if err == nil {
		t.Fatal("closing accepted partial unreceipted journal")
	}
	if a.strategyPreparationFor(saved, review.ID) != nil {
		t.Fatal("prepare token survived callback")
	}
	if err := a.StrategyPairPreparationAuthority(saved, review.ID, review.Revision); err == nil {
		t.Fatal("retained context authorized partial retry")
	}
	got, _ := os.ReadFile(filepath.Join(a.installation, "razvilka/state/strategy-lab.json"))
	if !bytes.Equal(got, raw) {
		t.Fatal("partial preparation changed StrategyLab")
	}
}

func TestStrategyPairPreparationCancellationRevokesOriginalToken(t *testing.T) {
	a, _, review, _ := strategyPairFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	err := a.WithStrategyPairPreparation(ctx, review.ID, func(scoped context.Context) error {
		cancel()
		if a.strategyPreparationFor(scoped, review.ID) != nil {
			t.Fatal("cancelled token accepted")
		}
		if err := a.StrategyPairPreparationAuthority(scoped, review.ID, review.Revision); err == nil {
			t.Fatal("cancelled authority accepted")
		}
		return ctx.Err()
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
}
