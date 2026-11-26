package nodestore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func archiveFixture(t *testing.T) PrivateSnapshot {
	t.Helper()
	s, _ := setup(t)
	importGood(t, s)
	a, err := s.ExportPrivate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestPrivateReviewAndOptionalEmptyExport(t *testing.T) {
	root := filepath.Join(t.TempDir(), "nodes")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if exported, err := s.ExportPrivateIfPresent(context.Background()); err != nil || exported != nil {
		t.Fatalf("empty optional export: %v %v", exported, err)
	}
	archive := archiveFixture(t)
	review, err := ReviewPrivateSnapshot(archive)
	if err != nil || review.Nodes != 1 || review.Sources != 1 {
		t.Fatalf("private review: %+v %v", review, err)
	}
	encoded, _ := json.Marshal(review)
	for _, secret := range []string{"fixture.example", "123e4567", "manual"} {
		if bytes.Contains(encoded, []byte(secret)) {
			t.Fatal("private review exposed node material")
		}
	}
}

func executeNodes(t *testing.T, target *RestoreTarget, archive PrivateSnapshot) (restorejournal.Outcome, error) {
	t.Helper()
	image, err := target.MergeImage(context.Background(), archive)
	if err != nil {
		return restorejournal.Clean, err
	}
	path := t.TempDir()
	os.Chmod(path, 0o700)
	j, err := restorejournal.Open(path, target.Binding(), map[string]restorejournal.Target{"nodes": target})
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	return j.Execute(context.Background(), map[string]restorejournal.Image{"nodes": image})
}

func TestArchiveCopyAndMergeKeepIDsAndFreshness(t *testing.T) {
	a := archiveFixture(t)
	s, _ := setup(t)
	for range 2 {
		session, err := s.BeginRestore(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if other, err := s.BeginRestore(context.Background()); err == nil {
			other.Close()
			t.Fatal("concurrent restore session")
		}
		if _, err := executeNodes(t, session, a); err != nil {
			t.Fatal(err)
		}
		if err := session.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := session.Read(context.Background()); err == nil {
			t.Fatal("closed session readable")
		}
	}
	snap, err := s.Snapshot(context.Background(), testTime.Add(2*time.Hour))
	if err != nil || len(snap.Nodes) != 1 || snap.Generation != 1 || snap.Nodes[0].State != "expired" || snap.Nodes[0].Health.State != "not_checked" {
		t.Fatal("restore refreshed or duplicated archive")
	}
	refreshed, err := s.Import(context.Background(), manual, good, testTime.Add(3*time.Hour), time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	session, _ := s.BeginRestore(context.Background())
	_, err = executeNodes(t, session, a)
	session.Close()
	if err != nil {
		t.Fatal(err)
	}
	after, _ := s.Snapshot(context.Background(), testTime.Add(3*time.Hour))
	if after.Generation != refreshed.Generation || after.Nodes[0].ID != refreshed.Nodes[0].ID || !after.Nodes[0].Origins[0].ReceivedAt.Equal(testTime.Add(3*time.Hour)) {
		t.Fatal("older archive replaced newer freshness")
	}
}

func TestPrivateRestorePreservesNodeGroups(t *testing.T) {
	source, _ := setup(t)
	snapshot := importGood(t, source)
	group, err := source.CreateGroup(context.Background(), "Основной резерв", "fallback", []string{snapshot.Nodes[0].ID}, snapshot.Nodes[0].ID, 30*time.Minute, testTime)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := source.ExportPrivate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	review, err := ReviewPrivateSnapshot(archive)
	if err != nil || review.Groups != 1 {
		t.Fatalf("review=%+v err=%v", review, err)
	}
	targetStore, _ := setup(t)
	session, err := targetStore.BeginRestore(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executeNodes(t, session, archive); err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	restored, err := targetStore.Snapshot(context.Background(), testTime)
	if err != nil || len(restored.Groups) != 1 || restored.Groups[0].ID != group.ID || restored.Groups[0].NodeIDs[0] != snapshot.Nodes[0].ID {
		t.Fatalf("restored=%+v err=%v", restored.Groups, err)
	}
}

func TestRestoreMergesExactCheckHistoryWithoutLosingNewerEvidence(t *testing.T) {
	s, _ := setup(t)
	first := importGood(t, s)
	id := first.Nodes[0].ID
	if _, err := s.Import(context.Background(), manual, good, testTime, 4*time.Hour, false); err != nil {
		t.Fatal(err)
	}
	record := func(probeID string, checkedAt time.Time, verdict, state string) CheckRecord {
		return CheckRecord{
			ProbeID: probeID, ServiceID: "telegram", NetworkProfile: "wan-0123456789ab",
			RoutePathID: "sing-box:" + id, TestLevel: "service", Verdict: verdict, State: state, Stage: "service",
			CheckedAt: checkedAt, ExpiresAt: checkedAt.Add(time.Hour), LatencyMS: 125, EgressIP: "203.0.113.25",
			HTTPStatus: 204, Message: "Точный выход проверен.",
		}
	}
	oldAt := testTime.Add(time.Minute)
	if _, err := s.RecordCheck(context.Background(), id, record("node-check-old", oldAt, "PASS", "available"), oldAt); err != nil {
		t.Fatal(err)
	}
	archive, err := s.ExportPrivate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	newAt := testTime.Add(2 * time.Minute)
	if _, err := s.RecordCheck(context.Background(), id, record("node-check-new", newAt, "BLOCKED", "unavailable"), newAt); err != nil {
		t.Fatal(err)
	}
	session, err := s.BeginRestore(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executeNodes(t, session, archive); err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	snapshot, err := s.Snapshot(context.Background(), newAt)
	if err != nil || len(snapshot.Nodes) != 1 {
		t.Fatalf("snapshot=%+v err=%v", snapshot, err)
	}
	health := snapshot.Nodes[0].Health
	if snapshot.Nodes[0].State != "degraded" || health.State != "unavailable" || len(health.History) != 2 || health.History[0].ProbeID != "node-check-new" {
		t.Fatalf("newer check was lost during restore: %+v", health)
	}
	if health.History[0].ProbeID != "node-check-new" || health.History[1].ProbeID != "node-check-old" {
		t.Fatalf("merged history order is wrong: %+v", health.History)
	}
}

func TestForeignIdentityAndInvalidArchiveNeverWrite(t *testing.T) {
	a := archiveFixture(t)
	s, path := setup(t)
	importGood(t, s)
	before := readBytes(t, path)
	session, err := s.BeginRestore(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.MergeImage(context.Background(), a); !errors.Is(err, restorejournal.ErrConflict) {
		t.Fatal("foreign identity key replaced populated store")
	}
	a.Content[0] = '!'
	if _, err := session.MergeImage(context.Background(), a); err == nil {
		t.Fatal("corrupt backup accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := session.Read(ctx); err == nil {
		t.Fatal("cancel ignored")
	}
	session.Close()
	if !bytes.Equal(before, readBytes(t, path)) {
		t.Fatal("failed merge changed disk")
	}
}

type failOnceAfterWrite struct {
	restorejournal.Target
	writes int
}

func (f *failOnceAfterWrite) CompareAndSwap(ctx context.Context, before, after restorejournal.Image) error {
	if err := f.Target.CompareAndSwap(ctx, before, after); err != nil {
		return err
	}
	f.writes++
	if f.writes == 1 {
		return restorejournal.ErrRecovery
	}
	return nil
}

func TestJournalRollsBackNodeWriteToAbsent(t *testing.T) {
	a := archiveFixture(t)
	s, path := setup(t)
	s.target = &failOnceAfterWrite{Target: s.target}
	session, _ := s.BeginRestore(context.Background())
	out, err := executeNodes(t, session, a)
	if err == nil || out != restorejournal.RolledBack {
		t.Fatalf("outcome %s err %v", out, err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + string(os.PathSeparator) + fileName); !os.IsNotExist(err) {
		t.Fatal("rollback did not restore absent file")
	}
	if _, err := s.Import(context.Background(), manual, good, testTime, time.Hour, false); err != nil {
		t.Fatal("writer did not resume after confirmed rollback")
	}
}

func TestOfflineRestoreUsesSameLeaseAndBinding(t *testing.T) {
	s, path := setup(t)
	if target, err := OpenRestoreTarget(path); err == nil {
		target.Close()
		t.Fatal("offline target bypassed live lease")
	}
	s.Close()
	target, err := OpenRestoreTarget(path)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := RestoreBinding(path)
	if err != nil || target.Binding() != binding {
		t.Fatal("wrong binding")
	}
	if _, err := executeNodes(t, target, archiveFixture(t)); err != nil {
		t.Fatal(err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if snap, err := reopened.Snapshot(context.Background(), testTime); err != nil || len(snap.Nodes) != 1 {
		t.Fatal("offline restore missing")
	}
}
