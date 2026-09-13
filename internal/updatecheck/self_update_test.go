package updatecheck

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

type updateTransport func(*http.Request) (*http.Response, error)

func (f updateTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func updateResponse(body []byte) *http.Response {
	return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)), Header: make(http.Header)}
}
func digestOf(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

func updateFixture(t *testing.T) (Release, []byte, []byte) {
	t.Helper()
	arch := runtime.GOARCH
	image := make([]byte, 64)
	copy(image, "\x7fELF")
	image[4] = 2
	image[5] = 1
	image[6] = 1
	machine := uint16(62)
	if arch == "arm64" {
		machine = 183
	}
	binary.LittleEndian.PutUint16(image[16:], 2)
	binary.LittleEndian.PutUint16(image[18:], machine)
	binary.LittleEndian.PutUint32(image[20:], 1)
	binary.LittleEndian.PutUint16(image[52:], 64)
	r := Release{ID: 51, Tag: "v0.19.0", Version: "0.19.0", PublishedAt: "2026-09-08T01:00:00Z", Page: "https://github.com/ArtixSx/RAZVILKA/releases/tag/v0.19.0", Architecture: arch}
	r.Binary = Asset{ID: 52, Name: "razvilka-linux-" + arch, Size: int64(len(image)), Digest: "sha256:" + digestOf(image)}
	r.Binary.URL = "https://github.com/ArtixSx/RAZVILKA/releases/download/" + r.Tag + "/" + r.Binary.Name
	files := map[string][]byte{}
	for name := range requiredInstallFiles(r) {
		files[name] = []byte("fixture\n")
	}
	files["dist/"+r.Binary.Name] = image
	files["dist/SHA256SUMS"] = []byte(digestOf(image) + "  " + r.Binary.Name + "\n")
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	for name, data := range files {
		if err := tw.WriteHeader(&tar.Header{Name: "RAZVILKA-" + r.Version + "/" + name, Mode: 0600, Typeflag: tar.TypeReg, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write(data)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	archive := out.Bytes()
	r.Archive = Asset{ID: 53, Name: "RAZVILKA-0.19.0-entware.tar.gz", Size: int64(len(archive)), Digest: "sha256:" + digestOf(archive), URL: "https://github.com/ArtixSx/RAZVILKA/releases/download/v0.19.0/RAZVILKA-0.19.0-entware.tar.gz"}
	return r, archive, releaseMetadata(r)
}
func releaseMetadata(r Release) []byte {
	assets := []map[string]any{}
	for _, a := range []Asset{r.Archive, r.Binary} {
		assets = append(assets, map[string]any{"id": a.ID, "name": a.Name, "size": a.Size, "digest": a.Digest, "browser_download_url": a.URL, "state": "uploaded"})
	}
	data, _ := json.Marshal(map[string]any{"id": r.ID, "tag_name": r.Tag, "html_url": r.Page, "published_at": r.PublishedAt, "assets": assets})
	return data
}

func TestSelfUpdateReleaseIdentityAndNoDowngrade(t *testing.T) {
	r, _, metadata := updateFixture(t)
	if _, err := parseRelease(metadata, "0.18.1-dev", runtime.GOARCH, 51); err != nil {
		t.Fatal(err)
	}
	for _, pair := range []struct {
		current, target string
		want            bool
	}{{"0.18.1-dev", "v0.18.0", false}, {"0.18.1-dev", "v0.18.1", true}, {"0.18.1", "v0.18.1", false}, {"local", "v1.0.0", false}, {"0.18.1", "v0.19.0-rc.1", false}, {"0.18.1", "v0.19.0", true}} {
		if got := CanUpgrade(pair.current, pair.target); got != pair.want {
			t.Fatalf("%s -> %s=%v", pair.current, pair.target, got)
		}
	}
	for _, change := range []func(*Release){func(r *Release) { r.ID = 99 }, func(r *Release) { r.Page = "https://github.com/other/RAZVILKA/releases/tag/v0.19.0" }, func(r *Release) { r.Archive.Digest = "" }, func(r *Release) { r.Archive.URL = "https://github.com/other/RAZVILKA/file" }, func(r *Release) { r.Binary.Size = MaximumBinaryBytes + 1 }} {
		bad := r
		change(&bad)
		if _, err := parseRelease(releaseMetadata(bad), "0.18.1", runtime.GOARCH, 51); err == nil {
			t.Fatalf("accepted modified release: %+v", bad)
		}
	}
}

func TestSelfUpdateVerifiedArchiveAndStoredManifest(t *testing.T) {
	r, archive, _ := updateFixture(t)
	dir := t.TempDir()
	root, err := ownedfs.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.WriteAtomic("release.tar.gz", archive, 0600); err != nil {
		t.Fatal(err)
	}
	hashes, err := ExtractInstallFiles(context.Background(), root, "release.tar.gz", r)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyExtracted(root, hashes, r); err != nil {
		t.Fatal(err)
	}
	old := hashes["scripts/upgrade-entware.sh"]
	delete(hashes, "scripts/upgrade-entware.sh")
	hashes["scripts/unrelated.sh"] = old
	if VerifyExtracted(root, hashes, r) == nil {
		t.Fatal("same-size manifest excluded executable installer")
	}
	delete(hashes, "scripts/unrelated.sh")
	hashes["scripts/upgrade-entware.sh"] = old
	if err := root.WriteAtomic("bundle/scripts/upgrade-entware.sh", []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if VerifyExtracted(root, hashes, r) == nil {
		t.Fatal("modified installer accepted")
	}
}

func TestSelfUpdateRejectsArchiveLinksTraversalAndBombHeaders(t *testing.T) {
	r, _, _ := updateFixture(t)
	for _, header := range []*tar.Header{{Name: "../outside", Typeflag: tar.TypeReg}, {Name: "RAZVILKA-0.19.0/link", Typeflag: tar.TypeSymlink, Linkname: "/opt/bin/razvilka"}, {Name: "RAZVILKA-0.19.0/scripts/upgrade-entware.sh", Typeflag: tar.TypeReg, Size: 257 << 10}, {Name: "RAZVILKA-0.19.0/fifo", Typeflag: tar.TypeFifo}} {
		t.Run(header.Name, func(t *testing.T) {
			var out bytes.Buffer
			gz := gzip.NewWriter(&out)
			tw := tar.NewWriter(gz)
			if err := tw.WriteHeader(header); err != nil {
				t.Fatal(err)
			}
			_ = tw.Close()
			_ = gz.Close()
			root, err := ownedfs.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			if err := root.WriteAtomic("bad.tar.gz", out.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := ExtractInstallFiles(context.Background(), root, "bad.tar.gz", r); err == nil {
				t.Fatal("unsafe archive accepted")
			}
		})
	}
}

func TestSelfUpdateDownloadHashFailureRemovesPartial(t *testing.T) {
	r, archive, _ := updateFixture(t)
	root, err := ownedfs.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	bad := append([]byte(nil), archive...)
	bad[len(bad)-1] ^= 1
	client := &http.Client{Transport: updateTransport(func(*http.Request) (*http.Response, error) { return updateResponse(bad), nil })}
	if Download(context.Background(), client, r.Archive, root, "release.tar.gz", nil) == nil {
		t.Fatal("bad hash accepted")
	}
	if _, err := root.ReadLimited("release.tar.gz", MaximumArchiveBytes); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed download remained")
	}
}

func readyUpdater(t *testing.T) *Updater {
	t.Helper()
	r, archive, metadata := updateFixture(t)
	dir := t.TempDir()
	exe := filepath.Join(dir, "current-binary")
	if err := os.WriteFile(exe, []byte("trusted current fixture"), 0700); err != nil {
		t.Fatal(err)
	}
	u := NewUpdater("0.18.1-dev", dir, Deployment{Executable: exe})
	u.eligibility = func(Deployment) error { return nil }
	u.space = func(string, int64) error { return nil }
	u.preflight = func(context.Context, string, Release) error { return nil }
	u.Client = &http.Client{Transport: updateTransport(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "api.github.com" {
			return updateResponse(metadata), nil
		}
		if req.URL.String() == r.Archive.URL {
			return updateResponse(archive), nil
		}
		return nil, errors.New("unexpected request")
	})}
	job, err := u.Prepare(7, "config-fixture")
	if err != nil || job.State != "preparing" {
		t.Fatalf("prepare: %+v %v", job, err)
	}
	select {
	case <-u.done:
	case <-time.After(5 * time.Second):
		t.Fatal("prepare did not join")
	}
	if job = u.Snapshot(); !job.CanApply || job.State != "ready" {
		t.Fatalf("not ready: %+v", job)
	}
	return u
}

func TestSelfUpdatePrepareCancelAndDoubleJob(t *testing.T) {
	u := NewUpdater("0.18.1", t.TempDir(), Deployment{})
	u.eligibility = func(Deployment) error { return nil }
	started := make(chan struct{})
	u.Client = &http.Client{Transport: updateTransport(func(r *http.Request) (*http.Response, error) {
		close(started)
		<-r.Context().Done()
		return nil, r.Context().Err()
	})}
	if _, err := u.Prepare(1, "x"); err != nil {
		t.Fatal(err)
	}
	<-started
	if _, err := u.Prepare(1, "x"); !errors.Is(err, ErrBusy) {
		t.Fatal("concurrent preparation accepted")
	}
	if _, err := u.Cancel(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := u.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	if job := u.Snapshot(); job.State != "cancelled" || job.CanApply {
		t.Fatalf("cancelled worker published review: %+v", job)
	}
}

func TestSelfUpdateApplyBindsReviewConfigAndAssetIdentity(t *testing.T) {
	u := readyUpdater(t)
	var launches atomic.Int32
	u.launch = func(string) (int, error) { launches.Add(1); return 345678, nil }
	job := u.Snapshot()
	for _, attempt := range []struct {
		id, token, fp string
		rev           uint64
	}{{job.ID, "different", "config-fixture", 7}, {job.ID, job.ReviewToken, "changed", 7}, {job.ID, job.ReviewToken, "config-fixture", 8}} {
		if _, err := u.Apply(context.Background(), attempt.id, attempt.token, attempt.rev, attempt.fp); !errors.Is(err, ErrReviewChanged) {
			t.Fatal("changed review accepted")
		}
	}
	original := u.Client.Transport
	u.Client.Transport = updateTransport(func(req *http.Request) (*http.Response, error) {
		response, err := original.RoundTrip(req)
		if err != nil {
			return nil, err
		}
		data, _ := io.ReadAll(response.Body)
		response.Body.Close()
		data = bytes.ReplaceAll(data, []byte(`"id":53`), []byte(`"id":54`))
		return updateResponse(data), nil
	})
	if _, err := u.Apply(context.Background(), job.ID, job.ReviewToken, 7, "config-fixture"); !errors.Is(err, ErrReviewChanged) {
		t.Fatal("replaced asset accepted")
	}
	if launches.Load() != 0 {
		t.Fatal("refusal launched installer")
	}
	u.Client.Transport = original
	result, err := u.Apply(context.Background(), job.ID, job.ReviewToken, 7, "config-fixture")
	if err != nil || result.State != "installing" || result.CanApply || launches.Load() != 1 {
		t.Fatalf("reviewed launch failed: %+v %v", result, err)
	}
	if _, err := u.Apply(context.Background(), job.ID, job.ReviewToken, 7, "config-fixture"); err == nil {
		t.Fatal("double install accepted")
	}
}

func TestSelfUpdatePostLaunchVisibleWriteFailureIsUncertain(t *testing.T) {
	u := readyUpdater(t)
	job := u.Snapshot()
	u.launch = func(string) (int, error) { return 345679, nil }
	u.persistHook = func(record updateRecord) error {
		root, err := ownedfs.Open(u.Directory)
		if err != nil {
			return err
		}
		defer root.Close()
		data, _ := json.Marshal(record)
		if err := root.WriteAtomic("current.json", data, 0600); err != nil {
			return err
		}
		if record.Job.HelperPID > 1 {
			return errors.New("simulated directory fsync failure after rename")
		}
		return nil
	}
	result, err := u.Apply(context.Background(), job.ID, job.ReviewToken, 7, "config-fixture")
	if !errors.Is(err, ErrHandoffUncertain) || result.HelperPID <= 1 || result.State != "installing" {
		t.Fatalf("launch incorrectly reported not started: %+v %v", result, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	u.Start(ctx)
	released := make(chan struct{})
	u.RetainHandoff(func() { close(released) })
	cancel()
	if err := u.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-released:
	default:
		t.Fatal("retained handoff failed shutdown join")
	}
}

func TestSelfUpdateMalformedOrMissingRecordRevokesReview(t *testing.T) {
	for _, missing := range []bool{false, true} {
		u := readyUpdater(t)
		file := filepath.Join(u.Directory, "current.json")
		if missing {
			if err := os.Remove(file); err != nil {
				t.Fatal(err)
			}
		} else if err := os.WriteFile(file, []byte("{broken"), 0600); err != nil {
			t.Fatal(err)
		}
		job := u.Snapshot()
		if job.State != "requires-review" || job.CanApply || job.ReviewToken != "" {
			t.Fatalf("damaged persisted record retained authority: %+v", job)
		}
	}
}

func TestSelfUpdateStaleHandoffAndCandidateRefusal(t *testing.T) {
	u := readyUpdater(t)
	u.record.Job.State = "installing"
	u.record.Job.HelperPID = 0
	u.record.Job.UpdatedAt = time.Now().Add(-time.Minute)
	u.record.Job.CanApply = false
	if err := u.persistLocked(); err != nil {
		t.Fatal(err)
	}
	if job := u.Snapshot(); job.State != "requires-review" {
		t.Fatalf("stale handoff stuck: %+v", job)
	}
	v := NewUpdater("0.18.1-dev", t.TempDir(), Deployment{Executable: "/opt/var/lib/razvilka-candidate/bin/razvilka", Port: "8788", Paths: ProductionPaths()})
	called := false
	v.Client = &http.Client{Transport: updateTransport(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, errors.New("must not download")
	})}
	job, err := v.Prepare(1, "x")
	if err != nil || job.State != "blocked" || called {
		t.Fatalf("candidate crossed into production: %+v %v", job, err)
	}
	if _, err := os.Stat(v.Directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("candidate refusal wrote update root")
	}
	if strings.Contains(job.Code, "/") {
		t.Fatal("public code exposed path")
	}
}

func TestSelfUpdateRestartKeepsAdmissionUntilHelperTerminalAndReaped(t *testing.T) {
	u := readyUpdater(t)
	u.record.Job.State = "restarting"
	u.record.Job.CanApply = false
	u.record.Job.ReviewToken = ""
	u.record.Job.HelperPID = 345680
	if err := u.persistLocked(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	restarted := NewUpdater("0.19.0", filepath.Dir(u.Directory), u.Deployment)
	var alive atomic.Bool
	alive.Store(true)
	restarted.alive = func(int) bool { return alive.Load() }
	restarted.Start(ctx)
	if !restarted.StartupPending() {
		t.Fatal("new daemon ignored in-progress installer")
	}
	released := make(chan struct{})
	restarted.RetainHandoff(func() { close(released) })
	if !restarted.InstallationLocked() {
		t.Fatal("new daemon has no write fence")
	}
	u.record.Job.State = "failed"
	u.record.Job.Message = "Preflight refused before stop"
	if err := u.persistLocked(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-released:
		t.Fatal("terminal journal released live helper")
	case <-time.After(1100 * time.Millisecond):
	}
	alive.Store(false)
	select {
	case <-released:
	case <-time.After(2 * time.Second):
		t.Fatal("refused/reaped helper left gate locked")
	}
	if err := restarted.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if restarted.InstallationLocked() {
		t.Fatal("completed handoff remained locked")
	}
}

func TestSelfUpdateHandoffRemainsLockedUntilReleaseCleanupCompletes(t *testing.T) {
	u := readyUpdater(t)
	u.record.Job.State = "completed"
	u.record.Job.HelperPID = 0
	if err := u.persistLocked(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	u.Start(ctx)
	entered, finish := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-finish:
		default:
			close(finish)
		}
	}()
	u.RetainHandoff(func() {
		close(entered)
		<-finish // The new daemon still joins exact-check/rollback cleanup.
	})
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("terminal helper did not request release")
	}
	if !u.InstallationLocked() {
		t.Fatal("terminal journal removed installation lock before joined release")
	}
	short, stopShort := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err := u.Wait(short)
	stopShort()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wait completed before release cleanup: %v", err)
	}
	close(finish)
	wait, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := u.Wait(wait); err != nil || u.InstallationLocked() {
		t.Fatalf("joined terminal helper retained lock: %v", err)
	}
}
