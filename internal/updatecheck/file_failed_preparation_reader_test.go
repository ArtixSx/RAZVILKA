package updatecheck

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Run the real asynchronous prepare producer, then use a cold reader and the
// shared controller inventory. Transport/preflight fixtures do not execute a
// candidate or model native production ownership acceptance.
func TestFailedPreparationProducerColdReaders(t *testing.T) {
	for _, kind := range []string{"space", "download-http", "download-sha", "extract", "partial-extract", "preflight", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			a, u, _ := failedMetadataReaderFixture(t)
			r, archive, _ := updateFixture(t)
			if kind == "extract" {
				archive = []byte("not a gzip archive")
				r.Archive.Size = int64(len(archive))
				r.Archive.Digest = "sha256:" + digestOf(archive)
			}
			if kind == "partial-extract" {
				var b bytes.Buffer
				gz := gzip.NewWriter(&b)
				tw := tar.NewWriter(gz)
				if err := tw.WriteHeader(&tar.Header{Name: "RAZVILKA-" + r.Version + "/scripts/S99razvilka", Mode: 0600, Typeflag: tar.TypeReg, Size: 1}); err != nil {
					t.Fatal(err)
				}
				_, _ = tw.Write([]byte("x"))
				_ = tw.Close()
				_ = gz.Close()
				archive = b.Bytes()
				r.Archive.Size = int64(len(archive))
				r.Archive.Digest = "sha256:" + digestOf(archive)
			}
			metadata := releaseMetadata(r)
			u.space = func(string, int64) error {
				if kind == "space" {
					return errors.New("insufficient-update-space")
				}
				return nil
			}
			u.preflight = func(context.Context, string, Release) error {
				return errors.New("candidate-version-or-architecture-refused")
			}
			u.Client = &http.Client{Transport: updateTransport(func(req *http.Request) (*http.Response, error) {
				if req.URL.Host == "api.github.com" {
					return updateResponse(metadata), nil
				}
				if kind == "download-http" {
					response := updateResponse(nil)
					response.StatusCode = 503
					return response, nil
				}
				if kind == "cancel" {
					u.mu.Lock()
					cancel := u.cancel
					u.mu.Unlock()
					cancel()
					return nil, context.Canceled
				}
				body := append([]byte(nil), archive...)
				if kind == "download-sha" {
					body[len(body)-1] ^= 1
				}
				return updateResponse(body), nil
			})}
			job, err := u.Prepare(8, u.record.ConfigFingerprint)
			if err != nil {
				t.Fatal(err)
			}
			select {
			case <-u.done:
			case <-time.After(5 * time.Second):
				t.Fatal("producer failed to join")
			}
			failed := u.Snapshot()
			if failed.State != "failed" && failed.State != "cancelled" {
				t.Fatalf("not terminal: %+v", failed)
			}
			before, err := os.ReadFile(filepath.Join(u.Directory, "current.json"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := a.requiredJournalReadVersion(context.Background()); err != nil {
				t.Fatalf("producer %s/%s fenced cold reader: %v", failed.Stage, failed.Code, err)
			}
			if _, err := retainedControllerImagesWithAdapter(context.Background(), a.installation, filepath.Dir(a.directory), a); err != nil {
				t.Fatal("shared inventory fenced", err)
			}
			after, _ := os.ReadFile(filepath.Join(u.Directory, "current.json"))
			if !bytes.Equal(before, after) {
				t.Fatal("read-only recognition changed header")
			}
			if a.Ready(context.Background(), job.ID) == nil {
				t.Fatal("failure granted apply authority")
			}
			// The same failure with an unknown/recovery artifact must never be skipped.
			if err := os.MkdirAll(filepath.Join(u.Directory, job.ID), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(u.Directory, job.ID, "control.bin"), []byte("retained"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := a.requiredJournalReadVersion(context.Background()); err == nil {
				t.Fatal("recovery artifact was ignored")
			}
		})
	}
}

func TestSubsequentPrepareRefusesUnsealedRecoveryEvidence(t *testing.T) {
	for _, name := range []string{"control.bin", "file-review.json", "private-snapshot.json", "start-candidate-panel.process.json"} {
		t.Run(name, func(t *testing.T) {
			_, u, r := failedMetadataReaderFixture(t)
			dir := filepath.Join(u.Directory, r.ID)
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, name)
			evidence := []byte("uncommitted recovery owner")
			if err := os.WriteFile(path, evidence, 0600); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(filepath.Join(u.Directory, "current.json"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := u.Prepare(8, u.record.ConfigFingerprint); !errors.Is(err, ErrBusy) {
				t.Fatal("orphan-producing preparation accepted", err)
			}
			after, _ := os.ReadFile(filepath.Join(u.Directory, "current.json"))
			retained, _ := os.ReadFile(path)
			if !bytes.Equal(before, after) || !bytes.Equal(evidence, retained) || u.cancel != nil {
				t.Fatal("refusal changed owner/evidence or started worker")
			}
		})
	}
}

func TestFailedPreparationCacheRejectsUnknownAndUnsafeArtifacts(t *testing.T) {
	for _, kind := range []string{"unknown", "staged", "private", "process", "nested-unknown", "oversize", "symlink", "unsafe-owner", "bad-release", "too-many", "invalid-byte-count"} {
		t.Run(kind, func(t *testing.T) {
			a, u, r := failedMetadataReaderFixture(t)
			release, _, _ := updateFixture(t)
			u.record.Job.Release = &release
			u.record.Job.Stage = "verifying"
			u.record.Job.Code = "archive-required-file-missing"
			u.record.Job.Downloaded = release.Archive.Size
			job := filepath.Join(a.directory, r.ID)
			if err := os.MkdirAll(job, 0700); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "unknown":
				_ = os.WriteFile(filepath.Join(job, "unexpected"), nil, 0600)
			case "staged":
				_ = os.Mkdir(filepath.Join(job, "staged"), 0700)
			case "private":
				_ = os.WriteFile(filepath.Join(job, "private-snapshot.json"), nil, 0600)
			case "process":
				_ = os.WriteFile(filepath.Join(job, "start-candidate-panel.process.json"), nil, 0600)
			case "nested-unknown":
				_ = os.MkdirAll(filepath.Join(job, "bundle/scripts"), 0700)
				_ = os.WriteFile(filepath.Join(job, "bundle/scripts/extra.sh"), nil, 0600)
			case "oversize":
				f, err := os.OpenFile(filepath.Join(job, "release.tar.gz"), os.O_CREATE|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				if err := f.Truncate(release.Archive.Size + 1); err != nil {
					t.Fatal(err)
				}
				f.Close()
			case "symlink":
				if err := os.Symlink(t.TempDir(), filepath.Join(job, "bundle")); err != nil {
					t.Skip("symlinks unavailable")
				}
			case "unsafe-owner":
				a.owned = func(string) error { return errors.New("unsafe ownership") }
			case "bad-release":
				u.record.Job.Release.Archive.URL = "https://example.invalid/file"
			case "too-many":
				for i := 0; i < 34; i++ {
					_ = os.WriteFile(filepath.Join(job, strings.Repeat("x", i+1)), nil, 0600)
				}
			case "invalid-byte-count":
				u.record.Job.Downloaded--
			}
			if err := u.persistLocked(); err != nil {
				t.Fatal(err)
			}
			if _, err := a.requiredJournalReadVersion(context.Background()); err == nil {
				t.Fatal("unsafe terminal cache admitted")
			}
			if _, err := retainedControllerImagesWithAdapter(context.Background(), a.installation, filepath.Dir(a.directory), a); err == nil {
				t.Fatal("unsafe cache omitted by controller inventory")
			}
		})
	}
}

func TestFailedPreparationCacheRejectsConcurrentChildChanges(t *testing.T) {
	for _, kind := range []string{"replace-child", "add-child"} {
		t.Run(kind, func(t *testing.T) {
			a, u, r := failedMetadataReaderFixture(t)
			release, _, _ := updateFixture(t)
			u.record.Job.Release = &release
			u.record.Job.Stage = "verifying"
			u.record.Job.Code = "archive-required-file-missing"
			u.record.Job.Downloaded = release.Archive.Size
			job := filepath.Join(a.directory, r.ID)
			scripts := filepath.Join(job, "bundle/scripts")
			path := filepath.Join(scripts, "S99razvilka")
			if err := os.MkdirAll(scripts, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("cache"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := u.persistLocked(); err != nil {
				t.Fatal(err)
			}
			changed := false
			a.owned = func(observed string) error {
				if observed == path && !changed {
					changed = true
					if kind == "replace-child" {
						if err := os.Rename(scripts, filepath.Join(t.TempDir(), "detached")); err != nil {
							return err
						}
						if err := os.Mkdir(scripts, 0700); err != nil {
							return err
						}
						return os.WriteFile(path, []byte("cache"), 0600)
					}
					return os.WriteFile(filepath.Join(scripts, "unexpected"), nil, 0600)
				}
				return nil
			}
			if _, err := a.requiredJournalReadVersion(context.Background()); err == nil {
				t.Fatal("concurrent cache substitution accepted")
			}
			if !changed {
				t.Fatal("race fixture was not exercised")
			}
		})
	}
}

func TestFailedPreparationClassifierDefersSealedAndEffectOwners(t *testing.T) {
	for _, stage := range []string{"applying", "recovering", "preflight"} {
		t.Run(stage, func(t *testing.T) {
			a, u, _ := fileAdapterFixture(t)
			u.record.Job.State = "failed"
			u.record.Job.Stage = stage
			if match, err := a.failedMetadataHeader(context.Background(), u.record); err != nil || match {
				t.Fatal("sealed effect owner intercepted", match, err)
			}

		})
	}
}

func TestFailedPreparationChangePreservesPairedAcceptedInventory(t *testing.T) {
	f := pairedReaderSetup(t)
	f.accept(t)
	f.inventoryPlacement(t)
	if match, err := f.adapter.failedMetadataHeader(f.ctx, f.updater.record); err != nil || match {
		t.Fatal("accepted immutable owner intercepted", match, err)
	}
	images, err := retainedControllerImagesWithAdapter(f.ctx, f.adapter.installation, filepath.Join(f.adapter.installation, "razvilka/state"), f.adapter)
	if err != nil || len(images) != 2 {
		t.Fatal("accepted unretired controller inventory regressed", images, err)
	}
	if _, err := f.adapter.requiredJournalReadVersion(f.ctx); err != nil {
		t.Fatal("accepted paired cold reader regressed", err)
	}
}
