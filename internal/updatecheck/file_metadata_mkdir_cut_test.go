package updatecheck

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func metadataMkdirCancellationProducer(t *testing.T, timeout bool) (*SelfUpdateFileAdapter, *Updater, string) {
	t.Helper()
	a, u, _ := failedMetadataReaderFixture(t)
	r, _, metadata := updateFixture(t)
	var ctx context.Context
	var cancel context.CancelFunc
	if timeout {
		ctx, cancel = context.WithTimeout(context.Background(), 500*time.Millisecond)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}
	t.Cleanup(cancel)
	u.Start(ctx)
	requests := 0
	u.Client = &http.Client{Transport: updateTransport(func(req *http.Request) (*http.Response, error) {
		requests++
		if req.URL.Host != "api.github.com" {
			return nil, errors.New("download-after-metadata-cancellation")
		}
		return updateResponse(metadata), nil
	})}
	// The real producer creates its own directory after this check returns.
	// Cancel here to hit the new immediate post-Mkdir context observation.
	u.space = func(string, int64) error {
		if timeout {
			<-ctx.Done()
		} else {
			cancel()
		}
		return nil
	}
	job, err := u.Prepare(8, u.record.ConfigFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-u.done:
	case <-time.After(3 * time.Second):
		t.Fatal("metadata cut producer did not join")
	}
	state, code := "cancelled", "prepare-cancelled"
	if timeout {
		state, code = "failed", "prepare-timeout"
	}
	got := u.Snapshot()
	if got.State != state || got.Code != code || got.Stage != "metadata" || got.Release == nil || got.Release.ID != r.ID || got.Downloaded != 0 || got.CanApply || got.CanCancel || got.ReviewToken != "" || requests != 1 {
		t.Fatalf("wrong actual producer cut: %+v requests=%d", got, requests)
	}
	entries, err := os.ReadDir(filepath.Join(u.Directory, job.ID))
	if err != nil || len(entries) != 0 {
		t.Fatal("producer did not retain exact empty Mkdir cut", entries, err)
	}
	return a, u, job.ID
}

func TestMetadataMkdirCancellationProducerColdReaders(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		name := "cancelled"
		if timeout {
			name = "timeout"
		}
		t.Run(name, func(t *testing.T) {
			a, u, id := metadataMkdirCancellationProducer(t, timeout)
			path := filepath.Join(u.Directory, "current.json")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := a.requiredJournalReadVersion(context.Background()); err != nil {
				t.Fatal("exact empty producer cut fenced cold reader", err)
			}
			if images, err := retainedControllerImagesWithAdapter(context.Background(), a.installation, filepath.Dir(a.directory), a); err != nil || len(images) != 0 {
				t.Fatal("exact empty cut fenced controller inventory", images, err)
			}
			if a.Ready(context.Background(), id) == nil {
				t.Fatal("empty cancellation granted update authority")
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(before, after) {
				t.Fatal("reader rewrote cancellation owner")
			}
			entries, err := os.ReadDir(filepath.Join(u.Directory, id))
			if err != nil || len(entries) != 0 {
				t.Fatal("reader mutated empty job", entries, err)
			}
		})
	}
}

func TestMetadataMkdirCancellationRefusesUnknownOrEffectCuts(t *testing.T) {
	for _, kind := range []string{"no-release", "space", "unknown-code", "raw-io-code", "wrong-state", "bytes", "invalid-release", "archive", "bundle", "control", "unknown", "unsafe-owner", "added-after-read", "replaced-root"} {
		t.Run(kind, func(t *testing.T) {
			a, u, id := metadataMkdirCancellationProducer(t, false)
			dir := filepath.Join(u.Directory, id)
			switch kind {
			case "no-release":
				u.record.Job.Release = nil
			case "space":
				u.record.Job.State = "failed"
				u.record.Job.Code = "insufficient-update-space"
			case "unknown-code":
				u.record.Job.Code = "future-cancel"
			case "raw-io-code":
				u.record.Job.State = "failed"
				u.record.Job.Code = "update-verification-failed"
			case "wrong-state":
				u.record.Job.State = "failed"
			case "bytes":
				u.record.Job.Downloaded = 1
			case "invalid-release":
				u.record.Job.Release.Archive.URL = "https://example.invalid/release"
			case "archive":
				_ = os.WriteFile(filepath.Join(dir, "release.tar.gz"), nil, 0600)
			case "bundle":
				_ = os.Mkdir(filepath.Join(dir, "bundle"), 0700)
			case "control":
				_ = os.WriteFile(filepath.Join(dir, "control.bin"), nil, 0600)
			case "unknown":
				_ = os.WriteFile(filepath.Join(dir, "unexpected"), nil, 0600)
			case "unsafe-owner":
				a.owned = func(string) error { return errors.New("unsafe-owner") }
			case "added-after-read", "replaced-root":
				calls := 0
				a.owned = func(path string) error {
					if path != dir {
						return nil
					}
					calls++
					if calls == 2 {
						if kind == "added-after-read" {
							return os.WriteFile(filepath.Join(dir, "unexpected"), nil, 0600)
						}
						if err := os.Rename(dir, filepath.Join(t.TempDir(), "retained")); err != nil {
							if runtime.GOOS == "windows" {
								t.Skip("Windows prevents replacing open root")
							}
							return err
						}
						return os.Mkdir(dir, 0700)
					}
					return nil
				}
			}
			if err := u.persistLocked(); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(filepath.Join(u.Directory, "current.json"))
			if _, err := a.requiredJournalReadVersion(context.Background()); err == nil {
				t.Fatal("non-exact metadata cut accepted")
			}
			after, _ := os.ReadFile(filepath.Join(u.Directory, "current.json"))
			if !bytes.Equal(before, after) {
				t.Fatal("refusal modified retained header")
			}
		})
	}
}
