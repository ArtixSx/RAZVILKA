//go:build linux && amd64 && razvilka_native_fixture

package components

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

type mihomoSourceCurrentNativeRead struct {
	mihomoReleaseFile
	read func(context.Context) (restorejournal.Image, error)
}

func (r *mihomoSourceCurrentNativeRead) Read(ctx context.Context) (restorejournal.Image, error) {
	return r.read(ctx)
}

// Actual installed managed/pool files, original writer/journal and controller
// origin. This does not Start a child, earn service evidence or prove LAN use.
func TestMihomoLiveSourceNativeCurrent(t *testing.T) {
	archive := os.Getenv("RAZVILKA_MIHOMO_ARCHIVE")
	if archive == "" {
		t.Skip("exact pinned native Mihomo archive required")
	}
	f, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	compressed, readErr := io.ReadAll(io.LimitReader(f, (64<<20)+1))
	closeErr := f.Close()
	if readErr != nil || closeErr != nil || len(compressed) > 64<<20 {
		t.Fatal("bounded archive read", readErr, closeErr)
	}
	m, info := mihomoReleaseFixture(t)
	parent, stop := context.WithTimeout(t.Context(), 120*time.Second)
	defer stop()
	image, err := m.stageMihomoArtifact(parent, compressed, info.PinnedSHA256, mihomoFixtureAdmission)
	clear(compressed)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := m.installMihomoImage(parent, info, image, mihomoFixtureAdmission, mihomoFixtureAdmission); err != nil || !result.OK {
		t.Fatal(result, err)
	}
	source, err := m.OpenMihomoLiveSource(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := source.Close(); err != nil {
			t.Error(err)
		}
	}()
	binary, receipt := source.session.files["a_binary"], source.session.files["b_receipt"]
	if _, ok := binary.(*restorejournal.ArtifactFileTarget); !ok {
		t.Fatal("fixture did not retain actual artifact target")
	}
	ref, err := mihomoArtifactReferenceOf(image)
	if err != nil {
		t.Fatal(err)
	}
	managed := source.session.paths["a_binary"]
	pool := filepath.Join(source.artifacts, ref.SHA256+".bin")
	managedInfo, managedErr := os.Stat(managed)
	poolInfo, poolErr := os.Stat(pool)
	if managedErr != nil || poolErr != nil || os.SameFile(managedInfo, poolInfo) {
		t.Fatal("two distinct actual files required", managedErr, poolErr)
	}
	current := func(t *testing.T) error {
		t.Helper()
		ctx, cancel := context.WithTimeout(parent, 5*time.Second)
		defer cancel()
		return source.Current(ctx)
	}
	if err := current(t); err != nil {
		t.Fatal("original current", err)
	}
	t.Run("receipt-after-close-original-context", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(parent, 5*time.Second)
		defer cancel()
		calls := 0
		cut := errors.New("original receipt read cut")
		source.session.files["b_receipt"] = &mihomoSourceCurrentNativeRead{mihomoReleaseFile: receipt, read: func(got context.Context) (restorejournal.Image, error) {
			calls++
			if got != ctx {
				return restorejournal.Image{}, errors.New("comparison context escaped to receipt")
			}
			// The original target mutex must already be released: no callback
			// or receipt read may run while its comparison proof is still open.
			actual, err := binary.Read(got)
			if err != nil || !sameMihomoImage(actual, image) {
				return restorejournal.Image{}, errors.Join(ErrMihomoLiveOwner, err)
			}
			return restorejournal.Image{}, cut
		}}
		defer func() { source.session.files["b_receipt"] = receipt }()
		err := source.Current(ctx)
		if calls != 1 || !errors.Is(err, cut) || !errors.Is(err, ErrMihomoLiveOwner) {
			t.Fatal("receipt read/error/context boundary changed", calls, err)
		}
	})
	t.Run("custom-target-original-read", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(parent, 5*time.Second)
		defer cancel()
		calls := 0
		cut := errors.New("custom original Read cut")
		fail := false
		source.session.files["a_binary"] = &mihomoSourceCurrentNativeRead{mihomoReleaseFile: binary, read: func(got context.Context) (restorejournal.Image, error) {
			calls++
			if got != ctx {
				return restorejournal.Image{}, errors.New("custom target context changed")
			}
			if fail {
				return restorejournal.Image{}, cut
			}
			return binary.Read(got)
		}}
		defer func() { source.session.files["a_binary"] = binary }()
		if err := source.Current(ctx); calls != 1 || err != nil {
			t.Fatal("nonconcrete original Read changed", calls, err)
		}
		fail = true
		if err := source.Current(ctx); calls != 2 || !errors.Is(err, cut) || !errors.Is(err, ErrMihomoLiveOwner) {
			t.Fatal("nonconcrete target bypassed", calls, err)
		}
	})
	for role, path := range map[string]string{"managed": managed, "pool": pool} {
		t.Run(role+"-actual-byte-mutation", func(t *testing.T) {
			mode := os.FileMode(0755)
			if role == "pool" {
				mode = 0555
			}
			if err := os.Chmod(path, mode|0200); err != nil {
				t.Fatal(err)
			}
			f, err := os.OpenFile(path, os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			var original [1]byte
			if n, err := f.ReadAt(original[:], 0); err != nil || n != 1 {
				f.Close()
				t.Fatal("original byte", n, err)
			}
			defer func() {
				_, e1 := f.WriteAt(original[:], 0)
				e2, e3 := f.Close(), os.Chmod(path, mode)
				if err := errors.Join(e1, e2, e3); err != nil {
					t.Error("restore fixture original byte", err)
				}
			}()
			changed := [1]byte{original[0] ^ 0xff}
			if _, err := f.WriteAt(changed[:], 0); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			if err := current(t); !errors.Is(err, ErrMihomoLiveOwner) {
				t.Fatal("fresh full bytes were not checked", err)
			}
		})
		if err := current(t); err != nil {
			t.Fatal("restored original files require a new successful read", role, err)
		}
	}
	t.Run("receipt-actual-byte-mutation", func(t *testing.T) {
		path := source.session.paths["b_receipt"]
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Error(err)
			}
		}()
		changed := append([]byte(nil), data...)
		changed[0] ^= 1
		if err := os.WriteFile(path, changed, 0600); err != nil {
			t.Fatal(err)
		}
		if err := current(t); !errors.Is(err, ErrMihomoLiveOwner) {
			t.Fatal("receipt mutation ignored", err)
		}
	})
	t.Run("canceled-and-unbounded", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(parent, 5*time.Second)
		cancel()
		if err := source.Current(ctx); !errors.Is(err, context.Canceled) {
			t.Fatal("original cancellation lost", err)
		}
		if err := source.Current(context.Background()); err == nil {
			t.Fatal("unbounded observation accepted")
		}
	})
	if err := current(t); err != nil {
		t.Fatal("closing fresh current", err)
	}
}
