//go:build linux && (amd64 || arm64)

package startuptools

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Synthetic ELF bytes are parsed and hashed, never executed. Three protected
// scratch roots stand for the profile's three ordered library roots.
func cpuidCaptureFixture(t *testing.T, arch string) *heldReview {
	t.Helper()
	dir, r := rootReviewFixture(t)
	r.profile.arch = arch
	r.profile.libraries = nil
	r.directories = nil
	for _, name := range []string{"opt-lib", "lib", "usr-lib"} {
		path := filepath.Join(dir, name)
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		r.profile.libraries = append(r.profile.libraries, path)
	}
	r.profile.loader = filepath.Join(r.profile.libraries[0], "loader.so")
	r.profile.main = filepath.Join(dir, "main")
	r.profile.aliases = [2]string{r.profile.main, r.profile.main}
	r.profile.extension = filepath.Join(r.profile.libraries[0], "extensions")
	if err := os.Mkdir(r.profile.extension, 0700); err != nil {
		t.Fatal(err)
	}
	for path, interpreter := range map[string]string{
		r.profile.loader: "", r.profile.main: r.profile.loader,
		filepath.Join(r.profile.extension, "module.so"): "",
	} {
		raw := elfFixture(interpreter, nil)
		if arch == "amd64" {
			binary.LittleEndian.PutUint16(raw[18:], 62)
		}
		if err := os.WriteFile(path, raw, 0700); err != nil {
			t.Fatal(err)
		}
		if path == r.profile.main {
			sum := sha256.Sum256(raw)
			r.profile.mainSHA = hex.EncodeToString(sum[:])
		}
	}
	return r
}

func cpuidOccupant(t *testing.T, path, kind string) {
	t.Helper()
	var err error
	switch kind {
	case "directory":
		err = os.Mkdir(path, 0700)
	case "file":
		err = os.WriteFile(path, []byte("shadow"), 0600)
	case "symlink":
		err = os.Symlink("missing-shadow-target", path)
	default:
		t.Fatal("unknown fixture kind")
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestARM64LoaderCPUIDAbsenceInCaptureDigestAndClosing(t *testing.T) {
	r := cpuidCaptureFixture(t, "arm64")
	ctx := context.Background()
	if err := r.capture(ctx); err != nil {
		t.Fatal("complete capture", err)
	}
	if err := r.unchanged(ctx); err != nil {
		t.Fatal("fresh complete closing", err)
	}
	digest, err := r.digest()
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range r.profile.libraries {
		path := filepath.Join(dir, "cpuid")
		if !r.absent[path] {
			t.Fatal("missing retained shadow absence", path)
		}
		delete(r.absent, path)
		without, err := r.digest()
		r.absent[path] = true
		if err != nil || without == digest {
			t.Fatal("shadow absence not digest-bound", err)
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := r.unchanged(canceled); err == nil {
		t.Fatal("canceled closing accepted")
	}
}

func TestARM64LoaderCPUIDPreexistingRefusedEveryRoot(t *testing.T) {
	for root := 0; root < 3; root++ {
		for _, kind := range []string{"directory", "file", "symlink"} {
			t.Run(string(rune('0'+root))+"/"+kind, func(t *testing.T) {
				r := cpuidCaptureFixture(t, "arm64")
				cpuidOccupant(t, filepath.Join(r.profile.libraries[root], "cpuid"), kind)
				err := r.capture(context.Background())
				if err == nil || !strings.Contains(err.Error(), "LOADER_VARIANT") {
					t.Fatal("wrong shadow refusal boundary", err)
				}
				if len(r.images) != 0 {
					t.Fatal("shadow check happened after image acquisition")
				}
			})
		}
	}
}

func TestARM64LoaderCPUIDAppearsAfterCaptureRefusesClosing(t *testing.T) {
	for root := 0; root < 3; root++ {
		for _, kind := range []string{"directory", "file", "symlink"} {
			t.Run(string(rune('0'+root))+"/"+kind, func(t *testing.T) {
				r := cpuidCaptureFixture(t, "arm64")
				if err := r.capture(context.Background()); err != nil {
					t.Fatal(err)
				}
				cpuidOccupant(t, filepath.Join(r.profile.libraries[root], "cpuid"), kind)
				err := r.unchanged(context.Background())
				if err == nil || !strings.Contains(err.Error(), "CHECK_ABSENCE") {
					t.Fatal("fresh closing failed to detect shadow", err)
				}
			})
		}
	}
}

func TestAMD64LoaderCPUIDDoesNotChangeVariantContract(t *testing.T) {
	r := cpuidCaptureFixture(t, "amd64")
	for _, dir := range r.profile.libraries {
		cpuidOccupant(t, filepath.Join(dir, "cpuid"), "directory")
	}
	if err := r.capture(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := r.unchanged(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, dir := range r.profile.libraries {
		if r.absent[filepath.Join(dir, "cpuid")] {
			t.Fatal("ARM64-only variant leaked into AMD64")
		}
	}
}
