//go:build linux && amd64 && razvilka_native_fixture

package components

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
	"golang.org/x/sys/unix"
)

// Full synchronous Current comparison only: original source mutex, controller
// origin, both complete artifact hashes, receipt and all closes are timed.
// Baseline differs solely by the pre-72db5626 serial read branch; other actual
// source methods are shared. This is not a historical binary or route benchmark.
//
//go:embed mihomo_live_source.go
var sourceCurrentNativeProduction string

//go:embed mihomo_live_source_current_measurement_native_linux_test.go
var sourceCurrentNativeMeasurement string

const sourceCurrentNativeBaselineCommit = "b9a0bfe10917205600e26b9c5ddfe98e73ce78fd"
const sourceCurrentNativeBaselineFileSHA = "4350d8763a5516119c9b10e84cc453e571b98ccfd8a31e566772f1cae887bc69"
const sourceCurrentNativeBaselineBodies = `func (s *MihomoLiveSource) Current(ctx context.Context) error {
	if s == nil || ctx == nil {
		return ErrMihomoLiveOwner
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.currentLocked(ctx)
}
func (s *MihomoLiveSource) currentLocked(ctx context.Context) error {
	if err := s.currentPrefixLocked(ctx); err != nil {
		return err
	}
	actual, err := s.session.files["a_binary"].Read(ctx)
	if err != nil || !sameMihomoImage(actual, s.image) {
		return errors.Join(ErrMihomoLiveOwner, err)
	}
	return s.currentReceiptLocked(ctx)
}
`

const sourceCurrentNativeParallelBranch = `	var actual restorejournal.Image
	var err error
	if target, ok := s.session.files["a_binary"].(*restorejournal.ArtifactFileTarget); ok && target != nil {
		// This original source already owns the expected image. Read BOTH full
		// files with the existing parallel two-SHA reader; no comparison handle
		// or derived context escapes. Its join/revocation/Close completes before
		// the original receipt read below. Other target implementations keep Read.
		err = target.WithExpectedReadComparison(ctx, s.image, func(_ context.Context, image restorejournal.Image, _ *restorejournal.ArtifactSourceComparison) error {
			if !sameMihomoImage(image, s.image) {
				return ErrMihomoLiveOwner
			}
			actual = image
			return nil
		})
	} else {
		actual, err = s.session.files["a_binary"].Read(ctx)
	}`

func (s *MihomoLiveSource) sourceCurrentSerialNative(ctx context.Context) error {
	if s == nil || ctx == nil {
		return ErrMihomoLiveOwner
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sourceCurrentSerialLockedNative(ctx)
}
func (s *MihomoLiveSource) sourceCurrentSerialLockedNative(ctx context.Context) error {
	if err := s.currentPrefixLocked(ctx); err != nil {
		return err
	}
	actual, err := s.session.files["a_binary"].Read(ctx)
	if err != nil || !sameMihomoImage(actual, s.image) {
		return errors.Join(ErrMihomoLiveOwner, err)
	}
	return s.currentReceiptLocked(ctx)
}

func sourceCurrentNativeBody(t *testing.T, source, name string) string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "source.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == name {
			var b bytes.Buffer
			if err := format.Node(&b, fset, fn.Body); err != nil {
				t.Fatal(err)
			}
			return strings.ReplaceAll(b.String(), "\n\n", "\n")
		}
	}
	t.Fatal("missing function", name)
	return ""
}
func TestMihomoLiveSourceCurrentNativeSourceParity(t *testing.T) {
	baseline := "package components\n" + sourceCurrentNativeBaselineBodies
	oldOuter := sourceCurrentNativeBody(t, baseline, "Current")
	if oldOuter != sourceCurrentNativeBody(t, sourceCurrentNativeProduction, "Current") || strings.Replace(oldOuter, "s.currentLocked(ctx)", "s.sourceCurrentSerialLockedNative(ctx)", 1) != sourceCurrentNativeBody(t, sourceCurrentNativeMeasurement, "sourceCurrentSerialNative") {
		t.Fatal("original wrapper lock/context/return changed")
	}
	if sourceCurrentNativeBody(t, baseline, "currentLocked") != sourceCurrentNativeBody(t, sourceCurrentNativeMeasurement, "sourceCurrentSerialLockedNative") {
		t.Fatal("original serial body changed")
	}
	oldRead := "\tactual, err := s.session.files[\"a_binary\"].Read(ctx)"
	if strings.Count(baseline, oldRead) != 1 {
		t.Fatal("ambiguous baseline read")
	}
	expected := strings.Replace(baseline, oldRead, sourceCurrentNativeParallelBranch, 1)
	if sourceCurrentNativeBody(t, expected, "currentLocked") != sourceCurrentNativeBody(t, sourceCurrentNativeProduction, "currentLocked") {
		t.Fatal("production differs beyond reviewed concrete-target read branch")
	}
	prior := sha256.Sum256([]byte(sourceCurrentNativeBaselineBodies))
	current := sha256.Sum256([]byte(strings.ReplaceAll(sourceCurrentNativeProduction, "\r\n", "\n")))
	t.Logf("SOURCE_CURRENT_PARITY baseline_commit=%s baseline_file_sha256=%s baseline_bodies_sha256=%x current_file_sha256=%x", sourceCurrentNativeBaselineCommit, sourceCurrentNativeBaselineFileSHA, prior, current)
}
func sourceCurrentNativeFixture(t *testing.T, parent context.Context) *MihomoLiveSource {
	t.Helper()
	archive, err := os.Open(os.Getenv("RAZVILKA_MIHOMO_ARCHIVE"))
	if err != nil {
		t.Fatal(err)
	}
	compressed, readErr := io.ReadAll(io.LimitReader(archive, (64<<20)+1))
	closeErr := archive.Close()
	if readErr != nil || closeErr != nil || len(compressed) > 64<<20 {
		t.Fatal("bounded pinned archive", readErr, closeErr)
	}
	m, info := mihomoReleaseFixture(t)
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
	t.Cleanup(func() {
		if err := source.Close(); err != nil {
			t.Error(err)
		}
	})
	return source
}
func sourceCurrentNativeCPU(t *testing.T, who int) int64 {
	t.Helper()
	var usage unix.Rusage
	if err := unix.Getrusage(who, &usage); err != nil {
		t.Fatal(err)
	}
	return usage.Utime.Nano() + usage.Stime.Nano()
}
func TestMihomoLiveSourceCurrentNativePaired(t *testing.T) {
	if os.Getenv("RAZVILKA_SOURCE_CURRENT_MEASURE") != "1" {
		t.Skip("explicit full source-current measurement required")
	}
	parent, stop := context.WithTimeout(t.Context(), 120*time.Second)
	defer stop()
	source := sourceCurrentNativeFixture(t, parent)
	target, concrete := source.session.files["a_binary"].(*restorejournal.ArtifactFileTarget)
	if !concrete || target == nil {
		t.Fatal("candidate requires the actual concrete artifact target")
	}
	versions := []struct {
		name string
		run  func(context.Context) error
	}{{"original-serial-source-current", source.sourceCurrentSerialNative}, {"parallel-two-sha-source-current", source.Current}}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	for _, v := range versions {
		ctx, cancel := context.WithTimeout(parent, 5*time.Second)
		err := v.run(ctx)
		cancel()
		if err != nil {
			t.Fatal("warmup", v.name, err)
		}
	}
	const samples = 2
	for pair := 0; pair < 8; pair++ {
		order := []int{0, 1}
		if pair%2 == 1 {
			order = []int{1, 0}
		}
		for _, index := range order {
			v := versions[index]
			threadBefore := sourceCurrentNativeCPU(t, unix.RUSAGE_THREAD)
			totalBefore := sourceCurrentNativeCPU(t, unix.RUSAGE_SELF)
			start := time.Now()
			for sample := 0; sample < samples; sample++ {
				ctx, cancel := context.WithTimeout(parent, 5*time.Second)
				err := v.run(ctx)
				cancel()
				if err != nil {
					t.Fatal("full Current failed", v.name, pair, sample, err)
				}
			}
			wall := time.Since(start)
			totalAfter := sourceCurrentNativeCPU(t, unix.RUSAGE_SELF)
			threadAfter := sourceCurrentNativeCPU(t, unix.RUSAGE_THREAD)
			row := map[string]any{"pair": pair, "variant": v.name, "samples": samples, "wall_ns": wall.Nanoseconds(), "thread_cpu_ns": threadAfter - threadBefore, "total_process_cpu_ns": totalAfter - totalBefore, "artifact_bytes": source.reference.BinarySize, "controller_bytes": source.reference.ParentOrigin.ExecutableSize, "artifact_sha256": source.reference.BinarySHA256, "controller_sha256": source.reference.ParentOrigin.ExecutableSHA256, "fresh_artifact_streams_per_current": 2, "scope": "complete original Current including controller SHA, 2 actual artifact hashes, receipt, locks, join and closes; warm files; not route/HTTP timing; thread CPU excludes worker SHA; process CPU includes runtime"}
			data, err := json.Marshal(row)
			if err != nil {
				t.Fatal(err)
			}
			t.Log("SOURCE_CURRENT_PAIR " + string(data))
		}
	}
	// Keep both image and original controller provenance explicit, without paths.
	if source.session.files["a_binary"] != target {
		t.Fatal("original binary target changed during population")
	}
	expected, err := mihomoReviewedRawArtifact("amd64")
	if err != nil || expected.SHA256 != source.reference.BinarySHA256 || expected.Size != source.reference.BinarySize {
		t.Fatal("actual source pin drift", err)
	}
	digest, err := hex.DecodeString(source.reference.ParentOrigin.ExecutableSHA256)
	if err != nil || len(digest) != 32 {
		t.Fatal("controller pin missing")
	}
}
