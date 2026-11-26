//go:build linux && amd64 && razvilka_native_fixture

package startuptools

import (
	"context"
	_ "embed"
	"errors"
	"io"
	"math"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Retain the exact old allocation for paired measurements against production.
//
//go:embed version_batch_linux.go
var versionNamesProductionSource string

//go:embed version_names_measurement_native_linux_test.go
var versionNamesCandidateSource string

func (r *heldReview) versionMetadataBeforeNamesReservation(ctx context.Context) error {
	noteVersionMetadataAttempt(r)
	if err := r.pathsCurrent(ctx); err != nil {
		return err
	}
	for _, image := range r.images {
		// Both complete pathsCurrent passes observe this exact ORIGINAL
		// canonical named node. There is no callback/effect between them;
		// keep the actual held FD check, avoiding a third named-path stat.
		if image == nil || image.file == nil || image.info == nil {
			return at("CHECK_HELD_FILE", nil)
		}
		node, exists := r.nodes[image.path]
		if !exists || node.path != image.path || node.info == nil || node.link != "" || !sameNode(image.info, node.info) {
			return at("CHECK_HELD_FILE", nil)
		}
		same, err := freshHeldNode(image.file, image.info)
		if err != nil || !same {
			return at("CHECK_HELD_FILE", err)
		}
	}
	canonical, err := r.versionExtensionPath()
	if err != nil {
		return err
	}
	file, err := openDirectory(canonical, r.nodes[canonical].info)
	if err != nil {
		return at("CHECK_EXTENSIONS", err)
	}
	entries, readErr := file.ReadDir(257)
	closeErr := file.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil || len(entries) > 256 {
		return at("CHECK_EXTENSIONS", errors.Join(readErr, closeErr))
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	slices.Sort(names)
	if !slices.Equal(names, r.extensions) {
		return at("CHECK_EXTENSION_SET", nil)
	}
	return r.pathsCurrent(ctx)
}

func TestVersionNamesCandidateSourceParity(t *testing.T) {
	production := strings.ReplaceAll(versionNamesProductionSource, "\r\n", "\n")
	candidate := strings.ReplaceAll(versionNamesCandidateSource, "\r\n", "\n")
	start := strings.Index(production, "func (r *heldReview) versionMetadataCurrent(")
	if start < 0 {
		t.Fatal("original full metadata function absent")
	}
	expected := strings.TrimSpace(production[start:])
	expected = strings.Replace(expected, "versionMetadataCurrent(", "versionMetadataBeforeNamesReservation(", 1)
	expected = strings.Replace(expected, "var nameStorage [256]string\n\tnames := nameStorage[:0]", "var names []string", 1)
	start = strings.Index(candidate, "func (r *heldReview) versionMetadataBeforeNamesReservation(")
	if start < 0 {
		t.Fatal("candidate full metadata function absent")
	}
	end := strings.Index(candidate[start:], "\nfunc TestVersionNamesCandidateSourceParity(")
	if end < 0 || strings.TrimSpace(candidate[start:start+end]) != expected {
		t.Fatal("metadata candidate drift beyond names backing initializer")
	}
}

func versionNamesActualLease(tb testing.TB, ctx context.Context) *Lease {
	tb.Helper()
	if os.Getenv("RAZVILKA_MANAGED_PROBE_NATIVE") != "1" {
		tb.Skip("explicit disposable native fixture only")
	}
	net, ne := os.Readlink("/proc/self/ns/net")
	hostNet, hne := os.Readlink("/proc/1/ns/net")
	mnt, me := os.Readlink("/proc/self/ns/mnt")
	hostMnt, hme := os.Readlink("/proc/1/ns/mnt")
	opt, oe := os.Stat("/opt")
	hostOpt, hoe := os.Stat("/proc/1/root/opt")
	if os.Geteuid() != 0 || ne != nil || hne != nil || me != nil || hme != nil || oe != nil || hoe != nil || net == hostNet || mnt == hostMnt || os.SameFile(opt, hostOpt) {
		tb.Fatal("actual disposable mount/network namespaces required")
	}
	l, err := AcquireNativeFixturePolicy(ctx, netidentity.NewProcProvider(), os.Getenv("RAZVILKA_MANAGED_PROBE_TOOLS_REVIEW"))
	if err != nil {
		tb.Fatal("actual protected tool producer", nativeStages(err))
	}
	tb.Cleanup(func() {
		if err := l.Close(); err != nil {
			tb.Error(err)
		}
	})
	return l
}

func TestVersionNamesCandidateActualParity(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	l := versionNamesActualLease(t, ctx)
	err := l.WithReadOnlyToolObservation(ctx, l.identity, l.digest, func(held context.Context) error {
		if err := l.review.versionMetadataCurrent(held); err != nil {
			return err
		}
		if err := l.review.versionMetadataBeforeNamesReservation(held); err != nil {
			return err
		}
		expired, stop := context.WithCancel(held)
		stop()
		if l.review.versionMetadataCurrent(expired) == nil || l.review.versionMetadataBeforeNamesReservation(expired) == nil {
			return errors.New("canceled metadata traversal accepted")
		}
		return l.review.versionMetadataCurrent(held)
	})
	if err != nil {
		t.Fatal("actual metadata/cancel parity", nativeStages(err))
	}
	t.Logf("actual metadata projection nodes=%d images=%d extensions=%d negative_paths=%d; original ReadDir257 and complete metadata passes retained", len(l.review.nodes), len(l.review.images), len(l.review.extensions), len(l.review.absent))
	bytes, largest := versionNamesImageBudget(t, l.review)
	t.Logf("actual acquired tool inventory held_images=%d held_image_bytes=%d largest_image_bytes=%d two_pass_payload_bytes=%d static_inventory_budget=true executed_read_count=false process_rss=false", len(l.review.images), bytes, largest, 2*bytes)
}

// This is only the immutable acquisition inventory's payload size. It does not
// observe files, grant freshness, count executed reads or bound process RSS.
// Call only after the original observation has completed its closing checks.
func versionNamesImageBudget(tb testing.TB, review *heldReview) (bytes, largest int64) {
	tb.Helper()
	if review == nil || len(review.images) == 0 {
		tb.Fatal("missing acquired image inventory")
	}
	for _, image := range review.images {
		if image == nil || image.info == nil || image.info.Size() <= 0 {
			tb.Fatal("invalid acquired image size")
		}
		size := image.info.Size()
		if size > math.MaxInt64/2-bytes {
			tb.Fatal("two-pass image budget overflow")
		}
		bytes += size
		largest = max(largest, size)
	}
	if bytes != review.bytes {
		tb.Fatal("acquired image sum differs from original review bytes")
	}
	return bytes, largest
}

func BenchmarkVersionMetadataNamesCandidate(b *testing.B) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	l := versionNamesActualLease(b, ctx)
	for _, sample := range []struct {
		name string
		read func(context.Context) error
	}{{"before_append", l.review.versionMetadataBeforeNamesReservation}, {"reserved_candidate", l.review.versionMetadataCurrent}} {
		b.Run(sample.name, func(b *testing.B) {
			// Enter the original source/provider interval on this subbenchmark's own
			// goroutine. No namespace observation is borrowed across a spawned worker.
			err := l.WithReadOnlyToolObservation(ctx, l.identity, l.digest, func(held context.Context) error {
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					if err := sample.read(held); err != nil {
						b.StopTimer()
						return err
					}
				}
				b.StopTimer()
				return nil
			})
			if err != nil {
				b.Fatal("actual complete source traversal", nativeStages(err))
			}
			b.ReportMetric(float64(len(l.review.extensions)), "extensions/op")
			b.ReportMetric(float64(len(l.review.nodes)), "nodes/op")
			bytes, largest := versionNamesImageBudget(b, l.review)
			// Static inventory metrics, deliberately not bytes/op: the measured
			// loop is metadata-only inside one original full-byte bracket.
			b.ReportMetric(float64(len(l.review.images)), "held_images")
			b.ReportMetric(float64(bytes), "held_image_bytes")
			b.ReportMetric(float64(largest), "largest_image_bytes")
			b.ReportMetric(float64(2*bytes), "two_pass_payload_bytes")
		})
	}
}
