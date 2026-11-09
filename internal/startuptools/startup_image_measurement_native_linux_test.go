//go:build linux && amd64 && razvilka_native_fixture

package startuptools

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Measurement only: private immutable bytes live inside one actual original
// observation callback. This is not a production lifetime/ownership design.
//
//go:embed review_linux.go
var startupImageProductionSource string

//go:embed startup_image_measurement_native_linux_test.go
var startupImageMeasurementSource string

type startupImageEntry struct {
	image   *heldImage
	file    *os.File
	info    os.FileInfo
	path    string
	digest  [32]byte
	data    []byte
	started bool
}

type startupImageMeasurement struct {
	review               *heldReview
	context              context.Context
	entries              map[*heldImage]*startupImageEntry
	paths                map[string]*heldImage
	retained             int64
	readBytes, readCalls int64
	capturing            bool
}

func newStartupImageMeasurement(ctx context.Context, r *heldReview) (*startupImageMeasurement, error) {
	if ctx == nil || ctx.Err() != nil || r == nil || len(r.images) == 0 || len(r.images) > maxImages || r.bytes <= 0 || r.bytes > maxReviewBytes {
		return nil, errors.New("image measurement input")
	}
	s := &startupImageMeasurement{review: r, context: ctx, entries: map[*heldImage]*startupImageEntry{}, paths: map[string]*heldImage{}, capturing: true}
	for path, image := range r.images {
		if image == nil || image.file == nil || image.info == nil || path != image.path || image.info.Size() <= 0 || image.info.Size() > maxImageBytes || s.entries[image] != nil {
			return nil, errors.New("image measurement inventory")
		}
		s.retained += image.info.Size()
		if s.retained > maxReviewBytes {
			return nil, errors.New("image measurement budget")
		}
		s.entries[image] = &startupImageEntry{image: image, file: image.file, info: image.info, path: image.path, digest: image.hash}
		s.paths[path] = image
	}
	if s.retained != r.bytes {
		return nil, errors.New("image measurement aggregate")
	}
	return s, nil
}

func (s *startupImageMeasurement) clear() {
	for _, entry := range s.entries {
		clear(entry.data)
		entry.data = nil
	}
	s.entries = nil
	s.paths = nil
	s.context = nil
}

func (s *startupImageMeasurement) bound(ctx context.Context) error {
	if ctx == nil {
		return errors.New("image measurement context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil || ctx != s.context || s.entries == nil || s.review.bytes != s.retained || len(s.review.images) != len(s.paths) {
		return errors.New("image measurement source")
	}
	for path, image := range s.paths {
		if s.review.images[path] != image {
			return errors.New("image measurement graph")
		}
	}
	return nil
}

func (s *startupImageMeasurement) current(ctx context.Context) error {
	if err := s.bound(ctx); err != nil {
		return err
	}
	err := s.review.unchangedImageMeasurement(ctx, s.read)
	return errors.Join(err, s.bound(ctx))
}

func (s *startupImageMeasurement) read(ctx context.Context, image *heldImage, size int64) ([32]byte, error) {
	var zero [32]byte
	if ctx == nil {
		return zero, errors.New("image measurement context")
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if s == nil || ctx != s.context || s.entries == nil {
		return zero, errors.New("image measurement source")
	}
	e := s.entries[image]
	if e == nil || e.image != image || e.file != image.file || e.info != image.info || e.path != image.path || e.digest != image.hash || size != e.info.Size() {
		return zero, errors.New("image measurement binding")
	}
	if s.capturing {
		if e.started {
			return zero, errors.New("duplicate image capture")
		}
		e.started = true
		if e.data == nil {
			e.data = make([]byte, size)
		}
		if int64(len(e.data)) != size {
			return zero, errors.New("image measurement storage")
		}
	} else if int64(len(e.data)) != size {
		return zero, errors.New("image measurement missing bytes")
	}
	h := sha256.New()
	buffer := imageHashBuffers.Get().(*[32 << 10]byte)
	defer imageHashBuffers.Put(buffer)
	equal := true
	for off := int64(0); off < size; {
		if err := ctx.Err(); err != nil {
			return zero, at("HASH_CONTEXT", err)
		}
		want := int(min(int64(len(buffer)), size-off))
		n, err := image.file.ReadAt(buffer[:want], off)
		s.readCalls++
		s.readBytes += int64(n)
		if n != want || err != nil {
			return zero, at("HASH_READ", err)
		}
		if s.capturing {
			copy(e.data[off:off+int64(n)], buffer[:n])
			_, _ = h.Write(buffer[:n])
		} else if !bytes.Equal(e.data[off:off+int64(n)], buffer[:n]) {
			equal = false
		}
		off += int64(n)
	}
	var tail [1]byte
	n, err := image.file.ReadAt(tail[:], size)
	s.readCalls++
	s.readBytes += int64(n)
	if n != 0 || !errors.Is(err, io.EOF) {
		return zero, at("HASH_SIZE_CHANGED", err)
	}
	if s.capturing {
		var got [32]byte
		copy(got[:], h.Sum(nil))
		if got != e.digest {
			return zero, errors.New("image measurement SHA")
		}
	} else if !equal {
		return zero, errors.New("image measurement bytes changed")
	}
	return e.digest, ctx.Err()
}

func (r *heldReview) unchangedImageMeasurement(ctx context.Context, read func(context.Context, *heldImage, int64) ([32]byte, error)) error {
	if err := r.pathsCurrent(ctx); err != nil {
		return err
	}
	for _, image := range r.images {
		before, err := image.file.Stat()
		path, pathErr := os.Lstat(image.path)
		if err != nil || pathErr != nil || !sameNode(image.info, before) || !sameNode(before, path) {
			return at("CHECK_HELD_FILE", errors.Join(err, pathErr))
		}
		hash, err := read(ctx, image, before.Size())
		after, afterErr := image.file.Stat()
		path, pathErr = os.Lstat(image.path)
		if err != nil || afterErr != nil || pathErr != nil || !sameNode(before, after) || !sameNode(after, path) || hash != image.hash {
			return at("CHECK_BYTES", errors.Join(err, afterErr, pathErr))
		}
	}
	canonical, err := r.resolveExisting(r.profile.extension)
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

func TestStartupImageMeasurementSourceParity(t *testing.T) {
	production := strings.ReplaceAll(startupImageProductionSource, "\r\n", "\n")
	candidate := strings.ReplaceAll(startupImageMeasurementSource, "\r\n", "\n")
	begin := strings.Index(production, "func (r *heldReview) unchanged(")
	end := strings.Index(production, "\nfunc (r *heldReview) pathsCurrent(")
	if begin < 0 || end < begin {
		t.Fatal("original unchanged body absent")
	}
	expected := production[begin:end]
	expected = strings.Replace(expected, "unchanged(ctx context.Context)", "unchangedImageMeasurement(ctx context.Context, read func(context.Context, *heldImage, int64) ([32]byte, error))", 1)
	expected = strings.Replace(expected, "hashImage(ctx, image.file, before.Size())", "read(ctx, image, before.Size())", 1)
	begin = strings.Index(candidate, "func (r *heldReview) unchangedImageMeasurement(")
	if begin < 0 {
		t.Fatal("candidate body absent")
	}
	end = strings.Index(candidate[begin:], "\nfunc TestStartupImageMeasurementSourceParity(")
	if end < 0 || strings.TrimSpace(candidate[begin:begin+end]) != strings.TrimSpace(expected) {
		t.Fatal("candidate changed source/metadata/EOF ordering beyond read helper")
	}
}

func TestStartupImageMeasurementActualParity(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	l := versionNamesActualLease(t, ctx)
	err := l.WithReadOnlyToolObservation(ctx, l.identity, l.digest, func(held context.Context) error {
		s, err := newStartupImageMeasurement(held, l.review)
		if err != nil {
			return err
		}
		defer s.clear()
		if err := l.review.unchanged(held); err != nil {
			return err
		}
		if err := s.current(held); err != nil {
			return err
		}
		s.capturing = false
		if err := s.current(held); err != nil {
			return err
		}
		if s.readBytes != 2*s.retained {
			return errors.New("incomplete actual full bytes")
		}
		stopped, stop := context.WithCancel(held)
		stop()
		if l.review.unchanged(stopped) == nil || s.current(stopped) == nil {
			return errors.New("canceled source accepted")
		}
		t.Logf("actual startup image snapshot images=%d retained_bytes=%d capture_plus_repeat_bytes=%d logical_ReadAt=%d; source closing remains outside callback; not RSS or production lifetime proof", len(s.entries), s.retained, s.readBytes, s.readCalls)
		return l.review.unchanged(held)
	})
	if err != nil {
		t.Fatal("actual full image parity", nativeStages(err))
	}
}

func BenchmarkStartupImageMeasurement(b *testing.B) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	l := versionNamesActualLease(b, ctx)
	for _, mode := range []string{"original_sha", "capture_sha_clear", "repeat_full_bytes"} {
		b.Run(mode, func(b *testing.B) {
			err := l.WithReadOnlyToolObservation(ctx, l.identity, l.digest, func(held context.Context) error {
				var retained *startupImageMeasurement
				if mode == "repeat_full_bytes" {
					var err error
					retained, err = newStartupImageMeasurement(held, l.review)
					if err != nil {
						return err
					}
					defer retained.clear()
					if err := retained.current(held); err != nil {
						return err
					}
					retained.capturing = false
				}
				b.ReportAllocs()
				b.SetBytes(l.review.bytes)
				b.ResetTimer()
				for range b.N {
					var err error
					switch mode {
					case "original_sha":
						err = l.review.unchanged(held)
					case "capture_sha_clear":
						var captured *startupImageMeasurement
						captured, err = newStartupImageMeasurement(held, l.review)
						if err == nil {
							err = captured.current(held)
							captured.clear()
						}
					case "repeat_full_bytes":
						err = retained.current(held)
					}
					if err != nil {
						b.StopTimer()
						return err
					}
				}
				b.StopTimer()
				return nil
			})
			if err != nil {
				b.Fatal("actual held source image measurement", nativeStages(err))
			}
			b.ReportMetric(float64(l.review.bytes), "payload_bytes/op")
			if mode != "original_sha" {
				b.ReportMetric(float64(l.review.bytes), "private_live_bytes")
			}
			b.ReportMetric(float64(len(l.review.images)), "images/op")
		})
	}
}

// This local model tests source and byte refusals; it cannot mint a public Lease.
func startupImageLocalFixture(t *testing.T) (*heldReview, *heldImage) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("protected metadata model requires root")
	}
	root := t.TempDir()
	path := filepath.Join(root, "image")
	raw := bytes.Repeat([]byte{0x63}, 3*(32<<10)+19)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	image := &heldImage{path: path, file: f, info: info, hash: sha256.Sum256(raw)}
	r := &heldReview{profile: profile{extension: root}, images: map[string]*heldImage{path: image}, nodes: map[string]heldNode{root: {path: root, info: dir}, path: {path: path, info: info}}, absent: map[string]bool{filepath.Join(root, "missing"): true}, extensions: []string{"image"}, bytes: info.Size()}
	return r, image
}

func TestStartupImageMeasurementRefusals(t *testing.T) {
	for _, mode := range []string{"same_size_mtime", "truncate", "append", "replacement", "digest", "graph", "extension", "negative_path", "canceled", "closed_fd"} {
		t.Run(mode, func(t *testing.T) {
			r, image := startupImageLocalFixture(t)
			ctx := t.Context()
			s, err := newStartupImageMeasurement(ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			defer s.clear()
			if err := s.current(ctx); err != nil {
				t.Fatal(err)
			}
			s.capturing = false
			switch mode {
			case "same_size_mtime":
				f, err := os.OpenFile(image.path, os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				_, err = f.WriteAt([]byte{0x64}, 0)
				closeErr := f.Close()
				if err != nil || closeErr != nil {
					t.Fatal(errors.Join(err, closeErr))
				}
				if err := os.Chtimes(image.path, image.info.ModTime(), image.info.ModTime()); err != nil {
					t.Fatal(err)
				}
				before := s.readBytes
				if _, err := s.read(ctx, image, image.info.Size()); err == nil || s.readBytes-before != image.info.Size() {
					t.Fatal("mismatch skipped complete fresh bytes")
				}
			case "truncate":
				if err := os.Truncate(image.path, 17); err != nil {
					t.Fatal(err)
				}
			case "append":
				if err := os.Truncate(image.path, image.info.Size()+1); err != nil {
					t.Fatal(err)
				}
			case "replacement":
				if err := os.Rename(image.path, image.path+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(image.path, []byte("new"), 0600); err != nil {
					t.Fatal(err)
				}
			case "digest":
				image.hash[0] ^= 1
			case "graph":
				copy := *image
				r.images[image.path] = &copy
			case "extension":
				if err := os.WriteFile(filepath.Join(filepath.Dir(image.path), "extra"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "negative_path":
				if err := os.WriteFile(filepath.Join(filepath.Dir(image.path), "missing"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "closed_fd":
				if err := image.file.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if s.current(ctx) == nil {
				t.Fatal("changed source accepted", mode)
			}
			if mode != "graph" && r.unchanged(ctx) == nil {
				t.Fatal("original unexpectedly accepts changed source", mode)
			}
		})
	}
}

// A deterministic cancellation trigger uses real reads, without replacing the FD.
type startupImageCancelTick struct {
	context.Context
	calls, stop int
}

func (c *startupImageCancelTick) Err() error {
	c.calls++
	if c.stop > 0 && c.calls >= c.stop {
		return context.Canceled
	}
	return c.Context.Err()
}

func TestStartupImageMeasurementReadBoundaries(t *testing.T) {
	for _, mode := range []string{"short_read", "tail_growth", "late_cancel", "wrong_capture_sha", "revoked"} {
		t.Run(mode, func(t *testing.T) {
			r, image := startupImageLocalFixture(t)
			ctx := &startupImageCancelTick{Context: t.Context()}
			s, err := newStartupImageMeasurement(ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			defer s.clear()
			if mode == "wrong_capture_sha" {
				image.hash[0] ^= 1
				s.entries[image].digest = image.hash
				got, err := s.read(ctx, image, image.info.Size())
				if err == nil || got != ([32]byte{}) || s.readBytes != image.info.Size() {
					t.Fatal("unauthenticated capture accepted or skipped full bytes")
				}
				return
			}
			if err := s.current(ctx); err != nil {
				t.Fatal(err)
			}
			s.capturing = false
			before := s.readBytes
			switch mode {
			case "short_read":
				if err := os.Truncate(image.path, 32<<10); err != nil {
					t.Fatal(err)
				}
			case "tail_growth":
				if err := os.Truncate(image.path, image.info.Size()+1); err != nil {
					t.Fatal(err)
				}
			case "late_cancel":
				ctx.stop = ctx.calls + 4
			case "revoked":
				s.clear()
			}
			got, err := s.read(ctx, image, image.info.Size())
			if err == nil || got != ([32]byte{}) {
				t.Fatal("read failure returned accepted digest")
			}
			if mode == "late_cancel" && (!errors.Is(err, context.Canceled) || s.readBytes <= before || s.readBytes-before >= image.info.Size()) {
				t.Fatal("cancellation did not follow partial actual read")
			}
			if mode == "tail_growth" && s.readBytes-before != image.info.Size()+1 {
				t.Fatal("actual EOF growth not observed")
			}
		})
	}
}

// This local test model is not shared by production. First successful capacity
// is fixed, at most8MiB; all later oversize/contention attempts use original SHA.
const startupImageSlotMeasurementCap = 8 << 20

type startupImageSlotMeasurement struct {
	active atomic.Bool
	self   *startupImageSlotMeasurement
	data   []byte
}
type startupImageSlotBorrow struct {
	self   *startupImageSlotBorrow
	slot   *startupImageSlotMeasurement
	closed atomic.Bool
}

func (s *startupImageSlotMeasurement) borrow(size int64) *startupImageSlotBorrow {
	if s == nil || size <= 0 || size > startupImageSlotMeasurementCap || !s.active.CompareAndSwap(false, true) {
		return nil
	}
	if s.self == nil {
		s.self = s
	}
	if s.self != s {
		s.active.Store(false)
		return nil
	}
	if s.data == nil {
		s.data = make([]byte, size)
	}
	if int64(len(s.data)) < size {
		s.active.Store(false)
		return nil
	}
	b := &startupImageSlotBorrow{slot: s}
	b.self = b
	return b
}
func (b *startupImageSlotBorrow) release() {
	if b == nil || b.self != b || b.slot == nil || !b.closed.CompareAndSwap(false, true) {
		return
	}
	clear(b.slot.data)
	b.slot.active.Store(false)
}

func startupImagePairMeasurement(ctx context.Context, r *heldReview, slot *startupImageSlotMeasurement) (used bool, result error) {
	// Decline before attempting snapshot capture. The original two complete
	// checks retain original short circuit order if no fixed storage is available.
	if r == nil || ctx == nil {
		return false, errors.New("pair review/context missing")
	}
	borrow := slot.borrow(r.bytes)
	if borrow == nil {
		if err := r.unchanged(ctx); err != nil {
			return false, err
		}
		return false, r.unchanged(ctx)
	}
	var snapshot *startupImageMeasurement
	defer func() {
		// Revoke every local image reference before clearing and releasing storage.
		if snapshot != nil {
			snapshot.entries = nil
			snapshot.paths = nil
			snapshot.context = nil
		}
		borrow.release()
		result = errors.Join(result, ctx.Err())
		if deadline, finite := ctx.Deadline(); finite && !time.Now().Before(deadline) {
			result = errors.Join(result, context.DeadlineExceeded)
		}
	}()
	var err error
	snapshot, err = newStartupImageMeasurement(ctx, r)
	if err != nil {
		return true, err
	}
	var offset int64
	for _, entry := range snapshot.entries {
		size := entry.info.Size()
		entry.data = borrow.slot.data[offset : offset+size]
		offset += size
	}
	if offset != r.bytes {
		return true, errors.New("pair byte budget")
	}
	if err := snapshot.current(ctx); err != nil {
		return true, err
	}
	snapshot.capturing = false
	return true, snapshot.current(ctx)
}

func BenchmarkStartupImagePairMeasurement(b *testing.B) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	l := versionNamesActualLease(b, ctx)
	if l.review.bytes > startupImageSlotMeasurementCap {
		b.Fatal("actual fixture exceeds model8MiB; do not mislabel fallback as snapshot")
	}
	for _, mode := range []string{"original_two_sha", "first_slot_pair_clear", "warm_slot_pair_clear"} {
		b.Run(mode, func(b *testing.B) {
			err := l.WithReadOnlyToolObservation(ctx, l.identity, l.digest, func(held context.Context) error {
				var warm startupImageSlotMeasurement
				if mode == "warm_slot_pair_clear" {
					initial := warm.borrow(l.review.bytes)
					if initial == nil {
						return errors.New("warm model unavailable")
					}
					initial.release()
				}
				b.ReportAllocs()
				b.SetBytes(2 * l.review.bytes)
				b.ResetTimer()
				for range b.N {
					var err error
					if mode == "original_two_sha" {
						err = l.review.unchanged(held)
						if err == nil {
							err = l.review.unchanged(held)
						}
					} else {
						var used bool
						if mode == "first_slot_pair_clear" {
							var first startupImageSlotMeasurement
							used, err = startupImagePairMeasurement(held, l.review, &first)
						} else {
							used, err = startupImagePairMeasurement(held, l.review, &warm)
						}
						if err == nil && !used {
							err = errors.New("snapshot benchmark silently fell back")
						}
					}
					if err != nil {
						b.StopTimer()
						return err
					}
				}
				b.StopTimer()
				return nil
			})
			if err != nil {
				b.Fatal("actual full source pair", nativeStages(err))
			}
			b.ReportMetric(float64(2*l.review.bytes), "payload_bytes/op")
			if mode != "original_two_sha" {
				b.ReportMetric(float64(l.review.bytes), "fixed_capacity_bytes")
			}
			b.ReportMetric(float64(len(l.review.images)), "images/op")
		})
	}
}

func TestStartupImageMeasurementFixedSlot(t *testing.T) {
	var slot startupImageSlotMeasurement
	if slot.borrow(startupImageSlotMeasurementCap+1) != nil || slot.data != nil {
		t.Fatal("oversize allocated")
	}
	first := slot.borrow(17)
	if first == nil {
		t.Fatal("first slot")
	}
	copyLease := startupImageSlotBorrow{self: first.self, slot: first.slot}
	copyLease.closed.Store(first.closed.Load())
	copyLease.release()
	if !slot.active.Load() {
		t.Fatal("copied lease released original")
	}
	slot.data[0] = 9
	if slot.borrow(17) != nil || slot.data[0] != 9 {
		t.Fatal("contention disturbed owner")
	}
	first.release()
	if slot.data[0] != 0 || slot.active.Load() {
		t.Fatal("slot not cleared")
	}
	if slot.borrow(18) != nil || len(slot.data) != 17 {
		t.Fatal("fixed capacity grew")
	}
	next := slot.borrow(17)
	if next == nil {
		t.Fatal("successor borrow")
	}
	slot.data[0] = 7
	first.release()
	copyLease.release()
	if slot.data[0] != 7 || !slot.active.Load() {
		t.Fatal("stale release disturbed successor")
	}
	next.release()
	copySlot := startupImageSlotMeasurement{self: slot.self, data: slot.data}
	copySlot.active.Store(slot.active.Load())
	if copySlot.borrow(17) != nil {
		t.Fatal("copied storage accepted")
	}
}

func TestStartupImageMeasurementConcurrentSlot(t *testing.T) {
	var slot startupImageSlotMeasurement
	var winners atomic.Int32
	start := make(chan struct{})
	release := make(chan struct{})
	ready := make(chan struct{}, 16)
	var joined sync.WaitGroup
	for range 16 {
		joined.Add(1)
		go func() {
			defer joined.Done()
			<-start
			b := slot.borrow(128)
			if b != nil {
				winners.Add(1)
				slot.data[0] = 73
			}
			ready <- struct{}{}
			if b != nil {
				<-release
				b.release()
			}
		}()
	}
	close(start)
	for range 16 {
		<-ready
	}
	if winners.Load() != 1 {
		close(release)
		joined.Wait()
		t.Fatal("exclusive slot", winners.Load())
	}
	close(release)
	joined.Wait()
	if slot.active.Load() || !bytes.Equal(slot.data, make([]byte, 128)) {
		t.Fatal("slot not joined/cleared")
	}
}

func TestStartupImageMeasurementPairStorageAndFallback(t *testing.T) {
	r, image := startupImageLocalFixture(t)
	ctx := t.Context()
	var slot startupImageSlotMeasurement
	used, err := startupImagePairMeasurement(ctx, r, &slot)
	if err != nil || !used || slot.active.Load() || !bytes.Equal(slot.data, make([]byte, len(slot.data))) {
		t.Fatal("actual full pair clear", err)
	}
	var tiny startupImageSlotMeasurement
	initial := tiny.borrow(1)
	initial.release()
	used, err = startupImagePairMeasurement(ctx, r, &tiny)
	if err != nil || used || len(tiny.data) != 1 {
		t.Fatal("capacity fallback not original pair", err)
	}
	held := slot.borrow(r.bytes)
	slot.data[0] = 77
	used, err = startupImagePairMeasurement(ctx, r, &slot)
	if err != nil || used || slot.data[0] != 77 || !slot.active.Load() {
		t.Fatal("busy fallback changed owner", err)
	}
	held.release()
	// Attempted authentication failure never falls back to a successful path.
	image.hash[0] ^= 1
	used, err = startupImagePairMeasurement(ctx, r, &slot)
	if err == nil || !used || slot.active.Load() || !bytes.Equal(slot.data, make([]byte, len(slot.data))) {
		t.Fatal("failed capture not cleared/refused")
	}
}

type startupImagePairFaultContext struct {
	context.Context
	check   func() error
	expired bool
}

func (c *startupImagePairFaultContext) Err() error {
	if c.check != nil {
		return c.check()
	}
	return c.Context.Err()
}
func (c *startupImagePairFaultContext) Deadline() (time.Time, bool) {
	if c.expired {
		return time.Now().Add(-time.Second), true
	}
	return c.Context.Deadline()
}

func TestStartupImageMeasurementPairFailureCleanup(t *testing.T) {
	for _, mode := range []string{"late_cancel", "panic", "post_clear_cancel", "absolute_deadline"} {
		t.Run(mode, func(t *testing.T) {
			r, _ := startupImageLocalFixture(t)
			var slot startupImageSlotMeasurement
			ctx := &startupImagePairFaultContext{Context: t.Context(), expired: mode == "absolute_deadline"}
			observedBytes := false
			ctx.check = func() error {
				if bytes.IndexByte(slot.data, 0x63) >= 0 {
					observedBytes = true
					if mode == "late_cancel" {
						return context.Canceled
					}
					if mode == "panic" {
						panic("actual capture partial-read panic")
					}
				}
				if mode == "post_clear_cancel" && observedBytes && !slot.active.Load() {
					return context.Canceled
				}
				return nil
			}
			var used bool
			var err error
			var panicked any
			func() {
				defer func() { panicked = recover() }()
				used, err = startupImagePairMeasurement(ctx, r, &slot)
			}()
			if slot.active.Load() || !bytes.Equal(slot.data, make([]byte, len(slot.data))) {
				t.Fatal("pair failed to clear/release")
			}
			if !observedBytes {
				t.Fatal("fault preceded actual capture bytes")
			}
			if mode == "panic" {
				if panicked == nil {
					t.Fatal("panic swallowed")
				}
				return
			}
			if panicked != nil || !used || err == nil {
				t.Fatal("pair failure lost", panicked, err)
			}
			expected := error(context.Canceled)
			if mode == "absolute_deadline" {
				expected = context.DeadlineExceeded
			}
			if !errors.Is(err, expected) {
				t.Fatal("pair failure cause", err)
			}
		})
	}
}
