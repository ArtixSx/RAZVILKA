//go:build linux && (amd64 || arm64)

package startuptools

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"reflect"
	"sync/atomic"
)

// The pinned Linux tool graph is 8,918,408 bytes. A 10MiB ceiling admits that
// graph with one actual-size allocation; it is not a router RSS guarantee.
const toolObservationImageLimit = 10 << 20

// One fixed-capacity process-wide storage slot, not a source observation.
// Never wait, resize or allocate a second backing array. Oversize and busy
// observations retain their original independent full-SHA checks.
type toolObservationImageScratch struct {
	busy atomic.Bool
	data []byte
}

var toolObservationScratch toolObservationImageScratch

type toolObservationImageEntry struct {
	image *heldImage
	file  *os.File
	info  os.FileInfo
	path  string
	hash  [32]byte
	data  []byte
	read  bool
}

// This value never leaves the original method's stack through a callback or
// context. Each outer observation authenticates its OWN opening bytes; only
// its closing calculation uses equality with those same bytes.
type toolObservationImage struct {
	self    *toolObservationImage
	ctx     context.Context
	review  *heldReview
	scratch *toolObservationImageScratch
	entries map[*heldImage]*toolObservationImageEntry
	paths   map[string]*heldImage
	bytes   int64
	phase   uint8 // 0=opening, 1=closing, 2=consumed/revoked
	reading bool
}

func borrowToolObservationImage(ctx context.Context, r *heldReview, slot *toolObservationImageScratch) (*toolObservationImage, error) {
	if ctx == nil {
		return nil, at("READ_OBSERVATION_SCOPE", nil)
	}
	if !reflect.TypeOf(ctx).Comparable() {
		return nil, nil // Optional storage cannot narrow the original context ABI.
	}
	if err := ctx.Err(); err != nil {
		return nil, at("READ_OBSERVATION_SCOPE", err)
	}
	if r == nil || slot == nil || r.bytes <= 0 || r.bytes > toolObservationImageLimit {
		return nil, nil
	}
	if len(r.images) == 0 || len(r.images) > maxImages {
		return nil, at("READ_OBSERVATION_SCOPE", nil)
	}
	var total int64
	seen := make(map[*heldImage]bool, len(r.images))
	for path, image := range r.images {
		if image == nil || image.file == nil || image.info == nil || image.path != path || seen[image] || image.info.Size() <= 0 || image.info.Size() > maxImageBytes {
			return nil, at("READ_OBSERVATION_SCOPE", nil)
		}
		seen[image] = true
		total += image.info.Size()
		if total > toolObservationImageLimit {
			return nil, nil
		}
	}
	if total != r.bytes {
		return nil, at("READ_OBSERVATION_SCOPE", nil)
	}
	if !slot.busy.CompareAndSwap(false, true) {
		return nil, nil
	}
	keep := false
	defer func() {
		if !keep {
			clear(slot.data)
			slot.busy.Store(false)
		}
	}()
	if slot.data == nil {
		slot.data = make([]byte, total)
	}
	if int64(len(slot.data)) < total {
		return nil, nil
	}
	s := &toolObservationImage{ctx: ctx, review: r, scratch: slot, entries: make(map[*heldImage]*toolObservationImageEntry, len(r.images)), paths: make(map[string]*heldImage, len(r.images)), bytes: total}
	s.self = s
	var offset int64
	for path, image := range r.images {
		n := image.info.Size()
		s.entries[image] = &toolObservationImageEntry{image: image, file: image.file, info: image.info, path: path, hash: image.hash, data: slot.data[offset : offset+n]}
		s.paths[path] = image
		offset += n
	}
	keep = true
	return s, nil
}

func (s *toolObservationImage) release() {
	if s == nil || s.self != s || s.scratch == nil {
		return
	}
	s.phase, s.reading = 2, false
	s.entries, s.paths, s.ctx = nil, nil, nil
	clear(s.scratch.data)
	s.scratch.busy.Store(false)
	s.scratch = nil
}

func (s *toolObservationImage) local(ctx context.Context, r *heldReview) error {
	if s == nil || s.self != s || s.scratch == nil || ctx == nil || !reflect.TypeOf(ctx).Comparable() || s.ctx != ctx || ctx.Err() != nil || s.review != r || s.phase > 1 || r == nil || r.bytes != s.bytes || len(r.images) != len(s.paths) {
		return at("READ_OBSERVATION_SCOPE", nil)
	}
	return nil
}

func (s *toolObservationImage) bound(ctx context.Context, r *heldReview) error {
	if err := s.local(ctx, r); err != nil {
		return err
	}
	for path, image := range s.paths {
		if r.images[path] != image {
			return at("READ_OBSERVATION_SCOPE", nil)
		}
	}
	return nil
}

// Only observationBytesWithImage supplies held, inside its original provider
// callback. The parent remains the exact caller context, across both freshly
// derived provider contexts; no caller can borrow the private snapshot.
func (s *toolObservationImage) current(parent, held context.Context, r *heldReview) (result error) {
	if err := s.bound(parent, r); err != nil {
		return err
	}
	if held == nil || held.Err() != nil || s.reading {
		return at("READ_OBSERVATION_SCOPE", nil)
	}
	s.reading = true
	defer func() {
		s.reading = false
		if result != nil || s.phase == 1 {
			s.phase = 2
		} else {
			s.phase = 1
			for _, e := range s.entries {
				e.read = false
			}
		}
	}()
	result = r.unchangedWithImageRead(held, s)
	return errors.Join(result, s.bound(parent, r), held.Err())
}

func (s *toolObservationImage) read(ctx context.Context, image *heldImage, size int64) ([32]byte, error) {
	var zero [32]byte
	if s == nil || !s.reading || s.phase > 1 || s.local(s.ctx, s.review) != nil || ctx == nil || ctx.Err() != nil {
		return zero, at("READ_OBSERVATION_SCOPE", nil)
	}
	e := s.entries[image]
	if e == nil || e.read || e.image != image || e.file != image.file || e.info != image.info || e.path != image.path || e.hash != image.hash || size != e.info.Size() || int64(len(e.data)) != size || s.review.images[e.path] != image {
		return zero, at("READ_OBSERVATION_SCOPE", nil)
	}
	e.read = true
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
		if n != want || err != nil {
			return zero, at("HASH_READ", err)
		}
		if s.phase == 0 {
			copy(e.data[off:off+int64(n)], buffer[:n])
			_, _ = h.Write(buffer[:n])
		} else if !bytes.Equal(e.data[off:off+int64(n)], buffer[:n]) {
			equal = false // Preserve every remaining read and the EOF check.
		}
		off += int64(n)
	}
	var tail [1]byte
	if n, err := image.file.ReadAt(tail[:], size); n != 0 || !errors.Is(err, io.EOF) {
		return zero, at("HASH_SIZE_CHANGED", err)
	}
	if s.phase == 0 {
		var got [32]byte
		copy(got[:], h.Sum(nil))
		if got != e.hash {
			return zero, at("CHECK_BYTES", nil)
		}
	} else if !equal {
		return zero, at("CHECK_BYTES", nil)
	}
	return e.hash, ctx.Err()
}
