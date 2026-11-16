//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"reflect"
	"sync/atomic"
)

// Private bytes for exactly one opening/closing self-image comparison. The
// existing process-wide scratch slot is storage only: no digest or authority
// survives release. Contention, a smaller fixed slot or a large executable
// retain the original two complete SHA reads without waiting or resizing.
type mihomoColdSelfImage struct {
	self  *mihomoColdSelfImage
	ctx   context.Context
	path  string
	lease *xrayDomainTCPImageLease
	phase atomic.Uint32 // 0=new, 1=reading opening, 2=open, 3=reading closing, 4=closed
	hash  string
}

func borrowMihomoColdSelfImage(ctx context.Context, path string, scratch *xrayDomainTCPImageScratch) (*mihomoColdSelfImage, error) {
	if ctx == nil || !reflect.TypeOf(ctx).Comparable() {
		return nil, ErrMihomoProbeRetirement
	}
	if err := xraySelectedTCPFinite(ctx); err != nil {
		return nil, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	lease := scratch.borrow(info.Size())
	if lease == nil {
		return nil, nil
	}
	i := &mihomoColdSelfImage{ctx: ctx, path: path, lease: lease}
	i.self = i
	return i, nil
}

func (i *mihomoColdSelfImage) release() {
	if i != nil && i.self == i {
		i.phase.Store(4)
		i.lease.release()
	}
}

// Both passes independently open the named file, retain every original stat
// and EOF check, and read every byte in the original 256KiB chunks. Only the
// closing SHA calculation becomes equality with authenticated opening bytes.
func (i *mihomoColdSelfImage) read(ctx context.Context) (hash string, info os.FileInfo, resultErr error) {
	if i == nil || i.self != i || ctx == nil || !reflect.TypeOf(ctx).Comparable() || ctx != i.ctx || i.lease == nil || i.lease.self != i.lease || i.lease.closed.Load() {
		return "", nil, ErrMihomoProbeRetirement
	}
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	opening := i.phase.CompareAndSwap(0, 1)
	if !opening && !i.phase.CompareAndSwap(2, 3) {
		return "", nil, ErrMihomoProbeRetirement
	}
	defer func() {
		if resultErr != nil || !opening {
			i.phase.Store(4)
		}
	}()
	file, err := os.Open(i.path)
	if err != nil {
		return "", nil, err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > 128<<20 || before.Size() != int64(len(i.lease.data)) {
		return "", nil, ErrMihomoProbeRetirement
	}
	h := sha256.New()
	const readChunk = 256 << 10
	var buf []byte
	if !opening {
		buf = make([]byte, readChunk)
	}
	equal := true
	for offset := int64(0); offset < before.Size(); {
		if err := ctx.Err(); err != nil {
			return "", nil, err
		}
		want := int(min(int64(readChunk), before.Size()-offset))
		var chunk []byte
		if opening {
			// Read and authenticate the SAME bytes directly into the private
			// image. Avoid an extra scratch copy; retain read size, normal race
			// instrumentation, source checks and partial-failure admission.
			chunk = i.lease.data[offset : offset+int64(want)]
		} else {
			chunk = buf[:want]
		}
		n, err := file.ReadAt(chunk, offset)
		if n != want || err != nil {
			return "", nil, ErrMihomoProbeRetirement
		}
		if opening {
			h.Write(chunk[:n])
		} else if !bytes.Equal(i.lease.data[offset:offset+int64(n)], chunk[:n]) {
			equal = false // Retain the complete fresh read after a mismatch.
		}
		offset += int64(n)
	}
	var tail [1]byte
	if n, err := file.ReadAt(tail[:], before.Size()); n != 0 || !errors.Is(err, io.EOF) {
		return "", nil, ErrMihomoProbeRetirement
	}
	after, err := file.Stat()
	named, namedErr := os.Stat(i.path)
	if err != nil || namedErr != nil || !os.SameFile(before, after) || !os.SameFile(before, named) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || !equal {
		return "", nil, ErrMihomoProbeRetirement
	}
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	if opening {
		i.hash = hex.EncodeToString(h.Sum(nil))
		if !i.phase.CompareAndSwap(1, 2) {
			return "", nil, ErrMihomoProbeRetirement
		}
	}
	return i.hash, after, nil
}
