package updatecheck

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
	"unsafe"
)

type ordinaryCountedImageReader struct {
	source io.Reader
	bytes  int
}

func (r *ordinaryCountedImageReader) Read(p []byte) (int, error) {
	n, err := r.source.Read(p)
	r.bytes += n
	return n, err
}

func ordinaryImageOwner(t *testing.T, ctx context.Context, data []byte) *ordinaryExecutableImage {
	t.Helper()
	r, err := newOrdinaryExecutableImage(ctx, digestBytes(data))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.clear)
	return r
}

func ordinaryImageBytes(size int) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i*251 + i/251)
	}
	return data
}

func TestOrdinaryImageFullyReadsEveryOriginalOccurrenceAndClears(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	data := ordinaryImageBytes(2*ordinaryImageChunk + 17)
	r := ordinaryImageOwner(t, ctx, data)
	deadline, _ := ctx.Deadline()
	if !r.deadline.Equal(deadline) || ordinaryImageRetainLimit+int(unsafe.Sizeof(*r)) > 64<<20 {
		t.Fatal("original deadline or explicit per-call image memory bound changed")
	}
	for i := 0; i < 20; i++ {
		actual := &ordinaryCountedImageReader{source: bytes.NewReader(data)}
		digest, err := r.verify(actual, int64(len(data)))
		if err != nil || digest != digestBytes(data) || actual.bytes != len(data) {
			t.Fatal("an executable occurrence skipped actual full bytes", i, actual.bytes, err)
		}
	}
	owned := r.image
	r.clear()
	if r.image != nil || r.original != nil || !bytes.Equal(owned, make([]byte, len(owned))) || !bytes.Equal(r.work[:], make([]byte, len(r.work))) {
		t.Fatal("per-call original image/work bytes survived release")
	}
	if _, err := r.verify(bytes.NewReader(data), int64(len(data))); err == nil {
		t.Fatal("released image enabled a later read")
	}
}

func TestOrdinaryImageDetectsChangedPhysicalBytesWithSameInodeSizeAndMtime(t *testing.T) {
	for _, offset := range []int64{0, ordinaryImageChunk, 2*ordinaryImageChunk + 16} {
		t.Run(bootstrapDecimal(uint64(offset)), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			data := ordinaryImageBytes(2*ordinaryImageChunk + 17)
			path := filepath.Join(t.TempDir(), "actual-image")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			before, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			r := ordinaryImageOwner(t, ctx, data)
			read := func() (int, error) {
				f, err := os.Open(path)
				if err != nil {
					return 0, err
				}
				defer f.Close()
				actual := &ordinaryCountedImageReader{source: f}
				_, err = r.verify(actual, before.Size())
				return actual.bytes, err
			}
			if _, err := read(); err != nil {
				t.Fatal(err)
			}
			owned := r.image
			f, err := os.OpenFile(path, os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			_, writeErr := f.WriteAt([]byte{data[offset] ^ 0xff}, offset)
			closeErr := f.Close()
			if writeErr != nil || closeErr != nil || os.Chtimes(path, before.ModTime(), before.ModTime()) != nil {
				t.Fatal("actual same-inode mutation could not be prepared")
			}
			after, err := os.Stat(path)
			if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
				t.Fatal("mutation changed inode/size/mtime instead of only contents")
			}
			count, err := read()
			if !errors.Is(err, ErrFileProtocol) || count != len(data) || !r.closed || !bytes.Equal(owned, make([]byte, len(owned))) {
				t.Fatal("same-metadata changed bytes passed or actual read/image cleanup was incomplete", count)
			}
		})
	}
}

type ordinaryImageFaultReader struct{ cause error }

func (r ordinaryImageFaultReader) Read([]byte) (int, error) { return 0, r.cause }

type ordinaryImageBoundaryReader struct {
	source io.Reader
	after  func()
}

func (r ordinaryImageBoundaryReader) Read(p []byte) (int, error) {
	n, err := r.source.Read(p)
	r.after()
	return n, err
}

func TestOrdinaryImageRefusesCopyNilFaultCancellationAndDeadline(t *testing.T) {
	data := ordinaryImageBytes(257)
	for _, kind := range []string{"copy", "nil", "fault", "cancel", "deadline"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			if kind == "deadline" {
				ctx, cancel = context.WithTimeout(context.Background(), 30*time.Millisecond)
				defer cancel()
			}
			r := ordinaryImageOwner(t, ctx, data)
			if _, err := r.verify(bytes.NewReader(data), int64(len(data))); err != nil {
				t.Fatal(err)
			}
			owned := r.image
			actual := &ordinaryCountedImageReader{source: bytes.NewReader(data)}
			var source io.Reader = actual
			var want error = ErrFileProtocol
			switch kind {
			case "copy":
				copy := *r
				if _, err := copy.verify(actual, int64(len(data))); err == nil || actual.bytes != 0 || r.closed {
					t.Fatal("copied byte witness read or invalidated the original owner")
				}
				return
			case "nil":
				source = nil
			case "fault":
				want = errors.New("original read failure")
				source = ordinaryImageFaultReader{want}
			case "cancel":
				want = context.Canceled
				source = ordinaryImageBoundaryReader{actual, cancel}
			case "deadline":
				want = context.DeadlineExceeded
				source = ordinaryImageBoundaryReader{actual, func() { <-ctx.Done() }}
			}
			if _, err := r.verify(source, int64(len(data))); !errors.Is(err, want) || !r.closed || !bytes.Equal(owned, make([]byte, len(owned))) {
				t.Fatal("read boundary supplied a grant or lost original failure/image cleanup")
			}
		})
	}
	for _, ctx := range []context.Context{nil, context.Background()} {
		if r, err := newOrdinaryExecutableImage(ctx, digestBytes(data)); r != nil || err == nil {
			t.Fatal("unbounded context created an original image owner")
		}
	}
}

type ordinaryZeroImageReader struct{ bytes int64 }

func (r *ordinaryZeroImageReader) Read(p []byte) (int, error) {
	clear(p)
	r.bytes += int64(len(p))
	return len(p), nil
}

func TestOrdinaryImageOversizeUsesBoundedOriginalStreamingSHA(t *testing.T) {
	size := int64(ordinaryImageRetainLimit) + 1
	if size > MaximumBinaryBytes {
		t.Skip("existing binary limit is smaller than retained-image limit")
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(&ordinaryZeroImageReader{}, size)); err != nil {
		t.Fatal(err)
	}
	digest := hex.EncodeToString(h.Sum(nil))
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	r, err := newOrdinaryExecutableImage(ctx, digest)
	if err != nil {
		t.Fatal(err)
	}
	defer r.clear()
	for i := 0; i < 2; i++ {
		actual := &ordinaryZeroImageReader{}
		if got, err := r.verify(io.LimitReader(actual, size), size); err != nil || got != digest || actual.bytes != size || r.image != nil {
			t.Fatal("large image allocated retained bytes or skipped original full streaming SHA", actual.bytes, err)
		}
	}
}
