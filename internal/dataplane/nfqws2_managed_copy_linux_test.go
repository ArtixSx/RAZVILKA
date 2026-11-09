//go:build linux

package dataplane

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
)

var nfqwsCopyReadError = errors.New("original managed hash read error")

type nfqwsCopyWriteFailure struct{}

func (nfqwsCopyWriteFailure) Write([]byte) (int, error) {
	return 3, io.ErrClosedPipe
}

func TestNFQWSManagedCopyWriteErrorPrecedence(t *testing.T) {
	for _, pooled := range []bool{false, true} {
		r := &nfqwsCopyReader{left: 17, chunk: 32768, last: nfqwsCopyReadError}
		var n int64
		var err error
		if pooled {
			n, err = nfqws2CopyManagedFile(nfqwsCopyWriteFailure{}, r)
		} else {
			n, err = io.Copy(nfqwsCopyWriteFailure{}, r)
		}
		if n != 3 || !errors.Is(err, io.ErrClosedPipe) {
			t.Fatal("original write failure lost precedence", n, err)
		}
	}
}

type nfqwsCopyFastSource struct{ used bool }

func (*nfqwsCopyFastSource) Read([]byte) (int, error) { panic("source WriterTo lost") }
func (r *nfqwsCopyFastSource) WriteTo(w io.Writer) (int64, error) {
	r.used = true
	n, err := w.Write([]byte("source"))
	return int64(n), err
}

type nfqwsCopyFastDestination struct{ used bool }

func (*nfqwsCopyFastDestination) Write(p []byte) (int, error) { return len(p), nil }
func (w *nfqwsCopyFastDestination) ReadFrom(io.Reader) (int64, error) {
	w.used = true
	return 7, nfqwsCopyReadError
}

func TestNFQWSManagedCopyFastPaths(t *testing.T) {
	r, w := &nfqwsCopyFastSource{}, &nfqwsCopyFastDestination{}
	if n, err := nfqws2CopyManagedFile(w, r); n != 6 || err != nil || !r.used || w.used {
		t.Fatal("WriterTo precedence changed", n, err)
	}
	if n, err := nfqws2CopyManagedFile(w, &nfqwsCopyReader{}); n != 7 || !errors.Is(err, nfqwsCopyReadError) || !w.used {
		t.Fatal("ReaderFrom dispatch changed", n, err)
	}
}

type nfqwsCopyReader struct {
	left, chunk int
	reads       []int
	last        error
}

func (r *nfqwsCopyReader) Read(p []byte) (int, error) {
	r.reads = append(r.reads, len(p))
	n := min(r.left, r.chunk, len(p))
	for i := range p[:n] {
		p[i] = 'x'
	}
	r.left -= n
	if r.left == 0 {
		return n, r.last
	}
	return n, nil
}

func TestNFQWSManagedCopyParity(t *testing.T) {
	for _, tc := range []struct {
		size, chunk int
		limit       int64
		last        error
	}{
		{98317, 32768, 64 << 20, io.EOF}, {17, 5, 99, nfqwsCopyReadError},
		{0, 32768, 99, io.EOF}, {98, 32768, 7, io.EOF}, {98, 32768, 0, io.EOF},
		{98, 32768, 33, io.EOF}, {32769, 32768, 32769, io.EOF},
	} {
		t.Run(fmt.Sprintf("%d/%d/%d/%v", tc.size, tc.chunk, tc.limit, tc.last), func(t *testing.T) {
			type result struct {
				n     int64
				err   error
				sum   string
				reads []int
			}
			run := func(pooled bool) result {
				r := &nfqwsCopyReader{left: tc.size, chunk: tc.chunk, last: tc.last}
				h := sha256.New()
				var n int64
				var err error
				if pooled {
					n, err = nfqws2CopyManagedFile(h, io.LimitReader(r, tc.limit))
				} else {
					n, err = io.Copy(h, io.LimitReader(r, tc.limit))
				}
				return result{n, err, hex.EncodeToString(h.Sum(nil)), r.reads}
			}
			if a, b := run(false), run(true); !reflect.DeepEqual(a, b) {
				t.Fatalf("fresh copy changed: before=%+v after=%+v", a, b)
			}
		})
	}
}

type nfqwsCopyScratchReader struct {
	held   []byte
	panics bool
}

func (r *nfqwsCopyScratchReader) Read(p []byte) (int, error) {
	r.held = p
	for i := range p {
		p[i] = 0xa7
	}
	if r.panics {
		panic("original managed hash panic")
	}
	return 0, nfqwsCopyReadError
}
func TestNFQWSManagedCopyClearsScratch(t *testing.T) {
	for _, panics := range []bool{false, true} {
		r := &nfqwsCopyScratchReader{panics: panics}
		func() {
			defer func() {
				got := recover()
				if panics && got != "original managed hash panic" || !panics && got != nil {
					t.Fatal("panic changed", got)
				}
			}()
			if _, err := nfqws2CopyManagedFile(sha256.New(), r); !errors.Is(err, nfqwsCopyReadError) {
				t.Fatal(err)
			}
		}()
		if len(r.held) != 32768 || !bytes.Equal(r.held, make([]byte, 32768)) {
			t.Fatal("source bytes retained after release")
		}
	}
}

func TestNFQWSManagedCopyFreshFiles(t *testing.T) {
	root := t.TempDir()
	program, asset := filepath.Join(root, "program"), filepath.Join(root, "asset")
	payload := bytes.Repeat([]byte("actual fresh managed bytes\n"), 2000)
	sum := sha256.Sum256(payload)
	for _, path := range []string{program, asset} {
		if err := os.WriteFile(path, payload, 0700); err != nil {
			t.Fatal(err)
		}
	}
	command := nfqws2ManagedProcessCommand{Program: nfqws2ManagedFile{Path: program, SHA256: hex.EncodeToString(sum[:])}, Assets: []nfqws2ManagedFile{{Path: asset, SHA256: hex.EncodeToString(sum[:])}}}
	if err := nfqws2ManagedFilesCurrent(command); err != nil {
		t.Fatal("actual original files", err)
	}
	info, err := os.Stat(asset)
	if err != nil {
		t.Fatal(err)
	}
	changed := bytes.Clone(payload)
	changed[len(changed)-1] ^= 1
	if err := os.WriteFile(asset, changed, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(asset, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := nfqws2ManagedFilesCurrent(command); !errors.Is(err, ErrNFQWSManagedProcessUnknown) {
		t.Fatal("same-size fresh byte mutation accepted", err)
	}
	if err := os.WriteFile(asset, payload, 0700); err != nil {
		t.Fatal(err)
	}
	if err := nfqws2ManagedFilesCurrent(command); err != nil {
		t.Fatal("fresh restored bytes refused", err)
	}
	if err := os.Remove(asset); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(program, asset); err != nil {
		t.Fatal(err)
	}
	if err := nfqws2ManagedFilesCurrent(command); !errors.Is(err, ErrNFQWSManagedProcessUnknown) {
		t.Fatal("symlink accepted", err)
	}
	if err := os.Remove(asset); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(asset, bytes.Repeat([]byte{'x'}, (4<<20)+1), 0700); err != nil {
		t.Fatal(err)
	}
	if err := nfqws2ManagedFilesCurrent(command); !errors.Is(err, ErrNFQWSManagedProcessUnknown) {
		t.Fatal("oversized asset accepted", err)
	}
}

func TestNFQWSManagedCopyConcurrent(t *testing.T) {
	var workers sync.WaitGroup
	for i := 0; i < 16; i++ {
		workers.Add(1)
		go func(value byte) {
			defer workers.Done()
			data := bytes.Repeat([]byte{value}, 65537)
			want := sha256.Sum256(data)
			for pass := 0; pass < 8; pass++ {
				h := sha256.New()
				n, err := nfqws2CopyManagedFile(h, io.LimitReader(bytes.NewReader(data), int64(len(data))+1))
				if err != nil || n != int64(len(data)) || !bytes.Equal(h.Sum(nil), want[:]) {
					t.Error("scratch/source contamination", n, err)
				}
			}
		}(byte(i))
	}
	workers.Wait()
}

func BenchmarkNFQWSManagedCopy(b *testing.B) {
	for _, size := range []int{80, 32769, 1 << 20} {
		file, err := os.CreateTemp(b.TempDir(), "actual-source")
		if err != nil {
			b.Fatal(err)
		}
		defer file.Close()
		payload := bytes.Repeat([]byte{'x'}, size)
		expected := sha256.Sum256(payload)
		if _, err := file.Write(payload); err != nil {
			b.Fatal(err)
		}
		for _, pooled := range []bool{false, true} {
			label := map[bool]string{false: "before", true: "after"}[pooled]
			b.Run(fmt.Sprintf("bytes%d/%s", size, label), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(size))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := file.Seek(0, io.SeekStart); err != nil {
						b.Fatal(err)
					}
					h := sha256.New()
					source := io.LimitReader(file, (64<<20)+1)
					var n int64
					var err error
					if pooled {
						n, err = nfqws2CopyManagedFile(h, source)
					} else {
						n, err = io.Copy(h, source)
					}
					if err != nil || n != int64(size) || !bytes.Equal(h.Sum(nil), expected[:]) {
						b.Fatal("actual file hash", n, err)
					}
				}
			})
		}
	}
}
