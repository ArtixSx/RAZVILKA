package strategylab

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

type compatibilityScratchFailure struct {
	buffer []byte
	cause  error
}

func (r *compatibilityScratchFailure) Read(p []byte) (int, error) {
	r.buffer = p
	for i := range p {
		p[i] = 0x7f
	}
	return len(p), r.cause
}

func TestCompatibilityFileScratchClearsOnReadFailure(t *testing.T) {
	cause := errors.New("original read failed")
	r := &compatibilityScratchFailure{cause: cause}
	n, err := compatibilityFileCopy(sha256.New(), r)
	if n != 32<<10 || !errors.Is(err, cause) {
		t.Fatal("original partial read or cause lost", n, err)
	}
	if len(r.buffer) != 32<<10 || !bytes.Equal(r.buffer, make([]byte, len(r.buffer))) {
		t.Fatal("read failure left payload bytes in reusable storage")
	}
}

func TestCompatibilityFileScratchConcurrentFreshContents(t *testing.T) {
	for worker := range 8 {
		t.Run(fmt.Sprint(worker), func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "actual.data")
			for iteration := range 6 {
				payload := bytes.Repeat([]byte{byte(worker*6 + iteration)}, 32765+iteration)
				if err := os.WriteFile(path, payload, 0600); err != nil {
					t.Fatal(err)
				}
				actual, err := compatibilityFileBindingAt(path, int64(len(payload)))
				want := sha256.Sum256(payload)
				if err != nil || actual.SHA256 != hex.EncodeToString(want[:]) || actual.Size != int64(len(payload)) {
					t.Fatal("fresh file bytes were not independently hashed", actual, err)
				}
				if _, err := compatibilityFileBindingAt(path, int64(len(payload)-1)); err == nil {
					t.Fatal("oversized file admitted")
				}
			}
		})
	}
}

// Matched in-memory copy only. This is allocation evidence, not a native
// workflow, file-ownership, router RAM or end-to-end performance benchmark.
func BenchmarkCompatibilityFileCopyScratch(b *testing.B) {
	data := bytes.Repeat([]byte{0x35}, 65537)
	for _, pooled := range []bool{false, true} {
		b.Run(fmt.Sprint(pooled), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(data)))
			for b.Loop() {
				r := io.LimitReader(bytes.NewReader(data), int64(len(data)+1))
				h := sha256.New()
				var n int64
				var err error
				if pooled {
					n, err = compatibilityFileCopy(h, r)
				} else {
					n, err = io.Copy(h, r)
				}
				if err != nil || n != int64(len(data)) {
					b.Fatal(n, err)
				}
			}
		})
	}
}
