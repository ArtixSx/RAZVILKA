package startuptools

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"testing"
)

// Measures complete reads of an actual retained descriptor, including the
// mandatory EOF check. Fixture creation and reference hashing are untimed.
func BenchmarkHashImage(b *testing.B) {
	for _, size := range []int{32 << 10, 1 << 20} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			file, err := os.CreateTemp(b.TempDir(), "held-image")
			if err != nil {
				b.Fatal(err)
			}
			defer file.Close()
			data := bytes.Repeat([]byte{0x5a}, size)
			if _, err := file.Write(data); err != nil {
				b.Fatal(err)
			}
			expected := sha256.Sum256(data)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				actual, err := hashImage(context.Background(), file, int64(size))
				if err != nil || actual != expected {
					b.Fatal("full hash mismatch", err)
				}
			}
		})
	}
}
