//go:build linux && (amd64 || arm64)

package netidentity

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"
)

func TestBoundedReadKeepsExactReadAndEOFBounds(t *testing.T) {
	for _, size := range []int{0, 1, 63, 64, 65, 511, 512, 513, 4095, 4096, 4097, 65536} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			data := bytes.Repeat([]byte{0xa5}, size)
			for _, limit := range []int{size, size + 1, 1 << 20, max(0, size-1)} {
				file, err := os.CreateTemp(t.TempDir(), "actual")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := file.Write(data); err != nil {
					t.Fatal(err)
				}
				if _, err := file.Seek(0, 0); err != nil {
					t.Fatal(err)
				}
				actual, ok := boundedRead(context.Background(), int(file.Fd()), limit)
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
				if ok != (size <= limit) || ok && !bytes.Equal(actual, data) || !ok && actual != nil {
					t.Fatalf("size=%d limit=%d accepted=%v returned=%d", size, limit, ok, len(actual))
				}
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if data, ok := boundedRead(ctx, -1, 4096); ok || data != nil {
		t.Fatal("canceled read accepted")
	}
	if data, ok := boundedRead(context.Background(), -1, 4096); ok || data != nil {
		t.Fatal("bad descriptor accepted")
	}
}
