package startuptools

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"testing"
)

func TestHashImageConcurrentFreshBytesAndFailures(t *testing.T) {
	for worker := range 8 {
		t.Run(fmt.Sprint(worker), func(t *testing.T) {
			t.Parallel()
			file, err := os.CreateTemp(t.TempDir(), "original")
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			for iteration := range 12 {
				data := bytes.Repeat([]byte{byte(worker*12 + iteration)}, 32768+worker*73+iteration)
				if err := file.Truncate(0); err != nil {
					t.Fatal(err)
				}
				if _, err := file.WriteAt(data, 0); err != nil {
					t.Fatal(err)
				}
				actual, err := hashImage(context.Background(), file, int64(len(data)))
				if err != nil || actual != sha256.Sum256(data) {
					t.Fatal("fresh whole bytes lost", err)
				}
				if _, err := hashImage(context.Background(), file, int64(len(data)-1)); err == nil {
					t.Fatal("extra byte admitted")
				}
				if _, err := hashImage(context.Background(), file, int64(len(data)+1)); err == nil {
					t.Fatal("short file admitted")
				}
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				if _, err := hashImage(ctx, file, int64(len(data))); !errors.Is(err, context.Canceled) {
					t.Fatal("cancellation lost", err)
				}
			}
		})
	}
}
