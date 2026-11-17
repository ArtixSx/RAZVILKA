//go:build linux && (amd64 || arm64) && razvilka_native_fixture

package netidentity

import (
	"io"
	"os"
	"strings"
	"testing"
)

func BenchmarkProcMountinfoUnescape(b *testing.B) {
	file, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		b.Fatal(err)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxMountBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(data) == 0 || len(data) > maxMountBytes || data[len(data)-1] != '\n' {
		b.Fatal("bounded complete actual mountinfo required", readErr, closeErr)
	}
	var paths []string
	for line := range strings.SplitSeq(string(data[:len(data)-1]), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 || len(line) > 65536 || len(paths) >= 2*8192 {
			b.Fatal("actual mountinfo field bounds")
		}
		paths = append(paths, fields[3], fields[4])
	}
	plain := 0
	for _, path := range paths {
		before, beforeOK := mountUnescapeBefore(path)
		after, afterOK := mountUnescape(path)
		if !beforeOK || before != after || beforeOK != afterOK {
			b.Fatal("actual root/point decoder parity")
		}
		if !strings.Contains(path, "\\") {
			plain++
		}
	}
	// Same captured actual field corpus for each side: decode-only allocation
	// evidence, never fresh kernel/provider, whole workflow or router proof.
	for _, sample := range []struct {
		name string
		read func(string) (string, bool)
	}{{"before_builder", mountUnescapeBefore}, {"plain_field", mountUnescape}} {
		b.Run(sample.name, func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				for _, path := range paths {
					if _, ok := sample.read(path); !ok {
						b.Fatal("actual field refused during paired measurement")
					}
				}
			}
			b.ReportMetric(float64(len(paths)), "paths/op")
			b.ReportMetric(float64(plain), "plain-paths/op")
		})
	}
}
