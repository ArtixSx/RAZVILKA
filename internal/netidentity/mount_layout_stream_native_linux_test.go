//go:build linux && (amd64 || arm64) && razvilka_native_fixture

package netidentity

import (
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
)

func BenchmarkProcMountLayoutStreamCandidate(b *testing.B) {
	file, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		b.Fatal(err)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxMountBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(data) == 0 || len(data) > maxMountBytes || data[len(data)-1] != '\n' {
		b.Fatal("bounded complete actual mountinfo required", readErr, closeErr)
	}
	var rootID uint64
	lines := 0
	for line := range strings.SplitSeq(string(data[:len(data)-1]), "\n") {
		lines++
		fields := strings.Fields(line)
		if len(fields) < 10 || len(line) > 65536 || lines > 8192 {
			b.Fatal("actual mountinfo field bounds")
		}
		if fields[3] == "/" && fields[4] == "/proc" {
			id, err := strconv.ParseUint(fields[0], 10, 64)
			if err != nil || id == 0 || rootID != 0 {
				b.Fatal("one actual proc root required")
			}
			rootID = id
		}
	}
	paths := []string{"/proc/self", "/proc/thread-self", "/proc/" + strconv.Itoa(os.Getpid()), "/proc/" + strconv.Itoa(os.Getpid()) + "/fdinfo", "/proc/sys/kernel/random/boot_id"}
	if rootID == 0 || !mountLayoutOK(data, rootID, paths) || !mountLayoutStreamCandidate(data, rootID, paths) {
		b.Fatal("actual complete parser parity refused")
	}
	// Both sides parse the same complete captured image. This measures parser
	// allocation/CPU only, never a fresh observation or full provider speed.
	for _, sample := range []struct {
		name  string
		parse func([]byte, uint64, []string) bool
	}{{"before_fields", mountLayoutOK}, {"stream_candidate", mountLayoutStreamCandidate}} {
		b.Run(sample.name, func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				if !sample.parse(data, rootID, paths) {
					b.Fatal("captured parser parity changed")
				}
			}
			b.ReportMetric(float64(len(data)), "captured-bytes/op")
			b.ReportMetric(float64(lines), "captured-lines/op")
		})
	}
}
