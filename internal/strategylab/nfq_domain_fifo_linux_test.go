//go:build linux

package strategylab

import (
	"context"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// Actual file/FIFO syscalls only; no source, component, native child or packet
// authority. The outer private test child bounds any accidental blocking open.
func TestNFQDomainWriterlessFIFORefusalIsBounded(t *testing.T) {
	const key = "RAZVILKA_NFQ_DOMAIN_FIFO_TEST_CHILD"
	if os.Getenv(key) == "1" {
		f, review, _ := nfqDomainReviewFixture(t)
		if err := os.Remove(f.include.Path); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(f.include.Path, 0400); err != nil {
			t.Fatal(err)
		}
		if f.current() == nil || compatibilityDomainFilesCurrent(*review.Domain) == nil {
			t.Fatal("FIFO became immutable material")
		}
		return
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestNFQDomainWriterlessFIFORefusalIsBounded$", "-test.count=1")
	cmd.Env = append(os.Environ(), key+"=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bounded FIFO refusal: %v %s", err, out)
	}
}
