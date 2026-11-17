//go:build linux && (amd64 || arm64) && razvilka_native_fixture

package startuptools

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func nc1812HintFixture(t *testing.T) (*heldReview, []byte) {
	t.Helper()
	r := cpuidCaptureFixture(t, "arm64") // Proves private /opt before any write.
	if err := os.Mkdir("/opt/sbin", 0700); err != nil {
		t.Fatal("exclusive private fixture directory", err)
	}
	t.Cleanup(func() {
		// The full-capture negative can retain this file even on refusal.
		// Close it before removing our exclusive directory; the original
		// protected-scratch cleanup subsequently sees an empty image set.
		if err := r.close(); err != nil {
			t.Error(err)
		}
		clear(r.images)
		if err := os.RemoveAll("/opt/sbin"); err != nil {
			t.Error(err)
		}
	})
	raw := elfFixture(r.profile.loader, nil)
	if err := os.WriteFile("/opt/sbin/xtables-multi", raw, 0700); err != nil {
		t.Fatal(err)
	}
	r.profile.main = "/opt/sbin/xtables-multi"
	r.profile.aliases = [2]string{r.profile.main, r.profile.main}
	r.profile.mainSHA = fmt.Sprintf("%x", sha256.Sum256(raw))
	return r, raw
}

func nc1812HintOpenFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, e := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name()))
		if err == nil && strings.HasPrefix(target, "/opt/sbin/xtables-multi") {
			count++
		}
	}
	return count
}

func TestNC1812SelectionNativeHintAndIndependentCapture(t *testing.T) {
	r, raw := nc1812HintFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
	defer cancel()
	before := nc1812HintOpenFDs(t)
	digest, err := readNC1812MainHint(ctx)
	if err != nil || digest != fmt.Sprintf("%x", sha256.Sum256(raw)) {
		t.Fatal("actual bounded hint", err)
	}
	if nc1812HintOpenFDs(t) != before {
		t.Fatal("hint retained an executable FD")
	}
	if _, err := nc1812ProfileForHint(digest, nc1812BaseTools); err == nil {
		t.Fatal("synthetic bytes selected real package profile")
	}
	// Exercise the exact full-capture MAIN_PIN boundary independently; the
	// synthetic ELF is never executed and no vendor identity is fabricated.
	if err := os.WriteFile(r.profile.main, append(raw, 0), 0700); err != nil {
		t.Fatal(err)
	}
	if err := r.capture(ctx); err == nil || !strings.Contains(err.Error(), "MAIN_PIN") {
		t.Fatal("full capture reused hint bytes", err)
	}
}

type nc1812HintMutationContext struct {
	context.Context
	calls  int
	mutate func()
}

func (c *nc1812HintMutationContext) Err() error {
	c.calls++
	// Small fixture: first context check, one hash chunk, then the original
	// hash's closing check. Mutation is after the hash, before FD/path closing.
	if c.calls == 3 {
		c.mutate()
	}
	return c.Context.Err()
}

func TestNC1812SelectionNativeHintClosingRefuses(t *testing.T) {
	for _, cut := range []string{"bytes", "same-bytes-replacement", "cancel"} {
		t.Run(cut, func(t *testing.T) {
			r, raw := nc1812HintFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
			defer cancel()
			before := nc1812HintOpenFDs(t)
			mutated := false
			wrapped := &nc1812HintMutationContext{Context: ctx, mutate: func() {
				mutated = true
				var err error
				switch cut {
				case "bytes":
					err = os.WriteFile(r.profile.main, append(raw, 0), 0700)
				case "same-bytes-replacement":
					tmp := "/opt/sbin/replacement"
					err = os.WriteFile(tmp, raw, 0700)
					if err == nil {
						err = os.Rename(tmp, r.profile.main)
					}
				case "cancel":
					cancel()
				}
				if err != nil {
					t.Fatal(err)
				}
			}}
			if digest, err := readNC1812MainHint(wrapped); digest != "" || err == nil || !mutated {
				t.Fatal("closing drift accepted", err, mutated)
			}
			if nc1812HintOpenFDs(t) != before {
				t.Fatal("refusal leaked hint FD")
			}
		})
	}
}

func TestNC1812SelectionNativeProtectedHintRefusals(t *testing.T) {
	for _, cut := range []string{"uid1001", "writable-parent", "empty", "oversize", "non-executable", "canceled"} {
		t.Run(cut, func(t *testing.T) {
			r, _ := nc1812HintFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
			defer cancel()
			var err error
			switch cut {
			case "uid1001":
				err = os.Chown("/opt/sbin", 1001, 1001)
			case "writable-parent":
				err = os.Chmod("/opt/sbin", 0777)
			case "empty":
				err = os.Truncate(r.profile.main, 0)
			case "oversize":
				err = os.Truncate(r.profile.main, maxImageBytes+1)
			case "non-executable":
				err = os.Chmod(r.profile.main, 0600)
			case "canceled":
				cancel()
			}
			if err != nil {
				t.Fatal(err)
			}
			if digest, err := readNC1812MainHint(ctx); digest != "" || err == nil {
				t.Fatal("unsafe hint admitted")
			}
		})
	}
}

func TestNC1812SelectionNativeConsumedBudgetRefusesAcquire(t *testing.T) {
	p := profile{arch: runtime.GOARCH}
	lease, err := acquireWithDeadline(context.Background(), netidentity.NewProcProvider(), p, time.Now().Add(-time.Second))
	if lease != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("chosen acquire renewed exhausted hint budget", err)
	}
}
