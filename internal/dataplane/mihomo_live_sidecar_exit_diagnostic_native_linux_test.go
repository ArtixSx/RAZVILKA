//go:build linux && razvilka_native_fixture

package dataplane

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

func TestMihomoSidecarExitDiagnosticWaitPublication(t *testing.T) {
	for _, tc := range []struct {
		name, command string
		code, signal  int
	}{
		{"success", "exit 0", 0, 0}, {"failure", "exit 7", 7, 0}, {"signal", "kill -TERM $$", -1, 15},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			n := &mihomoLiveSidecar{done: make(chan struct{}), started: true}
			n.self = n
			cmd := exec.CommandContext(ctx, "/bin/sh", "-c", tc.command)
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			go func() { n.waitErr = cmd.Wait(); n.state = cmd.ProcessState; close(n.done) }()
			// Reads before publication must not touch state; race mode validates
			// the same original done-channel publication boundary.
			for i := 0; i < 100; i++ {
				mihomoLiveSidecarExitSummary(n)
			}
			<-n.done
			available, code, signal := mihomoLiveSidecarExitSummary(n)
			if !available || code != tc.code || signal != tc.signal {
				t.Fatalf("unexpected bounded result: %t %d %d", available, code, signal)
			}
			copied := &mihomoLiveSidecar{self: n, started: true, done: n.done, state: n.state}
			if available, _, _ := mihomoLiveSidecarExitSummary(copied); available {
				t.Fatal("copied diagnostic owner accepted")
			}
		})
	}
	n := &mihomoLiveSidecar{done: make(chan struct{}), started: true}
	n.self = n
	for _, value := range []*mihomoLiveSidecar{nil, n} {
		if available, code, signal := mihomoLiveSidecarExitSummary(value); available || code != 0 || signal != 0 {
			t.Fatal("unjoined state reported")
		}
	}
	close(n.done)
	if available, _, _ := mihomoLiveSidecarExitSummary(n); available {
		t.Fatal("absent process state reported")
	}
}
